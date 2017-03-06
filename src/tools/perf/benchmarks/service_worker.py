# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import collections
import page_sets
import re

from core import perf_benchmark

from telemetry import benchmark
from telemetry.core import util
from telemetry.page import legacy_page_test
from telemetry.timeline import async_slice as async_slice_module
from telemetry.timeline import slice as slice_module
from telemetry.value import scalar

from measurements import timeline_controller
from metrics import speedindex


class _ServiceWorkerTimelineMetric(object):

  def AddResultsOfCounters(self, process, counter_regex_string, results):
    counter_filter = re.compile(counter_regex_string)
    for counter_name, counter in process.counters.iteritems():
      if not counter_filter.search(counter_name):
        continue

      total = sum(counter.totals)

      # Results objects cannot contain the '.' character, so remove that here.
      sanitized_counter_name = counter_name.replace('.', '_')

      results.AddValue(scalar.ScalarValue(
          results.current_page, sanitized_counter_name, 'count', total))
      results.AddValue(scalar.ScalarValue(
          results.current_page, sanitized_counter_name + '_avg', 'count',
          total / float(len(counter.totals))))

  def AddResultsOfEvents(
      self, process, thread_regex_string, event_regex_string, results):
    thread_filter = re.compile(thread_regex_string)
    event_filter = re.compile(event_regex_string)

    for thread in process.threads.itervalues():
      thread_name = thread.name.replace('/', '_')
      if not thread_filter.search(thread_name):
        continue

      filtered_events = []
      for event in thread.IterAllEvents():
        event_name = event.name.replace('.', '_')
        if event_filter.search(event_name):
          filtered_events.append(event)

      async_events_by_name = collections.defaultdict(list)
      sync_events_by_name = collections.defaultdict(list)
      for event in filtered_events:
        if isinstance(event, async_slice_module.AsyncSlice):
          async_events_by_name[event.name].append(event)
        elif isinstance(event, slice_module.Slice):
          sync_events_by_name[event.name].append(event)

      for event_name, event_group in async_events_by_name.iteritems():
        times = [e.duration for e in event_group]
        self._AddResultOfEvent(thread_name, event_name, times, results)

      for event_name, event_group in sync_events_by_name.iteritems():
        times = [e.self_time for e in event_group]
        self._AddResultOfEvent(thread_name, event_name, times, results)

  def _AddResultOfEvent(self, thread_name, event_name, times, results):
    total = sum(times)
    biggest_jank = max(times)

    # Results objects cannot contain the '.' character, so remove that here.
    sanitized_event_name = event_name.replace('.', '_')

    full_name = thread_name + '|' + sanitized_event_name
    results.AddValue(scalar.ScalarValue(
        results.current_page, full_name, 'ms', total))
    results.AddValue(scalar.ScalarValue(
        results.current_page, full_name + '_max', 'ms', biggest_jank))
    results.AddValue(scalar.ScalarValue(
        results.current_page, full_name + '_avg', 'ms', total / len(times)))


class _ServiceWorkerMeasurement(legacy_page_test.LegacyPageTest):
  """Measure Speed Index and TRACE_EVENTs"""

  def __init__(self):
    super(_ServiceWorkerMeasurement, self).__init__()
    self._timeline_controller = timeline_controller.TimelineController()
    self._speed_index = speedindex.SpeedIndexMetric()
    self._page_open_times = collections.defaultdict(int)

  def DidRunPage(self, platform):
    if platform.tracing_controller.is_tracing_running:
      platform.tracing_controller.StopTracing()

  def WillNavigateToPage(self, page, tab):
    self._timeline_controller.SetUp(page, tab)
    self._timeline_controller.Start(tab)
    self._speed_index.Start(page, tab)

  def ValidateAndMeasurePage(self, page, tab, results):
    # timeline_controller requires creation of at least a single interaction
    # record. service_worker should be refactored to follow the
    # timeline_based_measurement or it should not re-use timeline_controller
    # logic for start & stop tracing.
    with tab.action_runner.CreateInteraction('_DummyInteraction'):
      pass
    tab.WaitForDocumentReadyStateToBeComplete(40)
    self._timeline_controller.Stop(tab, results)

    # Retrieve TRACE_EVENTs
    timeline_metric = _ServiceWorkerTimelineMetric()
    browser_process = self._timeline_controller.model.browser_process
    filter_text = '(RegisterServiceWorker|'\
                  'UnregisterServiceWorker|'\
                  'ProcessAllocate|'\
                  'FindRegistrationForDocument|'\
                  'DispatchFetchEvent)'
    timeline_metric.AddResultsOfEvents(
        browser_process, 'IOThread', filter_text, results)

    # Record Speed Index
    def SpeedIndexIsFinished():
      return self._speed_index.IsFinished(tab)
    util.WaitFor(SpeedIndexIsFinished, 60)
    self._speed_index.Stop(page, tab)
    # Distinguish the first and second load from the subsequent loads
    url = str(page)
    chart_prefix = 'page_load'
    self._page_open_times[url] += 1
    if self._page_open_times[url] == 1:
      chart_prefix += '_1st'
    elif self._page_open_times[url] == 2:
      chart_prefix += '_2nd'
    else:
      chart_prefix += '_later'
    self._speed_index.AddResults(tab, results, chart_prefix)


class _ServiceWorkerMicroBenchmarkMeasurement(legacy_page_test.LegacyPageTest):
  """Record results reported by the JS microbenchmark."""

  def __init__(self):
    super(_ServiceWorkerMicroBenchmarkMeasurement, self).__init__()

  def ValidateAndMeasurePage(self, page, tab, results):
    del page  # unused
    tab.WaitForJavaScriptCondition('window.done', timeout=40)
    json = tab.EvaluateJavaScript('window.results || {}')
    for key, value in json.iteritems():
      results.AddValue(scalar.ScalarValue(
          results.current_page, key, value['units'], value['value']))


class ServiceWorkerPerfTest(perf_benchmark.PerfBenchmark):
  """Performance test of pages using ServiceWorker.

  The page set contains pages like Trained to Thrill and svgomg.
  Execution time of these pages will be shown as Speed Index, and TRACE_EVENTs
  are subsidiary information to understand performance regressions in more
  detail.
  """
  test = _ServiceWorkerMeasurement
  page_set = page_sets.ServiceWorkerPageSet

  @classmethod
  def Name(cls):
    return 'service_worker.service_worker'


@benchmark.Disabled('android-webview')  # http://crbug.com/653924
class ServiceWorkerMicroBenchmarkPerfTest(perf_benchmark.PerfBenchmark):
  """This test is a microbenchmark of service worker.

  The page set is a benchmark page that generates many concurrent requests
  handled by a service worker that does respondWith(new Response()). The test
  result is the response times.
  """
  test = _ServiceWorkerMicroBenchmarkMeasurement
  page_set = page_sets.ServiceWorkerMicroBenchmarkPageSet

  @classmethod
  def Name(cls):
    return 'service_worker.service_worker_micro_benchmark'

  @classmethod
  def ShouldDisable(cls, possible_browser):  # http://crbug.com/597656
      return (possible_browser.browser_type == 'reference' and
              possible_browser.platform.GetDeviceTypeName() == 'Nexus 5X')
