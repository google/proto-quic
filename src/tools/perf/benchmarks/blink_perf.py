# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os

from core import path_util
from core import perf_benchmark

from page_sets import webgl_supported_shared_state

from telemetry import benchmark
from telemetry import page as page_module
from telemetry.page import legacy_page_test
from telemetry.page import shared_page_state
from telemetry import story
from telemetry.timeline import bounds
from telemetry.timeline import model as model_module
from telemetry.timeline import tracing_config

from telemetry.value import list_of_scalar_values
from telemetry.value import trace


BLINK_PERF_BASE_DIR = os.path.join(path_util.GetChromiumSrcDir(),
                                   'third_party', 'WebKit', 'PerformanceTests')
SKIPPED_FILE = os.path.join(BLINK_PERF_BASE_DIR, 'Skipped')


def CreateStorySetFromPath(path, skipped_file,
                           shared_page_state_class=(
                               shared_page_state.SharedPageState)):
  assert os.path.exists(path)

  page_urls = []
  serving_dirs = set()

  def _AddPage(path):
    if not path.endswith('.html'):
      return
    if '../' in open(path, 'r').read():
      # If the page looks like it references its parent dir, include it.
      serving_dirs.add(os.path.dirname(os.path.dirname(path)))
    page_urls.append('file://' + path.replace('\\', '/'))

  def _AddDir(dir_path, skipped):
    for candidate_path in os.listdir(dir_path):
      if candidate_path == 'resources':
        continue
      candidate_path = os.path.join(dir_path, candidate_path)
      if candidate_path.startswith(skipped):
        continue
      if os.path.isdir(candidate_path):
        _AddDir(candidate_path, skipped)
      else:
        _AddPage(candidate_path)

  if os.path.isdir(path):
    skipped = []
    if os.path.exists(skipped_file):
      for line in open(skipped_file, 'r').readlines():
        line = line.strip()
        if line and not line.startswith('#'):
          skipped_path = os.path.join(os.path.dirname(skipped_file), line)
          skipped.append(skipped_path.replace('/', os.sep))
    _AddDir(path, tuple(skipped))
  else:
    _AddPage(path)
  ps = story.StorySet(base_dir=os.getcwd() + os.sep,
                      serving_dirs=serving_dirs)
  for url in page_urls:
    ps.AddStory(page_module.Page(
        url, ps, ps.base_dir,
        shared_page_state_class=shared_page_state_class))
  return ps


def _ComputeTraceEventsThreadTimeForBlinkPerf(
    model, renderer_thread, trace_events_to_measure):
  """ Compute the CPU duration for each of |trace_events_to_measure| during
  blink_perf test.

  Args:
    renderer_thread: the renderer thread which run blink_perf test.
    trace_events_to_measure: a list of string names of trace events to measure
    CPU duration for.

  Returns:
    a dictionary in which each key is a trace event' name (from
    |trace_events_to_measure| list), and value is a list of numbers that
    represents to total cpu time of that trace events in each blink_perf test.
  """
  trace_cpu_time_metrics = {}

  # Collect the bounds of "blink_perf.runTest" events.
  test_runs_bounds = []
  for event in renderer_thread.async_slices:
    if event.name == "blink_perf.runTest":
      test_runs_bounds.append(bounds.Bounds.CreateFromEvent(event))
  test_runs_bounds.sort(key=lambda b: b.min)

  for t in trace_events_to_measure:
    trace_cpu_time_metrics[t] = [0.0] * len(test_runs_bounds)

  for event_name in trace_events_to_measure:
    curr_test_runs_bound_index = 0
    prev_event = None
    for event in model.IterAllEventsOfName(event_name):
      if prev_event and prev_event.end >= event.start:
        continue
      while (curr_test_runs_bound_index < len(test_runs_bounds) and
             event.start > test_runs_bounds[curr_test_runs_bound_index].max):
        curr_test_runs_bound_index += 1
      if curr_test_runs_bound_index >= len(test_runs_bounds):
        break
      curr_test_bound = test_runs_bounds[curr_test_runs_bound_index]
      intersect_wall_time = bounds.Bounds.GetOverlapBetweenBounds(
          curr_test_bound, bounds.Bounds.CreateFromEvent(event))
      if event.thread_duration and event.duration:
        intersect_cpu_time = (
            intersect_wall_time * event.thread_duration / event.duration)
      else:
        intersect_cpu_time = intersect_wall_time
      trace_cpu_time_metrics[event_name][curr_test_runs_bound_index] += (
          intersect_cpu_time)
      prev_event = event
  return trace_cpu_time_metrics


class _BlinkPerfMeasurement(legacy_page_test.LegacyPageTest):
  """Tuns a blink performance test and reports the results."""

  def __init__(self):
    super(_BlinkPerfMeasurement, self).__init__()
    with open(os.path.join(os.path.dirname(__file__),
                           'blink_perf.js'), 'r') as f:
      self._blink_perf_js = f.read()

  def WillNavigateToPage(self, page, tab):
    del tab  # unused
    page.script_to_evaluate_on_commit = self._blink_perf_js

  def CustomizeBrowserOptions(self, options):
    options.AppendExtraBrowserArgs([
        '--js-flags=--expose_gc',
        '--enable-experimental-web-platform-features',
        # Note that both this flag:
        '--ignore-autoplay-restrictions',
        # and this flag:
        '--disable-gesture-requirement-for-media-playback',
        # should be used until every build from
        # ToT to Stable switches over to one flag or another. This is to support
        # reference builds.
        # --disable-gesture-requirement-for-media-playback is the old one and
        # can be removed after M60 goes to stable.
        '--enable-experimental-canvas-features',
        # TODO(qinmin): After fixing crbug.com/592017, remove this command line.
        '--reduce-security-for-testing'
    ])

  def SetOptions(self, options):
    super(_BlinkPerfMeasurement, self).SetOptions(options)
    if 'content-shell' in options.browser_options.browser_type:
      options.AppendExtraBrowserArgs('--expose-internals-for-testing')

  def _ContinueTestRunWithTracing(self, tab):
    tracing_categories = tab.EvaluateJavaScript(
        'testRunner.tracingCategories')
    config = tracing_config.TracingConfig()
    config.enable_chrome_trace = True
    config.chrome_trace_config.category_filter.AddFilterString(
        'blink.console')  # This is always required for js land trace event
    config.chrome_trace_config.category_filter.AddFilterString(
        tracing_categories)
    tab.browser.platform.tracing_controller.StartTracing(config)
    tab.EvaluateJavaScript('testRunner.scheduleTestRun()')
    tab.WaitForJavaScriptCondition('testRunner.isDone')
    return tab.browser.platform.tracing_controller.StopTracing()


  def PrintAndCollectTraceEventMetrics(self, trace_cpu_time_metrics, results):
    unit = 'ms'
    print
    for trace_event_name, cpu_times in trace_cpu_time_metrics.iteritems():
      print 'CPU times of trace event "%s":' % trace_event_name
      cpu_times_string = ', '.join(['{0:.10f}'.format(t) for t in cpu_times])
      print 'values %s %s' % (cpu_times_string, unit)
      avg = 0.0
      if cpu_times:
        avg = sum(cpu_times)/len(cpu_times)
      print 'avg', '{0:.10f}'.format(avg), unit
      results.AddValue(list_of_scalar_values.ListOfScalarValues(
          results.current_page, name=trace_event_name, units=unit,
          values=cpu_times))
      print
    print '\n'

  def ValidateAndMeasurePage(self, page, tab, results):
    tab.WaitForJavaScriptCondition(
        'testRunner.isDone || testRunner.isWaitingForTracingStart', timeout=600)
    trace_cpu_time_metrics = {}
    if tab.EvaluateJavaScript('testRunner.isWaitingForTracingStart'):
      trace_data = self._ContinueTestRunWithTracing(tab)
      trace_value = trace.TraceValue(page, trace_data)
      results.AddValue(trace_value)

      trace_events_to_measure = tab.EvaluateJavaScript(
          'window.testRunner.traceEventsToMeasure')
      model = model_module.TimelineModel(trace_data)
      renderer_thread = model.GetRendererThreadFromTabId(tab.id)
      trace_cpu_time_metrics = _ComputeTraceEventsThreadTimeForBlinkPerf(
          model, renderer_thread, trace_events_to_measure)

    log = tab.EvaluateJavaScript('document.getElementById("log").innerHTML')

    for line in log.splitlines():
      if line.startswith("FATAL: "):
        print line
        continue
      if not line.startswith('values '):
        continue
      parts = line.split()
      values = [float(v.replace(',', '')) for v in parts[1:-1]]
      units = parts[-1]
      metric = page.display_name.split('.')[0].replace('/', '_')
      results.AddValue(list_of_scalar_values.ListOfScalarValues(
          results.current_page, metric, units, values))

      break

    print log

    self.PrintAndCollectTraceEventMetrics(trace_cpu_time_metrics, results)


class _BlinkPerfBenchmark(perf_benchmark.PerfBenchmark):

  test = _BlinkPerfMeasurement

  @classmethod
  def Name(cls):
    return 'blink_perf.' + cls.tag

  def CreateStorySet(self, options):
    path = os.path.join(BLINK_PERF_BASE_DIR, self.subdir)
    return CreateStorySetFromPath(path, SKIPPED_FILE)


@benchmark.Owner(emails=['yukishiino@chromium.org',
                         'bashi@chromium.org',
                         'haraken@chromium.org'])
class BlinkPerfBindings(_BlinkPerfBenchmark):
  tag = 'bindings'
  subdir = 'Bindings'


@benchmark.Enabled('content-shell')
class BlinkPerfBlinkGC(_BlinkPerfBenchmark):
  tag = 'blink_gc'
  subdir = 'BlinkGC'


@benchmark.Owner(emails=['rune@opera.com'])
class BlinkPerfCSS(_BlinkPerfBenchmark):
  tag = 'css'
  subdir = 'CSS'


@benchmark.Disabled('android', # http://crbug.com/685320
                    'android-webview') # http://crbug.com/593200
@benchmark.Owner(emails=['junov@chromium.org'])
class BlinkPerfCanvas(_BlinkPerfBenchmark):
  tag = 'canvas'
  subdir = 'Canvas'

  @classmethod
  def ShouldDisable(cls, possible_browser):
    return cls.IsSvelte(possible_browser)  # http://crbug.com/593973.

  def CreateStorySet(self, options):
    path = os.path.join(BLINK_PERF_BASE_DIR, self.subdir)
    story_set = CreateStorySetFromPath(
        path, SKIPPED_FILE,
        shared_page_state_class=(
            webgl_supported_shared_state.WebGLSupportedSharedState))
    # WebGLSupportedSharedState requires the skipped_gpus property to
    # be set on each page.
    for page in story_set:
      page.skipped_gpus = []
    return story_set

  def SetExtraBrowserOptions(self, options):
    options.AppendExtraBrowserArgs([
        '--enable-color-correct-rendering',
    ])

@benchmark.Owner(emails=['yukishiino@chromium.org',
                         'bashi@chromium.org',
                         'haraken@chromium.org'])
class BlinkPerfDOM(_BlinkPerfBenchmark):
  tag = 'dom'
  subdir = 'DOM'


@benchmark.Owner(emails=['hayato@chromium.org'])
class BlinkPerfEvents(_BlinkPerfBenchmark):
  tag = 'events'
  subdir = 'Events'


@benchmark.Disabled('win8')  # http://crbug.com/462350
@benchmark.Owner(emails=['eae@chromium.org'])
class BlinkPerfLayout(_BlinkPerfBenchmark):
  tag = 'layout'
  subdir = 'Layout'

  @classmethod
  def ShouldDisable(cls, possible_browser):
    return cls.IsSvelte(possible_browser)  # http://crbug.com/551950


@benchmark.Owner(emails=['wangxianzhu@chromium.org'])
class BlinkPerfPaint(_BlinkPerfBenchmark):
  tag = 'paint'
  subdir = 'Paint'

  @classmethod
  def ShouldDisable(cls, possible_browser):
    return cls.IsSvelte(possible_browser)  # http://crbug.com/574483


@benchmark.Disabled('win')  # crbug.com/488493
@benchmark.Owner(emails=['yukishiino@chromium.org',
                         'bashi@chromium.org',
                         'haraken@chromium.org'])
class BlinkPerfParser(_BlinkPerfBenchmark):
  tag = 'parser'
  subdir = 'Parser'


@benchmark.Owner(emails=['kouhei@chromium.org', 'fs@opera.com'])
class BlinkPerfSVG(_BlinkPerfBenchmark):
  tag = 'svg'
  subdir = 'SVG'


@benchmark.Owner(emails=['hayato@chromium.org'])
class BlinkPerfShadowDOM(_BlinkPerfBenchmark):
  tag = 'shadow_dom'
  subdir = 'ShadowDOM'

  @classmethod
  def ShouldDisable(cls, possible_browser):  # http://crbug.com/702319
    return possible_browser.platform.GetDeviceTypeName() == 'Nexus 5X'
