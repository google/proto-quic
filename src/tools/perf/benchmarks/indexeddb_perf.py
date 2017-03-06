# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Runs Chromium's IndexedDB performance test. These test:

Databases:
  create/delete
Keys:
  create/delete
Indexes:
  create/delete
Data access:
  Random read/write
  Read cache
Cursors:
  Read & random writes
  Walking multiple
  Seeking.
"""

import json
import os

from core import path_util
from core import perf_benchmark

from telemetry import benchmark
from telemetry import page as page_module
from telemetry import story
from telemetry.page import legacy_page_test
from telemetry.value import scalar

from metrics import memory
from metrics import power

import page_sets

from telemetry.timeline import chrome_trace_category_filter
from telemetry.web_perf import timeline_based_measurement


IDB_CATEGORY = 'IndexedDB'
TIMELINE_REQUIRED_CATEGORY = 'blink.console'


class _IndexedDbMeasurement(legacy_page_test.LegacyPageTest):

  def __init__(self):
    super(_IndexedDbMeasurement, self).__init__()
    self._memory_metric = None
    self._power_metric = None

  def WillStartBrowser(self, platform):
    """Initialize metrics once right before the browser has been launched."""
    self._power_metric = power.PowerMetric(platform)

  def DidStartBrowser(self, browser):
    """Initialize metrics once right after the browser has been launched."""
    self._memory_metric = memory.MemoryMetric(browser)

  def DidNavigateToPage(self, page, tab):
    self._memory_metric.Start(page, tab)
    self._power_metric.Start(page, tab)

  def ValidateAndMeasurePage(self, page, tab, results):
    tab.WaitForDocumentReadyStateToBeComplete()
    tab.WaitForJavaScriptCondition('window.done', timeout=600)

    self._power_metric.Stop(page, tab)
    self._memory_metric.Stop(page, tab)

    self._memory_metric.AddResults(tab, results)
    self._power_metric.AddResults(tab, results)

    result_dict = json.loads(tab.EvaluateJavaScript(
        'JSON.stringify(automation.getResults());'))
    total = 0.0
    for key in result_dict:
      if key == 'OverallTestDuration':
        continue
      msec = float(result_dict[key])
      results.AddValue(scalar.ScalarValue(
          results.current_page, key, 'ms', msec, important=False))

      total += msec
    results.AddValue(scalar.ScalarValue(
        results.current_page, 'Total Perf', 'ms', total))

  def CustomizeBrowserOptions(self, options):
    memory.MemoryMetric.CustomizeBrowserOptions(options)
    power.PowerMetric.CustomizeBrowserOptions(options)


@benchmark.Disabled('linux') # crbug.com/677972
class IndexedDbOriginal(perf_benchmark.PerfBenchmark):
  """Chromium's IndexedDB Performance tests."""
  test = _IndexedDbMeasurement

  @classmethod
  def Name(cls):
    return 'indexeddb_perf'

  def CreateStorySet(self, options):
    indexeddb_dir = os.path.join(path_util.GetChromiumSrcDir(), 'chrome',
                                 'test', 'data', 'indexeddb')
    ps = story.StorySet(base_dir=indexeddb_dir)
    ps.AddStory(page_module.Page('file://perf_test.html', ps, ps.base_dir))
    return ps


@benchmark.Disabled('linux') # crbug.com/677972
class IndexedDbOriginalSectioned(perf_benchmark.PerfBenchmark):
  """Chromium's IndexedDB Performance tests."""
  test = _IndexedDbMeasurement
  page_set = page_sets.IndexedDBEndurePageSet

  @classmethod
  def Name(cls):
    return 'storage.indexeddb_endure'


@benchmark.Disabled('linux') # crbug.com/677972
class IndexedDbTracing(perf_benchmark.PerfBenchmark):
  """IndexedDB Performance tests that use tracing."""
  page_set = page_sets.IndexedDBEndurePageSet

  def CreateTimelineBasedMeasurementOptions(self):
    cat_filter = chrome_trace_category_filter.ChromeTraceCategoryFilter()
    cat_filter.AddIncludedCategory(IDB_CATEGORY)
    cat_filter.AddIncludedCategory(TIMELINE_REQUIRED_CATEGORY)

    return timeline_based_measurement.Options(
        overhead_level=cat_filter)

  @classmethod
  def Name(cls):
    return 'storage.indexeddb_endure_tracing'

  @classmethod
  def ValueCanBeAddedPredicate(cls, value, is_first_result):
    return 'idb' in value.name
