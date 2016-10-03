# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry.page import legacy_page_test
from telemetry.timeline import chrome_trace_category_filter
from telemetry.web_perf import timeline_based_measurement
from telemetry.web_perf.metrics import smoothness


class _CustomResultsWrapper(timeline_based_measurement.ResultsWrapperInterface):

  def __init__(self):
    super(_CustomResultsWrapper, self).__init__()
    self._pages_to_tir_labels = {}

  def _AssertNewValueHasSameInteractionLabel(self, new_value):
    tir_label = self._pages_to_tir_labels.get(new_value.page)
    if tir_label:
      assert tir_label == self._tir_label, (
          'Smoothness measurement do not support multiple interaction record '
          'labels per page yet. See crbug.com/453109 for more information.')
    else:
      self._pages_to_tir_labels[new_value.page] = self._tir_label

  def AddValue(self, value):
    self._AssertNewValueHasSameInteractionLabel(value)
    self._results.AddValue(value)


class Smoothness(legacy_page_test.LegacyPageTest):

  def __init__(self, needs_browser_restart_after_each_page=False):
    super(Smoothness, self).__init__(needs_browser_restart_after_each_page)
    self._results_wrapper = _CustomResultsWrapper()
    self._tbm = None

  @classmethod
  def CustomizeBrowserOptions(cls, options):
    options.AppendExtraBrowserArgs('--enable-gpu-benchmarking')
    options.AppendExtraBrowserArgs('--touch-events=enabled')

  def WillNavigateToPage(self, page, tab):
    # FIXME: Remove webkit.console when blink.console lands in chromium and
    # the ref builds are updated. crbug.com/386847
    custom_categories = [
        'webkit.console', 'blink.console', 'benchmark', 'trace_event_overhead']
    category_filter = chrome_trace_category_filter.ChromeTraceCategoryFilter(
        ','.join(custom_categories))

    options = timeline_based_measurement.Options(category_filter)
    options.config.enable_platform_display_trace = True
    options.SetLegacyTimelineBasedMetrics([smoothness.SmoothnessMetric()])
    for delay in page.GetSyntheticDelayCategories():
      options.category_filter.AddSyntheticDelay(delay)
    self._tbm = timeline_based_measurement.TimelineBasedMeasurement(
        options, self._results_wrapper)
    self._tbm.WillRunStory(tab.browser.platform)

  def ValidateAndMeasurePage(self, _, tab, results):
    self._tbm.Measure(tab.browser.platform, results)

  def DidRunPage(self, platform):
    if self._tbm:
      self._tbm.DidRunStory(platform)


class Repaint(Smoothness):

  def CustomizeBrowserOptions(self, options):
    options.AppendExtraBrowserArgs([
        '--enable-gpu-benchmarking'
    ])


class SmoothnessWithRestart(Smoothness):

  def __init__(self):
    super(SmoothnessWithRestart, self).__init__(
        needs_browser_restart_after_each_page=True)
