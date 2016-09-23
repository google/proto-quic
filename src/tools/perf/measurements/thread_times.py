# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry.page import legacy_page_test
from telemetry.timeline import chrome_trace_category_filter
from telemetry.web_perf.metrics import layout

from measurements import timeline_controller
from metrics import timeline


class ThreadTimes(legacy_page_test.LegacyPageTest):

  def __init__(self, report_silk_details=False):
    super(ThreadTimes, self).__init__()
    self._timeline_controller = None
    self._report_silk_details = report_silk_details

  def WillNavigateToPage(self, page, tab):
    self._timeline_controller = timeline_controller.TimelineController(
        enable_auto_issuing_record=False)
    if self._report_silk_details:
      # We need the other traces in order to have any details to report.
      self._timeline_controller.trace_categories = None
    else:
      self._timeline_controller.trace_categories = \
          chrome_trace_category_filter.CreateLowOverheadFilter().filter_string
    self._timeline_controller.SetUp(page, tab)

  def DidNavigateToPage(self, page, tab):
    del page  # unused
    self._timeline_controller.Start(tab)

  def ValidateAndMeasurePage(self, page, tab, results):
    del page  # unused
    self._timeline_controller.Stop(tab, results)
    metric = timeline.ThreadTimesTimelineMetric()
    renderer_thread = \
        self._timeline_controller.model.GetRendererThreadFromTabId(tab.id)
    if self._report_silk_details:
      metric.details_to_report = timeline.ReportSilkDetails
    metric.AddResults(self._timeline_controller.model, renderer_thread,
                      self._timeline_controller.smooth_records, results)
    layout_metric = layout.LayoutMetric()
    layout_metric.AddResults(self._timeline_controller.model, renderer_thread,
                             self._timeline_controller.smooth_records, results)

  def DidRunPage(self, platform):
    if self._timeline_controller:
      self._timeline_controller.CleanUp(platform)
