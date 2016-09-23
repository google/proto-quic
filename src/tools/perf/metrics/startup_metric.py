# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import collections
import json
import logging

from telemetry.core import exceptions
from telemetry.value import histogram_util
from telemetry.value import scalar

from metrics import Metric


class StartupMetric(Metric):
  'A metric for browser startup time.'

  # Seconds to wait for page loading complete.
  DEFAULT_LOADING_TIMEOUT = 90

  HISTOGRAMS_TO_RECORD = {
      'messageloop_start_time': (
          'Startup.BrowserMessageLoopStartTimeFromMainEntry'),
      'window_display_time': 'Startup.BrowserWindowDisplay',
      'open_tabs_time': 'Startup.BrowserOpenTabs',
      'first_non_empty_paint_time': 'Startup.FirstWebContents.NonEmptyPaint2',
      'first_main_frame_load_time': 'Startup.FirstWebContents.MainFrameLoad2'
  }

  def Start(self, page, tab):
    raise NotImplementedError()

  def Stop(self, page, tab):
    raise NotImplementedError()

  def _GetBrowserMainEntryTime(self, tab):
    """Returns the main entry time (in ms) of the browser."""
    histogram_type = histogram_util.BROWSER_HISTOGRAM
    high_bytes = histogram_util.GetHistogramSum(
        histogram_type,
        'Startup.BrowserMainEntryTimeAbsoluteHighWord',
        tab)
    low_bytes = histogram_util.GetHistogramSum(
        histogram_type,
        'Startup.BrowserMainEntryTimeAbsoluteLowWord',
        tab)
    if high_bytes == 0 and low_bytes == 0:
      return None
    return (int(high_bytes) << 32) | (int(low_bytes) << 1)

  def _RecordTabLoadTimes(self, tab, browser_main_entry_time_ms, results):
    """Records the tab load times for the browser. """
    TabLoadTime = collections.namedtuple(
        'TabLoadTime',
        ['request_start_ms', 'load_end_ms'])

    def RecordOneTab(t):
      def EvaluateInt(exp):
        val = t.EvaluateJavaScript(exp)
        if not val:
          logging.warn('%s undefined', exp)
          return 0
        return int(val)

      try:
        t.WaitForJavaScriptExpression(
            'window.performance.timing["loadEventEnd"] > 0',
            self.DEFAULT_LOADING_TIMEOUT)

        # EvaluateJavaScript(window.performance.timing) doesn't guarantee to
        # return the desired javascript object (crbug/472603). It may return an
        # empty object. However getting individual field works.
        # The behavior depends on WebKit implementation on different platforms.
        load_event_end = EvaluateInt(
            'window.performance.timing["loadEventEnd"]')
        request_start = EvaluateInt(
            'window.performance.timing["requestStart"]')

        return TabLoadTime(request_start, load_event_end)

      except exceptions.TimeoutException:
        # Low memory Android devices may not be able to load more than
        # one tab at a time, so may timeout when the test attempts to
        # access a background tab. Ignore these tabs.
        logging.error('Tab timed out on JavaScript access')

    # Only measure the foreground tab. We can't measure all tabs on Android
    # because on Android the data of the background tabs is loaded on demand,
    # when the user switches to them, rather than during startup. In view of
    # this, to get the same measures on all platform, we only measure the
    # foreground tab on all platforms.
    foreground_tab_stats = RecordOneTab(tab.browser.foreground_tab)

    if foreground_tab_stats:
      foreground_tab_load_complete = (
          foreground_tab_stats.load_end_ms - browser_main_entry_time_ms)
      results.AddValue(scalar.ScalarValue(
          results.current_page, 'foreground_tab_load_complete', 'ms',
          foreground_tab_load_complete))
      if foreground_tab_stats.request_start_ms > 0:
        results.AddValue(scalar.ScalarValue(
            results.current_page, 'foreground_tab_request_start', 'ms',
            foreground_tab_stats.request_start_ms - browser_main_entry_time_ms))

  def AddResults(self, tab, results):
    get_histogram_js = 'statsCollectionController.getBrowserHistogram("%s")'

    for display_name, histogram_name in self.HISTOGRAMS_TO_RECORD.iteritems():
      result = tab.EvaluateJavaScript(get_histogram_js % histogram_name)
      result = json.loads(result)
      measured_time = 0

      if 'sum' in result:
        # For all the histograms logged here, there's a single entry so sum
        # is the exact value for that entry.
        measured_time = result['sum']
      elif 'buckets' in result:
        measured_time = (result['buckets'][0]['high'] +
                         result['buckets'][0]['low']) / 2

      results.AddValue(scalar.ScalarValue(
          results.current_page, display_name, 'ms', measured_time))

    # Get tab load times.
    browser_main_entry_time_ms = self._GetBrowserMainEntryTime(tab)
    if browser_main_entry_time_ms is None:
      print 'Outdated Chrome version, browser main entry time not supported.'
      return
    self._RecordTabLoadTimes(tab, browser_main_entry_time_ms, results)
