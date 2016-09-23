# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""The tab switching measurement.

This measurement opens pages in different tabs. After all the tabs have opened,
it cycles through each tab in sequence, and records a histogram of the time
between when a tab was first requested to be shown, and when it was painted.
Power usage is also measured.
"""

import time

from telemetry.core import util
from telemetry.page import legacy_page_test
from telemetry.value import histogram
from telemetry.value import histogram_util

from metrics import keychain_metric
from metrics import power

# TODO: Revisit this test once multitab support is finalized.


class TabSwitching(legacy_page_test.LegacyPageTest):

  # Amount of time to measure, in seconds.
  SAMPLE_TIME = 30

  def __init__(self):
    super(TabSwitching, self).__init__()
    self.first_page_in_storyset = True
    self._power_metric = None

  def CustomizeBrowserOptions(self, options):
    keychain_metric.KeychainMetric.CustomizeBrowserOptions(options)

    options.AppendExtraBrowserArgs([
        '--enable-stats-collection-bindings'
    ])
    # Enable background networking so we can test its impact on power usage.
    options.disable_background_networking = False
    power.PowerMetric.CustomizeBrowserOptions(options)

  def WillStartBrowser(self, platform):
    self.first_page_in_storyset = True
    self._power_metric = power.PowerMetric(platform, TabSwitching.SAMPLE_TIME)

  def TabForPage(self, page, browser):
    del page  # unused
    if self.first_page_in_storyset:
      # The initial browser window contains a single tab, navigate that tab
      # rather than creating a new one.
      self.first_page_in_storyset = False
      return browser.tabs[0]

    return browser.tabs.New()

  def StopBrowserAfterPage(self, browser, page):
    # Restart the browser after the last page in the pageset.
    return len(browser.tabs) >= len(page.story_set.stories)

  def ValidateAndMeasurePage(self, page, tab, results):
    """On the last tab, cycle through each tab that was opened and then record
    a single histogram for the tab switching metric."""
    if len(tab.browser.tabs) != len(page.story_set.stories):
      return

    # Measure power usage of tabs after quiescence.
    util.WaitFor(tab.HasReachedQuiescence, 60)

    if tab.browser.platform.CanMonitorPower():
      self._power_metric.Start(page, tab)
      time.sleep(TabSwitching.SAMPLE_TIME)
      self._power_metric.Stop(page, tab)
      self._power_metric.AddResults(tab, results,)

    histogram_name = 'MPArch.RWH_TabSwitchPaintDuration'
    histogram_type = histogram_util.BROWSER_HISTOGRAM
    display_name = 'MPArch_RWH_TabSwitchPaintDuration'
    first_histogram = histogram_util.GetHistogram(
        histogram_type, histogram_name, tab)
    prev_histogram = first_histogram

    for t in tab.browser.tabs:
      t.Activate()

      def _IsDone():
        cur_histogram = histogram_util.GetHistogram(
            histogram_type, histogram_name, tab)
        diff_histogram = histogram_util.SubtractHistogram(
            cur_histogram, prev_histogram)
        return diff_histogram
      util.WaitFor(_IsDone, 30)
      prev_histogram = histogram_util.GetHistogram(
          histogram_type, histogram_name, tab)

    last_histogram = histogram_util.GetHistogram(
        histogram_type, histogram_name, tab)
    diff_histogram = histogram_util.SubtractHistogram(last_histogram,
                                                      first_histogram)

    results.AddSummaryValue(
        histogram.HistogramValue(None, display_name, 'ms',
                                 raw_value_json=diff_histogram,
                                 important=False))

    keychain_metric.KeychainMetric().AddResults(tab, results)

  def DidRunPage(self, platform):
    del platform  # unused
    self._power_metric.Close()
