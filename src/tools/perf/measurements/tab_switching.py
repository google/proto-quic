# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""The tab switching measurement.

This measurement opens pages in different tabs. After all the tabs have opened,
it cycles through each tab in sequence, and records a histogram of the time
between when a tab was first requested to be shown, and when it was painted.
Power usage is also measured.
"""

from telemetry.page import legacy_page_test
from telemetry.value import histogram
from telemetry.value import histogram_util

from metrics import keychain_metric


class TabSwitching(legacy_page_test.LegacyPageTest):
  def __init__(self):
    super(TabSwitching, self).__init__()
    self._first_histogram = None

  def CustomizeBrowserOptions(self, options):
    keychain_metric.KeychainMetric.CustomizeBrowserOptions(options)

    options.AppendExtraBrowserArgs(['--enable-stats-collection-bindings'])

  @classmethod
  def _GetTabSwitchHistogram(cls, tab_to_switch):
    histogram_name = 'MPArch.RWH_TabSwitchPaintDuration'
    histogram_type = histogram_util.BROWSER_HISTOGRAM
    return histogram_util.GetHistogram(
        histogram_type, histogram_name, tab_to_switch)

  def DidNavigateToPage(self, page, tab):
    """record the starting histogram"""
    self._first_histogram = self._GetTabSwitchHistogram(tab)

  def ValidateAndMeasurePage(self, page, tab, results):
    """record the ending histogram for the tab switching metric."""
    last_histogram = self._GetTabSwitchHistogram(tab)
    total_diff_histogram = histogram_util.SubtractHistogram(last_histogram,
                            self._first_histogram)

    display_name = 'MPArch_RWH_TabSwitchPaintDuration'
    results.AddSummaryValue(
        histogram.HistogramValue(None, display_name, 'ms',
            raw_value_json=total_diff_histogram,
            important=False))

    keychain_metric.KeychainMetric().AddResults(tab, results)
