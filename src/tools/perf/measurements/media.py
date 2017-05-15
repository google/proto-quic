# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry.page import legacy_page_test

from metrics import cpu
from metrics import media
from metrics import power
from metrics import system_memory


class Media(legacy_page_test.LegacyPageTest):
  """The MediaMeasurement class gathers media-related metrics on a page set.

  Media metrics recorded are controlled by metrics/media.js.  At the end of the
  test each metric for every media element in the page are reported.
  """

  def __init__(self):
    super(Media, self).__init__()
    self._media_metric = None
    # Used to add browser power and CPU metrics to results per test.
    self._add_browser_metrics = False
    self._cpu_metric = None
    self._memory_metric = None
    self._power_metric = None

  def WillStartBrowser(self, platform):
    self._power_metric = power.PowerMetric(platform)

  def CustomizeBrowserOptions(self, options):
    # Needed to run media actions in JS on touch-based devices as on Android.
    # Note that both of these flags should be used until every build from
    # ToT to Stable switches over to one flag or another. This is to support
    # reference builds.
    # --disable-gesture-requirement-for-media-playback is the old one and can be
    # removed after M60 goes to stable.
    options.AppendExtraBrowserArgs(
        ['--ignore-autoplay-restrictions',
         '--disable-gesture-requirement-for-media-playback'])
    power.PowerMetric.CustomizeBrowserOptions(options)

  def DidNavigateToPage(self, page, tab):
    """Override to do operations right after the page is navigated."""
    self._media_metric = media.MediaMetric(tab)
    self._media_metric.Start(page, tab)

    # Reset to false for every page.
    self._add_browser_metrics = (
        page.add_browser_metrics
        if hasattr(page, 'add_browser_metrics') else False)

    if self._add_browser_metrics:
      self._cpu_metric = cpu.CpuMetric(tab.browser)
      self._cpu_metric.Start(page, tab)
      self._memory_metric = system_memory.SystemMemoryMetric(tab.browser)
      self._memory_metric.Start(page, tab)
      self._power_metric.Start(page, tab)

  def ValidateAndMeasurePage(self, page, tab, results):
    """Measure the page's performance."""
    self._media_metric.Stop(page, tab)
    trace_name = self._media_metric.AddResults(tab, results)

    if self._add_browser_metrics:
      self._cpu_metric.Stop(page, tab)
      self._memory_metric.Stop(page, tab)
      self._power_metric.Stop(page, tab)
      self._cpu_metric.AddResults(tab, results, trace_name=trace_name)
      exclude_metrics = ['WorkingSetSizePeak', 'SystemCommitCharge', 'VMPeak',
                         'VM']
      self._memory_metric.AddResults(tab, results,
                                     trace_name=trace_name,
                                     exclude_metrics=exclude_metrics)
      self._power_metric.AddResults(tab, results)

  def DidRunPage(self, platform):
    del platform  # unused
    self._power_metric.Close()
