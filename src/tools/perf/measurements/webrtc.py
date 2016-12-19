# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry.page import legacy_page_test

from metrics import cpu
from metrics import media
from metrics import power
from metrics import webrtc_stats


class WebRTC(legacy_page_test.LegacyPageTest):
  """Gathers WebRTC-related metrics on a page set."""

  def __init__(self, particular_metrics=None):
    """Create the measurement and include selected stats.

    Args:
        particular_metrics: A list of the stats to include (see webrtc_stats.py
            for a list of valid names) or None to select all metrics.
    """
    super(WebRTC, self).__init__()
    self._cpu_metric = None
    self._media_metric = None
    self._power_metric = None
    self._particular_metrics = particular_metrics
    self._webrtc_stats_metric = None

  def WillStartBrowser(self, platform):
    self._power_metric = power.PowerMetric(platform)

  def DidStartBrowser(self, browser):
    self._cpu_metric = cpu.CpuMetric(browser)
    self._webrtc_stats_metric = webrtc_stats.WebRtcStatisticsMetric(
        self._particular_metrics)

  def DidNavigateToPage(self, page, tab):
    self._cpu_metric.Start(page, tab)
    self._media_metric = media.MediaMetric(tab)
    self._media_metric.Start(page, tab)
    self._power_metric.Start(page, tab)
    self._webrtc_stats_metric.Start(page, tab)

  def CustomizeBrowserOptions(self, options):
    options.AppendExtraBrowserArgs('--use-fake-device-for-media-stream')
    options.AppendExtraBrowserArgs('--use-fake-ui-for-media-stream')
    power.PowerMetric.CustomizeBrowserOptions(options)

  def ValidateAndMeasurePage(self, page, tab, results):
    """Measure the page's performance."""
    self._cpu_metric.Stop(page, tab)
    self._cpu_metric.AddResults(tab, results)

    # Add all media metrics except bytes (those aren't hooked up for WebRTC
    # video tags).
    exclude_metrics = ['decoded_video_bytes', 'decoded_audio_bytes']
    self._media_metric.Stop(page, tab)
    self._media_metric.AddResults(tab, results, exclude_metrics=exclude_metrics)

    self._power_metric.Stop(page, tab)
    self._power_metric.AddResults(tab, results)

    self._webrtc_stats_metric.Stop(page, tab)
    self._webrtc_stats_metric.AddResults(tab, results)

  def DidRunPage(self, platform):
    del platform  # unused
    self._power_metric.Close()
