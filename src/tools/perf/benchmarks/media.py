# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from core import perf_benchmark

from telemetry import benchmark
from telemetry.page import legacy_page_test
from telemetry.value import list_of_scalar_values
from telemetry.value import scalar

from measurements import media
import page_sets


class _MSEMeasurement(legacy_page_test.LegacyPageTest):

  def __init__(self):
    super(_MSEMeasurement, self).__init__()

  def ValidateAndMeasurePage(self, page, tab, results):
    del page  # unused
    media_metric = tab.EvaluateJavaScript('window.__testMetrics')
    trace = media_metric['id'] if 'id' in media_metric else None
    metrics = media_metric['metrics'] if 'metrics' in media_metric else []
    for m in metrics:
      trace_name = '%s.%s' % (m, trace)
      if isinstance(metrics[m], list):
        results.AddValue(list_of_scalar_values.ListOfScalarValues(
            results.current_page, trace_name, units='ms',
            values=[float(v) for v in metrics[m]],
            important=True))

      else:
        results.AddValue(scalar.ScalarValue(
            results.current_page, trace_name, units='ms',
            value=float(metrics[m]), important=True))


# android: See media.android.tough_video_cases below
# win8: crbug.com/531618
# crbug.com/565180: Only include cases that report time_to_play
@benchmark.Disabled('android', 'win8')
class Media(perf_benchmark.PerfBenchmark):
  """Obtains media metrics for key user scenarios."""
  test = media.Media
  page_set = page_sets.ToughVideoCasesPageSet

  @classmethod
  def Name(cls):
    return 'media.tough_video_cases'


# crbug.com/565180: Only include cases that don't report time_to_play
@benchmark.Disabled('android', 'win8')
class MediaExtra(perf_benchmark.PerfBenchmark):
  """Obtains extra media metrics for key user scenarios."""
  test = media.Media
  page_set = page_sets.ToughVideoCasesExtraPageSet

  @classmethod
  def Name(cls):
    return 'media.tough_video_cases_extra'


@benchmark.Disabled('android', 'mac')
class MediaNetworkSimulation(perf_benchmark.PerfBenchmark):
  """Obtains media metrics under different network simulations."""
  test = media.Media
  page_set = page_sets.MediaCnsCasesPageSet

  @classmethod
  def Name(cls):
    return 'media.media_cns_cases'


@benchmark.Enabled('android')
@benchmark.Disabled('l', 'android-webview')  # WebView: crbug.com/419689
class MediaAndroid(perf_benchmark.PerfBenchmark):
  """Obtains media metrics for key user scenarios on Android."""
  test = media.Media
  tag = 'android'
  page_set = page_sets.ToughVideoCasesPageSet
  # Exclude is_4k and 50 fps media files (garden* & crowd*).
  options = {'story_label_filter_exclude': 'is_4k,is_50fps'}

  @classmethod
  def ShouldDisable(cls, possible_browser):
    # crbug.com/448092
    if cls.IsSvelte(possible_browser):
        return True

    # crbug.com/647372
    if possible_browser.platform.GetDeviceTypeName() == 'Nexus 5X':
      return True

    return False

  @classmethod
  def Name(cls):
    return 'media.android.tough_video_cases'


@benchmark.Enabled('chromeos')
class MediaChromeOS4kOnly(perf_benchmark.PerfBenchmark):
  """Benchmark for media performance on ChromeOS using only is_4k test content.
  """
  test = media.Media
  tag = 'chromeOS4kOnly'
  page_set = page_sets.ToughVideoCasesPageSet
  options = {
      'story_label_filter': 'is_4k',
      # Exclude is_50fps test files: crbug/331816
      'story_label_filter_exclude': 'is_50fps'
  }

  @classmethod
  def Name(cls):
    return 'media.chromeOS4kOnly.tough_video_cases'


@benchmark.Enabled('chromeos')
class MediaChromeOS(perf_benchmark.PerfBenchmark):
  """Benchmark for media performance on all ChromeOS platforms.

  This benchmark does not run is_4k content, there's a separate benchmark for
  that.
  """
  test = media.Media
  tag = 'chromeOS'
  page_set = page_sets.ToughVideoCasesPageSet
  # Exclude is_50fps test files: crbug/331816
  options = {'story_label_filter_exclude': 'is_4k,is_50fps'}

  @classmethod
  def Name(cls):
    return 'media.chromeOS.tough_video_cases'


@benchmark.Disabled('android-webview')  # crbug.com/419689
class MediaSourceExtensions(perf_benchmark.PerfBenchmark):
  """Obtains media metrics for key media source extensions functions."""
  test = _MSEMeasurement
  page_set = page_sets.MseCasesPageSet

  @classmethod
  def Name(cls):
    return 'media.mse_cases'

  def SetExtraBrowserOptions(self, options):
    # Needed to allow XHR requests to return stream objects.
    options.AppendExtraBrowserArgs(
        ['--enable-experimental-web-platform-features',
         '--disable-gesture-requirement-for-media-playback'])
