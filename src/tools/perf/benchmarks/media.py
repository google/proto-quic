# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from core import perf_benchmark

from telemetry import benchmark
from telemetry.page import legacy_page_test
from telemetry.timeline import chrome_trace_category_filter
from telemetry.value import list_of_scalar_values
from telemetry.value import scalar
from telemetry.web_perf import timeline_based_measurement

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
# crbug.com/565180: Only include cases that report time_to_play
@benchmark.Disabled('android')
class MediaToughVideoCases(perf_benchmark.PerfBenchmark):
  """Obtains media metrics for key user scenarios."""
  test = media.Media
  page_set = page_sets.ToughVideoCasesPageSet

  @classmethod
  def Name(cls):
    return 'media.tough_video_cases'


@benchmark.Owner(emails=['johnchen@chromium.org', 'crouleau@chromium.org'],
                 component='Internals>Media')
@benchmark.Disabled('android')
class MediaToughVideoCasesTBMv2(perf_benchmark.PerfBenchmark):
  """Obtains media metrics using TBMv2.
  Will eventually replace MediaToughVideoCases class."""
  page_set = page_sets.ToughVideoCasesPageSet

  def CreateTimelineBasedMeasurementOptions(self):
    category_filter = chrome_trace_category_filter.ChromeTraceCategoryFilter()

    # 'toplevel' category provides CPU time slices used by # cpuTimeMetric.
    category_filter.AddIncludedCategory('toplevel')

    # 'rail' category is used by powerMetric to attribute different period of
    # time to different activities, such as video_animation, etc.
    category_filter.AddIncludedCategory('rail')

    options = timeline_based_measurement.Options(category_filter)
    options.config.enable_atrace_trace = True
    options.config.atrace_config.categories = ['sched']
    options.config.enable_battor_trace = True
    options.SetTimelineBasedMetrics(['powerMetric', 'cpuTimeMetric'])
    return options

  @classmethod
  def Name(cls):
    return 'media.tough_video_cases_tbmv2'


# crbug.com/565180: Only include cases that don't report time_to_play
@benchmark.Disabled('android')
@benchmark.Owner(emails=['crouleau@chromium.org', 'videostack-eng@google.com'])
class MediaExtra(perf_benchmark.PerfBenchmark):
  """Obtains extra media metrics for key user scenarios."""
  test = media.Media
  page_set = page_sets.ToughVideoCasesExtraPageSet

  @classmethod
  def Name(cls):
    return 'media.tough_video_cases_extra'


@benchmark.Disabled('android', 'mac')
@benchmark.Owner(emails=['crouleau@chromium.org', 'videostack-eng@google.com'])
class MediaNetworkSimulation(perf_benchmark.PerfBenchmark):
  """Obtains media metrics under different network simulations."""
  test = media.Media
  page_set = page_sets.MediaCnsCasesPageSet

  @classmethod
  def Name(cls):
    return 'media.media_cns_cases'


@benchmark.Disabled('l', 'android-webview')  # WebView: crbug.com/419689.
class MediaAndroid(perf_benchmark.PerfBenchmark):
  """Obtains media metrics for key user scenarios on Android."""
  test = media.Media
  tag = 'android'
  page_set = page_sets.ToughVideoCasesPageSet
  # Exclude is_4k and 50 fps media files (garden* & crowd*).
  options = {'story_tag_filter_exclude': 'is_4k,is_50fps'}

  @classmethod
  def ShouldDisable(cls, possible_browser):
    if possible_browser.platform.GetOSName() != "android":
      return True
    return cls.IsSvelte(possible_browser)

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
      'story_tag_filter': 'is_4k',
      # Exclude is_50fps test files: crbug/331816
      'story_tag_filter_exclude': 'is_50fps'
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
  options = {'story_tag_filter_exclude': 'is_4k,is_50fps'}

  @classmethod
  def Name(cls):
    return 'media.chromeOS.tough_video_cases'


@benchmark.Disabled('android-webview')  # crbug.com/419689
@benchmark.Owner(emails=['crouleau@chromium.org', 'videostack-eng@google.com'])
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
