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
@benchmark.Owner(emails=['crouleau@chromium.org'],
                 component='Internals>Media')
@benchmark.Disabled('android')
class MediaToughVideoCases(perf_benchmark.PerfBenchmark):
  """Obtains media metrics for key user scenarios."""
  test = media.Media
  page_set = page_sets.ToughVideoCasesPageSet

  @classmethod
  def Name(cls):
    return 'media.tough_video_cases'


@benchmark.Enabled('android')
@benchmark.Disabled('l', 'android-webview')  # WebView: crbug.com/419689.
@benchmark.Owner(emails=['crouleau@chromium.org', 'videostack-eng@google.com'],
                 component='Internals>Media')
class MediaAndroidToughVideoCases(perf_benchmark.PerfBenchmark):
  """Obtains media metrics for key user scenarios on Android."""
  test = media.Media
  tag = 'android'
  page_set = page_sets.ToughVideoCasesPageSet
  options = {'story_tag_filter_exclude': 'is_4k,is_50fps'}

  @classmethod
  def ShouldDisable(cls, possible_browser):
    return cls.IsSvelte(possible_browser)

  @classmethod
  def Name(cls):
    return 'media.android.tough_video_cases'


class _MediaTBMv2Benchmark(perf_benchmark.PerfBenchmark):
  page_set = page_sets.ToughVideoCasesPageSet

  def CreateTimelineBasedMeasurementOptions(self):
    category_filter = chrome_trace_category_filter.ChromeTraceCategoryFilter()

    # 'toplevel' category provides CPU time slices used by # cpuTimeMetric.
    category_filter.AddIncludedCategory('toplevel')

    # 'rail' category is used by powerMetric to attribute different period of
    # time to different activities, such as video_animation, etc.
    category_filter.AddIncludedCategory('rail')

    options = timeline_based_measurement.Options(category_filter)
    options.config.enable_battor_trace = True
    options.SetTimelineBasedMetrics(['powerMetric', 'cpuTimeMetric'])
    return options


# android: See media.android.tough_video_cases below
@benchmark.Owner(emails=['johnchen@chromium.org', 'crouleau@chromium.org'],
                 component='Internals>Media')
@benchmark.Disabled('android')
class MediaToughVideoCasesTBMv2(_MediaTBMv2Benchmark):
  """Obtains media metrics using TBMv2.
  Will eventually replace MediaToughVideoCases class."""

  @classmethod
  def Name(cls):
    return 'media.tough_video_cases_tbmv2'


@benchmark.Owner(emails=['johnchen@chromium.org', 'crouleau@chromium.org'],
                 component='Internals>Media')
@benchmark.Enabled('android')
@benchmark.Disabled('l', 'android-webview')  # WebView: crbug.com/419689.
class MediaAndroidToughVideoCasesTBMv2(_MediaTBMv2Benchmark):
  """Obtains media metrics for key user scenarios on Android using TBMv2.
  Will eventually replace MediaAndroidToughVideoCases class."""

  tag = 'android'
  options = {'story_tag_filter_exclude': 'is_4k,is_50fps'}

  @classmethod
  def ShouldDisable(cls, possible_browser):
    return cls.IsSvelte(possible_browser)

  @classmethod
  def Name(cls):
    return 'media.android.tough_video_cases_tbmv2'

  def SetExtraBrowserOptions(self, options):
    # By default, Chrome on Android does not allow autoplay
    # of media: it requires a user gesture event to start a video.
    # The following option works around that.
    # Note that both of these flags should be used until every build from
    # ToT to Stable switches over to one flag or another. This is to support
    # reference builds.
    # --disable-gesture-requirement-for-media-playback is the old one and can be
    # removed after M60 goes to stable.
    options.AppendExtraBrowserArgs(
        ['--ignore-autoplay-restrictions',
         '--disable-gesture-requirement-for-media-playback'])


@benchmark.Disabled('all')  # crbug/676345
@benchmark.Owner(emails=['crouleau@chromium.org', 'videostack-eng@google.com'],
                 component='Internals>Media')
class MediaNetworkSimulation(perf_benchmark.PerfBenchmark):
  """Obtains media metrics under different network simulations."""
  test = media.Media
  page_set = page_sets.MediaCnsCasesPageSet

  @classmethod
  def Name(cls):
    return 'media.media_cns_cases'


@benchmark.Disabled('android-webview')  # crbug.com/419689
@benchmark.Owner(emails=['crouleau@chromium.org', 'videostack-eng@google.com'],
                 component='Internals>Media>Source')
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
         '--ignore-autoplay-restrictions'])
