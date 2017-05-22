# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
from core import perf_benchmark

from benchmarks import v8_helper

from measurements import v8_detached_context_age_in_gc
import page_sets

from telemetry import benchmark
from telemetry.timeline import chrome_trace_category_filter
from telemetry.timeline import chrome_trace_config
from telemetry.web_perf import timeline_based_measurement


@benchmark.Owner(emails=['ulan@chromium.org'])
class V8DetachedContextAgeInGC(perf_benchmark.PerfBenchmark):
  """Measures the number of GCs needed to collect a detached context.

  http://www.chromium.org/developers/design-documents/rendering-benchmarks"""
  test = v8_detached_context_age_in_gc.V8DetachedContextAgeInGC
  page_set = page_sets.PageReloadCasesPageSet

  @classmethod
  def Name(cls):
    return 'v8.detached_context_age_in_gc'

  @classmethod
  def ShouldDisable(cls, possible_browser):
    # http://crbug.com/685350
    if possible_browser.platform.GetDeviceTypeName() == 'Nexus 9':
      return True
    return False


class _InfiniteScrollBenchmark(perf_benchmark.PerfBenchmark):
  """ Base class for infinite scroll benchmarks.
  """

  def SetExtraBrowserOptions(self, options):
    options.AppendExtraBrowserArgs([
        # Disable push notifications for Facebook.
        '--disable-notifications',
    ])
    v8_helper.AppendJSFlags(options, '--heap-growing-percent=10')

  def CreateTimelineBasedMeasurementOptions(self):
    categories = [
      # Disable all categories by default.
      '-*',
      # Memory categories.
      'disabled-by-default-memory-infra',
      # EQT categories.
      'blink.user_timing',
      'loading',
      'navigation',
      'toplevel',
      # V8 categories.
      'blink.console',
      'disabled-by-default-v8.compile',
      'disabled-by-default-v8.gc',
      'renderer.scheduler',
      'v8',
      'webkit.console'
    ]
    category_filter = chrome_trace_category_filter.ChromeTraceCategoryFilter(
        ','.join(categories))
    options = timeline_based_measurement.Options(category_filter)
    # TODO(ulan): Add frame time discrepancy once it is ported to TBMv2,
    # see crbug.com/606841.
    options.SetTimelineBasedMetrics([
      'expectedQueueingTimeMetric', 'v8AndMemoryMetrics'])
    # Setting an empty memory dump config disables periodic dumps.
    options.config.chrome_trace_config.SetMemoryDumpConfig(
        chrome_trace_config.MemoryDumpConfig())
    return options

  @classmethod
  def ValueCanBeAddedPredicate(cls, value, _):
    return ('v8' in value.name) or ('eqt' in value.name)

  @classmethod
  def ShouldTearDownStateAfterEachStoryRun(cls):
    return True


@benchmark.Disabled('android') # Android runs V8MobileInfiniteScroll.
@benchmark.Owner(emails=['ulan@chromium.org'])
class V8InfiniteScroll(_InfiniteScrollBenchmark):
  """Measures V8 GC metrics and memory usage while scrolling the top web pages.
  http://www.chromium.org/developers/design-documents/rendering-benchmarks"""

  page_set = page_sets.InfiniteScrollStorySet

  @classmethod
  def Name(cls):
    return 'v8.infinite_scroll_tbmv2'

@benchmark.Disabled('all')
@benchmark.Disabled('android') # Android runs V8MobileInfiniteScroll.
@benchmark.Owner(emails=['mvstaton@chromium.org'])
class V8InfiniteScrollTurbo(V8InfiniteScroll):
  """Measures V8 GC metrics using Ignition+TurboFan."""

  def SetExtraBrowserOptions(self, options):
    super(V8InfiniteScrollTurbo, self).SetExtraBrowserOptions(options)
    v8_helper.EnableTurbo(options)

  @classmethod
  def Name(cls):
    return 'v8.infinite_scroll-turbo_tbmv2'


@benchmark.Disabled('linux')  # crbug.com/715716
@benchmark.Disabled('android') # Android runs V8MobileInfiniteScroll.
@benchmark.Owner(emails=['hablich@chromium.org'])
class V8InfiniteScrollClassic(V8InfiniteScroll):
  """Measures V8 GC metrics using the Classic pipeline."""

  def SetExtraBrowserOptions(self, options):
    super(V8InfiniteScrollClassic, self).SetExtraBrowserOptions(options)
    v8_helper.EnableClassic(options)

  @classmethod
  def Name(cls):
    return 'v8.infinite_scroll-classic_tbmv2'


@benchmark.Enabled('android')
@benchmark.Owner(emails=['ulan@chromium.org'])
class V8MobileInfiniteScroll(_InfiniteScrollBenchmark):
  """Measures V8 GC metrics and memory usage while scrolling the top mobile
  web pages.
  http://www.chromium.org/developers/design-documents/rendering-benchmarks"""

  page_set = page_sets.MobileInfiniteScrollStorySet

  @classmethod
  def Name(cls):
    return 'v8.mobile_infinite_scroll_tbmv2'


@benchmark.Disabled('all') # was enabled only on android
@benchmark.Owner(emails=['mvstaton@chromium.org'])
class V8MobileInfiniteScrollTurbo(V8MobileInfiniteScroll):
  """Measures V8 GC metrics and memory usage while scrolling the top mobile
  web pages and running Ignition+TurboFan.
  http://www.chromium.org/developers/design-documents/rendering-benchmarks"""

  def SetExtraBrowserOptions(self, options):
    super(V8MobileInfiniteScrollTurbo, self).SetExtraBrowserOptions(options)
    v8_helper.EnableTurbo(options)

  @classmethod
  def Name(cls):
    return 'v8.mobile_infinite_scroll-turbo_tbmv2'


@benchmark.Enabled('android')
@benchmark.Owner(emails=['hablich@chromium.org'])
class V8MobileInfiniteScrollClassic(V8MobileInfiniteScroll):
  """Measures V8 GC metrics and memory usage while scrolling the top mobile
  web pages and running the Classic pipeline.
  http://www.chromium.org/developers/design-documents/rendering-benchmarks"""

  def SetExtraBrowserOptions(self, options):
    super(V8MobileInfiniteScrollClassic, self).SetExtraBrowserOptions(options)
    v8_helper.EnableClassic(options)

  @classmethod
  def Name(cls):
    return 'v8.mobile_infinite_scroll-classic_tbmv2'


class _Top25RuntimeStats(perf_benchmark.PerfBenchmark):
  options = {'pageset_repeat': 3}

  def CreateTimelineBasedMeasurementOptions(self):
    # TODO(fmeawad): most of the cat_filter information is extracted from
    # page_cycler_v2 TimelineBasedMeasurementOptionsForLoadingMetric because
    # used by the loadingMetric because the runtimeStatsMetric uses the
    # interactive time calculated internally by the loadingMetric.
    # It is better to share the code so that we can keep them in sync.
    cat_filter = chrome_trace_category_filter.ChromeTraceCategoryFilter()

    # "blink.console" is used for marking ranges in
    # cache_temperature.MarkTelemetryInternal.
    cat_filter.AddIncludedCategory('blink.console')

    # "navigation" and "blink.user_timing" are needed to capture core
    # navigation events.
    cat_filter.AddIncludedCategory('navigation')
    cat_filter.AddIncludedCategory('blink.user_timing')

    # "loading" is needed for first-meaningful-paint computation.
    cat_filter.AddIncludedCategory('loading')

    # "toplevel" category is used to capture TaskQueueManager events
    # necessary to compute time-to-interactive.
    cat_filter.AddIncludedCategory('toplevel')

    # V8 needed categories
    cat_filter.AddIncludedCategory('v8')
    cat_filter.AddDisabledByDefault('disabled-by-default-v8.runtime_stats')

    tbm_options = timeline_based_measurement.Options(
        overhead_level=cat_filter)
    tbm_options.SetTimelineBasedMetrics(['runtimeStatsMetric'])
    return tbm_options

  @classmethod
  def ShouldDisable(cls, possible_browser):
    if possible_browser.browser_type == 'reference':
      return True
    return False


@benchmark.Disabled('android', 'win', 'reference')  # crbug.com/664318
@benchmark.Owner(emails=['cbruni@chromium.org'])
class V8Top25RuntimeStats(_Top25RuntimeStats):
  """Runtime Stats benchmark for a 25 top V8 web pages.

  Designed to represent a mix between top websites and a set of pages that
  have unique V8 characteristics.
  """

  @classmethod
  def Name(cls):
    return 'v8.runtime_stats.top_25'

  def CreateStorySet(self, options):
    return page_sets.V8Top25StorySet()
