# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import os

from core import path_util
from core import perf_benchmark
from page_sets import google_pages

from benchmarks import v8_helper

from measurements import v8_detached_context_age_in_gc
from measurements import v8_gc_times
import page_sets
from telemetry import benchmark
from telemetry import story
from telemetry.timeline import chrome_trace_category_filter
from telemetry.timeline import chrome_trace_config
from telemetry.web_perf import timeline_based_measurement


def CreateV8TimelineBasedMeasurementOptions():
  category_filter = chrome_trace_category_filter.ChromeTraceCategoryFilter()
  category_filter.AddIncludedCategory('v8')
  category_filter.AddIncludedCategory('blink.console')
  category_filter.AddDisabledByDefault('disabled-by-default-v8.compile')
  options = timeline_based_measurement.Options(category_filter)
  options.SetTimelineBasedMetrics(['executionMetric'])
  return options


@benchmark.Disabled('win')        # crbug.com/416502
class V8Top25(perf_benchmark.PerfBenchmark):
  """Measures V8 GC metrics on the while scrolling down the top 25 web pages.

  http://www.chromium.org/developers/design-documents/rendering-benchmarks"""
  test = v8_gc_times.V8GCTimes
  page_set = page_sets.V8Top25SmoothPageSet

  @classmethod
  def ShouldDisable(cls, possible_browser):  # http://crbug.com/597656
    return (possible_browser.browser_type == 'reference' and
            possible_browser.platform.GetDeviceTypeName() == 'Nexus 5X')

  @classmethod
  def Name(cls):
    return 'v8.top_25_smooth'


@benchmark.Enabled('android')
class V8KeyMobileSites(perf_benchmark.PerfBenchmark):
  """Measures V8 GC metrics on the while scrolling down key mobile sites.

  http://www.chromium.org/developers/design-documents/rendering-benchmarks"""
  test = v8_gc_times.V8GCTimes
  page_set = page_sets.KeyMobileSitesSmoothPageSet

  @classmethod
  def Name(cls):
    return 'v8.key_mobile_sites_smooth'

  @classmethod
  def ShouldDisable(cls, possible_browser):  # http://crbug.com/597656
      return (possible_browser.browser_type == 'reference' and
              possible_browser.platform.GetDeviceTypeName() == 'Nexus 5X')


class V8DetachedContextAgeInGC(perf_benchmark.PerfBenchmark):
  """Measures the number of GCs needed to collect a detached context.

  http://www.chromium.org/developers/design-documents/rendering-benchmarks"""
  test = v8_detached_context_age_in_gc.V8DetachedContextAgeInGC
  page_set = page_sets.PageReloadCasesPageSet

  @classmethod
  def Name(cls):
    return 'v8.detached_context_age_in_gc'


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
    v8_categories = [
        'blink.console', 'disabled-by-default-v8.gc',
        'renderer.scheduler', 'v8', 'webkit.console']
    smoothness_categories = [
        'webkit.console', 'blink.console', 'benchmark', 'trace_event_overhead']
    memory_categories = ['blink.console', 'disabled-by-default-memory-infra']
    category_filter = chrome_trace_category_filter.ChromeTraceCategoryFilter(
        ','.join(['-*'] + v8_categories +
                 smoothness_categories + memory_categories))
    options = timeline_based_measurement.Options(category_filter)
    # TODO(ulan): Add frame time discrepancy once it is ported to TBMv2,
    # see crbug.com/606841.
    options.SetTimelineBasedMetrics(['v8AndMemoryMetrics'])
    # Setting an empty memory dump config disables periodic dumps.
    options.config.chrome_trace_config.SetMemoryDumpConfig(
        chrome_trace_config.MemoryDumpConfig())
    return options

  @classmethod
  def ValueCanBeAddedPredicate(cls, value, _):
    return 'v8' in value.name

  @classmethod
  def ShouldTearDownStateAfterEachStoryRun(cls):
    return True


class V8TodoMVC(perf_benchmark.PerfBenchmark):
  """Measures V8 Execution metrics on the TodoMVC examples."""
  page_set = page_sets.TodoMVCPageSet

  def CreateTimelineBasedMeasurementOptions(self):
    return CreateV8TimelineBasedMeasurementOptions()

  @classmethod
  def Name(cls):
    return 'v8.todomvc'

  @classmethod
  def ShouldDisable(cls, possible_browser):
    # This benchmark is flaky on Samsung Galaxy S5s.
    # http://crbug.com/644826
    return possible_browser.platform.GetDeviceTypeName() == 'SM-G900H'

  @classmethod
  def ShouldTearDownStateAfterEachStoryRun(cls):
    return True


class V8TodoMVCIgnition(V8TodoMVC):
  """Measures V8 Execution metrics on the TodoMVC examples using ignition."""
  page_set = page_sets.TodoMVCPageSet

  def SetExtraBrowserOptions(self, options):
    super(V8TodoMVCIgnition, self).SetExtraBrowserOptions(options)
    v8_helper.EnableIgnition(options)

  @classmethod
  def Name(cls):
    return 'v8.todomvc-ignition'


class V8InfiniteScroll(_InfiniteScrollBenchmark):
  """Measures V8 GC metrics and memory usage while scrolling the top web pages.
  http://www.chromium.org/developers/design-documents/rendering-benchmarks"""

  page_set = page_sets.InfiniteScrollPageSet

  @classmethod
  def Name(cls):
    return 'v8.infinite_scroll_tbmv2'


class V8InfiniteScrollIgnition(V8InfiniteScroll):
  """Measures V8 GC metrics using Ignition."""

  def SetExtraBrowserOptions(self, options):
    super(V8InfiniteScrollIgnition, self).SetExtraBrowserOptions(options)
    v8_helper.EnableIgnition(options)

  @classmethod
  def Name(cls):
    return 'v8.infinite_scroll-ignition_tbmv2'


@benchmark.Enabled('android')
class V8MobileInfiniteScroll(_InfiniteScrollBenchmark):
  """Measures V8 GC metrics and memory usage while scrolling the top mobile
  web pages.
  http://www.chromium.org/developers/design-documents/rendering-benchmarks"""

  page_set = page_sets.MobileInfiniteScrollPageSet

  @classmethod
  def Name(cls):
    return 'v8.mobile_infinite_scroll_tbmv2'

  @classmethod
  def ShouldDisable(cls, possible_browser):  # http://crbug.com/597656
      return (possible_browser.browser_type == 'reference' and
              possible_browser.platform.GetDeviceTypeName() == 'Nexus 5X')


class V8Adword(perf_benchmark.PerfBenchmark):
  """Measures V8 Execution metrics on the Adword page."""

  options = {'pageset_repeat': 3}

  def CreateTimelineBasedMeasurementOptions(self):
    return CreateV8TimelineBasedMeasurementOptions()

  def CreateStorySet(self, options):
    """Creates the instance of StorySet used to run the benchmark.

    Can be overridden by subclasses.
    """
    story_set = story.StorySet(
        archive_data_file=os.path.join(
            path_util.GetPerfStorySetsDir(), 'data', 'v8_pages.json'),
        cloud_storage_bucket=story.PARTNER_BUCKET)
    story_set.AddStory(google_pages.AdwordCampaignDesktopPage(story_set))
    return story_set

  @classmethod
  def Name(cls):
    return 'v8.google'

  @classmethod
  def ShouldDisable(cls, possible_browser):
    if cls.IsSvelte(possible_browser): # http://crbug.com/596556
      return True
    # http://crbug.com/623576
    if (possible_browser.platform.GetDeviceTypeName() == 'Nexus 5' or
        possible_browser.platform.GetDeviceTypeName() == 'Nexus 7'):
      return True
    return False

  @classmethod
  def ShouldTearDownStateAfterEachStoryRun(cls):
    return True


class _Top25RuntimeStats(perf_benchmark.PerfBenchmark):
  options = {'pageset_repeat': 1}

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
