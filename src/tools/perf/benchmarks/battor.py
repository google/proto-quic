# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os

from core import perf_benchmark
from telemetry.timeline import chrome_trace_category_filter
from telemetry.web_perf import timeline_based_measurement
import page_sets
from telemetry import benchmark


# TODO(rnephew): Remove BattOr naming from all benchmarks once the BattOr tests
# are the primary means of benchmarking power.
class _BattOrBenchmark(perf_benchmark.PerfBenchmark):

  def CreateTimelineBasedMeasurementOptions(self):
    category_filter = chrome_trace_category_filter.ChromeTraceCategoryFilter(
        filter_string='toplevel')
    options = timeline_based_measurement.Options(category_filter)
    options.config.chrome_trace_config.category_filter.AddFilterString('rail')
    # TODO(charliea): Reenable the CPU tracing agent once it no longer causes
    # indefinite hangs on Windows.
    # https://crbug.com/647443
    # TODO(charliea): Reenable BattOr tracing on the main perf waterfall once
    # the BattOrs stop crashing as their SD cards fill up.
    # crbug.com/652384
    options.config.enable_battor_trace = (
        os.environ.get('BUILDBOT_MASTERNAME') == 'chromium.perf.fyi')
    options.config.enable_chrome_trace = True
    options.config.enable_atrace_trace = True
    options.config.atrace_config.categories = ['sched']
    options.SetTimelineBasedMetrics(
        ['powerMetric', 'clockSyncLatencyMetric', 'cpuTimeMetric'])
    return options

  @classmethod
  def ShouldDisable(cls, possible_browser):
    # Only run if BattOr is detected.
    if not possible_browser.platform.HasBattOrConnected():
      return True

    # Galaxy S5s have problems with running system health metrics.
    # http://crbug.com/600463
    galaxy_s5_type_name = 'SM-G900H'
    return possible_browser.platform.GetDeviceTypeName() == galaxy_s5_type_name

  @classmethod
  def ShouldTearDownStateAfterEachStoryRun(cls):
    return True


# android: See battor.android.tough_video_cases below
# win8: crbug.com/531618
# crbug.com/565180: Only include cases that report time_to_play
# Taken directly from media benchmark.
@benchmark.Disabled('android', 'win8')
class BattOrToughVideoCases(_BattOrBenchmark):
  """Obtains media metrics for key user scenarios."""
  page_set = page_sets.ToughVideoCasesPageSet

  @classmethod
  def Name(cls):
    return 'battor.tough_video_cases'


# TODO(rnephew): Add a version that scrolls.
class BattOrSystemHealthLoadingDesktop(_BattOrBenchmark):
  """Desktop Chrome Memory System Health Benchmark."""

  def CreateStorySet(self, options):
    return page_sets.SystemHealthStorySet(platform='desktop', case='load')

  @classmethod
  def ShouldDisable(cls, possible_browser):
    return (
        super(BattOrSystemHealthLoadingDesktop, cls).ShouldDisable(
            possible_browser) or
        possible_browser.platform.GetDeviceTypeName() != 'Desktop')

  @classmethod
  def Name(cls):
    return 'battor.system_health_loading_desktop'


class BattOrSystemHealthLoadingMobile(_BattOrBenchmark):
  """Mobile Chrome Memory System Health Benchmark."""

  def CreateStorySet(self, options):
    return page_sets.SystemHealthStorySet(platform='mobile', case='load')

  @classmethod
  def ShouldDisable(cls, possible_browser):
    if possible_browser.platform.GetDeviceTypeName() == 'Desktop':
      return True
    if (possible_browser.browser_type == 'reference' and
        possible_browser.platform.GetDeviceTypeName() == 'Nexus 5X'):
      return True

    return super(BattOrSystemHealthLoadingMobile, cls).ShouldDisable(
        possible_browser)

  @classmethod
  def Name(cls):
    return 'battor.system_health_loading_mobile'


class BattOrPowerCases(_BattOrBenchmark):
  page_set = page_sets.power_cases.PowerCasesPageSet

  @classmethod
  def Name(cls):
    return 'battor.power_cases'


@benchmark.Disabled('all')  # crbug.com/651384.
class BattOrPowerCasesNoChromeTrace(_BattOrBenchmark):
  page_set = page_sets.power_cases.PowerCasesPageSet

  def CreateTimelineBasedMeasurementOptions(self):
    options = timeline_based_measurement.Options()
    # TODO(charliea): Reenable BattOr tracing on the main perf waterfall once
    # the BattOrs stop crashing as their SD cards fill up.
    # crbug.com/652384
    options.config.enable_battor_trace = (
        os.environ.get('BUILDBOT_MASTERNAME') == 'chromium.perf.fyi')
    options.config.enable_chrome_trace = False
    options.config.chrome_trace_config.SetDefaultOverheadFilter()
    options.SetTimelineBasedMetrics(['powerMetric', 'clockSyncLatencyMetric'])
    return options

  @classmethod
  def Name(cls):
    return 'battor.power_cases_no_chrome_trace'


@benchmark.Enabled('mac')
class BattOrTrivialPages(_BattOrBenchmark):

  def CreateStorySet(self, options):
    # We want it to wait for 30 seconds to be comparable to legacy power tests.
    return page_sets.MacGpuTrivialPagesStorySet(wait_in_seconds=30)

  @classmethod
  def Name(cls):
    return 'battor.trivial_pages'

@benchmark.Enabled('mac')
class BattOrSteadyStatePages(_BattOrBenchmark):

  def CreateStorySet(self, options):
    # We want it to wait for 30 seconds to be comparable to legacy power tests.
    return page_sets.IdleAfterLoadingStories(wait_in_seconds=30)

  @classmethod
  def Name(cls):
    return 'battor.steady_state'
