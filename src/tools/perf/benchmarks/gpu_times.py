# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from core import perf_benchmark

from benchmarks import silk_flags

from telemetry import benchmark
from telemetry.timeline import chrome_trace_category_filter
from telemetry.web_perf.metrics import gpu_timeline
from telemetry.web_perf import timeline_based_measurement

import page_sets

TOPLEVEL_CATEGORIES = ['disabled-by-default-gpu.device',
                       'disabled-by-default-gpu.service']


class _GPUTimes(perf_benchmark.PerfBenchmark):

  def CreateTimelineBasedMeasurementOptions(self):
    cat_string = ','.join(TOPLEVEL_CATEGORIES)
    cat_filter = chrome_trace_category_filter.ChromeTraceCategoryFilter(
        cat_string)

    options = timeline_based_measurement.Options(overhead_level=cat_filter)
    options.SetLegacyTimelineBasedMetrics([gpu_timeline.GPUTimelineMetric()])
    return options


@benchmark.Disabled('all')  # http://crbug.com/453131, http://crbug.com/527543
class GPUTimesKeyMobileSites(_GPUTimes):
  """Measures GPU timeline metric on key mobile sites."""
  page_set = page_sets.KeyMobileSitesSmoothPageSet

  @classmethod
  def Name(cls):
    return 'gpu_times.key_mobile_sites_smooth'


@benchmark.Disabled('all')  # http://crbug.com/453131, http://crbug.com/527543
class GPUTimesGpuRasterizationKeyMobileSites(_GPUTimes):
  """Measures GPU timeline metric on key mobile sites with GPU rasterization.
  """
  page_set = page_sets.KeyMobileSitesSmoothPageSet

  def SetExtraBrowserOptions(self, options):
    silk_flags.CustomizeBrowserOptionsForGpuRasterization(options)

  @classmethod
  def Name(cls):
    return 'gpu_times.gpu_rasterization.key_mobile_sites_smooth'


@benchmark.Disabled('all')  # http://crbug.com/453131, http://crbug.com/517476
class GPUTimesTop25Sites(_GPUTimes):
  """Measures GPU timeline metric for the top 25 sites."""
  page_set = page_sets.Top25SmoothPageSet

  @classmethod
  def Name(cls):
    return 'gpu_times.top_25_smooth'


@benchmark.Disabled('all')  # http://crbug.com/453131, http://crbug.com/517476
class GPUTimesGpuRasterizationTop25Sites(_GPUTimes):
  """Measures GPU timeline metric for the top 25 sites with GPU rasterization.
  """
  page_set = page_sets.Top25SmoothPageSet

  def SetExtraBrowserOptions(self, options):
    silk_flags.CustomizeBrowserOptionsForGpuRasterization(options)

  @classmethod
  def Name(cls):
    return 'gpu_times.gpu_rasterization.top_25_smooth'
