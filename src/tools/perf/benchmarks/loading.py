# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from core import perf_benchmark
import page_sets

from benchmarks import page_cycler_v2
from telemetry import benchmark
from telemetry.page import cache_temperature


@benchmark.Disabled('all')  # crbug.com/654215
class LoadingMobile(perf_benchmark.PerfBenchmark):
  """ A benchmark measuring loading performance of mobile sites. """

  options = {'pageset_repeat': 2}

  def CreateTimelineBasedMeasurementOptions(self):
    return page_cycler_v2.TimelineBasedMeasurementOptionsForLoadingMetric()

  @classmethod
  def Name(cls):
    return 'loading.mobile'

  def CreateStorySet(self, options):
    return page_sets.LoadingMobileStorySet(cache_temperatures=[
          cache_temperature.ANY])
