# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from core import perf_benchmark

from telemetry import benchmark
from telemetry.timeline import chrome_trace_category_filter
from telemetry.web_perf import timeline_based_measurement
from telemetry.web_perf.metrics import jitter_timeline

import page_sets


JITTER_CATEGORY = 'cdp.perf'
TIMELINE_REQUIRED_CATEGORY = 'blink.console'


@benchmark.Owner(emails=['jaydasika@chromium.org'])
class Jitter(perf_benchmark.PerfBenchmark):
  """Timeline based measurement benchmark for jitter."""

  page_set = page_sets.JitterPageSet

  def CreateTimelineBasedMeasurementOptions(self):
    cat_filter = chrome_trace_category_filter.ChromeTraceCategoryFilter()
    cat_filter.AddIncludedCategory(JITTER_CATEGORY)
    cat_filter.AddIncludedCategory(TIMELINE_REQUIRED_CATEGORY)
    options = timeline_based_measurement.Options(
        overhead_level=cat_filter)
    options.SetLegacyTimelineBasedMetrics(
        [jitter_timeline.JitterTimelineMetric()])
    return options

  @classmethod
  def Name(cls):
    return 'jitter'
