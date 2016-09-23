# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from core import perf_benchmark

from telemetry import benchmark
from telemetry.timeline import chrome_trace_category_filter
from telemetry.timeline import chrome_trace_config
from telemetry.web_perf import timeline_based_measurement

import page_sets


class TracingWithDebugOverhead(perf_benchmark.PerfBenchmark):

  page_set = page_sets.Top10PageSet

  def CreateTimelineBasedMeasurementOptions(self):
    options = timeline_based_measurement.Options(
        timeline_based_measurement.DEBUG_OVERHEAD_LEVEL)
    options.SetTimelineBasedMetrics(['tracingMetric'])
    return options

  @classmethod
  def Name(cls):
    return 'tracing.tracing_with_debug_overhead'


# TODO(ssid): Enable on reference builds once stable browser starts supporting
# background mode memory-infra. crbug.com/621195.
@benchmark.Disabled('reference')
class TracingWithBackgroundMemoryInfra(perf_benchmark.PerfBenchmark):
  """Measures the overhead of background memory-infra dumps"""
  page_set = page_sets.Top10PageSet

  def CreateTimelineBasedMeasurementOptions(self):
    # Enable only memory-infra category with periodic background mode dumps
    # every 200 milliseconds.
    trace_memory = chrome_trace_category_filter.ChromeTraceCategoryFilter(
        filter_string='-*,blink.console,disabled-by-default-memory-infra')
    options = timeline_based_measurement.Options(overhead_level=trace_memory)
    memory_dump_config = chrome_trace_config.MemoryDumpConfig()
    memory_dump_config.AddTrigger('background', 200)
    options.config.chrome_trace_config.SetMemoryDumpConfig(memory_dump_config)
    options.SetTimelineBasedMetrics(['tracingMetric'])
    return options

  @classmethod
  def Name(cls):
    return 'tracing.tracing_with_background_memory_infra'
