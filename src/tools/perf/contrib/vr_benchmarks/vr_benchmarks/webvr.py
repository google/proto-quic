# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from benchmarks import memory
from core import perf_benchmark
from telemetry import benchmark
from telemetry.timeline import chrome_trace_category_filter
from telemetry.timeline import chrome_trace_config
from telemetry.web_perf import timeline_based_measurement
from contrib.vr_benchmarks.vr_page_sets import webvr_sample_pages


@benchmark.Owner(emails=['bsheedy@chromium.org', 'leilei@chromium.org'])
class XrWebVrStatic(perf_benchmark.PerfBenchmark):
  """Measures WebVR performance with sample pages."""

  @classmethod
  def AddBenchmarkCommandLineArgs(cls, parser):
    parser.add_option('--shared-prefs-file',
                      help='The path relative to the Chromium source root '
                           'to a file containing a JSON list of shared '
                           'preference files to edit and how to do so. '
                           'See examples in //chrome/android/'
                           'shared_preference_files/test/')

  def CreateCoreTimelineBasedMeasurementOptions(self):
    memory_categories = ['blink.console', 'disabled-by-default-memory-infra']
    gpu_categories = ['gpu']
    category_filter = chrome_trace_category_filter.ChromeTraceCategoryFilter(
        ','.join(['-*'] + memory_categories + gpu_categories))
    options = timeline_based_measurement.Options(category_filter)
    options.config.enable_android_graphics_memtrack = True
    options.config.enable_platform_display_trace = True

    options.SetTimelineBasedMetrics(['memoryMetric', 'webvrMetric'])
    options.config.chrome_trace_config.SetMemoryDumpConfig(
        chrome_trace_config.MemoryDumpConfig())
    return options

  def CreateStorySet(self, options):
    return webvr_sample_pages.WebVrSamplePageSet()

  def SetExtraBrowserOptions(self, options):
    memory.SetExtraBrowserOptionsForMemoryMeasurement(options)
    options.AppendExtraBrowserArgs(['--enable-webvr',])

  @classmethod
  def Name(cls):
    return 'xr.webvr.static'

  @classmethod
  def ValueCanBeAddedPredicate(cls, value, is_first_result):
    return memory.DefaultValueCanBeAddedPredicateForMemoryMeasurement(value)
