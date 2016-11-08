# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from core import perf_benchmark

import ct_benchmarks_util
from measurements import rasterize_and_record_micro
import page_sets
from page_sets import repaint_helpers
from telemetry import benchmark


class _RasterizeAndRecordMicro(perf_benchmark.PerfBenchmark):

  @classmethod
  def AddBenchmarkCommandLineArgs(cls, parser):
    parser.add_option('--start-wait-time', type='float',
                      default=2,
                      help='Wait time before the benchmark is started '
                      '(must be long enough to load all content)')
    parser.add_option('--rasterize-repeat', type='int',
                      default=100,
                      help='Repeat each raster this many times. Increase '
                      'this value to reduce variance.')
    parser.add_option('--record-repeat', type='int',
                      default=100,
                      help='Repeat each record this many times. Increase '
                      'this value to reduce variance.')
    parser.add_option('--timeout', type='int',
                      default=120,
                      help='The length of time to wait for the micro '
                      'benchmark to finish, expressed in seconds.')
    parser.add_option('--report-detailed-results',
                      action='store_true',
                      help='Whether to report additional detailed results.')

  @classmethod
  def Name(cls):
    return 'rasterize_and_record_micro'

  def CreatePageTest(self, options):
    return rasterize_and_record_micro.RasterizeAndRecordMicro(
        options.start_wait_time, options.rasterize_repeat,
        options.record_repeat, options.timeout, options.report_detailed_results)


# RasterizeAndRecord disabled on mac because of crbug.com/350684.
# RasterizeAndRecord disabled on windows because of crbug.com/338057.
@benchmark.Disabled('mac', 'win',
                    'android')  # http://crbug.com/610018
class RasterizeAndRecordMicroTop25(_RasterizeAndRecordMicro):
  """Measures rasterize and record performance on the top 25 web pages.

  http://www.chromium.org/developers/design-documents/rendering-benchmarks"""
  page_set = page_sets.Top25PageSet

  @classmethod
  def Name(cls):
    return 'rasterize_and_record_micro.top_25'


@benchmark.Disabled('mac', 'win', 'android')  # http://crbug.com/531597
class RasterizeAndRecordMicroKeyMobileSites(_RasterizeAndRecordMicro):
  """Measures rasterize and record performance on the key mobile sites.

  http://www.chromium.org/developers/design-documents/rendering-benchmarks"""
  page_set = page_sets.KeyMobileSitesPageSet

  @classmethod
  def Name(cls):
    return 'rasterize_and_record_micro.key_mobile_sites'


@benchmark.Disabled('all') # http://crbug.com/610424
class RasterizeAndRecordMicroKeySilkCases(_RasterizeAndRecordMicro):
  """Measures rasterize and record performance on the silk sites.

  http://www.chromium.org/developers/design-documents/rendering-benchmarks"""

  @classmethod
  def Name(cls):
    return 'rasterize_and_record_micro.key_silk_cases'

  def CreateStorySet(self, options):
    return page_sets.KeySilkCasesPageSet(run_no_page_interactions=True)


@benchmark.Enabled('android')
class RasterizeAndRecordMicroPolymer(_RasterizeAndRecordMicro):
  """Measures rasterize and record performance on the Polymer cases.

  http://www.chromium.org/developers/design-documents/rendering-benchmarks"""

  @classmethod
  def Name(cls):
    return 'rasterize_and_record_micro.polymer'

  def CreateStorySet(self, options):
    return page_sets.PolymerPageSet(run_no_page_interactions=True)


# New benchmark only enabled on Linux until we've observed behavior for a
# reasonable period of time.
@benchmark.Disabled('mac', 'win', 'android')
class RasterizeAndRecordMicroPartialInvalidation(_RasterizeAndRecordMicro):
  """Measures rasterize and record performance for partial inval. on big pages.

  http://www.chromium.org/developers/design-documents/rendering-benchmarks"""
  page_set = page_sets.PartialInvalidationCasesPageSet

  @classmethod
  def Name(cls):
    return 'rasterize_and_record_micro.partial_invalidation'


# Disabled because we do not plan on running CT benchmarks on the perf
# waterfall any time soon.
@benchmark.Disabled('all')
class RasterizeAndRecordMicroCT(_RasterizeAndRecordMicro):
  """Measures rasterize and record performance for Cluster Telemetry."""

  @classmethod
  def Name(cls):
    return 'rasterize_and_record_micro_ct'

  @classmethod
  def AddBenchmarkCommandLineArgs(cls, parser):
    _RasterizeAndRecordMicro.AddBenchmarkCommandLineArgs(parser)
    ct_benchmarks_util.AddBenchmarkCommandLineArgs(parser)

  @classmethod
  def ProcessCommandLineArgs(cls, parser, args):
    ct_benchmarks_util.ValidateCommandLineArgs(parser, args)

  def CreateStorySet(self, options):
    return page_sets.CTPageSet(
        options.urls_list, options.user_agent, options.archive_data_file,
        run_page_interaction_callback=repaint_helpers.WaitThenRepaint)
