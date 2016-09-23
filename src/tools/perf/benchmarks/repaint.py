# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from core import perf_benchmark

from benchmarks import silk_flags
import ct_benchmarks_util
from measurements import smoothness
import page_sets
from telemetry import benchmark


class _Repaint(perf_benchmark.PerfBenchmark):

  @classmethod
  def AddBenchmarkCommandLineArgs(cls, parser):
    parser.add_option('--mode', type='string',
                      default='viewport',
                      help='Invalidation mode. '
                      'Supported values: fixed_size, layer, random, viewport.')
    parser.add_option('--width', type='int',
                      default=None,
                      help='Width of invalidations for fixed_size mode.')
    parser.add_option('--height', type='int',
                      default=None,
                      help='Height of invalidations for fixed_size mode.')

  @classmethod
  def Name(cls):
    return 'repaint'

  def CreateStorySet(self, options):
    return page_sets.KeyMobileSitesRepaintPageSet(
        options.mode, options.width, options.height)

  def CreatePageTest(self, options):
    return smoothness.Repaint()

# crbug.com/499320
#@benchmark.Enabled('android')


@benchmark.Disabled('all')
class RepaintKeyMobileSites(_Repaint):
  """Measures repaint performance on the key mobile sites.

  http://www.chromium.org/developers/design-documents/rendering-benchmarks"""

  @classmethod
  def Name(cls):
    return 'repaint.key_mobile_sites_repaint'


# crbug.com/502179
@benchmark.Enabled('android')
@benchmark.Disabled('all')
class RepaintGpuRasterizationKeyMobileSites(_Repaint):
  """Measures repaint performance on the key mobile sites with forced GPU
  rasterization.

  http://www.chromium.org/developers/design-documents/rendering-benchmarks"""
  tag = 'gpu_rasterization'

  def SetExtraBrowserOptions(self, options):
    silk_flags.CustomizeBrowserOptionsForGpuRasterization(options)

  @classmethod
  def Name(cls):
    return 'repaint.gpu_rasterization.key_mobile_sites_repaint'


# Disabled because we do not plan on running CT benchmarks on the perf
# waterfall any time soon.
@benchmark.Disabled('all')
class RepaintCT(_Repaint):
  """Measures repaint performance for Cluster Telemetry."""

  @classmethod
  def Name(cls):
    return 'repaint_ct'

  @classmethod
  def AddBenchmarkCommandLineArgs(cls, parser):
    _Repaint.AddBenchmarkCommandLineArgs(parser)
    ct_benchmarks_util.AddBenchmarkCommandLineArgs(parser)

  @classmethod
  def ProcessCommandLineArgs(cls, parser, args):
    ct_benchmarks_util.ValidateCommandLineArgs(parser, args)

  def CreateStorySet(self, options):
    return page_sets.CTPageSet(
        options.urls_list, options.user_agent, options.archive_data_file)
