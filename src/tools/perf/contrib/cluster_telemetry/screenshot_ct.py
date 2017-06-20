# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from core import perf_benchmark

from contrib.cluster_telemetry import ct_benchmarks_util
from contrib.cluster_telemetry import page_set
from contrib.cluster_telemetry import repaint_helpers
from contrib.cluster_telemetry import screenshot

class ScreenshotCT(perf_benchmark.PerfBenchmark):
  """Captures PNG screenshots of web pages for Cluster Telemetry. Screenshots
     written to local file with path-safe urls of pages as filenames. Cluster
     Telemetry is then used for aggregation and analysis."""

  @classmethod
  def Name(cls):
    return 'screenshot_ct'

  @classmethod
  def AddBenchmarkCommandLineArgs(cls, parser):
    ct_benchmarks_util.AddBenchmarkCommandLineArgs(parser)
    parser.add_option('--png-outdir', type='string',
                      default=None,
                      help='Output directory for the PNG files')
    parser.add_option('--wait-time', type='float', default=0,
                      help='Wait time before the benchmark is started')

  @classmethod
  def ProcessCommandLineArgs(cls, parser, args):
    ct_benchmarks_util.ValidateCommandLineArgs(parser, args)
    if not args.png_outdir:
      parser.error('Please specify --png-outdir')

  def CreatePageTest(self, options):
    return screenshot.Screenshot(options.png_outdir)

  def CreateStorySet(self, options):
    return page_set.CTPageSet(
        options.urls_list, options.user_agent, options.archive_data_file,
        run_page_interaction_callback=repaint_helpers.WaitThenRepaint)
