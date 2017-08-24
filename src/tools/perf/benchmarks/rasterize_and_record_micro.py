# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from core import perf_benchmark

from measurements import rasterize_and_record_micro
import page_sets
from telemetry import benchmark
from telemetry import story


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


@benchmark.Owner(
    emails=['vmpstr@chromium.org', 'wkorman@chromium.org'],
    component='Internals>Compositing>Rasterization')
class RasterizeAndRecordMicroTop25(_RasterizeAndRecordMicro):
  """Measures rasterize and record performance on the top 25 web pages.

  http://www.chromium.org/developers/design-documents/rendering-benchmarks"""
  page_set = page_sets.Top25PageSet

  @classmethod
  def Name(cls):
    return 'rasterize_and_record_micro.top_25'

  def GetExpectations(self):
    class StoryExpectations(story.expectations.StoryExpectations):
      def SetExpectations(self):
        self.DisableStory('http://www.cnn.com', [story.expectations.ALL],
                          'crbug.com/528472')
        self.DisableStory('https://mail.google.com/mail/',
                          [story.expectations.ALL],
                          'crbug.com/747021')
        self.DisableStory('Wikipedia (1 tab)',
                          [story.expectations.ALL_MAC],
                          'crbug.com/756117')
        self.DisableStory('Wordpress',
                          [story.expectations.ALL_MAC],
                          'crbug.com/756117')
        self.DisableStory('http://news.yahoo.com',
                          [story.expectations.ALL_MAC],
                          'crbug.com/756117')
        self.DisableStory('http://sports.yahoo.com/',
                          [story.expectations.ALL_MAC],
                          'crbug.com/756117')
    return StoryExpectations()


@benchmark.Owner(
    emails=['vmpstr@chromium.org', 'wkorman@chromium.org'],
    component='Internals>Compositing>Rasterization')
class RasterizeAndRecordMicroPartialInvalidation(_RasterizeAndRecordMicro):
  """Measures rasterize and record performance for partial inval. on big pages.

  http://www.chromium.org/developers/design-documents/rendering-benchmarks"""
  page_set = page_sets.PartialInvalidationCasesPageSet

  @classmethod
  def Name(cls):
    return 'rasterize_and_record_micro.partial_invalidation'

  def GetExpectations(self):
    class StoryExpectations(story.expectations.StoryExpectations):
      def SetExpectations(self):
        pass # Nothing disabled.
    return StoryExpectations()
