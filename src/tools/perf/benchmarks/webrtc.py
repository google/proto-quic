# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from core import perf_benchmark

import page_sets
from telemetry import benchmark
from telemetry import story
from telemetry.timeline import chrome_trace_category_filter
from telemetry.web_perf import timeline_based_measurement


@benchmark.Owner(emails=['qiangchen@chromium.org', # For smoothness metrics
                         'ehmaldonado@chromium.org',
                         'phoglund@chromium.org'])
class WebrtcPerfBenchmark(perf_benchmark.PerfBenchmark):
  """Base class for WebRTC metrics for real-time communications tests."""
  page_set = page_sets.WebrtcPageSet

  @classmethod
  def Name(cls):
    return 'webrtc'

  def CreateCoreTimelineBasedMeasurementOptions(self):
    categories = [
        # Disable all categories by default.
        '-*',
        'toplevel',
        # WebRTC
        'webmediaplayerms',
    ]

    category_filter = chrome_trace_category_filter.ChromeTraceCategoryFilter(
        filter_string=','.join(categories))
    options = timeline_based_measurement.Options(category_filter)
    options.SetTimelineBasedMetrics([
        'cpuTimeMetric',
        'webrtcRenderingMetric',
    ])
    return options

  def SetExtraBrowserOptions(self, options):
    options.AppendExtraBrowserArgs('--use-fake-device-for-media-stream')
    options.AppendExtraBrowserArgs('--use-fake-ui-for-media-stream')

  def GetExpectations(self):
    class StoryExpectations(story.expectations.StoryExpectations):
      def SetExpectations(self):
        # TODO(qyearsley, mcasas): Add webrtc.audio when http://crbug.com/468732
        # is fixed, or revert https://codereview.chromium.org/1544573002/ when
        # http://crbug.com/568333 is fixed.
        self.DisableStory('audio_call_opus_10s',
                          [story.expectations.ALL],
                          'crbug.com/468732')
        self.DisableStory('audio_call_g772_10s',
                          [story.expectations.ALL],
                          'crbug.com/468732')
        self.DisableStory('audio_call_pcmu_10s',
                          [story.expectations.ALL],
                          'crbug.com/468732')
        self.DisableStory('audio_call_isac/1600_10s',
                          [story.expectations.ALL],
                          'crbug.com/468732')
    return StoryExpectations()
