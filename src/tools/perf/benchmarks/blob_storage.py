# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from core import perf_benchmark

from telemetry import story
from telemetry.timeline import chrome_trace_category_filter
from telemetry.web_perf import timeline_based_measurement

import page_sets


BLOB_CATEGORY = 'Blob'
TIMELINE_REQUIRED_CATEGORY = 'blink.console'


class BlobStorage(perf_benchmark.PerfBenchmark):
  """Timeline based measurement benchmark for Blob Storage."""

  page_set = page_sets.BlobWorkshopPageSet

  def CreateCoreTimelineBasedMeasurementOptions(self):
    cat_filter = chrome_trace_category_filter.ChromeTraceCategoryFilter()
    cat_filter.AddIncludedCategory(BLOB_CATEGORY)
    cat_filter.AddIncludedCategory(TIMELINE_REQUIRED_CATEGORY)

    return timeline_based_measurement.Options(
        overhead_level=cat_filter)

  # Necessary until crbug.com/544306 is finished.
  def SetExtraBrowserOptions(self, options):
    options.AppendExtraBrowserArgs(
        ['--enable-experimental-web-platform-features'])

  @classmethod
  def Name(cls):
    return 'blob_storage.blob_storage'

  @classmethod
  def ValueCanBeAddedPredicate(cls, value, is_first_result):
    if ('blob-writes' not in value.name and
        'blob-reads' not in value.name):
      return False
    return value.values != None


  def GetExpectations(self):
    class StoryExpectations(story.expectations.StoryExpectations):
      def SetExpectations(self):
        self.DisableStory('blob-mass-create-80MBx5', [story.expectations.ALL],
                          'crbug.com/510815')
        self.DisableStory('blob-create-read-10MBx30',
                          [story.expectations.ANDROID_ONE], 'crbug.com/739214')
        self.DisableStory('blob-create-read-80MBx5',
                          [story.expectations.ANDROID_ONE,
                           story.expectations.ANDROID_NEXUS5X_WEBVIEW,
                           story.expectations.ANDROID_NEXUS6_WEBVIEW],
                          'crbug.com/739214')
        self.DisableStory('blob-mass-create-10MBx30',
                          [story.expectations.ANDROID_ONE,
                           story.expectations.ANDROID_NEXUS5X_WEBVIEW,
                           story.expectations.ANDROID_NEXUS6_WEBVIEW],
                          'crbug.com/739214')
        self.DisableStory('blob-mass-create-1MBx200',
                          [story.expectations.ANDROID_ONE], 'crbug.com/739214')
        self.DisableStory('blob-mass-create-150KBx200',
                          [story.expectations.ANDROID_ONE], 'crbug.com/739214')
    return StoryExpectations()
