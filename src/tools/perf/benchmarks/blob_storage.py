# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from core import perf_benchmark

from telemetry import benchmark
from telemetry.timeline import chrome_trace_category_filter
from telemetry.web_perf import timeline_based_measurement

import page_sets


BLOB_CATEGORY = 'Blob'
TIMELINE_REQUIRED_CATEGORY = 'blink.console'


# http://crbug.com/499325
# http://crbug.com/595069
@benchmark.Disabled('android', 'win')
class BlobStorage(perf_benchmark.PerfBenchmark):
  """Timeline based measurement benchmark for Blob Storage."""

  page_set = page_sets.BlobWorkshopPageSet

  def CreateTimelineBasedMeasurementOptions(self):
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
    return page_sets.BlobWorkshopStoryExpectations()
