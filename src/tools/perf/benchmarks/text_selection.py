# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from core import perf_benchmark

from telemetry import benchmark
from telemetry.timeline import chrome_trace_category_filter
from telemetry.web_perf import timeline_based_measurement

import page_sets

TEXT_SELECTION_CATEGORY = 'blink'
TIMELINE_REQUIRED_CATEGORY = 'blink.console'


class _TextSelection(perf_benchmark.PerfBenchmark):
  page_set = page_sets.TextSelectionSitesPageSet

  def CreateTimelineBasedMeasurementOptions(self):
    cat_filter = chrome_trace_category_filter.ChromeTraceCategoryFilter()
    cat_filter.AddIncludedCategory(TEXT_SELECTION_CATEGORY)
    cat_filter.AddIncludedCategory(TIMELINE_REQUIRED_CATEGORY)

    return timeline_based_measurement.Options(
        overhead_level=cat_filter)

  @classmethod
  def Name(cls):
    return 'text_selection'

  @classmethod
  def ValueCanBeAddedPredicate(cls, value, is_first_result):
    if 'text-selection' not in value.name:
      return False
    return value.values != None


# See crbug.com/519044
@benchmark.Disabled('all')
@benchmark.Owner(emails=['mfomitchev@chromium.org'])
class TextSelectionDirection(_TextSelection):
  """Measure text selection metrics while dragging a touch selection handle on a
  subset of top ten mobile sites and using the 'direction' touch selection
  strategy."""

  def SetExtraBrowserOptions(self, options):
    options.AppendExtraBrowserArgs(['--touch-selection-strategy=direction'])

  @classmethod
  def Name(cls):
    return 'text_selection.direction'


# See crbug.com/519044
@benchmark.Disabled('all')
@benchmark.Owner(emails=['mfomitchev@chromium.org'])
class TextSelectionCharacter(_TextSelection):
  """Measure text selection metrics while dragging a touch selection handle on a
  subset of top ten mobile sites and using the 'character' touch selection
  strategy."""

  def SetExtraBrowserOptions(self, options):
    options.AppendExtraBrowserArgs(['--touch-selection-strategy=character'])

  @classmethod
  def Name(cls):
    return 'text_selection.character'
