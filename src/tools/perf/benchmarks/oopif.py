# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# TODO(rnephew): Migrate to loading benchmark harness.
from core import perf_benchmark
import page_sets

from benchmarks import loading_metrics_category
from telemetry import benchmark
from telemetry import story
from telemetry.page import cache_temperature
from telemetry.web_perf import timeline_based_measurement

class _OopifBase(perf_benchmark.PerfBenchmark):
  options = {'pageset_repeat': 2}

  def CreateTimelineBasedMeasurementOptions(self):
    tbm_options = timeline_based_measurement.Options()
    loading_metrics_category.AugmentOptionsForLoadingMetrics(tbm_options)
    return tbm_options

  @classmethod
  def ShouldDisable(cls, possible_browser):
    # crbug.com/619254
    if possible_browser.browser_type == 'reference':
      return True

    # crbug.com/616781
    if (cls.IsSvelte(possible_browser) or
        possible_browser.platform.GetDeviceTypeName() == 'Nexus 5X' or
        possible_browser.platform.GetDeviceTypeName() == 'AOSP on BullHead'):
      return True

    return False


@benchmark.Disabled('reference', 'android')
@benchmark.Owner(emails=['nasko@chromium.org'])
class PageCyclerV2BasicOopifIsolated(_OopifBase):
  """ A benchmark measuring performance of out-of-process iframes. """
  page_set = page_sets.OopifBasicPageSet

  @classmethod
  def Name(cls):
    return 'page_cycler_v2_site_isolation.basic_oopif'

  def SetExtraBrowserOptions(self, options):
    options.AppendExtraBrowserArgs(['--site-per-process'])

  def CreateStorySet(self, options):
    return page_sets.OopifBasicPageSet(cache_temperatures=[
          cache_temperature.PCV1_COLD, cache_temperature.PCV1_WARM])

  def GetExpectations(self):
    class StoryExpectations(story.expectations.StoryExpectations):
      def SetExpectations(self):
        pass # No tests disabled.
    return StoryExpectations()


@benchmark.Disabled('android')
@benchmark.Owner(emails=['nasko@chromium.org'])
class PageCyclerV2BasicOopif(_OopifBase):
  """ A benchmark measuring performance of the out-of-process iframes page
  set, without running in out-of-process iframes mode.. """
  page_set = page_sets.OopifBasicPageSet

  @classmethod
  def Name(cls):
    return 'page_cycler_v2.basic_oopif'

  def CreateStorySet(self, options):
    return page_sets.OopifBasicPageSet(cache_temperatures=[
          cache_temperature.PCV1_COLD, cache_temperature.PCV1_WARM])

  def GetExpectations(self):
    class StoryExpectations(story.expectations.StoryExpectations):
      def SetExpectations(self):
        pass # No tests disabled.
    return StoryExpectations()
