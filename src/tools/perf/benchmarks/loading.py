# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from core import perf_benchmark
import page_sets

from benchmarks import loading_metrics_category
from telemetry import benchmark
from telemetry import story
from telemetry.page import cache_temperature
from telemetry.page import traffic_setting
from telemetry.web_perf import timeline_based_measurement


class _LoadingBase(perf_benchmark.PerfBenchmark):
  """ A base class for loading benchmarks. """

  options = {'pageset_repeat': 2}

  def CreateCoreTimelineBasedMeasurementOptions(self):
    tbm_options = timeline_based_measurement.Options()
    loading_metrics_category.AugmentOptionsForLoadingMetrics(tbm_options)
    return tbm_options


@benchmark.Owner(emails=['kouhei@chormium.org', 'ksakamoto@chromium.org'])
class LoadingDesktop(_LoadingBase):
  """ A benchmark measuring loading performance of desktop sites. """
  SUPPORTED_PLATFORMS = [story.expectations.ALL_DESKTOP]

  @classmethod
  def ShouldDisable(cls, possible_browser):
    return possible_browser.browser_type == 'reference'

  def CreateStorySet(self, options):
    return page_sets.LoadingDesktopStorySet(
        cache_temperatures=[cache_temperature.PCV1_COLD,
                            cache_temperature.PCV1_WARM,])

  def GetExpectations(self):
    class StoryExpectations(story.expectations.StoryExpectations):
      def SetExpectations(self):
        self.DisableStory(
            'uol.com.br', [story.expectations.ALL_LINUX], 'crbug.com/752611')
        self.DisableStory(
            'Orange', [story.expectations.ALL_WIN], 'crbug.com/723783')
    return StoryExpectations()

  @classmethod
  def Name(cls):
    return 'loading.desktop'


@benchmark.Owner(emails=['kouhei@chromium.org', 'ksakamoto@chromium.org'])
class LoadingMobile(_LoadingBase):
  """ A benchmark measuring loading performance of mobile sites. """
  SUPPORTED_PLATFORMS = [story.expectations.ALL_MOBILE]

  @classmethod
  def ShouldDisable(cls, possible_browser):
    # crbug.com/619254
    if possible_browser.browser_type == 'reference':
      return True

    # crbug.com/676612
    if ((possible_browser.platform.GetDeviceTypeName() == 'Nexus 6' or
         possible_browser.platform.GetDeviceTypeName() == 'AOSP on Shamu') and
        possible_browser.browser_type == 'android-webview'):
      return True

    return False

  def CreateStorySet(self, options):
    return page_sets.LoadingMobileStorySet(
        cache_temperatures=[cache_temperature.ANY],
        traffic_settings=[traffic_setting.NONE, traffic_setting.REGULAR_3G])

  def GetExpectations(self):
    class StoryExpectations(story.expectations.StoryExpectations):
      def SetExpectations(self):
        self.DisableStory('GFK', [story.expectations.ALL],
                          'N5X Timeout issue: crbug.com/702175')
        self.DisableStory('MLSMatrix', [story.expectations.ALL],
                          'N5XTimeout issue: crbug.com/702175')
        self.DisableStory('EBS', [story.expectations.ALL],
                          'N5XTimeout issue: crbug.com/702175')
        self.DisableStory('IBI', [story.expectations.ALL],
                          'N5XTimeout issue: crbug.com/702175')
        self.DisableStory('SBS', [story.expectations.ALL],
                          'N5XTimeout issue: crbug.com/702175')
        self.DisableStory('FuturaSciences', [story.expectations.ALL],
                          'N5XTimeout issue: crbug.com/702175')
        self.DisableStory('HashOcean', [story.expectations.ALL],
                          'N5XTimeout issue: crbug.com/702175')
        self.DisableStory('163', [story.expectations.ALL],
                          'N5XTimeout issue: crbug.com/702175')
        self.DisableStory('G1', [story.expectations.ALL], 'crbug.com/656861')
        self.DisableStory('Dramaq', [story.expectations.ANDROID_NEXUS5X],
                          'Test Failure: crbug.com/750747')
        self.DisableStory('Hongkiat', [story.expectations.ANDROID_NEXUS5X],
                          'Test Failure: crbug.com/750747')
        # TODO(rnephew): Uncomment Disablings. crbug.com/728882
        # self.DisableStory(
        #     'AirHorner', [story.expectations.ALL], 'crbug.com/653775')
        # self.DisableStory(
        #     'BusRouter', [story.expectations.ALL], 'crbug.com/653775')
        # self.DisableStory('WikiOffline', [story.expectations.ALL],
        #                   'crbug.com/653775')
        # self.DisableStory(
        #     'Detik', [story.expectations.ALL], 'crbug.com/653775')
        # self.DisableStory(
        #     'Blogspot', [story.expectations.ALL], 'crbug.com/653775')
    return StoryExpectations()

  @classmethod
  def Name(cls):
    return 'loading.mobile'
