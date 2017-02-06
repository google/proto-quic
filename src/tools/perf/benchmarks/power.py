# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from core import perf_benchmark

from benchmarks import silk_flags
from measurements import power
import page_sets
from telemetry import benchmark


@benchmark.Enabled('android')
class PowerAndroidAcceptance(perf_benchmark.PerfBenchmark):
  """Android power acceptance test."""
  test = power.Power
  page_set = page_sets.AndroidAcceptancePageSet

  def SetExtraBrowserOptions(self, options):
    options.full_performance_mode = False

  @classmethod
  def Name(cls):
    return 'power.android_acceptance'


@benchmark.Enabled('android')
class PowerTypical10Mobile(perf_benchmark.PerfBenchmark):
  """Android typical 10 mobile power test."""
  test = power.Power
  page_set = page_sets.Typical10MobilePageSet

  def SetExtraBrowserOptions(self, options):
    options.full_performance_mode = False

  @classmethod
  def ShouldDisable(cls, possible_browser):
    # http://crbug.com/597656
    if (possible_browser.browser_type == 'reference' and
        possible_browser.platform.GetDeviceTypeName() == 'Nexus 5X'):
      return True

    # crbug.com/671631
    return possible_browser.platform.GetDeviceTypeName() == 'Nexus 9'

  @classmethod
  def Name(cls):
    return 'power.typical_10_mobile'

# This benchmark runs only on android but it is disabled on android as well
# because of http://crbug.com/683238
# @benchmark.Enabled('android')
@benchmark.Disabled('all')
@benchmark.Disabled('android-webview')  # http://crbug.com/622300
class PowerToughAdCases(perf_benchmark.PerfBenchmark):
  """Android power test with tough ad pages."""
  test = power.Power
  page_set = page_sets.ToughAdCasesPageSet

  def SetExtraBrowserOptions(self, options):
    options.full_performance_mode = False

  @classmethod
  def Name(cls):
    return 'power.tough_ad_cases'

  @classmethod
  def ShouldDisable(cls, possible_browser):
     # http://crbug.com/563968, http://crbug.com/593973
    return (cls.IsSvelte(possible_browser) or
      (possible_browser.browser_type ==  'reference' and
       possible_browser.platform.GetDeviceTypeName() == 'Nexus 5X'))


@benchmark.Enabled('android')
@benchmark.Disabled('all')
class PowerTypical10MobileReload(perf_benchmark.PerfBenchmark):
  """Android typical 10 mobile power reload test."""
  test = power.LoadPower
  page_set = page_sets.Typical10MobileReloadPageSet

  def SetExtraBrowserOptions(self, options):
    options.full_performance_mode = False

  @classmethod
  def Name(cls):
    return 'power.typical_10_mobile_reload'


@benchmark.Enabled('android')
class PowerGpuRasterizationTypical10Mobile(perf_benchmark.PerfBenchmark):
  """Measures power on key mobile sites with GPU rasterization."""
  tag = 'gpu_rasterization'
  test = power.Power
  page_set = page_sets.Typical10MobilePageSet

  def SetExtraBrowserOptions(self, options):
    silk_flags.CustomizeBrowserOptionsForGpuRasterization(options)
    options.full_performance_mode = False

  @classmethod
  def Name(cls):
    return 'power.gpu_rasterization.typical_10_mobile'

  @classmethod
  def ShouldDisable(cls, possible_browser):
    # http://crbug.com/563968
    if cls.IsSvelte(possible_browser):
      return True


    # http://crbug.com/593973
    if (possible_browser.browser_type ==  'reference' and
        possible_browser.platform.GetDeviceTypeName() == 'Nexus 5X'):
      return True

    # http://crbug.com/671631
    return possible_browser.platform.GetDeviceTypeName() == 'Nexus 9'


@benchmark.Enabled('mac')
class PowerTop10(perf_benchmark.PerfBenchmark):
  """Top 10 quiescent power test."""
  test = power.QuiescentPower
  page_set = page_sets.Top10QuiescentPageSet

  def SetExtraBrowserOptions(self, options):
    options.full_performance_mode = False

  @classmethod
  def Name(cls):
    return 'power.top_10'


@benchmark.Enabled('mac')
class PowerGpuRasterizationTop10(perf_benchmark.PerfBenchmark):
  """Top 10 quiescent power test with GPU rasterization enabled."""
  tag = 'gpu_rasterization'
  test = power.QuiescentPower
  page_set = page_sets.Top10QuiescentPageSet

  def SetExtraBrowserOptions(self, options):
    silk_flags.CustomizeBrowserOptionsForGpuRasterization(options)
    options.full_performance_mode = False

  @classmethod
  def Name(cls):
    return 'power.gpu_rasterization.top_10'


@benchmark.Enabled('mac')
class PowerTop25(perf_benchmark.PerfBenchmark):
  """Top 25 quiescent power test."""
  test = power.QuiescentPower
  page_set = page_sets.Top25PageSet

  def SetExtraBrowserOptions(self, options):
    options.full_performance_mode = False

  @classmethod
  def Name(cls):
    return 'power.top_25'

  def CreateStorySet(self, _):
    stories = self.page_set()
    to_remove = [x for x in stories if self.IsPageNotQuiescent(x.url)]
    for story in to_remove:
      stories.RemoveStory(story)
    return stories

  @staticmethod
  def IsPageNotQuiescent(page_url):
    # Exclude sites not suitable for this benchmark because they do not
    # consistently become quiescent within 60 seconds.
    non_quiescent_urls = [
      'techcrunch.com',
      'docs.google.com',
      'plus.google.com'
    ]

    return any(url in page_url for url in non_quiescent_urls)


@benchmark.Enabled('mac')
class PowerGpuRasterizationTop25(PowerTop25):
  """Top 25 quiescent power test with GPU rasterization enabled."""
  tag = 'gpu_rasterization'

  def SetExtraBrowserOptions(self, options):
    silk_flags.CustomizeBrowserOptionsForGpuRasterization(options)
    options.full_performance_mode = False

  @classmethod
  def Name(cls):
    return 'power.gpu_rasterization.top_25'


@benchmark.Enabled('mac')
class PowerScrollingTrivialPage(perf_benchmark.PerfBenchmark):
  """Measure power consumption for some very simple pages."""
  test = power.QuiescentPower
  page_set = page_sets.TrivialSitesStorySet

  @classmethod
  def Name(cls):
    return 'power.trivial_pages'

@benchmark.Enabled('mac')
class PowerSteadyStatePages(perf_benchmark.PerfBenchmark):
  """Measure power consumption for real web sites in steady state (no user
  interactions)."""
  test = power.QuiescentPower
  page_set = page_sets.IdleAfterLoadingStories

  @classmethod
  def Name(cls):
    return 'power.steady_state'
