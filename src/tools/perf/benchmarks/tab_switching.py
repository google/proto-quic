# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from core import perf_benchmark

from measurements import tab_switching
import page_sets
from telemetry import benchmark


@benchmark.Enabled('has tabs')
@benchmark.Disabled('android')  # http://crbug.com/460084
@benchmark.Disabled('mac-reference')  # http://crbug.com/634378
class TabSwitchingTop10(perf_benchmark.PerfBenchmark):
  """This test records the MPArch.RWH_TabSwitchPaintDuration histogram.

  The histogram is a measure of the time between when a tab was requested to be
  shown, and when first paint occurred. The script opens 10 pages in different
  tabs, waits for them to load, and then switches to each tab and records the
  metric. The pages were chosen from Alexa top ranking sites.
  """
  test = tab_switching.TabSwitching
  page_set = page_sets.Top10PageSet

  @classmethod
  def Name(cls):
    return 'tab_switching.top_10'

  @classmethod
  def ShouldTearDownStateAfterEachStoryRun(cls):
    return False


@benchmark.Enabled('has tabs')
@benchmark.Disabled('mac-reference')  # http://crbug.com/612774
@benchmark.Disabled('android')  # http://crbug.com/460084
class TabSwitchingTypical25(perf_benchmark.PerfBenchmark):
  """This test records the MPArch.RWH_TabSwitchPaintDuration histogram.

  The histogram is a measure of the time between when a tab was requested to be
  shown, and when first paint occurred. The script opens 25 pages in different
  tabs, waits for them to load, and then switches to each tab and records the
  metric. The pages were chosen from Alexa top ranking sites.
  """
  test = tab_switching.TabSwitching

  def CreateStorySet(self, options):
    return page_sets.Typical25PageSet(run_no_page_interactions=True)

  @classmethod
  def Name(cls):
    return 'tab_switching.typical_25'

  @classmethod
  def ShouldTearDownStateAfterEachStoryRun(cls):
    return False


@benchmark.Disabled('android')  # http://crbug.com/460084
@benchmark.Disabled('mac-reference')  # http://crbug.com/634360
@benchmark.Enabled('has tabs')
class TabSwitchingFiveBlankTabs(perf_benchmark.PerfBenchmark):
  """This test records the MPArch.RWH_TabSwitchPaintDuration histogram.

  The histogram is a measure of the time between when a tab was requested to be
  shown, and when first paint occurred. The script opens 5 blank pages in
  different tabs, waits for them to load, and then switches to each tab and
  records the metric. Blank pages are use to detect unnecessary idle wakeups.
  """
  test = tab_switching.TabSwitching
  page_set = page_sets.FiveBlankPagesPageSet
  options = {'pageset_repeat': 10}

  @classmethod
  def Name(cls):
    return 'tab_switching.five_blank_pages'

  @classmethod
  def ShouldTearDownStateAfterEachStoryRun(cls):
    return False


@benchmark.Enabled('has tabs')
# http://crbug.com/460084, http://crbug.com/488067, http://crbug.com/634347
# win: http://crbug.com/677311
@benchmark.Disabled('android', 'linux', 'mac-reference', 'win')
class TabSwitchingToughEnergyCases(perf_benchmark.PerfBenchmark):
  """This test records the MPArch.RWH_TabSwitchPaintDuration histogram.

  The histogram is a measure of the time between when a tab was requested to be
  shown, and when first paint occurred. The script opens each page in a
  different tab, waits for them to load, and then switches to each tab and
  records the metric. The pages were written by hand to stress energy usage.
  """
  test = tab_switching.TabSwitching
  page_set = page_sets.ToughEnergyCasesPageSet
  options = {'pageset_repeat': 10}

  @classmethod
  def Name(cls):
    return 'tab_switching.tough_energy_cases'

  @classmethod
  def ShouldTearDownStateAfterEachStoryRun(cls):
    return False


@benchmark.Enabled('has tabs')
@benchmark.Disabled('android')  # http://crbug.com/460084
class TabSwitchingToughImageCases(perf_benchmark.PerfBenchmark):
  """This test records the MPArch.RWH_TabSwitchPaintDuration histogram.

  The histogram is a measure of the time between when a tab was requested to be
  shown, and when first paint occurred. The script opens each page in different
  tabs, waits for them to load, and then switches to each tab and records the
  metric. The pages were chosen by hand to stress the image decoding system.
  """
  test = tab_switching.TabSwitching
  page_set = page_sets.ToughImageCasesPageSet

  @classmethod
  def Name(cls):
    return 'tab_switching.tough_image_cases'

  @classmethod
  def ShouldTearDownStateAfterEachStoryRun(cls):
    return False
