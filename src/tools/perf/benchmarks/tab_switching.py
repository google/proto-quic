# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from core import perf_benchmark

from measurements import tab_switching
import page_sets
from telemetry import benchmark


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
