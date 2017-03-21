# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from core import perf_benchmark

from measurements import blink_style
import page_sets
from telemetry import benchmark


@benchmark.Disabled('win8')
class BlinkStyleTop25(perf_benchmark.PerfBenchmark):
  """Measures performance of Blink's style engine (CSS Parsing, Style Recalc,
  etc.) on the top 25 pages.
  """
  test = blink_style.BlinkStyle
  page_set = page_sets.Top25PageSet

  @classmethod
  def Name(cls):
    return 'blink_style.top_25'


@benchmark.Disabled('all')  # crbug.com/702194
#@benchmark.Enabled('android')
class BlinkStyleKeyMobileSites(perf_benchmark.PerfBenchmark):
  """Measures performance of Blink's style engine (CSS Parsing, Style Recalc,
  etc.) on key mobile sites.
  """
  test = blink_style.BlinkStyle
  page_set = page_sets.KeyMobileSitesPageSet

  @classmethod
  def ShouldDisable(cls, possible_browser):  # http://crbug.com/597656
    return (possible_browser.browser_type == 'reference' and
            possible_browser.platform.GetDeviceTypeName() == 'Nexus 5X')

  @classmethod
  def Name(cls):
    return 'blink_style.key_mobile_sites'


@benchmark.Enabled('android')
class BlinkStylePolymer(perf_benchmark.PerfBenchmark):
  """Measures performance of Blink's style engine (CSS Parsing, Style Recalc,
  etc.) for Polymer cases.
  """
  test = blink_style.BlinkStyle
  page_set = page_sets.PolymerPageSet

  @classmethod
  def Name(cls):
    return 'blink_style.polymer'
