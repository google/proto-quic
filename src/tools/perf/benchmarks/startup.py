# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from core import perf_benchmark
from measurements import startup
import page_sets
from telemetry import benchmark


class _StartupCold(perf_benchmark.PerfBenchmark):
  """Measures cold startup time with a clean profile."""
  options = {'pageset_repeat': 5}

  @classmethod
  def Name(cls):
    return 'startup'

  def CreatePageTest(self, options):
    return startup.Startup(cold=True)


class _StartupWarm(perf_benchmark.PerfBenchmark):
  """Measures warm startup time with a clean profile."""
  options = {'pageset_repeat': 20}

  @classmethod
  def Name(cls):
    return 'startup'

  @classmethod
  def ValueCanBeAddedPredicate(cls, _, is_first_result):
    return not is_first_result

  def CreatePageTest(self, options):
    return startup.Startup(cold=False)


@benchmark.Disabled('snowleopard')  # crbug.com/336913
@benchmark.Disabled('android')
class StartupColdBlankPage(_StartupCold):
  """Measures cold startup time with a clean profile."""
  tag = 'cold'
  page_set = page_sets.BlankPageSet

  @classmethod
  def Name(cls):
    return 'startup.cold.blank_page'


@benchmark.Disabled('android')
class StartupWarmBlankPage(_StartupWarm):
  """Measures warm startup time with a clean profile."""
  tag = 'warm'
  page_set = page_sets.BlankPageSet

  @classmethod
  def Name(cls):
    return 'startup.warm.blank_page'


@benchmark.Disabled('reference',                   # http://crbug.com/476882
                    'android',                     # http://crbug.com/481919
                    'yosemite',                    # http://crbug.com/605485
                    'mac',                         # http://crbug.com/700843
                    'content-shell')               # No pregenerated profiles.
class StartupLargeProfileColdBlankPage(_StartupCold):
  """Measures cold startup time with a large profile."""
  tag = 'cold'
  page_set = page_sets.BlankPageSetWithLargeProfile
  options = {'pageset_repeat': 3}

  def __init__(self, max_failures=None):
    super(StartupLargeProfileColdBlankPage, self).__init__(max_failures)

  def SetExtraBrowserOptions(self, options):
    options.browser_startup_timeout = 10 * 60

  @classmethod
  def Name(cls):
    return 'startup.large_profile.cold.blank_page'


@benchmark.Disabled('reference',                   # http://crbug.com/476882
                    'android',                     # http://crbug.com/481919
                    'yosemite',                    # http://crbug.com/605485
                    'mac',                         # http://crbug.com/700843
                    'win',                         # http://crbug.com/704137
                    'content-shell')               # No pregenerated profiles.
class StartupLargeProfileWarmBlankPage(_StartupWarm):
  """Measures warm startup time with a large profile."""
  tag = 'warm'
  page_set = page_sets.BlankPageSetWithLargeProfile
  options = {'pageset_repeat': 4}

  def __init__(self, max_failures=None):
    super(StartupLargeProfileWarmBlankPage, self).__init__(max_failures)

  def SetExtraBrowserOptions(self, options):
    options.browser_startup_timeout = 10 * 60

  @classmethod
  def Name(cls):
    return 'startup.large_profile.warm.blank_page'
