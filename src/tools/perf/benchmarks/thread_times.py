# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from core import perf_benchmark

from benchmarks import silk_flags
from measurements import thread_times
import page_sets
from telemetry import benchmark


class _ThreadTimes(perf_benchmark.PerfBenchmark):

  @classmethod
  def AddBenchmarkCommandLineArgs(cls, parser):
    parser.add_option('--report-silk-details', action='store_true',
                      help='Report details relevant to silk.')

  @classmethod
  def Name(cls):
    return 'thread_times'

  @classmethod
  def ValueCanBeAddedPredicate(cls, value, _):
    # Default to only reporting per-frame metrics.
    return 'per_second' not in value.name

  def SetExtraBrowserOptions(self, options):
    silk_flags.CustomizeBrowserOptionsForThreadTimes(options)

  def CreatePageTest(self, options):
    return thread_times.ThreadTimes(options.report_silk_details)


@benchmark.Enabled('android')
@benchmark.Owner(emails=['vmiura@chromium.org'])
class ThreadTimesKeySilkCases(_ThreadTimes):
  """Measures timeline metrics while performing smoothness action on key silk
  cases."""
  page_set = page_sets.KeySilkCasesPageSet

  @classmethod
  def Name(cls):
    return 'thread_times.key_silk_cases'

  def GetExpectations(self):
    return page_sets.KeySilkCasesStoryExpectations()


@benchmark.Enabled('android', 'linux')
class ThreadTimesKeyHitTestCases(_ThreadTimes):
  """Measure timeline metrics while performing smoothness action on key hit
  testing cases."""
  page_set = page_sets.KeyHitTestCasesPageSet

  @classmethod
  def Name(cls):
    return 'thread_times.key_hit_test_cases'

  def GetExpectations(self):
    return page_sets.KeyHitTestCasesStoryExpectations()


@benchmark.Enabled('android')
class ThreadTimesFastPathMobileSites(_ThreadTimes):
  """Measures timeline metrics while performing smoothness action on
  key mobile sites labeled with fast-path tag.
  http://www.chromium.org/developers/design-documents/rendering-benchmarks"""
  page_set = page_sets.KeyMobileSitesSmoothPageSet
  options = {'story_tag_filter': 'fastpath'}

  @classmethod
  def Name(cls):
    return 'thread_times.key_mobile_sites_smooth'

  def GetExpectations(self):
    return page_sets.KeyMobileSitesStoryExpectations()


@benchmark.Enabled('android')
@benchmark.Owner(emails=['vmiura@chromium.org'])
class ThreadTimesSimpleMobileSites(_ThreadTimes):
  """Measures timeline metric using smoothness action on simple mobile sites
  http://www.chromium.org/developers/design-documents/rendering-benchmarks"""
  page_set = page_sets.SimpleMobileSitesPageSet

  @classmethod
  def Name(cls):
    return 'thread_times.simple_mobile_sites'

  def GetExpectations(self):
    return page_sets.SimpleMobileSitesStoryExpectations()


@benchmark.Owner(emails=['vmiura@chromium.org'])
class ThreadTimesCompositorCases(_ThreadTimes):
  """Measures timeline metrics while performing smoothness action on
  tough compositor cases, using software rasterization.

  http://www.chromium.org/developers/design-documents/rendering-benchmarks"""
  page_set = page_sets.ToughCompositorCasesPageSet

  def SetExtraBrowserOptions(self, options):
    super(ThreadTimesCompositorCases, self).SetExtraBrowserOptions(options)
    silk_flags.CustomizeBrowserOptionsForSoftwareRasterization(options)

  @classmethod
  def Name(cls):
    return 'thread_times.tough_compositor_cases'

  def GetExpectations(self):
    return page_sets.ToughCompositorCaseStoryExpectations()


@benchmark.Enabled('android')
@benchmark.Owner(emails=['ykyyip@chromium.org'])
class ThreadTimesPolymer(_ThreadTimes):
  """Measures timeline metrics while performing smoothness action on
  Polymer cases."""
  page_set = page_sets.PolymerPageSet

  @classmethod
  def Name(cls):
    return 'thread_times.polymer'

  def GetExpectations(self):
    return page_sets.PolymerThreadTimesStoryExpectations()


@benchmark.Enabled('android')
@benchmark.Owner(emails=['skyostil@chromium.org'])
class ThreadTimesKeyIdlePowerCases(_ThreadTimes):
  """Measures timeline metrics for sites that should be idle in foreground
  and background scenarios. The metrics are per-second rather than per-frame."""
  page_set = page_sets.KeyIdlePowerCasesPageSet

  @classmethod
  def Name(cls):
    return 'thread_times.key_idle_power_cases'

  @classmethod
  def ValueCanBeAddedPredicate(cls, value, _):
    # Only report per-second metrics.
    return 'per_frame' not in value.name and 'mean_frame' not in value.name

  def GetExpectations(self):
    return page_sets.KeyIdlePowerCasesStoryExpectations()


@benchmark.Enabled('android')
class ThreadTimesKeyNoOpCases(_ThreadTimes):
  """Measures timeline metrics for common interactions and behaviors that should
  have minimal cost. The metrics are per-second rather than per-frame."""
  page_set = page_sets.KeyNoOpCasesPageSet

  @classmethod
  def Name(cls):
    return 'thread_times.key_noop_cases'

  @classmethod
  def ValueCanBeAddedPredicate(cls, value, _):
    # Only report per-second metrics.
    return 'per_frame' not in value.name and 'mean_frame' not in value.name

  def GetExpectations(self):
    return page_sets.KeyNoOpCasesStoryExpectations()


@benchmark.Owner(emails=['tdresser@chromium.org'])
class ThreadTimesToughScrollingCases(_ThreadTimes):
  """Measure timeline metrics while performing smoothness action on tough
  scrolling cases."""
  page_set = page_sets.ToughScrollingCasesPageSet

  @classmethod
  def Name(cls):
    return 'thread_times.tough_scrolling_cases'

  def GetExpectations(self):
    return page_sets.ToughScrollingCasesStoryExpectations()
