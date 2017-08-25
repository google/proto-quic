# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from core import perf_benchmark
from measurements import startup
import page_sets
from telemetry import benchmark
from telemetry import story


class _StartWithExt(perf_benchmark.PerfBenchmark):
  """Base benchmark for testing startup with extensions."""
  page_set = page_sets.BlankPageSetWithExtensionProfile
  tag = None

  @classmethod
  def Name(cls):
    return 'start_with_ext.blank_page'

  @classmethod
  def ValueCanBeAddedPredicate(cls, _, is_first_result):
    return not is_first_result

  def SetExtraBrowserOptions(self, options):
    options.disable_default_apps = False

  def CreatePageTest(self, _):
    is_cold = (self.tag == 'cold')
    return startup.Startup(cold=is_cold)


@benchmark.Enabled('has tabs')
@benchmark.Disabled('mac')  # crbug.com/563424
@benchmark.Disabled('win', 'linux', 'reference', 'android')
class StartWithExtCold(_StartWithExt):
  """Measure time to start Chrome cold with extensions."""
  options = {'pageset_repeat': 5}
  tag = 'cold'

  @classmethod
  def Name(cls):
    return 'start_with_ext.cold.blank_page'

  def GetExpectations(self):
    class StoryExpectations(story.expectations.StoryExpectations):
      def SetExpectations(self):
        pass # blank_page.html not disabled.
    return StoryExpectations()


@benchmark.Enabled('has tabs')
@benchmark.Disabled('mac')  # crbug.com/563424
@benchmark.Disabled('win', 'linux', 'reference', 'android')
class StartWithExtWarm(_StartWithExt):
  """Measure time to start Chrome warm with extensions."""
  options = {'pageset_repeat': 20}
  tag = 'warm'

  @classmethod
  def Name(cls):
    return 'start_with_ext.warm.blank_page'

  def GetExpectations(self):
    class StoryExpectations(story.expectations.StoryExpectations):
      def SetExpectations(self):
        pass # blank_page.html not disabled.
    return StoryExpectations()
