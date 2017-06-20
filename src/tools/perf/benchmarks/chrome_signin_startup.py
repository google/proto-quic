# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from core import perf_benchmark
from measurements import startup
import page_sets
from telemetry import benchmark
from telemetry import story


class _StartupWarm(perf_benchmark.PerfBenchmark):
  """Measures warm startup time with a clean profile."""
  options = {'pageset_repeat': 5}

  @classmethod
  def Name(cls):
    return 'chrome_signin_starup'

  def CreatePageTest(self, options):
    return startup.Startup(cold=False)


@benchmark.Disabled('all')  # crbug.com/551938
# On android logging in is done through system accounts workflow.
@benchmark.Disabled('android')
class SigninStartup(_StartupWarm):
  """Measures warm startup time of signing a profile into Chrome."""
  page_set = page_sets.ChromeSigninPageSet

  @classmethod
  def Name(cls):
    return 'startup.warm.chrome_signin'

  def GetExpectations(self):
    class StoryExpectations(story.expectations.StoryExpectations):
      def SetExpectations(self):
        pass # chrome://signin-internals not disabled.
    return StoryExpectations()
