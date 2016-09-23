# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Run all system health stories used by system health benchmarks.

Only memory benchmarks are used when running these stories to make the total
cycle time manageable. Other system health benchmarks should be using the same
stories as memory ones, only with fewer actions (no memory dumping).
"""

import unittest

from core import perf_benchmark

from telemetry import benchmark as benchmark_module
from telemetry import decorators
from telemetry.core import discover
from telemetry.internal.browser import browser_finder
from telemetry.testing import options_for_unittests
from telemetry.testing import progress_reporter

from benchmarks import system_health


def GetSystemHealthBenchmarksToSmokeTest():
  sh_benchmark_classes = discover.DiscoverClassesInModule(
      system_health, perf_benchmark.PerfBenchmark,
      index_by_class_name=True).values()
  return list(b for b in sh_benchmark_classes if
              b.Name().startswith('system_health.memory'))


_DISABLED_TESTS = frozenset({
  # crbug.com/629123
  'benchmarks.system_health_smoke_test.SystemHealthBenchmarkSmokeTest.system_health.memory_mobile.browse:news:hackernews',  # pylint: disable=line-too-long
  'benchmarks.system_health_smoke_test.SystemHealthBenchmarkSmokeTest.system_health.memory_mobile.browse:news:nytimes',  # pylint: disable=line-too-long
  # crbug.com/637230
  'benchmarks.system_health_smoke_test.SystemHealthBenchmarkSmokeTest.system_health.memory_desktop.browse:news:cnn',  # pylint: disable=line-too-long

  # crbug.com/641934
  # These tests are taking too long (more than 100s each).
  # TODO(nedn): reenable these test once we have more capacity to run them on
  # CQ.
  'benchmarks.system_health_smoke_test.SystemHealthBenchmarkSmokeTest.system_health.memory_mobile.browse:news:flipboard',  # pylint: disable=line-too-long
  'benchmarks.system_health_smoke_test.SystemHealthBenchmarkSmokeTest.system_health.memory_mobile.browse:media:imgur',  # pylint: disable=line-too-long
  'benchmarks.system_health_smoke_test.SystemHealthBenchmarkSmokeTest.system_health.memory_mobile.browse:media:youtube',  # pylint: disable=line-too-long
  'benchmarks.system_health_smoke_test.SystemHealthBenchmarkSmokeTest.system_health.memory_mobile.browse:media:facebook_photos',  # pylint: disable=line-too-long
  'benchmarks.system_health_smoke_test.SystemHealthBenchmarkSmokeTest.system_health.memory_mobile.browse:news:reddit',  # pylint: disable=line-too-long
  'benchmarks.system_health_smoke_test.SystemHealthBenchmarkSmokeTest.system_health.memory_mobile.browse:social:facebook',  # pylint: disable=line-too-long
  'benchmarks.system_health_smoke_test.SystemHealthBenchmarkSmokeTest.system_health.memory_mobile.load:news:cnn',  # pylint: disable=line-too-long

  # Permenently disabled from smoke test for being long-running.
  'benchmarks.system_health_smoke_test.SystemHealthBenchmarkSmokeTest.system_health.memory_mobile.long_running:tools:gmail-foreground',  # pylint: disable=line-too-long
  'benchmarks.system_health_smoke_test.SystemHealthBenchmarkSmokeTest.system_health.memory_mobile.long_running:tools:gmail-background',  # pylint: disable=line-too-long
  'benchmarks.system_health_smoke_test.SystemHealthBenchmarkSmokeTest.system_health.memory_desktop.long_running:tools:gmail-foreground',  # pylint: disable=line-too-long
  'benchmarks.system_health_smoke_test.SystemHealthBenchmarkSmokeTest.system_health.memory_desktop.long_running:tools:gmail-background',  # pylint: disable=line-too-long
})


def _GenerateSmokeTestCase(benchmark_class, story_to_smoke_test):

  # NOTE TO SHERIFFS: DO NOT DISABLE THIS TEST.
  #
  # This smoke test dynamically tests all system health user stories. So
  # disabling it for one failing or flaky benchmark would disable a much
  # wider swath of coverage  than is usally intended. Instead, if a test is
  # failing, disable it by putting it into the _DISABLED_TESTS list above.
  @benchmark_module.Disabled('chromeos')  # crbug.com/351114
  def RunTest(self):

    class SinglePageBenchmark(benchmark_class):  # pylint: disable=no-init
      def CreateStorySet(self, options):
        # pylint: disable=super-on-old-class
        story_set = super(SinglePageBenchmark, self).CreateStorySet(options)
        assert story_to_smoke_test in story_set.stories
        story_set.stories = [story_to_smoke_test]
        return story_set

    options = GenerateBenchmarkOptions(benchmark_class)
    possible_browser = browser_finder.FindBrowser(options)
    if possible_browser is None:
      self.skipTest('Cannot find the browser to run the test.')
    if (SinglePageBenchmark.ShouldDisable(possible_browser) or
        not decorators.IsEnabled(benchmark_class, possible_browser)[0]):
      self.skipTest('Benchmark %s is disabled' % SinglePageBenchmark.Name())

    if self.id() in _DISABLED_TESTS:
      self.skipTest('Test is explictly disabled')

    self.assertEqual(0, SinglePageBenchmark().Run(options),
                     msg='Failed: %s' % benchmark_class)

  # We attach the test method to SystemHealthBenchmarkSmokeTest dynamically
  # so that we can set the test method name to include
  # '<benchmark class name>.<story display name>'.
  test_method_name = '%s.%s' % (
      benchmark_class.Name(), story_to_smoke_test.display_name)

  class SystemHealthBenchmarkSmokeTest(unittest.TestCase):
    pass

  setattr(SystemHealthBenchmarkSmokeTest, test_method_name, RunTest)

  return SystemHealthBenchmarkSmokeTest(methodName=test_method_name)


def GenerateBenchmarkOptions(benchmark_class):
  # Set the benchmark's default arguments.
  options = options_for_unittests.GetCopy()
  options.output_format = 'none'
  parser = options.CreateParser()

  # TODO(nednguyen): probably this logic of setting up the benchmark options
  # parser & processing the options should be sharable with telemetry's
  # core.
  benchmark_class.AddCommandLineArgs(parser)
  benchmark_module.AddCommandLineArgs(parser)
  benchmark_class.SetArgumentDefaults(parser)
  options.MergeDefaultValues(parser.get_default_values())

  benchmark_class.ProcessCommandLineArgs(None, options)
  benchmark_module.ProcessCommandLineArgs(None, options)
  # Only measure a single story so that this test cycles reasonably quickly.
  options.pageset_repeat = 1
  options.page_repeat = 1
  # Enable browser logging in the smoke test only. Hopefully, this will detect
  # all crashes and hence remove the need to enable logging in actual perf
  # benchmarks.
  options.browser_options.logging_verbosity = 'non-verbose'
  return options


def load_tests(loader, standard_tests, pattern):
  del loader, standard_tests, pattern  # unused
  suite = progress_reporter.TestSuite()
  benchmark_classes = GetSystemHealthBenchmarksToSmokeTest()
  assert benchmark_classes, 'This list should never be empty'
  for benchmark_class in benchmark_classes:

    # HACK: these options should be derived from options_for_unittests which are
    # the resolved options from run_tests' arguments. However, options is only
    # parsed during test time which happens after load_tests are called.
    # Since none of our system health benchmarks creates stories based on
    # command line options, it should be ok to pass options=None to
    # CreateStorySet.
    for story_to_smoke_test in (
        benchmark_class().CreateStorySet(options=None).stories):
      suite.addTest(
          _GenerateSmokeTestCase(benchmark_class, story_to_smoke_test))

  return suite
