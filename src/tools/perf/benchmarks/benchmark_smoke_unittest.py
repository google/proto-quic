# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Run the first page of one benchmark for every module.

Only benchmarks that have a composable measurement are included.
Ideally this test would be comprehensive, however, running one page
of every benchmark would run impractically long.
"""

import os
import sys
import unittest

from telemetry import benchmark as benchmark_module
from telemetry.core import discover
from telemetry import decorators
from telemetry.internal.browser import browser_finder
from telemetry.testing import options_for_unittests
from telemetry.testing import progress_reporter

from benchmarks import battor
from benchmarks import image_decoding
from benchmarks import indexeddb_perf
from benchmarks import jetstream
from benchmarks import kraken
from benchmarks import octane
from benchmarks import rasterize_and_record_micro
from benchmarks import speedometer
from benchmarks import v8_browsing


def SmokeTestGenerator(benchmark, num_pages=1):
  """Generates a benchmark that includes first N pages from pageset.

  Args:
    benchmark: benchmark object to make smoke test.
    num_pages: use the first N pages to run smoke test.
  """
  # NOTE TO SHERIFFS: DO NOT DISABLE THIS TEST.
  #
  # This smoke test dynamically tests all benchmarks. So disabling it for one
  # failing or flaky benchmark would disable a much wider swath of coverage
  # than is usally intended. Instead, if a particular benchmark is failing,
  # disable it in tools/perf/benchmarks/*.
  @benchmark_module.Disabled('chromeos')  # crbug.com/351114
  @benchmark_module.Disabled('android')  # crbug.com/641934
  def BenchmarkSmokeTest(self):
    # Only measure a single page so that this test cycles reasonably quickly.
    benchmark.options['pageset_repeat'] = 1

    class SinglePageBenchmark(benchmark):  # pylint: disable=no-init

      def CreateStorySet(self, options):
        # pylint: disable=super-on-old-class
        story_set = super(SinglePageBenchmark, self).CreateStorySet(options)

        # Only smoke test the first story since smoke testing everything takes
        # too long.
        for s in story_set.stories[num_pages:]:
          story_set.RemoveStory(s)
        return story_set

    # Set the benchmark's default arguments.
    options = options_for_unittests.GetCopy()
    options.output_formats = ['none']
    parser = options.CreateParser()

    benchmark.AddCommandLineArgs(parser)
    benchmark_module.AddCommandLineArgs(parser)
    benchmark.SetArgumentDefaults(parser)
    options.MergeDefaultValues(parser.get_default_values())

    benchmark.ProcessCommandLineArgs(None, options)
    benchmark_module.ProcessCommandLineArgs(None, options)

    possible_browser = browser_finder.FindBrowser(options)
    if SinglePageBenchmark.ShouldDisable(possible_browser):
      self.skipTest('Benchmark %s has ShouldDisable return True' %
                    SinglePageBenchmark.Name())

    self.assertEqual(0, SinglePageBenchmark().Run(options),
                     msg='Failed: %s' % benchmark)

  return BenchmarkSmokeTest


# The list of benchmark modules to be excluded from our smoke tests.
_BLACK_LIST_TEST_MODULES = {
    image_decoding,  # Always fails on Mac10.9 Tests builder.
    indexeddb_perf,  # Always fails on Win7 & Android Tests builder.
    octane,  # Often fails & take long time to timeout on cq bot.
    rasterize_and_record_micro,  # Always fails on cq bot.
    speedometer,  # Takes 101 seconds.
    jetstream,  # Take 206 seconds.
    kraken,  # Flaky on Android, crbug.com/626174.
    v8_browsing, # Flaky on Android, crbug.com/628368.
    battor #Flaky on android, crbug.com/618330.
}


def MergeDecorators(method, method_attribute, benchmark, benchmark_attribute):
  # Do set union of attributes to eliminate duplicates.
  merged_attributes = getattr(method, method_attribute, set()).union(
      getattr(benchmark, benchmark_attribute, set()))
  if merged_attributes:
    setattr(method, method_attribute, merged_attributes)


def load_tests(loader, standard_tests, pattern):
  del loader, standard_tests, pattern  # unused
  suite = progress_reporter.TestSuite()

  benchmarks_dir = os.path.dirname(__file__)
  top_level_dir = os.path.dirname(benchmarks_dir)

  # Using the default of |index_by_class_name=False| means that if a module
  # has multiple benchmarks, only the last one is returned.
  all_benchmarks = discover.DiscoverClasses(
      benchmarks_dir, top_level_dir, benchmark_module.Benchmark,
      index_by_class_name=False).values()
  for benchmark in all_benchmarks:
    if sys.modules[benchmark.__module__] in _BLACK_LIST_TEST_MODULES:
      continue
    # TODO(tonyg): Smoke doesn't work with session_restore yet.
    if (benchmark.Name().startswith('session_restore') or
        benchmark.Name().startswith('skpicture_printer')):
      continue

    if hasattr(benchmark, 'generated_profile_archive'):
      # We'd like to test these, but don't know how yet.
      continue

    class BenchmarkSmokeTest(unittest.TestCase):
      pass

    # tab_switching needs more than one page to test correctly.
    if 'tab_switching' in benchmark.Name():
      method = SmokeTestGenerator(benchmark, num_pages=2)
    else:
      method = SmokeTestGenerator(benchmark)

    # Make sure any decorators are propagated from the original declaration.
    # (access to protected members) pylint: disable=protected-access
    # TODO(dpranke): Since we only pick the first test from every class
    # (above), if that test is disabled, we'll end up not running *any*
    # test from the class. We should probably discover all of the tests
    # in a class, and then throw the ones we don't need away instead.

    disabled_benchmark_attr = decorators.DisabledAttributeName(benchmark)
    disabled_method_attr = decorators.DisabledAttributeName(method)
    enabled_benchmark_attr = decorators.EnabledAttributeName(benchmark)
    enabled_method_attr = decorators.EnabledAttributeName(method)

    MergeDecorators(method, disabled_method_attr, benchmark,
                    disabled_benchmark_attr)
    MergeDecorators(method, enabled_method_attr, benchmark,
                    enabled_benchmark_attr)

    setattr(BenchmarkSmokeTest, benchmark.Name(), method)

    suite.addTest(BenchmarkSmokeTest(benchmark.Name()))

  return suite
