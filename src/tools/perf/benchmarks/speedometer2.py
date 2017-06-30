# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Apple's Speedometer 2 performance benchmark.
"""

import os

from core import path_util
from core import perf_benchmark

from telemetry import benchmark
from telemetry import page as page_module
from telemetry.page import legacy_page_test
from telemetry import story
from telemetry.value import list_of_scalar_values


_SPEEDOMETER_DIR = os.path.join(path_util.GetChromiumSrcDir(),
    'third_party', 'WebKit', 'PerformanceTests', 'Speedometer')


class Speedometer2Measurement(legacy_page_test.LegacyPageTest):
  def __init__(self):
    super(Speedometer2Measurement, self).__init__()

  def ValidateAndMeasurePage(self, page, tab, results):
    tab.WaitForDocumentReadyStateToBeComplete()
    iterationCount = 10
    # A single iteration on android takes ~75 seconds, the benchmark times out
    # when running for 10 iterations.
    if tab.browser.platform.GetOSName() == 'android':
      iterationCount = 3

    enabled_suites = tab.EvaluateJavaScript("""
      (function() {
        var suitesNames = [];
        Suites.forEach(function(s) {
          if (!s.disabled)
            suitesNames.push(s.name);
        });
        return suitesNames;
       })();""")

    tab.ExecuteJavaScript("""
        // Store all the results in the benchmarkClient
        var testDone = false;
        var iterationCount = {{ count }};
        var benchmarkClient = {};
        var suiteValues = [];
        var totalValues = [];
        benchmarkClient.didRunSuites = function(measuredValues) {
          suiteValues.push(measuredValues);
          totalValues.push(measuredValues.total);
        };
        benchmarkClient.didFinishLastIteration = function () {
          testDone = true;
        };
        var runner = new BenchmarkRunner(Suites, benchmarkClient);
        runner.runMultipleIterations(iterationCount);
        """,
        count=iterationCount)
    tab.WaitForJavaScriptCondition('testDone', timeout=600)
    results.AddValue(list_of_scalar_values.ListOfScalarValues(
        page, 'Total', 'ms',
        tab.EvaluateJavaScript('totalValues'),
        important=True))

    # Extract the timings for each suite
    for suite_name in enabled_suites:
      results.AddValue(list_of_scalar_values.ListOfScalarValues(
          page, suite_name, 'ms',
          tab.EvaluateJavaScript("""
              var suite_times = [];
              for(var i = 0; i < iterationCount; i++) {
                suite_times.push(
                    suiteValues[i].tests[{{ key }}].total);
              };
              suite_times;
              """,
              key=suite_name), important=False))


@benchmark.Disabled('all')  # Schedule this benchmark in crbug.com/734061
@benchmark.Owner(emails=['verwaest@chromium.org, mvstanton@chromium.org'])
class Speedometer2(perf_benchmark.PerfBenchmark):
  test = Speedometer2Measurement

  @classmethod
  def Name(cls):
    return 'speedometer2'

  def CreateStorySet(self, options):
    ps = story.StorySet(base_dir=_SPEEDOMETER_DIR,
        serving_dirs=[_SPEEDOMETER_DIR])
    ps.AddStory(page_module.Page(
       'file://InteractiveRunner.html', ps, ps.base_dir, name='Speedometer2'))
    return ps
