# Copyright 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Runs spaceport.io's PerfMarks benchmark."""

import json
import logging
import os

from core import path_util
from core import perf_benchmark

from telemetry import benchmark
from telemetry import page as page_module
from telemetry.page import legacy_page_test
from telemetry import story
from telemetry.value import list_of_scalar_values
from telemetry.value import scalar

DESCRIPTIONS = {
    'canvasDrawImageFullClear':
        'Using a canvas element to render. Bitmaps are blitted to the canvas '
        'using the "drawImage" function and the canvas is fully cleared at '
        'the beginning of each frame.',
    'canvasDrawImageFullClearAlign':
        'Same as canvasDrawImageFullClear except all "x" and "y" values are '
        'rounded to the nearest integer. This can be more efficient on '
        'translate on certain browsers.',
    'canvasDrawImagePartialClear':
        'Using a canvas element to render. Bitmaps are blitted to the canvas '
        'using the "drawImage" function and pixels drawn in the last frame '
        'are cleared to the clear color at the beginning of each frame. '
        'This is generally slower on hardware accelerated implementations, '
        'but sometimes faster on CPU-based implementations.',
    'canvasDrawImagePartialClearAlign':
        'Same as canvasDrawImageFullClearAlign but only partially clearing '
        'the canvas each frame.',
    'css2dBackground':
        'Using div elements that have a background image specified using CSS '
        'styles. These div elements are translated, scaled, and rotated using '
        'CSS-2D transforms.',
    'css2dImg':
        'Same as css2dBackground, but using img elements instead of div '
        'elements.',
    'css3dBackground':
        'Same as css2dBackground, but using CSS-3D transforms.',
    'css3dImg':
        'Same as css2dImage but using CSS-3D tranforms.',
}


class _SpaceportMeasurement(legacy_page_test.LegacyPageTest):

  def __init__(self):
    super(_SpaceportMeasurement, self).__init__()

  def CustomizeBrowserOptions(self, options):
    options.AppendExtraBrowserArgs('--disable-gpu-vsync')

  def ValidateAndMeasurePage(self, page, tab, results):
    del page  # unused
    tab.WaitForJavaScriptCondition(
        '!document.getElementById("start-performance-tests").disabled',
        timeout=60)

    tab.ExecuteJavaScript("""
        window.__results = {};
        window.console.log = function(str) {
            if (!str) return;
            var key_val = str.split(': ');
            if (!key_val.length == 2) return;
            __results[key_val[0]] = key_val[1];
        };
        document.getElementById('start-performance-tests').click();
        """)

    num_results = 0
    num_tests_in_spaceport = 24
    while num_results < num_tests_in_spaceport:
      tab.WaitForJavaScriptCondition(
          'Object.keys(window.__results).length > {{ num_results }}',
          num_results=num_results,
          timeout=180)
      num_results = tab.EvaluateJavaScript(
          'Object.keys(window.__results).length')
      logging.info('Completed test %d of %d',
                   num_results, num_tests_in_spaceport)

    result_dict = json.loads(tab.EvaluateJavaScript(
        'JSON.stringify(window.__results)'))
    for key in result_dict:
      chart, trace = key.split('.', 1)
      results.AddValue(scalar.ScalarValue(
          results.current_page, '%s.%s' % (chart, trace),
          'objects (bigger is better)', float(result_dict[key]),
          important=False, description=DESCRIPTIONS.get(chart)))
    results.AddValue(list_of_scalar_values.ListOfScalarValues(
        results.current_page, 'Score', 'objects (bigger is better)',
        [float(x) for x in result_dict.values()],
        description='Combined score for all parts of the spaceport benchmark.'))


# crbug.com/166703: This test frequently times out on Windows.
@benchmark.Disabled('mac', 'win',
                    'linux', 'android')  # crbug.com/525112
class Spaceport(perf_benchmark.PerfBenchmark):
  """spaceport.io's PerfMarks benchmark.

  http://spaceport.io/community/perfmarks

  This test performs 3 animations (rotate, translate, scale) using a variety of
  methods (css, webgl, canvas, etc) and reports the number of objects that can
  be simultaneously animated while still achieving 30FPS.
  """
  test = _SpaceportMeasurement

  @classmethod
  def Name(cls):
    return 'spaceport'

  def CreateStorySet(self, options):
    spaceport_dir = os.path.join(path_util.GetChromiumSrcDir(), 'chrome',
                                 'test', 'data', 'third_party', 'spaceport')
    ps = story.StorySet(base_dir=spaceport_dir)
    ps.AddStory(page_module.Page('file://index.html', ps, ps.base_dir))
    return ps
