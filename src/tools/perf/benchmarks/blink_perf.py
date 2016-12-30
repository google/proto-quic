# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os

from core import path_util
from core import perf_benchmark

from telemetry import benchmark
from telemetry import page as page_module
from telemetry.page import legacy_page_test
from telemetry.page import shared_page_state
from telemetry import story
from telemetry.value import list_of_scalar_values

from benchmarks import pywebsocket_server
from page_sets import webgl_supported_shared_state


BLINK_PERF_BASE_DIR = os.path.join(path_util.GetChromiumSrcDir(),
                                   'third_party', 'WebKit', 'PerformanceTests')
SKIPPED_FILE = os.path.join(BLINK_PERF_BASE_DIR, 'Skipped')


def CreateStorySetFromPath(path, skipped_file,
                           shared_page_state_class=(
                               shared_page_state.SharedPageState)):
  assert os.path.exists(path)

  page_urls = []
  serving_dirs = set()

  def _AddPage(path):
    if not path.endswith('.html'):
      return
    if '../' in open(path, 'r').read():
      # If the page looks like it references its parent dir, include it.
      serving_dirs.add(os.path.dirname(os.path.dirname(path)))
    page_urls.append('file://' + path.replace('\\', '/'))

  def _AddDir(dir_path, skipped):
    for candidate_path in os.listdir(dir_path):
      if candidate_path == 'resources':
        continue
      candidate_path = os.path.join(dir_path, candidate_path)
      if candidate_path.startswith(skipped):
        continue
      if os.path.isdir(candidate_path):
        _AddDir(candidate_path, skipped)
      else:
        _AddPage(candidate_path)

  if os.path.isdir(path):
    skipped = []
    if os.path.exists(skipped_file):
      for line in open(skipped_file, 'r').readlines():
        line = line.strip()
        if line and not line.startswith('#'):
          skipped_path = os.path.join(os.path.dirname(skipped_file), line)
          skipped.append(skipped_path.replace('/', os.sep))
    _AddDir(path, tuple(skipped))
  else:
    _AddPage(path)
  ps = story.StorySet(base_dir=os.getcwd() + os.sep,
                      serving_dirs=serving_dirs)
  for url in page_urls:
    ps.AddStory(page_module.Page(
        url, ps, ps.base_dir,
        shared_page_state_class=shared_page_state_class))
  return ps


class _BlinkPerfMeasurement(legacy_page_test.LegacyPageTest):
  """Tuns a blink performance test and reports the results."""

  def __init__(self):
    super(_BlinkPerfMeasurement, self).__init__()
    with open(os.path.join(os.path.dirname(__file__),
                           'blink_perf.js'), 'r') as f:
      self._blink_perf_js = f.read()

  def WillNavigateToPage(self, page, tab):
    del tab  # unused
    page.script_to_evaluate_on_commit = self._blink_perf_js

  def CustomizeBrowserOptions(self, options):
    options.AppendExtraBrowserArgs([
        '--js-flags=--expose_gc',
        '--enable-experimental-web-platform-features',
        '--disable-gesture-requirement-for-media-playback',
        '--enable-experimental-canvas-features',
        # TODO(qinmin): After fixing crbug.com/592017, remove this command line.
        '--reduce-security-for-testing'
    ])
    if 'content-shell' in options.browser_type:
      options.AppendExtraBrowserArgs('--expose-internals-for-testing')

  def ValidateAndMeasurePage(self, page, tab, results):
    tab.WaitForJavaScriptExpression('testRunner.isDone', 600)

    log = tab.EvaluateJavaScript('document.getElementById("log").innerHTML')

    for line in log.splitlines():
      if line.startswith("FATAL: "):
        print line
        continue
      if not line.startswith('values '):
        continue
      parts = line.split()
      values = [float(v.replace(',', '')) for v in parts[1:-1]]
      units = parts[-1]
      metric = page.display_name.split('.')[0].replace('/', '_')
      results.AddValue(list_of_scalar_values.ListOfScalarValues(
          results.current_page, metric, units, values))

      break

    print log


class _BlinkPerfMeasurementSlimmingPaintInvalidation(_BlinkPerfMeasurement):
  """Measures blink perf with the new paint invalidation system (see:
  https://goo.gl/eQczQW). The benchmarks using this measurement should be
  removed when slimming paint invalidation ships."""
  def CustomizeBrowserOptions(self, options):
    _BlinkPerfMeasurement.CustomizeBrowserOptions(self, options)
    options.AppendExtraBrowserArgs([
        '--enable-blink-features=SlimmingPaintInvalidation'
    ])


class _BlinkPerfBenchmark(perf_benchmark.PerfBenchmark):
  test = _BlinkPerfMeasurement

  @classmethod
  def Name(cls):
    return 'blink_perf.' + cls.tag

  def CreateStorySet(self, options):
    path = os.path.join(BLINK_PERF_BASE_DIR, self.subdir)
    return CreateStorySetFromPath(path, SKIPPED_FILE)


class _SharedPywebsocketPageState(shared_page_state.SharedPageState):
  """Runs a pywebsocket server."""

  def __init__(self, test, finder_options, user_story_set):
    super(_SharedPywebsocketPageState, self).__init__(
        test, finder_options, user_story_set)
    self.platform.StartLocalServer(pywebsocket_server.PywebsocketServer())


class BlinkPerfBindings(_BlinkPerfBenchmark):
  tag = 'bindings'
  subdir = 'Bindings'

  @classmethod
  def ShouldDisable(cls, possible_browser):
    # http://crbug.com/563979
    return (cls.IsSvelte(possible_browser)
      # http://crbug.com/653970
      or (possible_browser.browser_type == 'reference' and
        possible_browser.platform.GetOSName() == 'android'))


@benchmark.Enabled('content-shell')
class BlinkPerfBlinkGC(_BlinkPerfBenchmark):
  tag = 'blink_gc'
  subdir = 'BlinkGC'


class BlinkPerfCSS(_BlinkPerfBenchmark):
  tag = 'css'
  subdir = 'CSS'


@benchmark.Disabled('android-webview', # http://crbug.com/593200
                    'reference')  # http://crbug.com/576779
class BlinkPerfCanvas(_BlinkPerfBenchmark):
  tag = 'canvas'
  subdir = 'Canvas'

  @classmethod
  def ShouldDisable(cls, possible_browser):
    return cls.IsSvelte(possible_browser)  # http://crbug.com/593973.

  def CreateStorySet(self, options):
    path = os.path.join(BLINK_PERF_BASE_DIR, self.subdir)
    story_set = CreateStorySetFromPath(
        path, SKIPPED_FILE,
        shared_page_state_class=(
            webgl_supported_shared_state.WebGLSupportedSharedState))
    # WebGLSupportedSharedState requires the skipped_gpus property to
    # be set on each page.
    for page in story_set:
      page.skipped_gpus = []
    return story_set


class BlinkPerfDOM(_BlinkPerfBenchmark):
  tag = 'dom'
  subdir = 'DOM'


@benchmark.Disabled('win')  # http://crbug.com/588819
class BlinkPerfEvents(_BlinkPerfBenchmark):
  tag = 'events'
  subdir = 'Events'


@benchmark.Disabled('win8')  # http://crbug.com/462350
@benchmark.Disabled('win-reference')  # http://crbug.com/642884
class BlinkPerfLayout(_BlinkPerfBenchmark):
  tag = 'layout'
  subdir = 'Layout'

  @classmethod
  def ShouldDisable(cls, possible_browser):
    return cls.IsSvelte(possible_browser)  # http://crbug.com/551950


class BlinkPerfPaint(_BlinkPerfBenchmark):
  tag = 'paint'
  subdir = 'Paint'

  @classmethod
  def ShouldDisable(cls, possible_browser):
    return cls.IsSvelte(possible_browser)  # http://crbug.com/574483


class BlinkPerfPaintSlimmingPaintInvalidation(BlinkPerfPaint):
  tag = 'paint_slimmingpaintinvalidation'
  test = _BlinkPerfMeasurementSlimmingPaintInvalidation


@benchmark.Disabled('win')  # crbug.com/488493
class BlinkPerfParser(_BlinkPerfBenchmark):
  tag = 'parser'
  subdir = 'Parser'


class BlinkPerfSVG(_BlinkPerfBenchmark):
  tag = 'svg'
  subdir = 'SVG'


class BlinkPerfSVGSlimmingPaintInvalidation(BlinkPerfSVG):
  tag = 'svg_slimmingpaintinvalidation'
  test = _BlinkPerfMeasurementSlimmingPaintInvalidation


class BlinkPerfShadowDOM(_BlinkPerfBenchmark):
  tag = 'shadow_dom'
  subdir = 'ShadowDOM'


# This benchmark is for local testing, doesn't need to run on bots.
@benchmark.Disabled('all')
class BlinkPerfXMLHttpRequest(_BlinkPerfBenchmark):
  tag = 'xml_http_request'
  subdir = 'XMLHttpRequest'


# Disabled on Windows and ChromeOS due to https://crbug.com/521887
#@benchmark.Disabled('win', 'chromeos')
# Disabling on remaining platforms due to heavy flake https://crbug.com/646938
@benchmark.Disabled('all')
class BlinkPerfPywebsocket(_BlinkPerfBenchmark):
  """The blink_perf.pywebsocket tests measure turn-around-time of 10MB
  send/receive for XHR, Fetch API and WebSocket. We might ignore < 10%
  regressions, because the tests are noisy and such regressions are
  often unreproducible (https://crbug.com/549017).
  """
  tag = 'pywebsocket'
  subdir = 'Pywebsocket'

  def CreateStorySet(self, options):
    path = os.path.join(BLINK_PERF_BASE_DIR, self.subdir)
    return CreateStorySetFromPath(
        path, SKIPPED_FILE,
        shared_page_state_class=_SharedPywebsocketPageState)

  @classmethod
  def ShouldDisable(cls, possible_browser):
    return cls.IsSvelte(possible_browser)  # http://crbug.com/551950
