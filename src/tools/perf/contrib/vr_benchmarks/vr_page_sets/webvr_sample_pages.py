# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import os
from telemetry.page import page as page_module
from telemetry import story
from contrib.vr_benchmarks.vr_page_sets import (shared_android_vr_page_state
                                                as vr_state)


SAMPLE_DIR = os.path.join(os.path.dirname(__file__),
                          '..', '..', '..', '..', '..',
                          'chrome', 'test', 'data', 'vr',
                          'webvr_info', 'samples')


class WebVrSamplePage(page_module.Page):
  def __init__(self, get_parameters, page_set):
    url = 'test-slow-render.html'
    if get_parameters:
      url += '?' + '&'.join(get_parameters)
    name = url.replace('.html', '')
    url = 'file://' + os.path.join(SAMPLE_DIR, url)
    super(WebVrSamplePage, self).__init__(
        url=url, page_set=page_set, name=name,
        shared_page_state_class=vr_state.SharedAndroidVrPageState)

  def RunPageInteractions(self, action_runner):
      action_runner.TapElement(selector='canvas[id="webgl-canvas"]')
      action_runner.MeasureMemory(True)


class WebVrSamplePageSet(story.StorySet):
  """A page set using the official WebVR sample with settings tweaked."""

  def __init__(self):
    super(WebVrSamplePageSet, self).__init__()

    # Standard sample app with no changes
    self.AddStory(WebVrSamplePage(['canvasClickPresents=1',
                                   'renderScale=1'], self))
    # Increased render scale
    self.AddStory(WebVrSamplePage(['canvasClickPresents=1',
                                   'renderScale=1.5'], self))
    # Default render scale, increased load
    self.AddStory(WebVrSamplePage(['canvasClickPresents=1',
                                   'renderScale=1',
                                   'heavyGpu=1',
                                   'cubeScale=0.2',
                                   'workTime=5'], self))
    # Further increased load
    self.AddStory(WebVrSamplePage(['canvasClickPresents=1',
                                   'renderScale=1',
                                   'heavyGpu=1',
                                   'cubeScale=0.3',
                                   'workTime=10'], self))
