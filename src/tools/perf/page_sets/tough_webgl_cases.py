# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry.page import page as page_module
from telemetry import story

from page_sets import webgl_supported_shared_state


class ToughWebglCasesPage(page_module.Page):

  def __init__(self, url, page_set):
    super(ToughWebglCasesPage, self).__init__(
        url=url, page_set=page_set,
        shared_page_state_class=(
            webgl_supported_shared_state.WebGLSupportedSharedState),
        make_javascript_deterministic=False)
    self.archive_data_file = 'data/tough_webgl_cases.json'


  @property
  def skipped_gpus(self):
    # crbug.com/462729
    return ['arm', 'broadcom', 'hisilicon', 'imagination', 'qualcomm',
            'vivante']

  def RunNavigateSteps(self, action_runner):
    super(ToughWebglCasesPage, self).RunNavigateSteps(action_runner)
    action_runner.WaitForJavaScriptCondition(
        'document.readyState == "complete"')
    action_runner.Wait(2)

  def RunPageInteractions(self, action_runner):
    with action_runner.CreateInteraction('WebGLAnimation'):
      action_runner.Wait(5)


class ToughWebglCasesPageSet(story.StorySet):

  """
  Description: Self-driven WebGL animation examples
  """

  def __init__(self):
    super(ToughWebglCasesPageSet, self).__init__(
      archive_data_file='data/tough_webgl_cases.json',
      cloud_storage_bucket=story.PUBLIC_BUCKET)

    urls_list = [
      # pylint: disable=line-too-long
      'http://www.khronos.org/registry/webgl/sdk/demos/google/nvidia-vertex-buffer-object/index.html',
      # pylint: disable=line-too-long
      'http://www.khronos.org/registry/webgl/sdk/demos/google/san-angeles/index.html',
      # pylint: disable=line-too-long
      'http://www.khronos.org/registry/webgl/sdk/demos/google/particles/index.html',
      'http://www.khronos.org/registry/webgl/sdk/demos/webkit/Earth.html',
      # pylint: disable=line-too-long
      'http://www.khronos.org/registry/webgl/sdk/demos/webkit/ManyPlanetsDeep.html',
      'http://webglsamples.org/aquarium/aquarium.html',
      'http://webglsamples.org/blob/blob.html',
      # pylint: disable=line-too-long
      'http://webglsamples.org/dynamic-cubemap/dynamic-cubemap.html',
      # pylint: disable=line-too-long
      'http://kenrussell.github.io/webgl-animometer/Animometer/tests/3d/webgl.html',
    ]
    for url in urls_list:
      self.AddStory(ToughWebglCasesPage(url, self))
