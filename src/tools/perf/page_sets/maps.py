# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry.page import page as page_module
from telemetry import story

from page_sets import webgl_supported_shared_state


class MapsPage(page_module.Page):

  def __init__(self, page_set):
    super(MapsPage, self).__init__(
      url='http://localhost:8000/performance.html',
      page_set=page_set,
      shared_page_state_class=(
          webgl_supported_shared_state.WebGLSupportedSharedState))
    self.archive_data_file = 'data/maps.json'

  @property
  def skipped_gpus(self):
    # Skip this intensive test on low-end devices. crbug.com/464731
    return ['arm']

  def RunNavigateSteps(self, action_runner):
    super(MapsPage, self).RunNavigateSteps(action_runner)
    action_runner.Wait(3)

  def RunPageInteractions(self, action_runner):
    with action_runner.CreateInteraction('MapAnimation'):
      action_runner.WaitForJavaScriptCondition(
        'window.testMetrics != undefined', timeout=120)


class MapsPageSet(story.StorySet):

  """ Google Maps examples """

  def __init__(self):
    super(MapsPageSet, self).__init__(
        archive_data_file='data/maps.json',
        cloud_storage_bucket=story.PUBLIC_BUCKET)

    self.AddStory(MapsPage(self))
