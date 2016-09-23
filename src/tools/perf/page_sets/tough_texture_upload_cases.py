# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
from telemetry.page import page as page_module
from telemetry import story


class ToughTextureUploadCasesPage(page_module.Page):

  def __init__(self, url, page_set):
    super(
      ToughTextureUploadCasesPage,
      self).__init__(
        url=url,
        page_set=page_set)

  def RunPageInteractions(self, action_runner):
    with action_runner.CreateInteraction('Animation'):
      action_runner.Wait(10)


class ToughTextureUploadCasesPageSet(story.StorySet):

  """
  Description: A collection of texture upload performance tests
  """

  def __init__(self):
    super(ToughTextureUploadCasesPageSet, self).__init__()

    urls_list = [
      'file://tough_texture_upload_cases/background_color_animation.html',
      # pylint: disable=line-too-long
      'file://tough_texture_upload_cases/background_color_animation_with_gradient.html',
      'file://tough_texture_upload_cases/small_texture_uploads.html',
      'file://tough_texture_upload_cases/medium_texture_uploads.html',
      'file://tough_texture_upload_cases/large_texture_uploads.html',
      # http://crbug.com/453131 - Our memory usage on low memory devices are
      # not constrained enough to run this page, disable until we are more
      # bounded on memory usage.
      # 'file://tough_texture_upload_cases/extra_large_texture_uploads.html',
    ]
    for url in urls_list:
      self.AddStory(ToughTextureUploadCasesPage(url, self))

