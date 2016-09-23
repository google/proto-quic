# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry.page import page as page_module
from telemetry import story


class LoFiPreviewPage(page_module.Page):
  """
  A test page for the chrome proxy Lo-Fi preview tests.
  Checks that a LoFi preview page is served.
  """

  def __init__(self, url, page_set):
    super(LoFiPreviewPage, self).__init__(url=url, page_set=page_set)


class LoFiPreviewStorySet(story.StorySet):
  """ Chrome proxy test sites """

  def __init__(self):
    super(LoFiPreviewStorySet, self).__init__()

    urls_list = [
      'http://check.googlezip.net/test.html',
    ]

    for url in urls_list:
      self.AddStory(LoFiPreviewPage(url, self))
