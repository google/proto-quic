# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry.page import page as page_module
from telemetry import story


class FallbackViaHeaderPage(page_module.Page):

  def __init__(self, url, page_set):
    super(FallbackViaHeaderPage, self).__init__(url=url, page_set=page_set)


class FallbackViaHeaderStorySet(story.StorySet):
  """ Chrome proxy test sites """

  def __init__(self):
    super(FallbackViaHeaderStorySet, self).__init__()

    urls_list = [
        'http://chromeproxy-test.appspot.com/default?respStatus=200',
        'http://chromeproxy-test.appspot.com/default?respStatus=413',
    ]

    for url in urls_list:
      self.AddStory(FallbackViaHeaderPage(url, self))
