# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry.page import page as page_module
from telemetry import story


class LoFiPageCache(page_module.Page):
  """
  A test page for the chrome proxy Lo-Fi cache tests.
  Checks that LoFi placeholder images are not loaded from cache on page reloads
  when LoFi mode is disabled or data reduction proxy is disabled.
  """

  def __init__(self, url, page_set):
    super(LoFiPageCache, self).__init__(url=url, page_set=page_set)


class LoFiCacheStorySet(story.StorySet):
  """ Chrome proxy test sites """

  def __init__(self):
    super(LoFiCacheStorySet, self).__init__()

    urls_list = [
      'http://check.googlezip.net/cacheable/test.html',
      'http://check.googlezip.net/cacheable/test.html',
    ]

    for url in urls_list:
      self.AddStory(LoFiPageCache(url, self))
