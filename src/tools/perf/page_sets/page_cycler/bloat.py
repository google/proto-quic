# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
from telemetry.page import page as page_module
from telemetry import story


class BloatPage(page_module.Page):

  def __init__(self, url, page_set):
    super(BloatPage, self).__init__(url=url, page_set=page_set)


class BloatPageSet(story.StorySet):

  """ Bloat page_cycler benchmark """

  def __init__(self):
    super(BloatPageSet, self).__init__(
      # pylint: disable=line-too-long
      serving_dirs=set(['../../../../data/page_cycler/bloat']),
      cloud_storage_bucket=story.PUBLIC_BUCKET)

    self.AddStory(BloatPage(
      'file://../../../../data/page_cycler/bloat/gmail_load_cleardot/',
      self))
