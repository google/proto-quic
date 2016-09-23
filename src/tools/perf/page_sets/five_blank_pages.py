# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
from telemetry.page import page as page_module
from telemetry import story


# The PageSet searches for pages relative to the directory the page class is
# defined in so we need to subclass here.
class BlankPage(page_module.Page):
  pass


class FiveBlankPagesPageSet(story.StorySet):

  """ Five blank pages. """

  def __init__(self):
    super(FiveBlankPagesPageSet, self).__init__()
    for _ in xrange(5):
      self.AddStory(BlankPage('file://blank_page/blank_page.html', self))
