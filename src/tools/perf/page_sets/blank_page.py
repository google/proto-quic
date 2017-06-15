# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
from telemetry.page import page as page_module
from telemetry import story


class BlankPage(page_module.Page):
  def __init__(self, url, page_set, name):
    super(BlankPage, self).__init__(url, page_set=page_set, name=name)

  def RunPageInteractions(self, action_runner):
    # Request a RAF and wait for it to be processed to ensure that the metric
    # Startup.FirstWebContents.NonEmptyPaint2 is recorded.
    action_runner.ExecuteJavaScript(
        """
        this.hasRunRAF = 0;
        requestAnimationFrame(function() {
            this.hasRunRAF = 1;
        });
        """
    )
    action_runner.WaitForJavaScriptCondition("this.hasRunRAF == 1")

class BlankPageSet(story.StorySet):
  """A single blank page."""

  def __init__(self):
    super(BlankPageSet, self).__init__()
    self.AddStory(BlankPage('file://blank_page/blank_page.html',
                            self, 'blank_page.html'))
