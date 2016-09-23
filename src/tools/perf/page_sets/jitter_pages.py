# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
from telemetry import page as page_module
from telemetry import story
from telemetry.page import shared_page_state


def _IssueMarkerAndScroll(action_runner):
  with action_runner.CreateGestureInteraction('ScrollAction'):
    action_runner.ScrollPage()

class JitterPage(page_module.Page):

  def __init__(self, url, page_set, name=''):
    super(JitterPage, self).__init__(
        url=url, page_set=page_set, name=name,
        shared_page_state_class=shared_page_state.SharedDesktopPageState)

  def RunPageInteractions(self, action_runner):
    _IssueMarkerAndScroll(action_runner)

class JitterPageSet(story.StorySet):

  def __init__(self):
    super(JitterPageSet, self).__init__()

    urls = [
        # one fixed layer with no jitter
        'file://jitter_test_cases/fixed.html',
        # one layer that jitters
        'file://jitter_test_cases/one_layer_jitter.html',
        # one layer inside another, both jitter together
        'file://jitter_test_cases/child_jitter_with_parent.html',
        # two non overlapping layers jitter
        'file://jitter_test_cases/two_layers_jitter.html',
        # jittering layer size bigger
        'file://jitter_test_cases/big_layer_jitter.html',
    ]

    for url in urls:
      self.AddStory(JitterPage(url, self))
