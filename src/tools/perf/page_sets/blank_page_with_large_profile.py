# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
from page_sets import pregenerated_large_profile_shared_state
from telemetry.page import page as page_module
from telemetry import story


class BlankPageWithLargeProfile(page_module.Page):
  def __init__(self, url, page_set):
    super(BlankPageWithLargeProfile, self).__init__(
        url=url, page_set=page_set,
        shared_page_state_class=pregenerated_large_profile_shared_state.
        PregeneratedLargeProfileSharedState)


class BlankPageSetWithLargeProfile(story.StorySet):
  """A single blank page loaded with a large profile."""

  def __init__(self):
    super(BlankPageSetWithLargeProfile, self).__init__()
    self.AddStory(BlankPageWithLargeProfile(
        'file://blank_page/blank_page.html', self))
