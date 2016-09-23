# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from page_sets import extension_profile_shared_state
from telemetry.page import page as page_module
from telemetry import story


class BlankPageWithExtensionProfile(page_module.Page):
  """A single blank page loaded with a profile with many extensions."""

  def __init__(self, url, page_set):
    super(BlankPageWithExtensionProfile, self).__init__(
        url=url, page_set=page_set,
        shared_page_state_class=extension_profile_shared_state.
                                ExtensionProfileSharedState)


class BlankPageSetWithExtensionProfile(story.StorySet):
  """PageSet tied to BlankPageWithExtensionProfile."""

  def __init__(self):
    super(BlankPageSetWithExtensionProfile, self).__init__()
    self.AddStory(BlankPageWithExtensionProfile(
        'file://blank_page/blank_page.html', self))
