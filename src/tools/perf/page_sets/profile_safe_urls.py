# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
from profile_creators import profile_safe_url_list
from telemetry.page import page as page_module
from telemetry.page import shared_page_state
from telemetry import story


class ProfileSafeUrlPage(page_module.Page):
  def __init__(self, url, page_set):
    super(ProfileSafeUrlPage, self).__init__(
        url=url,
        # Make sure story name is not too long and has type 'str' instead of
        # 'unicode'.
        name=str(url[:140]),
        page_set = page_set,
        shared_page_state_class=shared_page_state.SharedDesktopPageState,
        credentials_path = 'data/credentials.json')
    self.credentials = 'google'


class ProfileSafeUrlsPageSet(story.StorySet):
  """Safe urls used for profile generation."""

  def __init__(self):
    super(ProfileSafeUrlsPageSet, self).__init__(
      archive_data_file='data/profile_safe_urls.json',
      cloud_storage_bucket=story.PARTNER_BUCKET)

    # Only use the first 500 urls to prevent the .wpr files from getting too
    # big.
    safe_urls = profile_safe_url_list.GetShuffledSafeUrls()[0:500]
    for safe_url in safe_urls:
      self.AddStory(ProfileSafeUrlPage(safe_url, self))
