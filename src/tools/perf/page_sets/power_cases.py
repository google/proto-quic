# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry.page import page as page_module
from telemetry.page import shared_page_state
from telemetry import story


URL_LIST = [
    'https://webkit.org/blog-files/3d-transforms/poster-circle.html',
    # Does not autoplay on Android devices.
    'https://www.youtube.com/watch?v=3KANI2dpXLw?autoplay=1',
    'about:blank'
]


class PowerCasesPage(page_module.Page):

  def __init__(self, url, page_set, name=''):
    super(PowerCasesPage, self).__init__(
        url=url, page_set=page_set, name=name,
        credentials_path = 'data/credentials.json',
        shared_page_state_class=shared_page_state.SharedDesktopPageState)
    self.archive_data_file = 'data/power_cases.json'

  def RunPageInteractions(self, action_runner):
    action_runner.Wait(10)


class PowerCasesPageSet(story.StorySet):
  """Power hungry pages, used for power testing."""

  def __init__(self):
    super(PowerCasesPageSet, self).__init__(
        archive_data_file='data/power_cases.json',
        cloud_storage_bucket=story.PARTNER_BUCKET)

    for url in URL_LIST:
      self.AddStory(PowerCasesPage(url, self))
