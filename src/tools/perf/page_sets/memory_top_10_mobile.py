# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import re

from telemetry.page import page as page_module
from telemetry.page import shared_page_state
from telemetry import story

from devil.android.sdk import keyevent # pylint: disable=import-error

from page_sets import top_10_mobile


class MemoryMeasurementPage(page_module.Page):
  """Abstract class for measuring memory on a story unit."""

  _PHASE = NotImplemented

  def __init__(self, story_set, name, url):
    super(MemoryMeasurementPage, self).__init__(
        page_set=story_set, name=name, url=url,
        shared_page_state_class=shared_page_state.SharedMobilePageState,
        grouping_keys={'phase': self._PHASE})


class ForegroundPage(MemoryMeasurementPage):
  """Take a measurement after loading a regular webpage."""

  _PHASE = 'foreground'

  def __init__(self, story_set, name, url):
    super(ForegroundPage, self).__init__(story_set, name, url)

  def RunPageInteractions(self, action_runner):
    action_runner.tab.WaitForDocumentReadyStateToBeComplete()
    action_runner.MeasureMemory(self.story_set.DETERMINISTIC_MODE)


class BackgroundPage(MemoryMeasurementPage):
  """Take a measurement while Chrome is in the background."""

  _PHASE = 'background'

  def __init__(self, story_set, name):
    super(BackgroundPage, self).__init__(story_set, name, 'about:blank')

  def RunPageInteractions(self, action_runner):
    action_runner.tab.WaitForDocumentReadyStateToBeComplete()

    # Launch clock app, pushing Chrome to the background.
    android_browser = action_runner.tab.browser
    android_browser.Background()

    # Take measurement.
    action_runner.MeasureMemory(self.story_set.DETERMINISTIC_MODE)

    # Go back to Chrome.
    android_browser.platform.android_action_runner.InputKeyEvent(
        keyevent.KEYCODE_BACK)


class MemoryTop10Mobile(story.StorySet):
  """User story to measure foreground/background memory in top 10 mobile."""
  DETERMINISTIC_MODE = True

  def __init__(self):
    super(MemoryTop10Mobile, self).__init__(
        archive_data_file='data/memory_top_10_mobile.json',
        cloud_storage_bucket=story.PARTNER_BUCKET)

    for url in top_10_mobile.URL_LIST:
      # We name pages so their foreground/background counterparts are easy
      # to identify. For example 'http://google.com' becomes
      # 'http_google_com' and 'after_http_google_com' respectively.
      name = re.sub(r'\W+', '_', url)
      self.AddStory(ForegroundPage(self, name, url))
      self.AddStory(BackgroundPage(self, 'after_' + name))


class MemoryTop10MobileRealistic(MemoryTop10Mobile):
  """Top 10 mobile user story in realistic mode.

  This means, in particular, neither forced GCs nor clearing caches.
  """
  DETERMINISTIC_MODE = False
