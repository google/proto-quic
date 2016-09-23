# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
from telemetry.page import shared_page_state
from telemetry import story

from page_sets import top_pages


def _Reload(action_runner):
  # Numbers below are chosen arbitrarily. For the V8DetachedContextAgeInGC
  # the number of reloads should be high enough so that V8 could do few
  # incremental GCs.
  NUMBER_OF_RELOADS = 7
  WAIT_TIME = 2
  for _ in xrange(NUMBER_OF_RELOADS):
    action_runner.ReloadPage()
    action_runner.Wait(WAIT_TIME)


def _CreatePageClassWithReload(page_cls):
  class DerivedSmoothPage(page_cls):  # pylint: disable=no-init

    def RunPageInteractions(self, action_runner):
      _Reload(action_runner)
  return DerivedSmoothPage


class PageReloadCasesPageSet(story.StorySet):

  """ Pages for testing GC efficiency on page reload. """

  def __init__(self):
    super(PageReloadCasesPageSet, self).__init__(
        archive_data_file='data/top_25.json',
        cloud_storage_bucket=story.PARTNER_BUCKET)

    shared_desktop_state = shared_page_state.SharedDesktopPageState

    self.AddStory(_CreatePageClassWithReload(
        top_pages.GoogleWebSearchPage)(self, shared_desktop_state))
    self.AddStory(_CreatePageClassWithReload(
        top_pages.GoogleDocPage)(self, shared_desktop_state))
