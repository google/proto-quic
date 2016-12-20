# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry.page import page
from telemetry.page import cache_temperature as cache_temperature_module
from telemetry.page import shared_page_state


_TTI_WAIT_TIME = 10
_NAVIGATION_TIMEOUT = 180
_WEB_CONTENTS_TIMEOUT = 180

class PageCyclerStory(page.Page):

  def __init__(self, url, page_set,
      shared_page_state_class=shared_page_state.SharedDesktopPageState,
      cache_temperature=cache_temperature_module.ANY, **kwargs):
    super(PageCyclerStory, self).__init__(
        url=url, page_set=page_set,
        shared_page_state_class=shared_page_state_class,
        cache_temperature=cache_temperature,
        **kwargs)

  def RunNavigateSteps(self, action_runner):
    url = self.file_path_url_with_scheme if self.is_file else self.url
    action_runner.Navigate(url,
                           self.script_to_evaluate_on_commit,
                           timeout_in_seconds=_NAVIGATION_TIMEOUT)

  def RunPageInteractions(self, action_runner):
    action_runner.tab.WaitForDocumentReadyStateToBeComplete(
        _WEB_CONTENTS_TIMEOUT)
    action_runner.Wait(_TTI_WAIT_TIME)
