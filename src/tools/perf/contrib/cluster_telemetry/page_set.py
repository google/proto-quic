# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.


from telemetry.page import traffic_setting as traffic_setting_module
from telemetry.page import page as page_module
from telemetry.page import shared_page_state
from telemetry import story


class CTPage(page_module.Page):

  def __init__(self, url, page_set, shared_page_state_class, archive_data_file,
               traffic_setting, run_page_interaction_callback):
    super(CTPage, self).__init__(
        url=url,
        page_set=page_set,
        shared_page_state_class=shared_page_state_class,
        traffic_setting=traffic_setting,
        name=url)
    self.archive_data_file = archive_data_file
    self._run_page_interaction_callback = run_page_interaction_callback

  def RunNavigateSteps(self, action_runner):
    action_runner.Navigate(self.url)

  def RunPageInteractions(self, action_runner):
    if self._run_page_interaction_callback:
      self._run_page_interaction_callback(action_runner)


class CTPageSet(story.StorySet):
  """Page set used by CT Benchmarks."""

  def __init__(self, urls_list, user_agent, archive_data_file,
               traffic_setting=traffic_setting_module.NONE,
               run_page_interaction_callback=None):
    if user_agent == 'mobile':
      shared_page_state_class = shared_page_state.SharedMobilePageState
    elif user_agent == 'desktop':
      shared_page_state_class = shared_page_state.SharedDesktopPageState
    else:
      raise ValueError('user_agent %s is unrecognized' % user_agent)

    super(CTPageSet, self).__init__(archive_data_file=archive_data_file)

    for url in urls_list.split(','):
      self.AddStory(
          CTPage(url, self, shared_page_state_class=shared_page_state_class,
                 archive_data_file=archive_data_file,
                 traffic_setting=traffic_setting,
                 run_page_interaction_callback=run_page_interaction_callback))
