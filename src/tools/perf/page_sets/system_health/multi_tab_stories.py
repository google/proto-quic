# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import py_utils
import logging

from page_sets.system_health import system_health_story
from page_sets.system_health import story_tags
from page_sets.system_health import platforms


class MultiTabStory(system_health_story.SystemHealthStory):
  ABSTRACT_STORY = True

  def __init__(self, story_set, take_memory_measurement, tabset_repeat=1):
    super(MultiTabStory, self).__init__(story_set, take_memory_measurement)
    self._tabset_repeat = tabset_repeat

  def RunNavigateSteps(self, action_runner):
    tabs = action_runner.tab.browser.tabs

    # No need to create the first tab as there is already one
    # when the browser is ready,
    url_list = self.URL_LIST * self._tabset_repeat
    if url_list:
      action_runner.Navigate(url_list[0])
    for url in url_list[1:]:
      new_tab = tabs.New()
      new_tab.action_runner.Navigate(url)

    for i, url in enumerate(url_list):
      try:
        tabs[i].action_runner.WaitForNetworkQuiescence()
      except py_utils.TimeoutException:
        logging.warning('WaitForNetworkQuiescence() timeout, url[%d]: %s'
                        % (i, url))

  def RunPageInteractions(self, action_runner):
    for tab in action_runner.tab.browser.tabs:
      tab.Activate()
      tab.WaitForFrameToBeDisplayed()


class MultiTabTypical24Story(MultiTabStory):
  """Load 24 different web sites in 24 tabs, then cycle through each tab."""
  NAME = 'multitab:misc:typical24'
  TAGS = [story_tags.TABS_SWITCHING]
  URL_LIST = [
    # Why: Alexa games #48
    'http://www.nick.com/games',
    # Why: Alexa sports #45
    'http://www.rei.com/',
    # Why: Alexa sports #50
    'http://www.fifa.com/',
    # Why: Alexa shopping #41
    'http://www.gamestop.com/ps3',
    # Why: Alexa news #55
    ('http://www.economist.com/news/science-and-technology/21573529-small-'
     'models-cosmic-phenomena-are-shedding-light-real-thing-how-build'),
    # Why: Alexa news #67
    'http://www.theonion.com',
    'http://arstechnica.com/',
    # Why: Alexa home #10
    'http://allrecipes.com/Recipe/Pull-Apart-Hot-Cross-Buns/Detail.aspx',
    'http://www.html5rocks.com/en/',
    'http://www.mlb.com/',
    'http://gawker.com/5939683/based-on-a-true-story-is-a-rotten-lie-i-hope-you-never-believe',
    'http://www.imdb.com/title/tt0910970/',
    'http://www.flickr.com/search/?q=monkeys&f=hp',
    'http://money.cnn.com/',
    'http://www.nationalgeographic.com/',
    'http://premierleague.com',
    'http://www.osubeavers.com/',
    'http://walgreens.com',
    'http://colorado.edu',
    ('http://www.ticketmaster.com/JAY-Z-and-Justin-Timberlake-tickets/artist/'
     '1837448?brand=none&tm_link=tm_homeA_rc_name2'),
    # pylint: disable=line-too-long
    'http://www.theverge.com/2013/3/5/4061684/inside-ted-the-smartest-bubble-in-the-world',
    'http://www.airbnb.com/',
    'http://www.ign.com/',
    # Why: Alexa health #25
    'http://www.fda.gov',
  ]
  URL = URL_LIST[0]
  SUPPORTED_PLATFORMS = platforms.DESKTOP_ONLY
