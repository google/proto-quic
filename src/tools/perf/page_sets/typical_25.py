# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import shutil

from profile_creators import profile_generator
from telemetry.page import page as page_module
from telemetry.page import cache_temperature as cache_temperature_module
from telemetry.page import shared_page_state
from telemetry import story


class Typical25ProfileSharedState(shared_page_state.SharedDesktopPageState):
  """Shared state associated with a profile generated from 25 navigations.

  Generates a shared profile on initialization.
  """

  def __init__(self, test, finder_options, story_set):
    super(Typical25ProfileSharedState, self).__init__(
        test, finder_options, story_set)
    from profile_creators import small_profile_extender
    generator = profile_generator.ProfileGenerator(
        small_profile_extender.SmallProfileExtender,
        'small_profile')
    self._out_dir, self._owns_out_dir = generator.Run(finder_options)
    if self._out_dir:
      finder_options.browser_options.profile_dir = self._out_dir
    else:
      finder_options.browser_options.dont_override_profile = True

  def TearDownState(self):
    """Clean up generated profile directory."""
    super(Typical25ProfileSharedState, self).TearDownState()
    if self._owns_out_dir:
      shutil.rmtree(self._out_dir)


class Typical25Page(page_module.Page):

  def __init__(self, url, page_set, run_no_page_interactions,
      shared_page_state_class=shared_page_state.SharedDesktopPageState,
      cache_temperature=None):
    super(Typical25Page, self).__init__(
        url=url, page_set=page_set,
        shared_page_state_class=shared_page_state_class,
        cache_temperature=cache_temperature)
    self._run_no_page_interactions = run_no_page_interactions

  def RunPageInteractions(self, action_runner):
    if self._run_no_page_interactions:
      action_runner.WaitForJavaScriptCondition(
          'performance.timing.loadEventStart > 0')
      return
    with action_runner.CreateGestureInteraction('ScrollAction'):
      action_runner.ScrollPage()


class Typical25PageSet(story.StorySet):

  """ Pages designed to represent the median, not highly optimized web """

  def __init__(self, run_no_page_interactions=False,
               page_class=Typical25Page,
               cache_temperatures=None):
    super(Typical25PageSet, self).__init__(
      archive_data_file='data/typical_25.json',
      cloud_storage_bucket=story.PARTNER_BUCKET)
    if cache_temperatures is None:
      cache_temperatures = [cache_temperature_module.ANY]

    urls_list = [
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

    for url in urls_list:
      for temp in cache_temperatures:
        self.AddStory(page_class(
          url, self, run_no_page_interactions, cache_temperature=temp))
