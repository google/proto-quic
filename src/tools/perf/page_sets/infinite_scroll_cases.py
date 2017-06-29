# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import sys

from page_sets.login_helpers import facebook_login
from page_sets.system_health import platforms
from telemetry.core import discover
from telemetry.page import page
from telemetry.page import shared_page_state
from telemetry import story

class _InfiniteScrollStory(page.Page):
  """ Base class for infinite scroll stories."""

  NAME = NotImplemented
  URL = NotImplemented
  SUPPORTED_PLATFORMS = platforms.ALL_PLATFORMS

  SCROLL_DISTANCE = 25000
  SCROLL_STEP = 1000
  MAX_SCROLL_RETRIES = 5
  TIME_BEFORE_SCROLL_RETRY_IN_SECONDS = 2
  TIME_TO_WAIT_BEFORE_STARTING_IN_SECONDS = 5

  def __init__(self, story_set):
    super(_InfiniteScrollStory, self).__init__(
        page_set=story_set, url=self.URL, name=self.NAME,
        shared_page_state_class=shared_page_state.SharedPageState,
        credentials_path='data/credentials.json')
    # TODO(ulan): Remove this once crbug.com/541508 is fixed.
    self.script_to_evaluate_on_commit = '''
        window.WebSocket = undefined;
        window.Worker = undefined;
        window.performance = undefined;'''

  def RunPageInteractions(self, action_runner):
    with action_runner.CreateInteraction('Load'):
      action_runner.WaitForJavaScriptCondition(
        'document.body != null && '
        'document.body.scrollHeight > window.innerHeight && '
        '!document.body.addEventListener("touchstart", function() {})')
    with action_runner.CreateInteraction('Wait'):
      action_runner.Wait(self.TIME_TO_WAIT_BEFORE_STARTING_IN_SECONDS)
    with action_runner.CreateInteraction('GC'):
      action_runner.ForceGarbageCollection()
    with action_runner.CreateInteraction('Begin'):
      action_runner.tab.browser.DumpMemory()
    with action_runner.CreateInteraction('Scrolling'):
      self._Scroll(action_runner, self.SCROLL_DISTANCE, self.SCROLL_STEP)
    with action_runner.CreateInteraction('End'):
      action_runner.tab.browser.DumpMemory()

  def _Scroll(self, action_runner, distance, step_size):
    """ This function scrolls the webpage by the given scroll distance in
    multiple steps, where each step (except the last one) has the given size.

    If scrolling gets stuck, the functions retries scrolling MAX_SCROLL_RETRIES
    times waiting TIME_BEFORE_SCROLL_RETRY_IN_SECONDS seconds between retries.
    """
    remaining = distance - action_runner.EvaluateJavaScript('window.scrollY')
    retry_count = 0
    # Scroll until the window.scrollY is within 1 pixel of the target distance.
    while remaining > 1:
      action_runner.ScrollPage(distance=min(remaining, step_size) + 1)
      new_remaining = (distance -
          action_runner.EvaluateJavaScript('window.scrollY'))
      if remaining == new_remaining:
        # Scrolling is stuck. This can happen if the page is loading
        # resources. Give the page some time and retry scrolling.
        if retry_count == self.MAX_SCROLL_RETRIES:
          raise Exception('Scrolling stuck at %d' % remaining)
        retry_count += 1
        action_runner.Wait(self.TIME_BEFORE_SCROLL_RETRY_IN_SECONDS)
      else:
        retry_count = 0
        remaining = new_remaining

class DiscourseDesktopStory(_InfiniteScrollStory):
  NAME = 'discourse'
  URL = ('https://meta.discourse.org/t/the-official-discourse-tags-plugin' +
     '-discourse-tagging/26482')
  SUPPORTED_PLATFORMS = platforms.DESKTOP_ONLY

class DiscourseMobileStory(_InfiniteScrollStory):
  NAME = 'discourse'
  URL = ('https://meta.discourse.org/t/the-official-discourse-tags-plugin' +
     '-discourse-tagging/26482')
  SUPPORTED_PLATFORMS = platforms.MOBILE_ONLY
  SCROLL_DISTANCE = 15000

class FacebookDesktopStory(_InfiniteScrollStory):
  NAME = 'facebook'
  URL = 'https://www.facebook.com/shakira'
  SUPPORTED_PLATFORMS = platforms.DESKTOP_ONLY

class FacebookMobileStory(_InfiniteScrollStory):
  NAME = 'facebook'
  URL = 'https://m.facebook.com/shakira'
  SUPPORTED_PLATFORMS = platforms.MOBILE_ONLY
  def RunNavigateSteps(self, action_runner):
    facebook_login.LoginWithMobileSite(
        action_runner, 'facebook3', self.credentials_path)
    super(FacebookMobileStory, self).RunNavigateSteps(action_runner)

class FlickrDesktopStory(_InfiniteScrollStory):
  NAME = 'flickr'
  URL = 'https://www.flickr.com/explore'
  SUPPORTED_PLATFORMS = platforms.DESKTOP_ONLY

class FlickrMobileStory(_InfiniteScrollStory):
  NAME = 'flickr'
  URL = 'https://www.flickr.com/explore'
  SUPPORTED_PLATFORMS = platforms.MOBILE_ONLY
  SCROLL_DISTANCE = 10000

class PinterestMobileStory(_InfiniteScrollStory):
  NAME = 'pinterest'
  URL = 'https://www.pinterest.com/all'
  SUPPORTED_PLATFORMS = platforms.MOBILE_ONLY

class TumblrStory(_InfiniteScrollStory):
  NAME = 'tumblr'
  URL = 'http://techcrunch.tumblr.com/'

class TwitterDesktopStory(_InfiniteScrollStory):
  NAME = 'twitter'
  URL = 'https://twitter.com/taylorswift13'
  SUPPORTED_PLATFORMS = platforms.DESKTOP_ONLY

class InfiniteScrollStorySet(story.StorySet):
  """ Desktop story set. """
  def __init__(self):
    super(InfiniteScrollStorySet, self).__init__(
        archive_data_file='data/infinite_scroll.json',
        cloud_storage_bucket=story.PARTNER_BUCKET)
    for story_class in _FindInfiniteScrollStoryClasses(platforms.DESKTOP):
      self.AddStory(story_class(self))

class MobileInfiniteScrollStorySet(story.StorySet):
  """ Mobile story set. """
  def __init__(self):
    super(MobileInfiniteScrollStorySet, self).__init__(
        archive_data_file='data/mobile_infinite_scroll.json',
        cloud_storage_bucket=story.PARTNER_BUCKET)
    for story_class in _FindInfiniteScrollStoryClasses(platforms.MOBILE):
      self.AddStory(story_class(self))

def _FindInfiniteScrollStoryClasses(platform):
  # Sort the classes by their names so that their order is stable and
  # deterministic.
  for unused_cls_name, cls in sorted(discover.DiscoverClassesInModule(
      module=sys.modules[__name__], base_class=_InfiniteScrollStory,
      index_by_class_name=True).iteritems()):
    if platform in cls.SUPPORTED_PLATFORMS:
      yield cls
