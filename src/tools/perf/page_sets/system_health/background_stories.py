# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from page_sets.system_health import platforms
from page_sets.system_health import system_health_story
from page_sets.system_health.loading_stories import LoadGmailMobileStory

_WAIT_FOR_VIDEO_SECONDS = 5

class _BackgroundStory(system_health_story.SystemHealthStory):
  """Abstract base class for background stories

  As in _LoadingStory except it puts the browser into the
  background before measuring.
  """
  ABSTRACT_STORY = True
  SUPPORTED_PLATFORMS = platforms.MOBILE_ONLY

  def _Measure(self, action_runner):
    action_runner.tab.browser.Background()
    super(_BackgroundStory, self)._Measure(action_runner)


class BackgroundGoogleStory(_BackgroundStory):
  NAME = 'background:search:google'
  URL = 'https://www.google.co.uk/#q=tom+cruise+movies'

  def _DidLoadDocument(self, action_runner):
    # Activte the immersive movie browsing experience
    action_runner.WaitForElement(selector='g-fab')
    action_runner.ScrollPageToElement(selector='g-fab')
    action_runner.TapElement(selector='g-fab')


class BackgroundFacebookMobileStory(_BackgroundStory):
  NAME = 'background:social:facebook'
  URL = 'https://www.facebook.com/rihanna'
  SUPPORTED_PLATFORMS = platforms.MOBILE_ONLY


class BackgroundNytimesMobileStory(_BackgroundStory):
  """The third top website in http://www.alexa.com/topsites/category/News"""
  NAME = 'background:news:nytimes'
  URL = 'http://www.nytimes.com/2016/10/04/us/politics/vice-presidential-debate.html?_r=0'
  SUPPORTED_PLATFORMS = platforms.MOBILE_ONLY

  def _DidLoadDocument(self, action_runner):
    # Dismiss the 'You have n free articles' message.
    action_runner.WaitForElement(selector='.growl-dismiss')
    action_runner.TapElement(selector='.growl-dismiss')

    # Tap the 'Show Full Article' button.
    action_runner.WaitForElement(selector='#additional-content button')
    action_runner.ScrollPageToElement(selector='#additional-content button')
    # TapElement seems flaky here so use JavaScript instead.
    action_runner.ExecuteJavaScript(
        'document.querySelector("#additional-content button").click()')

    # Scroll to video, start it and then wait for a few seconds.
    action_runner.WaitForElement(selector='.nytd-player-poster')
    action_runner.ScrollPageToElement(selector='.nytd-player-poster')
    action_runner.TapElement(selector='.nytd-player-poster')
    action_runner.Wait(_WAIT_FOR_VIDEO_SECONDS)


class BackgroundImgurMobileStory(_BackgroundStory):
  NAME = 'background:media:imgur'
  URL = 'http://imgur.com/gallery/hUita'
  SUPPORTED_PLATFORMS = platforms.MOBILE_ONLY


class BackgroundGmailMobileStory(LoadGmailMobileStory):
  NAME = 'background:tools:gmail'
  SUPPORTED_PLATFORMS = platforms.MOBILE_ONLY

  def _Measure(self, action_runner):
    action_runner.tab.browser.Background()
    super(BackgroundGmailMobileStory, self)._Measure(action_runner)

