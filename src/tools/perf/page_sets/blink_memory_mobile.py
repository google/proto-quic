# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import logging

from telemetry.page import page as page_module
from telemetry.page import shared_page_state
from telemetry import story

from page_sets.login_helpers import google_login


DUMP_WAIT_TIME = 3


class BlinkMemoryMobilePage(page_module.Page):
  def __init__(self, url, page_set, name):
    super(BlinkMemoryMobilePage, self).__init__(
        url=url, page_set=page_set, name=name,
        shared_page_state_class=shared_page_state.SharedMobilePageState,
        credentials_path='data/credentials.json')
    self.archive_data_file = 'data/blink_memory_mobile.json'

  def _DumpMemory(self, action_runner, phase):
    with action_runner.CreateInteraction(phase):
      action_runner.Wait(DUMP_WAIT_TIME)
      action_runner.ForceGarbageCollection()
      action_runner.SimulateMemoryPressureNotification('critical')
      action_runner.Wait(DUMP_WAIT_TIME)
      if not action_runner.tab.browser.DumpMemory():
        logging.error('Unable to get a memory dump for %s.', self.name)

  def RunPageInteractions(self, action_runner):
    action_runner.ScrollPage()
    self._DumpMemory(action_runner, 'scrolled')


class TheVergePage(BlinkMemoryMobilePage):
  COMMENT_LINK_SELECTOR = '.show_comments_link'

  def __init__(self, page_set):
    super(TheVergePage, self).__init__(
        'http://www.theverge.com/2015/8/11/9133883/taylor-swift-spotify-discover-weekly-what-is-going-on',
        page_set=page_set,
        name='TheVerge')

  def RunPageInteractions(self, action_runner):
    action_runner.WaitForElement(selector=TheVergePage.COMMENT_LINK_SELECTOR)
    action_runner.ExecuteJavaScript(
        'window.location.hash = "comments"')
    action_runner.TapElement(
        selector=TheVergePage.COMMENT_LINK_SELECTOR)
    action_runner.WaitForJavaScriptCondition(
        'window.Chorus.Comments.collection.length > 0')
    super(TheVergePage, self).RunPageInteractions(action_runner)


class FacebookPage(BlinkMemoryMobilePage):
  def __init__(self, page_set):
    super(FacebookPage, self).__init__(
        'https://facebook.com/barackobama',
        page_set=page_set,
        name='Facebook')

  def RunNavigateSteps(self, action_runner):
    super(FacebookPage, self).RunNavigateSteps(action_runner)
    action_runner.WaitForJavaScriptCondition(
        'document.getElementById("u_0_c") !== null &&'
        'document.body.scrollHeight > window.innerHeight')


class GmailPage(BlinkMemoryMobilePage):
  def __init__(self, page_set):
    super(GmailPage, self).__init__(
        'https://mail.google.com/mail/',
        page_set=page_set,
        name='Gmail')

  def RunNavigateSteps(self, action_runner):
    google_login.LoginGoogleAccount(action_runner, 'google',
                                    self.credentials_path)
    super(GmailPage, self).RunNavigateSteps(action_runner)
    action_runner.WaitForElement(selector='#apploadingdiv')
    action_runner.WaitForJavaScriptCondition(
        'document.querySelector("#apploadingdiv").style.opacity == "0"')


class BlinkMemoryMobilePageSet(story.StorySet):
  """Key mobile sites for Blink memory reduction."""

  def __init__(self):
    super(BlinkMemoryMobilePageSet, self).__init__(
        archive_data_file='data/blink_memory_mobile.json',
        cloud_storage_bucket=story.PARTNER_BUCKET)

    # Why: High rate of Blink's memory consumption rate.
    self.AddStory(BlinkMemoryMobilePage(
        'https://www.pinterest.com',
        page_set=self,
        name='Pinterest'))
    self.AddStory(FacebookPage(self))
    self.AddStory(TheVergePage(self))

    # Why: High rate of Blink's memory comsumption rate on low-RAM devices.
    self.AddStory(BlinkMemoryMobilePage(
        'http://en.m.wikipedia.org/wiki/Wikipedia',
        page_set=self,
        name='Wikipedia (1 tab) - delayed scroll start',))
    self.AddStory(BlinkMemoryMobilePage(
        url='http://www.reddit.com/r/programming/comments/1g96ve',
        page_set=self,
        name='Reddit'))
    self.AddStory(BlinkMemoryMobilePage(
        'https://en.blog.wordpress.com/2012/09/04/freshly-pressed-editors-picks-for-august-2012/',
        page_set=self,
        name='Wordpress'))

    # Why: Renderer memory usage is high.
    self.AddStory(BlinkMemoryMobilePage(
        'http://worldjournal.com/',
        page_set=self,
        name='Worldjournal'))

    # Why: Key products.
    self.AddStory(GmailPage(page_set=self))
    self.AddStory(BlinkMemoryMobilePage(
        'http://googlewebmastercentral.blogspot.com/2015/04/rolling-out-mobile-friendly-update.html?m=1',
        page_set=self,
        name='Blogger'))
    self.AddStory(BlinkMemoryMobilePage(
        'https://plus.google.com/app/basic/110031535020051778989/posts?source=apppromo',
        page_set=self,
        name='GooglePlus'))
