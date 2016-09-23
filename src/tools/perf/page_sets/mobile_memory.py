# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
from telemetry.page import page as page_module
from telemetry.page import shared_page_state
from telemetry import story


class MobileMemoryPage(page_module.Page):

  def __init__(self, url, page_set):
    super(MobileMemoryPage, self).__init__(
        url=url, page_set=page_set, credentials_path = 'data/credentials.json',
        shared_page_state_class=shared_page_state.SharedMobilePageState)
    self.archive_data_file = 'data/mobile_memory.json'


class GmailPage(MobileMemoryPage):

  def __init__(self, page_set):
    super(GmailPage, self).__init__(
        url='https://mail.google.com/mail/mu',
        page_set=page_set)

    self.reload_and_gc = [{'action': 'reload'},
                          {'action': 'wait',
                           'seconds': 15},
                          {'action': 'js_collect_garbage'}]
    self.credentials = 'google'

  def ReloadAndGc(self, action_runner):
    action_runner.ReloadPage()
    action_runner.Wait(15)
    action_runner.ForceGarbageCollection()

  def RunPageInteractions(self, action_runner):
    for _ in xrange(3):
      self.ReloadAndGc(action_runner)


class GoogleSearchPage(MobileMemoryPage):

  """ Why: Tests usage of discardable memory """

  def __init__(self, page_set):
    super(GoogleSearchPage, self).__init__(
        url='https://www.google.com/search?site=&tbm=isch&q=google',
        page_set=page_set)

  def RunPageInteractions(self, action_runner):
    with action_runner.CreateGestureInteraction('ScrollAction'):
      action_runner.ScrollPage()
    action_runner.Wait(3)
    with action_runner.CreateGestureInteraction('ScrollAction'):
      action_runner.ScrollPage()
    action_runner.Wait(3)
    with action_runner.CreateGestureInteraction('ScrollAction'):
      action_runner.ScrollPage()
    action_runner.Wait(3)
    with action_runner.CreateGestureInteraction('ScrollAction'):
      action_runner.ScrollPage()
    action_runner.WaitForJavaScriptCondition(
        'document.getElementById("rg_s").childElementCount > 300')


class ScrollPage(MobileMemoryPage):

  def __init__(self, url, page_set):
    super(ScrollPage, self).__init__(url=url, page_set=page_set)

  def RunPageInteractions(self, action_runner):
    with action_runner.CreateGestureInteraction('ScrollAction'):
      action_runner.ScrollPage()


class MobileMemoryPageSet(story.StorySet):

  """ Mobile sites with interesting memory characteristics """

  def __init__(self):
    super(MobileMemoryPageSet, self).__init__(
        archive_data_file='data/mobile_memory.json',
        cloud_storage_bucket=story.PARTNER_BUCKET)

    self.AddStory(GmailPage(self))
    self.AddStory(GoogleSearchPage(self))

    urls_list = [
      # Why: Renderer process memory bloat
      'http://techcrunch.com',
      # pylint: disable=line-too-long
      'http://techcrunch.com/2014/02/17/pixel-brings-brings-old-school-video-game-art-to-life-in-your-home/',
      'http://techcrunch.com/2014/02/15/kickstarter-coins-2/',
      'http://techcrunch.com/2014/02/15/was-y-combinator-worth-it/',
    ]

    for url in urls_list:
      self.AddStory(ScrollPage(url, self))
