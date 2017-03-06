# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
from page_sets import mobile_facebook_page
from telemetry.page import page as page_module
from telemetry.page import shared_page_state
from telemetry import story

TIME_TO_WAIT_BEFORE_STARTING_IN_SECONDS = 5
SCROLL_TIMEOUT_IN_SECONDS = 120

# TODO(ulan): Remove this once crbug.com/541508 is fixed.
STARTUP_SCRIPT = '''
    window.WebSocket = undefined;
    window.Worker = undefined;
    window.performance = undefined;'''

def _ScrollAction(action_runner, scroll_amount, delay, repeat):
  with action_runner.CreateInteraction('Begin'):
    action_runner.tab.browser.DumpMemory()
  with action_runner.CreateInteraction('Scrolling'):
    action_runner.RepeatableBrowserDrivenScroll(
      y_scroll_distance_ratio=scroll_amount,
      repeat_delay_ms=delay,
      repeat_count=repeat,
      timeout=SCROLL_TIMEOUT_IN_SECONDS)
  with action_runner.CreateInteraction('End'):
    action_runner.tab.browser.DumpMemory()

def _WaitAction(action_runner):
  with action_runner.CreateInteraction('Load'):
    action_runner.WaitForJavaScriptCondition(
      'document.body != null && '
      'document.body.scrollHeight > window.innerHeight && '
      '!document.body.addEventListener("touchstart", function() {})')
  with action_runner.CreateInteraction('Wait'):
    action_runner.Wait(TIME_TO_WAIT_BEFORE_STARTING_IN_SECONDS)
  with action_runner.CreateInteraction('GC'):
    action_runner.ForceGarbageCollection()

class MobileInfiniteScrollPage(page_module.Page):
  def __init__(self, url, page_set, name, scroll_amount, delay, repeat,
               credentials=None):
    super(MobileInfiniteScrollPage, self).__init__(
        url=url, page_set=page_set, name=name,
        shared_page_state_class=shared_page_state.SharedPageState,
       credentials_path='data/credentials.json')
    self.credentials = credentials
    self.script_to_evaluate_on_commit = STARTUP_SCRIPT
    self.scroll_amount = scroll_amount
    self.delay = delay
    self.repeat = repeat

  def RunPageInteractions(self, action_runner):
    _WaitAction(action_runner)
    _ScrollAction(action_runner, self.scroll_amount, self.delay,
                       self.repeat)

class MobileInfiniteScrollFacebookPage(mobile_facebook_page.MobileFacebookPage):
  def __init__(self, url, page_set, name, scroll_amount, delay, repeat):
    super(MobileInfiniteScrollFacebookPage, self).__init__(
        url=url, page_set=page_set,
        shared_page_state_class=shared_page_state.SharedPageState,
        name=name)
    self.script_to_evaluate_on_commit = STARTUP_SCRIPT
    self.scroll_amount = scroll_amount
    self.delay = delay
    self.repeat = repeat

  def RunPageInteractions(self, action_runner):
    _WaitAction(action_runner)
    _ScrollAction(action_runner, self.scroll_amount, self.delay,
                       self.repeat)

class MobileInfiniteScrollPageSet(story.StorySet):
  """ Top mobile pages that can be scrolled for many pages. """
  def __init__(self):
    super(MobileInfiniteScrollPageSet, self).__init__(
        archive_data_file='data/mobile_infinite_scroll.json',
        cloud_storage_bucket=story.PARTNER_BUCKET)
    # The scroll distance is chosen such that the page can be scrolled
    # continuously through the test without hitting the end of the page.
    SCROLL_FAR = 60
    SCROLL_PAGE = 1
    pages = [
        ('https://m.facebook.com/shakira', 'facebook', SCROLL_FAR, 0, 0),
        ('https://www.pinterest.com/all', 'pinterest', SCROLL_FAR, 0, 0),
        ('http://techcrunch.tumblr.com/', 'tumblr', SCROLL_FAR, 0, 0),
        ('https://www.flickr.com/explore', 'flickr', SCROLL_FAR, 0, 0),
        ('https://meta.discourse.org/t/the-official-discourse-tags-plugin-discourse-tagging/26482',
         'discourse', SCROLL_PAGE, 10, 30)
    ]
    self.AddStory(
      MobileInfiniteScrollFacebookPage(pages[0][0], self, pages[0][1],
                                       pages[0][2], pages[0][3], pages[0][4]))
    for (url, name, scroll_amount, delay, repeat) in pages[1:]:
      self.AddStory(
        MobileInfiniteScrollPage(url, self, name, scroll_amount, delay, repeat))
