# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
from telemetry.page import page as page_module
from telemetry.page import shared_page_state
from telemetry import story

from page_sets.login_helpers import google_login
from page_sets import top_pages


def _IssueMarkerAndScroll(action_runner):
  with action_runner.CreateGestureInteraction('ScrollAction'):
    action_runner.ScrollPage()


def _CreatePageClassWithSmoothInteractions(page_cls):
  class DerivedSmoothPage(page_cls):  # pylint: disable=no-init

    def RunPageInteractions(self, action_runner):
      action_runner.Wait(1)
      _IssueMarkerAndScroll(action_runner)
  return DerivedSmoothPage


class TopSmoothPage(page_module.Page):

  def __init__(self, url, page_set, name='', credentials=None):
    if name == '':
      name = url
    super(TopSmoothPage, self).__init__(
        url=url, page_set=page_set, name=name,
        shared_page_state_class=shared_page_state.SharedDesktopPageState,
        credentials_path='data/credentials.json')
    self.credentials = credentials

  def RunPageInteractions(self, action_runner):
    action_runner.Wait(1)
    _IssueMarkerAndScroll(action_runner)


class GmailSmoothPage(top_pages.TopPages):

  """ Why: productivity, top google properties """

  def __init__(self, page_set,
               shared_page_state_class=shared_page_state.SharedPageState):
    # TODO(flackr): This is duplicating page logic from top_pages.py but is
    # the only way to update https://mail.google.com/mail/ for this test without
    # updating the 14 other recordings, as the gmail login flow has changed.
    # https://crbug.com/590766 tracks updating google_login.py to support
    # legacy and new login flow.
    super(GmailSmoothPage, self).__init__(
        url='https://mail.google.com/mail/',
        page_set=page_set,
        shared_page_state_class=shared_page_state_class)

  def RunNavigateSteps(self, action_runner):
    google_login.LoginGoogleAccount(action_runner, 'google3',
                                    self.credentials_path)
    super(GmailSmoothPage, self).RunNavigateSteps(action_runner)
    action_runner.WaitForJavaScriptCondition(
        'window.gmonkey !== undefined &&'
        'document.getElementById("gb") !== null',
        timeout=120)

  def RunPageInteractions(self, action_runner):
    action_runner.ExecuteJavaScript('''
        gmonkey.load('2.0', function(api) {
          window.__scrollableElementForTelemetry = api.getScrollableElement();
        });''')
    action_runner.WaitForJavaScriptCondition(
        'window.__scrollableElementForTelemetry != null')
    action_runner.Wait(1)
    with action_runner.CreateGestureInteraction('ScrollAction'):
      action_runner.ScrollElement(
          element_function='window.__scrollableElementForTelemetry')


class GoogleCalendarSmoothPage(top_pages.GoogleCalendarPage):

  """ Why: productivity, top google properties """

  def RunPageInteractions(self, action_runner):
    action_runner.Wait(1)
    with action_runner.CreateGestureInteraction('ScrollAction'):
      action_runner.ScrollElement(selector='#scrolltimedeventswk')


class GoogleDocSmoothPage(top_pages.GoogleDocPage):

  """ Why: productivity, top google properties; Sample doc in the link """

  def RunPageInteractions(self, action_runner):
    action_runner.Wait(1)
    with action_runner.CreateGestureInteraction('ScrollAction'):
      action_runner.ScrollElement(selector='.kix-appview-editor')


class ESPNSmoothPage(top_pages.ESPNPage):

  """ Why: #1 sports """

  def RunPageInteractions(self, action_runner):
    action_runner.Wait(1)
    with action_runner.CreateGestureInteraction('ScrollAction'):
      action_runner.ScrollPage(left_start_ratio=0.1)


class Top25SmoothPageSet(story.StorySet):

  """ Pages hand-picked for 2012 CrOS scrolling tuning efforts. """

  def __init__(self, techcrunch=True):
    super(Top25SmoothPageSet, self).__init__(
        archive_data_file='data/top_25_smooth.json',
        cloud_storage_bucket=story.PARTNER_BUCKET)

    desktop_state_class = shared_page_state.SharedDesktopPageState

    self.AddStory(_CreatePageClassWithSmoothInteractions(
        top_pages.GoogleWebSearchPage)(self, desktop_state_class))
    self.AddStory(GmailSmoothPage(self, desktop_state_class))
    self.AddStory(GoogleCalendarSmoothPage(self, desktop_state_class))
    self.AddStory(_CreatePageClassWithSmoothInteractions(
        top_pages.GoogleImageSearchPage)(self, desktop_state_class))
    self.AddStory(GoogleDocSmoothPage(self, desktop_state_class))
    self.AddStory(_CreatePageClassWithSmoothInteractions(
        top_pages.GooglePlusPage)(self, desktop_state_class))
    self.AddStory(_CreatePageClassWithSmoothInteractions(
        top_pages.YoutubePage)(self, desktop_state_class))
    self.AddStory(_CreatePageClassWithSmoothInteractions(
        top_pages.BlogspotPage)(self, desktop_state_class))
    self.AddStory(_CreatePageClassWithSmoothInteractions(
        top_pages.WordpressPage)(self, desktop_state_class))
    self.AddStory(_CreatePageClassWithSmoothInteractions(
        top_pages.FacebookPage)(self, desktop_state_class))
    self.AddStory(_CreatePageClassWithSmoothInteractions(
        top_pages.LinkedinPage)(self, desktop_state_class))
    self.AddStory(_CreatePageClassWithSmoothInteractions(
        top_pages.WikipediaPage)(self, desktop_state_class))
    self.AddStory(_CreatePageClassWithSmoothInteractions(
        top_pages.TwitterPage)(self, desktop_state_class))
    self.AddStory(_CreatePageClassWithSmoothInteractions(
        top_pages.PinterestPage)(self, desktop_state_class))
    self.AddStory(ESPNSmoothPage(self, desktop_state_class))
    self.AddStory(_CreatePageClassWithSmoothInteractions(
        top_pages.WeatherPage)(self, desktop_state_class))
    self.AddStory(_CreatePageClassWithSmoothInteractions(
        top_pages.YahooGamesPage)(self, desktop_state_class))

    other_urls = [
        # Why: #1 news worldwide (Alexa global)
        'http://news.yahoo.com',
        # Why: #2 news worldwide
        # crbug.com/528474
        #'http://www.cnn.com',
        # Why: #1 world commerce website by visits; #3 commerce in the US by
        # time spent
        # crbug.com/667432
        #'http://www.amazon.com',
        # Why: #1 commerce website by time spent by users in US
        'http://www.ebay.com',
        # Why: #1 Alexa recreation
        'http://booking.com',
        # Why: #1 Alexa reference
        'http://answers.yahoo.com',
        # Why: #1 Alexa sports
        'http://sports.yahoo.com/',
    ]

    if techcrunch:
      # Why: top tech blog
      other_urls.append('http://techcrunch.com')

    for url in other_urls:
      self.AddStory(TopSmoothPage(url, self))
