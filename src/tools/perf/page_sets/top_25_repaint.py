# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
from telemetry.page import page as page_module
from telemetry.page import shared_page_state
from telemetry import story

from page_sets import repaint_helpers
from page_sets import top_pages


class TopRepaintPage(page_module.Page):

  def __init__(self, url, page_set, mode, width, height, name=''):
    super(TopRepaintPage, self).__init__(
        url=url, page_set=page_set, name=name,
        credentials_path='data/credentials.json',
        shared_page_state_class=shared_page_state.SharedDesktopPageState)
    self._mode = mode
    self._width = width
    self._height = height

  def RunPageInteractions(self, action_runner):
    repaint_helpers.Repaint(
        action_runner, mode=self._mode, width=self._width, height=self._height)


def _CreatePageClassWithRepaintInteractions(page_cls, mode, width, height):
  class DerivedRepaintPage(page_cls):  # pylint: disable=no-init

    def RunPageInteractions(self, action_runner):
      repaint_helpers.Repaint(
          action_runner, mode=mode, width=width, height=height)

  return DerivedRepaintPage


class Top25RepaintPageSet(story.StorySet):

  """ Pages hand-picked for 2012 CrOS scrolling tuning efforts. """

  def __init__(self, mode='viewport', width=None, height=None):
    super(Top25RepaintPageSet, self).__init__(
        archive_data_file='data/top_25_repaint.json',
        cloud_storage_bucket=story.PARTNER_BUCKET)

    top_page_classes = [
        top_pages.GoogleWebSearchPage,
        top_pages.GoogleImageSearchPage,
        top_pages.GmailPage,
        top_pages.GoogleCalendarPage,
        top_pages.GoogleDocPage,
        top_pages.GooglePlusPage,
        top_pages.YoutubePage,
        top_pages.BlogspotPage,
        top_pages.WordpressPage,
        top_pages.FacebookPage,
        top_pages.LinkedinPage,
        top_pages.WikipediaPage,
        top_pages.TwitterPage,
        top_pages.PinterestPage,
        top_pages.ESPNPage,
        top_pages.WeatherPage,
        top_pages.YahooGamesPage,
    ]

    for cl in top_page_classes:
      self.AddStory(_CreatePageClassWithRepaintInteractions(
          cl, mode=mode, width=width, height=height)
                        (self, shared_page_state.SharedDesktopPageState))

    other_urls = [
        # Why: #1 news worldwide (Alexa global)
        'http://news.yahoo.com',
        # Why: #2 news worldwide
        'http://www.cnn.com',
        # Why: #1 world commerce website by visits; #3 commerce in the US by
        # time spent
        'http://www.amazon.com',
        # Why: #1 commerce website by time spent by users in US
        'http://www.ebay.com',
        # Why: #1 Alexa recreation
        'http://booking.com',
        # Why: #1 Alexa reference
        'http://answers.yahoo.com',
        # Why: #1 Alexa sports
        'http://sports.yahoo.com/',
        # Why: top tech blog
        'http://techcrunch.com'
    ]

    for url in other_urls:
      self.AddStory(
          TopRepaintPage(url, self, mode=mode, height=height, width=width))
