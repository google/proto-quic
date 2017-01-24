# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
from telemetry.page import page as page_module
from telemetry.page import shared_page_state
from telemetry import story

from page_sets import key_mobile_sites_pages
from page_sets import repaint_helpers



def _CreatePageClassWithRepaintInteractions(page_cls, mode, height, width):
  class DerivedRepaintPage(page_cls):  # pylint: disable=no-init

    def RunPageInteractions(self, action_runner):
      repaint_helpers.Repaint(
        action_runner, mode=mode, width=width, height=height)

  return DerivedRepaintPage


class KeyMobileSitesRepaintPage(page_module.Page):

  def __init__(self, url, page_set, mode, height, width, name='', tags=None):
    super(KeyMobileSitesRepaintPage, self).__init__(
        url=url, page_set=page_set, name=name,
        shared_page_state_class=shared_page_state.SharedMobilePageState,
        credentials_path='data/credentials.json', tags=tags)
    self.archive_data_file = 'data/key_mobile_sites_repaint.json'
    self._mode = mode
    self._width = width
    self._height = height

  def RunPageInteractions(self, action_runner):
    repaint_helpers.Repaint(
        action_runner, mode=self._mode, width=self._width, height=self._height)


class KeyMobileSitesRepaintPageSet(story.StorySet):

  """ Key mobile sites with repaint interactions. """

  def __init__(self, mode='viewport', width=None, height=None):
    super(KeyMobileSitesRepaintPageSet, self).__init__(
      archive_data_file='data/key_mobile_sites_repaint.json',
      cloud_storage_bucket=story.PARTNER_BUCKET)


    # Add pages with predefined classes that contain custom navigation logic.
    predefined_page_classes = [
      key_mobile_sites_pages.CapitolVolkswagenPage,
      key_mobile_sites_pages.TheVergeArticlePage,
      key_mobile_sites_pages.CnnArticlePage,
      key_mobile_sites_pages.FacebookPage,
      key_mobile_sites_pages.YoutubeMobilePage,
      key_mobile_sites_pages.LinkedInPage,
      key_mobile_sites_pages.YahooAnswersPage,
      key_mobile_sites_pages.GmailPage,
      key_mobile_sites_pages.GoogleNewsMobilePage,
      key_mobile_sites_pages.GoogleNewsMobile2Page,
      key_mobile_sites_pages.AmazonNicolasCagePage,
      # Page behaves non-deterministically, replaced with test version for now.
      # key_mobile_sites_pages.GroupClonedPage,

      # mean_input_event_latency cannot be tracked correctly for
      # GroupClonedListImagesPage. See crbug.com/409086.
      # key_mobile_sites_pages.GroupClonedListImagesPage,
    ]
    for page_class in predefined_page_classes:
      self.AddStory(
        _CreatePageClassWithRepaintInteractions(
            page_class, mode=mode, height=height, width=width)(self))

    # Add pages with custom tags.

    # Why: Top news site.
    self.AddStory(KeyMobileSitesRepaintPage(
      url='http://nytimes.com/', page_set=self, tags=['fastpath'],
      mode=mode, height=height, width=width))

    # Why: Image-heavy site.
    self.AddStory(KeyMobileSitesRepaintPage(
      url='http://cuteoverload.com', page_set=self, tags=['fastpath'],
      mode=mode, height=height, width=width))

    # Why: #11 (Alexa global), google property; some blogger layouts
    # have infinite scroll but more interesting.
    self.AddStory(KeyMobileSitesRepaintPage(
      url='http://googlewebmastercentral.blogspot.com/',
      page_set=self, name='Blogger', mode=mode, height=height, width=width))

    # Why: #18 (Alexa global), Picked an interesting post """
    self.AddStory(KeyMobileSitesRepaintPage(
      url='http://en.blog.wordpress.com/2012/09/04/freshly-pressed-editors-picks-for-august-2012/',
      page_set=self,
      name='Wordpress', mode=mode, height=height, width=width))

   # Why: #6 (Alexa) most visited worldwide, picked an interesting page
    self.AddStory(KeyMobileSitesRepaintPage(
      url='http://en.wikipedia.org/wiki/Wikipedia',
      page_set=self,
      name='Wikipedia (1 tab)', mode=mode, height=height, width=width))

    # Why: #8 (Alexa global), picked an interesting page
    # Forbidden (Rate Limit Exceeded)
    # self.AddStory(KeyMobileSitesRepaintPage(
    #  url='http://twitter.com/katyperry', page_set=self, name='Twitter'))

    # Why: #37 (Alexa global) """
    self.AddStory(KeyMobileSitesRepaintPage(
        url='http://pinterest.com',
        page_set=self,
        name='Pinterest', mode=mode, height=height, width=width))

    # Why: #1 sports.
    # Fails often; crbug.com/249722'
    # self.AddStory(KeyMobileSitesRepaintPage(
    # url='http://espn.go.com', page_set=self, name='ESPN'))
    # Why: crbug.com/231413
    # Doesn't scroll; crbug.com/249736
    # self.AddStory(KeyMobileSitesRepaintPage(
    #                 url='http://forecast.io', page_set=self))
    # Why: crbug.com/169827
    self.AddStory(KeyMobileSitesRepaintPage(
      url='http://slashdot.org/', page_set=self, tags=['fastpath'],
      mode=mode, width=width, height=height))

    # Why: #5 Alexa news """

    self.AddStory(KeyMobileSitesRepaintPage(
      url='http://www.reddit.com/r/programming/comments/1g96ve',
      page_set=self, tags=['fastpath'],
      mode=mode, width=width, height=height))

    # Why: Problematic use of fixed position elements """
    self.AddStory(KeyMobileSitesRepaintPage(
      url='http://www.boingboing.net', page_set=self, tags=['fastpath'],
      mode=mode, width=width, height=height))

    # Add simple pages with no custom navigation logic or tags.
    urls_list = [
      # Why: Social; top Google property; Public profile; infinite scrolls.
      'https://plus.google.com/app/basic/110031535020051778989/posts?source=apppromo',
      # Why: crbug.com/242544
      ('http://www.androidpolice.com/2012/10/03/rumor-evidence-mounts-that-an-'
       'lg-optimus-g-nexus-is-coming-along-with-a-nexus-phone-certification-'
       'program/'),
      # Why: crbug.com/149958
      'http://gsp.ro',
      # Why: Top tech blog
      'http://theverge.com',
      # Why: Top tech site
      'http://digg.com',
      # Why: Top Google property; a Google tab is often open
      'https://www.google.com/#hl=en&q=barack+obama',
      # Why: #1 news worldwide (Alexa global)
      'http://news.yahoo.com',
      # Why: #2 news worldwide
      'http://www.cnn.com',
      # Why: #1 commerce website by time spent by users in US
      'http://shop.mobileweb.ebay.com/searchresults?kw=viking+helmet',
      # Why: #1 Alexa recreation
      'http://www.booking.com/searchresults.html?src=searchresults&latitude=65.0500&longitude=25.4667',
      # Why: #1 Alexa sports
      'http://sports.yahoo.com/',
      # Why: Top tech blog
      'http://techcrunch.com',
      # Why: #6 Alexa sports
      'http://mlb.com/',
      # Why: #14 Alexa California
      'http://www.sfgate.com/',
      # Why: Non-latin character set
      'http://worldjournal.com/',
      # Why: Mobile wiki
      'http://www.wowwiki.com/World_of_Warcraft:_Mists_of_Pandaria',
      # Why: #15 Alexa news
      'http://online.wsj.com/home-page',
      # Why: Image-heavy mobile site
      'http://www.deviantart.com/',
      # Why: Top search engine
      ('http://www.baidu.com/s?wd=barack+obama&rsv_bp=0&rsv_spt=3&rsv_sug3=9&'
       'rsv_sug=0&rsv_sug4=3824&rsv_sug1=3&inputT=4920'),
      # Why: Top search engine
      'http://www.bing.com/search?q=sloths',
      # Why: Good example of poor initial scrolling
      'http://ftw.usatoday.com/2014/05/spelling-bee-rules-shenanigans'
    ]

    for url in urls_list:
      self.AddStory(KeyMobileSitesRepaintPage(
          url, self, mode=mode, height=height, width=width))
