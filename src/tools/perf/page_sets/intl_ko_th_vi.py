# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from page_sets import page_cycler_story
from telemetry import story
from telemetry.page import cache_temperature as cache_temperature_module
from telemetry.page import shared_page_state


class IntlKoThViPage(page_cycler_story.PageCyclerStory):

  def __init__(self, url, page_set, cache_temperature=None):
    super(IntlKoThViPage, self).__init__(
        url=url, page_set=page_set,
        shared_page_state_class=shared_page_state.SharedDesktopPageState,
        cache_temperature=cache_temperature)


class IntlKoThViPageSet(story.StorySet):

  """ Popular pages in Korean, Thai and Vietnamese. """

  def __init__(self, cache_temperatures=None):
    super(IntlKoThViPageSet, self).__init__(
      archive_data_file='data/intl_ko_th_vi.json',
      cloud_storage_bucket=story.PARTNER_BUCKET)
    if cache_temperatures is None:
      cache_temperatures = [cache_temperature_module.ANY]

    urls_list = [
      # Why: #7 site in Vietnam
      'http://us.24h.com.vn/',
      # Why: #6 site in Vietnam
      'http://vnexpress.net/',
      # Why: #18 site in Vietnam
      'http://vietnamnet.vn/',
      # Why: #5 site in Vietnam
      # Disabled, see crbug.com/682351.
      # pylint: disable=line-too-long
      #'http://news.zing.vn/the-gioi/ba-dam-thep-margaret-thatcher-qua-doi/a312895.html#home_noibat1',
      'http://kenh14.vn/home.chn',
      # Why: #5 site in Korea
      'http://www.naver.com/',
      # Why: #9 site in Korea
      'http://www.daum.net/',
      # Why: #25 site in Korea
      'http://www.donga.com/',
      'http://www.chosun.com/',
      'http://www.danawa.com/',
      # Why: #10 site in Thailand
      'http://pantip.com/',
      'http://thaimisc.com/'
    ]

    for url in urls_list:
      for temp in cache_temperatures:
        self.AddStory(IntlKoThViPage(url, self, cache_temperature=temp))
