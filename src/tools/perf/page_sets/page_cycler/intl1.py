# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
from telemetry.page import page as page_module
from telemetry import story

class Intl1Page(page_module.Page):

  def __init__(self, url, page_set):
    super(Intl1Page, self).__init__(url=url, page_set=page_set)


class Intl1PageSet(story.StorySet):

  """ Intl1 page_cycler benchmark """

  def __init__(self):
    super(Intl1PageSet, self).__init__(
      # pylint: disable=line-too-long
      serving_dirs=set(['../../../../data/page_cycler/intl1']))

    urls_list = [
      'file://../../../../data/page_cycler/intl1/126.com/',
      'file://../../../../data/page_cycler/intl1/2ch.net/',
      'file://../../../../data/page_cycler/intl1/6park.com/',
      'file://../../../../data/page_cycler/intl1/affili.net/',
      'file://../../../../data/page_cycler/intl1/allegro.pl/',
      'file://../../../../data/page_cycler/intl1/apeha.ru/',
      'file://../../../../data/page_cycler/intl1/baidu.com/',
      'file://../../../../data/page_cycler/intl1/bbs.wefong.com/',
      'file://../../../../data/page_cycler/intl1/blog.skyrock.com/',
      'file://../../../../data/page_cycler/intl1/cmfu.com/',
      'file://../../../../data/page_cycler/intl1/cn.yahoo.com/',
      'file://../../../../data/page_cycler/intl1/contra.gr/',
      'file://../../../../data/page_cycler/intl1/dtiblog.com/',
      'file://../../../../data/page_cycler/intl1/el.wikipedia.org/',
      'file://../../../../data/page_cycler/intl1/elmundo.es/',
      'file://../../../../data/page_cycler/intl1/ettoday.com/',
      'file://../../../../data/page_cycler/intl1/exblog.jp/',
      'file://../../../../data/page_cycler/intl1/excite.co.jp/',
      'file://../../../../data/page_cycler/intl1/fc2.com/',
      'file://../../../../data/page_cycler/intl1/fora.pl/',
      'file://../../../../data/page_cycler/intl1/free.fr/',
      'file://../../../../data/page_cycler/intl1/golem.de/',
      'file://../../../../data/page_cycler/intl1/goo.ne.jp/',
      'file://../../../../data/page_cycler/intl1/haberturk.com/',
      'file://../../../../data/page_cycler/intl1/hatena.ne.jp/',
      'file://../../../../data/page_cycler/intl1/home.altervista.org/',
      'file://../../../../data/page_cycler/intl1/hurriyet.com.tr/',
      'file://../../../../data/page_cycler/intl1/jugem.jp/',
      'file://../../../../data/page_cycler/intl1/kakaku.com/',
      'file://../../../../data/page_cycler/intl1/mixi.jp/',
      'file://../../../../data/page_cycler/intl1/naftemporiki.gr/',
      'file://../../../../data/page_cycler/intl1/narod.yandex.ru/',
      'file://../../../../data/page_cycler/intl1/news.163.com/',
      'file://../../../../data/page_cycler/intl1/partyflock.nl/',
      'file://../../../../data/page_cycler/intl1/pchome.com.tw/',
      'file://../../../../data/page_cycler/intl1/phoenixtv.com/',
      'file://../../../../data/page_cycler/intl1/photofile.ru/',
      'file://../../../../data/page_cycler/intl1/pl.wikipedia.org/',
      'file://../../../../data/page_cycler/intl1/ricardo.ch/',
      'file://../../../../data/page_cycler/intl1/ru.wikipedia.org/',
      'file://../../../../data/page_cycler/intl1/ruten.com.tw/',
      'file://../../../../data/page_cycler/intl1/sport24.gr/',
      'file://../../../../data/page_cycler/intl1/terra.es/',
      'file://../../../../data/page_cycler/intl1/udn.com/',
      'file://../../../../data/page_cycler/intl1/uwants.com/',
      'file://../../../../data/page_cycler/intl1/voila.fr/',
      'file://../../../../data/page_cycler/intl1/www.alice.it/',
      'file://../../../../data/page_cycler/intl1/www.amazon.co.jp/',
      'file://../../../../data/page_cycler/intl1/www.auction.co.kr/',
      'file://../../../../data/page_cycler/intl1/www.chinaren.com/',
      'file://../../../../data/page_cycler/intl1/www.chosun.com/',
      'file://../../../../data/page_cycler/intl1/www.danawa.com/',
      'file://../../../../data/page_cycler/intl1/www.daum.net/',
      'file://../../../../data/page_cycler/intl1/www.dcinside.com/',
      'file://../../../../data/page_cycler/intl1/www.eastmoney.com/',
      'file://../../../../data/page_cycler/intl1/zol.com.cn/'
    ]

    for url in urls_list:
      self.AddStory(Intl1Page(url, self))
