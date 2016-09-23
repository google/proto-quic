# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
from telemetry.page import page as page_module
from telemetry import story

class Intl2Page(page_module.Page):

  def __init__(self, url, page_set):
    super(Intl2Page, self).__init__(url=url, page_set=page_set)
    # pylint: disable=line-too-long


class Intl2PageSet(story.StorySet):

  """
  Description: Intl2 page_cycler benchmark
  """

  def __init__(self):
    super(Intl2PageSet, self).__init__(
      # pylint: disable=line-too-long
      serving_dirs=set(['../../../../data/page_cycler/intl2']))

    urls_list = [
      'file://../../../../data/page_cycler/intl2/arabicnews.google.com/',
      'file://../../../../data/page_cycler/intl2/bn.wikipedia.org/',
      'file://../../../../data/page_cycler/intl2/exteen.com/',
      'file://../../../../data/page_cycler/intl2/farsnews.com/',
      'file://../../../../data/page_cycler/intl2/hindi.webdunia.com/',
      'file://../../../../data/page_cycler/intl2/in.telugu.yahoo.com/',
      'file://../../../../data/page_cycler/intl2/isna.ir/',
      'file://../../../../data/page_cycler/intl2/kapook.com/',
      'file://../../../../data/page_cycler/intl2/kooora.com/',
      'file://../../../../data/page_cycler/intl2/manager.co.th/',
      'file://../../../../data/page_cycler/intl2/masrawy.com/',
      'file://../../../../data/page_cycler/intl2/ml.wikipedia.org/',
      'file://../../../../data/page_cycler/intl2/msn.co.il/',
      'file://../../../../data/page_cycler/intl2/news.bbc.co.uk/',
      'file://../../../../data/page_cycler/intl2/news.google.com/',
      'file://../../../../data/page_cycler/intl2/sh3bwah.com/',
      'file://../../../../data/page_cycler/intl2/sgkalesh.blogspot.com/',
      'file://../../../../data/page_cycler/intl2/tapuz.co.il/',
      'file://../../../../data/page_cycler/intl2/thaimisc.com/',
      'file://../../../../data/page_cycler/intl2/vietnamnet.vn/',
      'file://../../../../data/page_cycler/intl2/vnexpress.net/',
      'file://../../../../data/page_cycler/intl2/walla.co.il/',
      'file://../../../../data/page_cycler/intl2/www.aljayyash.net/',
      'file://../../../../data/page_cycler/intl2/www.bbc.co.uk/',
      'file://../../../../data/page_cycler/intl2/www.google.com.sa/',
      'file://../../../../data/page_cycler/intl2/www.islamweb.net/',
      'file://../../../../data/page_cycler/intl2/www.mthai.com/',
      'file://../../../../data/page_cycler/intl2/www.startimes2.com/',
      'file://../../../../data/page_cycler/intl2/www.jagran.com/',
      'file://../../../../data/page_cycler/intl2/ynet.co.il/'
    ]

    for url in urls_list:
      self.AddStory(Intl2Page(url, self))
