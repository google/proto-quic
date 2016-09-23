# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
from telemetry.page import page as page_module
from telemetry import story


class AlexaUsPage(page_module.Page):

  def __init__(self, url, page_set):
    super(AlexaUsPage, self).__init__(url=url, page_set=page_set)


class AlexaUsPageSet(story.StorySet):

  """ Alexa US page_cycler benchmark  """

  def __init__(self):
    super(AlexaUsPageSet, self).__init__(
      # pylint: disable=line-too-long
      serving_dirs=set(['../../../../data/page_cycler/alexa_us']))

    urls_list = [
      # pylint: disable=line-too-long
      'file://../../../../data/page_cycler/alexa_us/accountservices.passport.net/',
      'file://../../../../data/page_cycler/alexa_us/sfbay.craigslist.org/',
      'file://../../../../data/page_cycler/alexa_us/www.amazon.com/',
      'file://../../../../data/page_cycler/alexa_us/www.aol.com/',
      'file://../../../../data/page_cycler/alexa_us/www.bbc.co.uk/',
      'file://../../../../data/page_cycler/alexa_us/www.blogger.com/',
      'file://../../../../data/page_cycler/alexa_us/www.cnn.com/',
      'file://../../../../data/page_cycler/alexa_us/www.ebay.com/',
      'file://../../../../data/page_cycler/alexa_us/www.flickr.com/',
      'file://../../../../data/page_cycler/alexa_us/www.friendster.com/',
      'file://../../../../data/page_cycler/alexa_us/www.go.com/',
      'file://../../../../data/page_cycler/alexa_us/www.google.com/',
      'file://../../../../data/page_cycler/alexa_us/www.imdb.com/',
      'file://../../../../data/page_cycler/alexa_us/www.megaupload.com/',
      'file://../../../../data/page_cycler/alexa_us/www.msn.com/',
      'file://../../../../data/page_cycler/alexa_us/www.myspace.com/',
      'file://../../../../data/page_cycler/alexa_us/www.orkut.com/',
      'file://../../../../data/page_cycler/alexa_us/www.wikipedia.org/',
      'file://../../../../data/page_cycler/alexa_us/www.xanga.com/',
      'file://../../../../data/page_cycler/alexa_us/www.youtube.com/'
    ]

    for url in urls_list:
      self.AddStory(AlexaUsPage(url, self))
