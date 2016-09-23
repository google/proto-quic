# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
from telemetry.page import page as page_module
from telemetry.page import shared_page_state
from telemetry import story


class ToughImageCasesPage(page_module.Page):

  def __init__(self, url, page_set):
    super(ToughImageCasesPage, self).__init__(
        url=url, page_set=page_set,
        shared_page_state_class=shared_page_state.SharedDesktopPageState)


class ToughImageCasesPageSet(story.StorySet):

  """ A collection of image-heavy sites. """

  def __init__(self):
    super(ToughImageCasesPageSet, self).__init__()

    urls_list = [
      'http://www.free-pictures-photos.com/aviation/airplane-306.jpg',
      ('http://upload.wikimedia.org/wikipedia/commons/c/cb/'
       'General_history%2C_Alaska_Yukon_Pacific_Exposition%'
       '2C_fully_illustrated_-_meet_me_in_Seattle_1909_-_Page_78.jpg')
    ]

    for url in urls_list:
      self.AddStory(ToughImageCasesPage(url, self))
