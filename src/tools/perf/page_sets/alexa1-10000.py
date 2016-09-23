# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import json
import os

from telemetry.page import page as page_module
from telemetry.page import shared_page_state
from telemetry import story


__location__ = os.path.realpath(
      os.path.join(os.getcwd(), os.path.dirname(__file__)))

# Generated on 2013-09-03 13:59:53.459117 by rmistry using
# create_page_set.py.
_TOP_10000_ALEXA_FILE = os.path.join(__location__, 'alexa1-10000-urls.json')


class Alexa1To10000Page(page_module.Page):

  def __init__(self, url, page_set):
    super(Alexa1To10000Page, self).__init__(
        url=url, page_set=page_set,
        shared_page_state_class=shared_page_state.SharedDesktopPageState)

  def RunPageInteractions(self, action_runner):
    with action_runner.CreateGestureInteraction('ScrollAction'):
      action_runner.ScrollPage()


class Alexa1To10000PageSet(story.StorySet):
  """ Top 1-10000 Alexa global.
      Generated on 2013-09-03 13:59:53.459117 by rmistry using
      create_page_set.py.
  """

  def __init__(self):
    super(Alexa1To10000PageSet, self).__init__()

    with open(_TOP_10000_ALEXA_FILE) as f:
      urls_list = json.load(f)
    for url in urls_list:
      self.AddStory(Alexa1To10000Page(url, self))
