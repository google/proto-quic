# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
from telemetry.page import page as page_module
from telemetry import story


class StartupPagesRecordPage(page_module.Page):

  def __init__(self, url, page_set):
    super(StartupPagesRecordPage, self).__init__(url=url, page_set=page_set)
    self.archive_data_file = 'data/startup_pages.json'


class StartupPagesRecordPageSet(story.StorySet):

  """ Pages to record data for testing starting Chrome with a URL.
      We can't use startup_pages.json with record_wpr, since record_wpr
      requires a default navigate step, which we don't want for startup
      testing; but we do want to record the pages it uses. Also, record_wpr
      fails on about:blank, which we want to include in startup testing.
  """

  def __init__(self):
    super(StartupPagesRecordPageSet, self).__init__(
        archive_data_file='data/startup_pages.json')

    urls_list = [
        # Why: typical page
        'http://bbc.co.uk',
        # TODO(charliea): Reenable this when kabook.com is no longer crashing.
        # crbug.com/667470
        # Why: Horribly complex page - stress test!
        # 'http://kapook.com',
    ]

    for url in urls_list:
      self.AddStory(StartupPagesRecordPage(url, self))
