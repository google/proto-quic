# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
from telemetry.page import page as page_module
from telemetry.page import shared_page_state
from telemetry import story

from page_sets.login_helpers import chrome_login


class ChromeSigninPage(page_module.Page):
  """A page that signs in a user to Chrome."""

  def __init__(self, page_set):
    super(ChromeSigninPage, self).__init__(
        url='chrome://signin-internals',
        page_set=page_set,
        credentials_path='data/chrome_signin_credentials.json',
        credentials_bucket=story.INTERNAL_BUCKET,
        shared_page_state_class=shared_page_state.SharedDesktopPageState)

  def RunPageInteractions(self, action_runner):
    # Use page.credentials_path because it is automatically translated into a
    # full path relative to the page.
    chrome_login.LoginChromeAccount(action_runner, 'chrome',
        credentials_path=self.credentials_path)


class ChromeSigninPageSet(story.StorySet):

  def __init__(self):
    super(ChromeSigninPageSet, self).__init__(
        archive_data_file='data/chrome_signin_archive.json',
        cloud_storage_bucket=story.INTERNAL_BUCKET)
    self.AddStory(ChromeSigninPage(self))
