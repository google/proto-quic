# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from page_sets.login_helpers import facebook_login

from telemetry.page import page as page_module


class MobileFacebookPage(page_module.Page):
  def __init__(self, url, page_set, shared_page_state_class, name='facebook'):
    super(MobileFacebookPage, self).__init__(
        url=url, page_set=page_set, name=name,
        credentials_path='data/credentials.json',
        shared_page_state_class=shared_page_state_class)
  def RunNavigateSteps(self, action_runner):
    facebook_login.LoginWithMobileSite(action_runner, 'facebook3',
                                       self.credentials_path)
    super(MobileFacebookPage, self).RunNavigateSteps(action_runner)
