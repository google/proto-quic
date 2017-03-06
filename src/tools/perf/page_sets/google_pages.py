# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from page_sets.login_helpers import google_login

from telemetry.page import page as page_module
from telemetry.page import shared_page_state
from telemetry.util import js_template

import os

def _DeterministicPerformanceCounters():
  with open(os.path.join(os.path.dirname(__file__),
          'deterministic_performance_counters.js')) as f:
    return f.read()

class GooglePages(page_module.Page):
  def __init__(self, url, page_set, shared_page_state_class,
               name='', credentials=None):
    super(GooglePages, self).__init__(
        url=url, page_set=page_set, name=name,
        credentials_path='data/credentials.json',
        shared_page_state_class=shared_page_state_class)
    self.credentials = credentials
    self.script_to_evaluate_on_commit = _DeterministicPerformanceCounters()


class GmailPage(GooglePages):
  def __init__(self, page_set,
               shared_page_state_class=shared_page_state.SharedPageState):
    super(GmailPage, self).__init__(
        url='https://mail.google.com/mail/',
        page_set=page_set,
        shared_page_state_class=shared_page_state_class)

  def RunNavigateSteps(self, action_runner):
    google_login.LoginGoogleAccount(action_runner, 'google',
                                    self.credentials_path)
    super(GmailPage, self).RunNavigateSteps(action_runner)
    action_runner.WaitForJavaScriptCondition(
        'window.gmonkey !== undefined &&'
        'document.getElementById("gb") !== null')

class GoogleDocPage(GooglePages):
  def __init__(self, page_set,
               shared_page_state_class=shared_page_state.SharedPageState):
    super(GoogleDocPage, self).__init__(
        # pylint: disable=line-too-long
        url='https://docs.google.com/document/d/1X-IKNjtEnx-WW5JIKRLsyhz5sbsat3mfTpAPUSX3_s4/view',
        page_set=page_set,
        shared_page_state_class=shared_page_state_class)

  def RunNavigateSteps(self, action_runner):
    google_login.LoginGoogleAccount(action_runner, 'google',
                                    self.credentials_path)
    super(GoogleDocPage, self).RunNavigateSteps(action_runner)
    action_runner.Wait(2)
    action_runner.WaitForJavaScriptCondition(
        'document.getElementsByClassName("kix-appview-editor").length')


INTERACTION_NAME = 'Interaction.AppLoad'
class AdwordCampaignDesktopPage(page_module.Page):
  def __init__(self, page_set):
    super(AdwordCampaignDesktopPage, self).__init__(
        url='https://adwords.google.com/cm/CampaignMgmt',
        page_set=page_set, name='AdwordsCampaign',
        credentials_path='data/credentials.json',
        shared_page_state_class=shared_page_state.SharedDesktopPageState)
    self.script_to_evaluate_on_commit = js_template.Render(
        'console.time({{ label }});', label=INTERACTION_NAME)

  def RunNavigateSteps(self, action_runner):
    google_login.LoginGoogleAccount(action_runner, 'google3',
                                    self.credentials_path)
    super(AdwordCampaignDesktopPage, self).RunNavigateSteps(action_runner)

  def RunPageInteractions(self, action_runner):
    action_runner.WaitForElement(text='Welcome to AdWords!')
    action_runner.ExecuteJavaScript(
        'console.timeEnd({{ label }});', label=INTERACTION_NAME)
