# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
from page_sets.login_helpers import login_utils


# JavaScript conditions which are true when the email and password inputs on
# the Google Login page are visible respectively.
_EMAIL_INPUT_VISIBLE_CONDITION = (
    'document.querySelector("#Email:not(.hidden)") !== null')
_PASSWORD_INPUT_VISIBLE_CONDITION = (
    'document.querySelector("#Passwd:not(.hidden)") !== null')


def LoginGoogleAccount(action_runner, credential,
                       credentials_path=login_utils.DEFAULT_CREDENTIAL_PATH):
  """Logs in into Google account.

  This function navigates the tab into Google's login page and logs in a user
  using credentials in |credential| part of the |credentials_path| file.

  Args:
    action_runner: Action runner responsible for running actions on the page.
    credential: The credential to retrieve from the credentials file
        (type string).
    credentials_path: The string that specifies the path to credential file.

  NOTE: it's recommended to use 'googletest' credential from
  page_sets/data/credentials.json credential since it is a Google test account
  and will not trigger anti-bot verification. Other google credentials are kept
  until all telemetry pages are updated to use the 'googletest' credential.

  Raises:
    exceptions.Error: See ExecuteJavaScript()
    for a detailed list of possible exceptions.
  """
  account_name, password = login_utils.GetAccountNameAndPassword(
      credential, credentials_path=credentials_path)

  action_runner.Navigate(
       'https://accounts.google.com/ServiceLogin?continue='
       'https%3A%2F%2Faccounts.google.com%2FManageAccount')

  # Wait until either the email or password input is visible.
  action_runner.WaitForJavaScriptCondition('%s || %s' % (
      _EMAIL_INPUT_VISIBLE_CONDITION, _PASSWORD_INPUT_VISIBLE_CONDITION))

  # If the email input is visible, this is the first Google login within the
  # browser session, so we must enter both email and password. Otherwise, only
  # password is required.
  if action_runner.EvaluateJavaScript(_EMAIL_INPUT_VISIBLE_CONDITION):
    login_utils.InputForm(action_runner, account_name, input_id='Email',
                          form_id='gaia_firstform')
    action_runner.ClickElement(selector='#gaia_firstform #next')

  login_utils.InputForm(action_runner, password, input_id='Passwd')
  action_runner.ClickElement(selector='#signIn')
  action_runner.WaitForElement(text='My Account')
