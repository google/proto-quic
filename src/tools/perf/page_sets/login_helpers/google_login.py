# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
from page_sets.login_helpers import login_utils

# Selectors for the email, password, and next buttons for google login flow.
# Use multiple selectors to allow for different versions of the site.
_EMAIL_SELECTOR = ','.join([
    'input[type=email]:not([aria-hidden=true])',
    '#Email:not(.hidden)'])
_EMAIL_NEXT_SELECTOR = ','.join([
    '#identifierNext',
    '#gaia_firstform #next'])
_PASSWORD_SELECTOR = ','.join([
    'input[type=password]:not([aria-hidden=true])',
    '#Passwd:not(.hidden)'])
_SIGNIN_SELECTOR = ','.join([
    '#passwordNext',
    '#signIn'])


# JavaScript conditions which are true when the email and password inputs on
# the Google Login page are visible respectively.
_EMAIL_INPUT_VISIBLE_CONDITION = (
    'document.querySelector("%s") !== null' % (_EMAIL_SELECTOR))
_PASSWORD_INPUT_VISIBLE_CONDITION = (
    'document.querySelector("%s") !== null' % (_PASSWORD_SELECTOR))


def LoginGoogleAccount(action_runner,
                       credential='googletest',  # Recommended credential.
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
  action_runner.WaitForJavaScriptCondition('{{ @a }} || {{ @b }}',
      a=_EMAIL_INPUT_VISIBLE_CONDITION, b=_PASSWORD_INPUT_VISIBLE_CONDITION)

  # If the email input is visible, this is the first Google login within the
  # browser session, so we must enter both email and password. Otherwise, only
  # password is required.
  if action_runner.EvaluateJavaScript(_EMAIL_INPUT_VISIBLE_CONDITION):
    login_utils.InputWithSelector(action_runner, account_name, _EMAIL_SELECTOR)
    action_runner.ClickElement(selector=_EMAIL_NEXT_SELECTOR)

  login_utils.InputWithSelector(action_runner, password, _PASSWORD_SELECTOR)
  action_runner.ClickElement(selector=_SIGNIN_SELECTOR)
  action_runner.WaitForElement(text='My Account')
