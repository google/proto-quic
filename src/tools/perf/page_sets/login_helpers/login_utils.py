# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import json
import os


DEFAULT_CREDENTIAL_PATH = os.path.join(
    os.path.dirname(__file__), os.path.pardir, 'data', 'credentials.json')


def GetAccountNameAndPassword(credential,
                              credentials_path=DEFAULT_CREDENTIAL_PATH):
  """Returns username and password for |credential| in credentials_path file.

  Args:
    credential: The credential to retrieve from the file (type string).
    credentials_path: The string that specifies the path to credential file.

  Returns:
    A tuple (username, password) in which both are username and password
    strings.
  """
  with open(credentials_path, 'r') as f:
    credentials = json.load(f)
  c = credentials.get(credential)
  return c['username'], c['password']

def InputWithSelector(action_runner, input_text, input_selector):
  """Sets the text value of an input field in a form on the page.

  Waits until the input element exists on the page. Then executes JS to populate
  the value property of the element with |input_text|.

  Args:
    action_runner: ActionRunner instance to execute JS to populate form fields.
    input_text: Text string to populate the input field with.
    input_selector: The selector of the input element.


  Raises:
    exceptions.TimeoutException: If waiting to find the element times out.
    exceptions.Error: See ExecuteJavaScript() for a detailed list of
      possible exceptions.
  """
  action_runner.WaitForElement(selector=input_selector)
  action_runner.ExecuteJavaScript(
      'document.querySelector("%s").value = "%s";' %
      (input_selector, input_text))

def InputForm(action_runner, input_text, input_id, form_id=None):
  """Sets the text value of an input field in a form on the page.

  Waits until the input element exists on the page. Then executes JS to populate
  the value property of the element with |input_text|.

  Args:
    action_runner: ActionRunner instance to execute JS to populate form fields.
    input_text: Text string to populate the input field with.
    input_id: Id of the input field to populate. (type string).
    form_id: Optional form id string to identify |input_id| in querySelector.

  Raises:
    exceptions.TimeoutException: If waiting to find the element times out.
    exceptions.Error: See ExecuteJavaScript() for a detailed list of
      possible exceptions.
  """
  if form_id and input_id:
    element_selector = '#%s #%s' % (form_id, input_id)
  elif input_id:
    element_selector = '#%s' % (input_id)
  else:
    raise ValueError("Input ID can not be None or empty.")
  InputWithSelector(action_runner, input_text, element_selector)

