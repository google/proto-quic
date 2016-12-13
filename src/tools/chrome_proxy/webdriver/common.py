# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import argparse
import json
import os
import re
import socket
import shlex
import sys
import time
import traceback

sys.path.append(os.path.join(os.path.dirname(__file__), os.pardir, os.pardir,
  os.pardir, 'third_party', 'webdriver', 'pylib'))
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

# TODO(robertogden): Add logging.


def ParseFlags():
  """Parses the given command line arguments.

  Returns:
    A new Namespace object with class properties for each argument added below.
    See pydoc for argparse.
  """
  parser = argparse.ArgumentParser()
  parser.add_argument('--browser_args', nargs=1, type=str, help='Override '
    'browser flags in code with these flags')
  parser.add_argument('--via_header_value', metavar='via_header', nargs=1,
    default='1.1 Chrome-Compression-Proxy', help='What the via should match to '
    'be considered valid')
  parser.add_argument('--android', help='If given, attempts to run the test on '
    'Android via adb. Ignores usage of --chrome_exec', action='store_true')
  parser.add_argument('--android_package', nargs=1,
    default='com.android.chrome', help='Set the android package for Chrome')
  parser.add_argument('--chrome_exec', nargs=1, type=str, help='The path to '
    'the Chrome or Chromium executable')
  parser.add_argument('chrome_driver', nargs=1, type=str, help='The path to '
    'the ChromeDriver executable. If not given, the default system chrome '
    'will be used.')
  # TODO(robertogden): Log sys.argv here.
  return parser.parse_args(sys.argv[1:])

def HandleException(test_name=None):
  """Writes the exception being handled and a stack trace to stderr.

  Args:
    test_name: The string name of the test that led to this exception.
  """
  sys.stderr.write("**************************************\n")
  sys.stderr.write("**************************************\n")
  sys.stderr.write("**                                  **\n")
  sys.stderr.write("**       UNCAUGHT EXCEPTION         **\n")
  sys.stderr.write("**                                  **\n")
  sys.stderr.write("**************************************\n")
  sys.stderr.write("**************************************\n")
  if test_name:
    sys.stderr.write("Failed test: %s" % test_name)
  traceback.print_exception(*sys.exc_info())
  sys.exit(1)

class TestDriver:
  """The main driver for an integration test.

  This class is the tool that is used by every integration test to interact with
  the Chromium browser and validate proper functionality. This class sits on top
  of the Selenium Chrome Webdriver with added utility and helper functions for
  Chrome-Proxy. This class should be used with Python's 'with' operator.

  Attributes:
    _flags: A Namespace object from the call to ParseFlags()
    _driver: A reference to the driver object from the Chrome Driver library.
    _chrome_args: A set of string arguments to start Chrome with.
    _url: The string URL that Chrome will navigate to for this test.
  """

  def __init__(self):
    self._flags = ParseFlags()
    self._driver = None
    self._chrome_args = set()
    self._url = ''

  def __enter__(self):
    return self

  def __exit__(self, exc_type, exc_value, tb):
    if self._driver:
      self._StopDriver()

  def _OverrideChromeArgs(self):
    """Overrides any given arguments in the code with those given on the command
    line.

    Arguments that need to be overridden may contain different values for
    a flag given in the code. In that case, check by the flag whether to
    override the argument.
    """
    def GetDictKey(argument):
      return argument.split('=', 1)[0]
    if self._flags.browser_args and len(self._flags.browser_args) > 0:
      # Build a dict of flags mapped to the whole argument.
      original_args = {}
      for arg in self._chrome_args:
          original_args[GetDictKey(arg)] = arg
      # Override flags given in code with any command line arguments.
      for override_arg in shlex.split(self._flags.browser_args[0]):
        arg_key = GetDictKey(override_arg)
        if arg_key in original_args:
          self._chrome_args.remove(original_args[arg_key])
        self._chrome_args.add(override_arg)
    # Always add the flag that allows histograms to be queried in javascript.
    self._chrome_args.add('--enable-stats-collection-bindings')

  def _StartDriver(self):
    """Parses the flags to pass to Chromium, then starts the ChromeDriver.

    If running Android, the Android package name is passed to ChromeDriver here.
    """
    self._OverrideChromeArgs()
    capabilities = {
      'loggingPrefs': {'performance': 'INFO'},
      'chromeOptions': {
        'args': list(self._chrome_args)
      }
    }
    if self._flags.android:
      capabilities['chromeOptions'].update({
        'androidPackage': self._flags.android_package,
      })
    elif self._flags.chrome_exec:
      capabilities['chrome.binary'] = self._flags.chrome_exec
    driver = webdriver.Chrome(executable_path=self._flags.chrome_driver[0],
      desired_capabilities=capabilities)
    driver.command_executor._commands.update({
      'getAvailableLogTypes': ('GET', '/session/$sessionId/log/types'),
      'getLog': ('POST', '/session/$sessionId/log')})
    self._driver = driver

  def _StopDriver(self):
    """Nicely stops the ChromeDriver.
    """
    self._driver.quit()
    self._driver = None

  def AddChromeArgs(self, args):
    """Adds multiple arguments that will be passed to Chromium at start.

    Args:
      args: An iterable of strings, each an argument to pass to Chrome at start.
    """
    for arg in args:
      self._chrome_args.add(arg)

  def AddChromeArg(self, arg):
    """Adds a single argument that will be passed to Chromium at start.

    Args:
      arg: a string argument to pass to Chrome at start
    """
    self._chrome_args.add(arg)

  def RemoveChromeArgs(self, args):
    """Removes multiple arguments that will no longer be passed to Chromium at
    start.

    Args:
        args: An iterable of strings to no longer use the next time Chrome
          starts.
    """
    for arg in args:
      self._chrome_args.discard(arg)

  def RemoveChromeArg(self, arg):
    """Removes a single argument that will no longer be passed to Chromium at
    start.

    Args:
      arg: A string flag to no longer use the next time Chrome starts.
    """
    self._chrome_args.discard(arg)

  def ClearChromeArgs(self):
    """Removes all arguments from Chromium at start.
    """
    self._chrome_args.clear()

  def ClearCache(self):
    """Clears the browser cache.

    Important note: ChromeDriver automatically starts
    a clean copy of Chrome on every instantiation.
    """
    self.ExecuteJavascript('if(window.chrome && chrome.benchmarking && '
      'chrome.benchmarking.clearCache){chrome.benchmarking.clearCache(); '
      'chrome.benchmarking.clearPredictorCache();chrome.benchmarking.'
      'clearHostResolverCache();}')

  def SetURL(self, url):
    """Sets the URL that the browser will navigate to during the test.

    Args:
      url: The string URL to navigate to
    """
    self._url = url

  def LoadPage(self, timeout=30):
    """Starts Chromium with any arguments previously given and navigates to the
    given URL.

    Args:
      timeout: Page load timeout in seconds.
    """
    if not self._driver:
      self._StartDriver()
    self._driver.set_page_load_timeout(timeout)
    self._driver.get(self._url)

  def ExecuteJavascript(self, script, timeout=30):
    """Executes the given javascript in the browser's current page in an
    anonymous function.

    If you expect a result and don't get one, try adding a return statement or
    using ExecuteJavascriptStatement() below.

    Args:
      script: A string of Javascript code.
      timeout: Timeout for the Javascript code to return in seconds.
    Returns:
      A string of the verbatim output from the Javascript execution.
    """
    if not self._driver:
      self._StartDriver()
    # TODO(robertogden): Use 'driver.set_script_timeout(timeout)' instead after
    # crbug/672114 is fixed.
    default_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    script_result = self._driver.execute_script(script)
    socket.setdefaulttimeout(default_timeout)
    return script_result

  def ExecuteJavascriptStatement(self, script, timeout=30):
    """Wraps ExecuteJavascript() for use with a single statement.

    Behavior is analogous to 'function(){ return <script> }();'

    Args:
      script: A string of Javascript code.
      timeout: Timeout for the Javascript code to return in seconds.
    Returns:
      A string of the verbatim output from the Javascript execution.
    """
    return self.ExecuteJavascript("return " + script, timeout)

  def GetHistogram(self, histogram):
    js_query = 'statsCollectionController.getBrowserHistogram("%s")' % histogram
    string_response = self.ExecuteJavascriptStatement(js_query)
    return json.loads(string_response)

  def GetPerformanceLogs(self, method_filter=r'Network\.responseReceived'):
    """Returns all logged Performance events from Chrome.

    Args:
      method_filter: A regex expression to match the method of logged events
        against. Only logs who's method matches the regex will be returned.
    Returns:
      Performance logs as a list of dicts, since the last time this function was
      called.
    """
    all_messages = []
    for log in self._driver.execute('getLog', {'type': 'performance'})['value']:
      message = json.loads(log['message'])['message']
      if re.match(method_filter, message['method']):
        all_messages.append(message)
    return all_messages

  def GetHTTPResponses(self, include_favicon=False):
    """Parses the Performance Logs and returns a list of HTTPResponse objects.

    This function should be called exactly once after every page load.

    Args:
      include_favicon: A bool that if True will include responses for favicons.
    Returns:
      A list of HTTPResponse objects, each representing a single completed HTTP
      transaction by Chrome.
    """
    def MakeHTTPResponse(log_dict):
      params = log_dict['params']
      response_dict = params['response']
      http_response_dict = {
        'response_headers': response_dict['headers'],
        'request_headers': response_dict['requestHeaders'],
        'url': response_dict['url'],
        'status': response_dict['status'],
        'request_type': params['type']
      }
      return HTTPResponse(**http_response_dict)
    all_responses = []
    for message in self.GetPerformanceLogs():
      response = MakeHTTPResponse(message)
      is_favicon = response.url.endswith('favicon.ico')
      if not is_favicon or include_favicon:
        all_responses.append(response)
    return all_responses

class HTTPResponse:
  """This class represents a single HTTP transaction (request and response) by
  Chrome.

  This class also includes several convenience functions for ChromeProxy
  specific assertions.

  Attributes:
    _response_headers: A dict of response headers.
    _request_headers: A dict of request headers.
    _url: the fetched url
    _status: The integer status code of the response
    _request_type: What caused this request (Document, XHR, etc)
    _flags: A Namespace object from ParseFlags()
  """

  def __init__(self, response_headers, request_headers, url, status,
      request_type):
    self._response_headers = response_headers
    self._request_headers = request_headers
    self._url = url
    self._status = status
    self._request_type = request_type
    self._flags = ParseFlags()

  def __str__(self):
    self_dict = {
      'response_headers': self._response_headers,
      'request_headers': self._request_headers,
      'url': self._url,
      'status': self._status,
      'request_type': self._request_type
    }
    return json.dumps(self_dict)

  @property
  def response_headers(self):
    return self._response_headers

  @property
  def request_headers(self):
    return self._request_headers

  @property
  def url(self):
    return self._url

  @property
  def status(self):
    return self._status

  @property
  def request_type(self):
    return self._request_type

  def ResponseHasViaHeader(self):
    return 'via' in self._response_headers and (self._response_headers['via'] ==
      self._flags.via_header_value)

  def WasXHR(self):
    return self.request_type == 'XHR'
