# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import argparse
import json
import logging
import os
import re
import socket
import shlex
import sys
import time
import traceback
import unittest
import urlparse

sys.path.append(os.path.join(os.path.dirname(__file__), os.pardir, os.pardir,
  os.pardir, 'third_party', 'webdriver', 'pylib'))
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

def ParseFlags():
  """Parses the given command line arguments.

  Returns:
    A new Namespace object with class properties for each argument added below.
    See pydoc for argparse.
  """
  def TestFilter(v):
    try:
      # The filtering here allows for any number of * wildcards with a required
      # . separator between classname and methodname, but no other special
      # characters.
      return re.match(r'^([A-Za-z_0-9\*]+\.)?[A-Za-z_0-9\*]+$', v).group(0)
    except:
      raise argparse.ArgumentTypeError('Test filter "%s" is not a valid filter'
        % v)
  parser = argparse.ArgumentParser()
  parser.add_argument('--browser_args', type=str, help='Override browser flags '
    'in code with these flags')
  parser.add_argument('--via_header_value',
    default='1.1 Chrome-Compression-Proxy', help='What the via should match to '
    'be considered valid')
  parser.add_argument('--android', help='If given, attempts to run the test on '
    'Android via adb. Ignores usage of --chrome_exec', action='store_true')
  parser.add_argument('--android_package',
    default='com.android.chrome', help='Set the android package for Chrome')
  parser.add_argument('--chrome_exec', type=str, help='The path to '
    'the Chrome or Chromium executable')
  parser.add_argument('chrome_driver', type=str, help='The path to '
    'the ChromeDriver executable. If not given, the default system chrome '
    'will be used.')
  parser.add_argument('--disable_buffer', help='Causes stdout and stderr from '
    'tests to output normally. Otherwise, the standard output and standard '
    'error streams are buffered during the test run, and output from a '
    'passing test is discarded. Output will always be echoed normally on test '
    'fail or error and is added to the failure messages.', action='store_true')
  parser.add_argument('-c', '--catch', help='Control-C during the test run '
    'waits for the current test to end and then reports all the results so '
    'far. A second Control-C raises the normal KeyboardInterrupt exception.',
    action='store_true')
  parser.add_argument('-f', '--failfast', help='Stop the test run on the first '
    'error or failure.', action='store_true')
  parser.add_argument('--test_filter', '--gtest_filter', type=TestFilter,
    help='The filter to use when discovering tests to run, in the form '
    '<class name>.<method name> Wildcards (*) are accepted. Default=*',
    default='*')
  parser.add_argument('--logging_level', choices=['DEBUG', 'INFO', 'WARN',
    'ERROR', 'CRIT'], default='WARN', help='The logging verbosity for log '
    'messages, printed to stderr. To see stderr logging output during a '
    'successful test run, also pass --disable_buffer. Default=ERROR')
  parser.add_argument('--log_file', help='If given, write logging statements '
    'to the given file instead of stderr.')
  return parser.parse_args(sys.argv[1:])

def GetLogger(name='common'):
  """Creates a Logger instance with the given name and returns it.

  If a logger has already been created with the same name, that instance is
  returned instead.

  Args:
    name: The name of the logger to return.
  Returns:
    A logger with the given name.
  """
  logger = logging.getLogger(name)
  if hasattr(logger, "initialized"):
    return logger
  logging_level = ParseFlags().logging_level
  if logging_level == 'DEBUG':
    logger.setLevel(logging.DEBUG)
  elif logging_level == 'INFO':
    logger.setLevel(logging.INFO)
  elif logging_level == 'WARN':
    logger.setLevel(logging.WARNING)
  elif logging_level == 'ERROR':
    logger.setLevel(logging.ERROR)
  elif logging_level == 'CRIT':
    logger.setLevel(logging.CRITICAL)
  else:
    logger.setLevel(logging.NOTSET)
  formatter = logging.Formatter('%(asctime)s %(funcName)s() %(levelname)s: '
    '%(message)s')
  if ParseFlags().log_file:
    fh = logging.FileHandler(ParseFlags().log_file)
    fh.setFormatter(formatter)
    logger.addHandler(fh)
  else:
    ch = logging.StreamHandler(sys.stderr)
    ch.setFormatter(formatter)
    logger.addHandler(ch)
  logger.initialized = True
  return logger

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
    _has_logs: Boolean flag set when a page is loaded and cleared when logs are
      fetched.
  """

  def __init__(self):
    self._flags = ParseFlags()
    self._driver = None
    self._chrome_args = set()
    self._url = ''
    self._logger = GetLogger(name='TestDriver')
    self._has_logs = False

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
      for override_arg in shlex.split(self._flags.browser_args):
        arg_key = GetDictKey(override_arg)
        if arg_key in original_args:
          self._chrome_args.remove(original_args[arg_key])
          self._logger.info('Removed Chrome flag. %s', original_args[arg_key])
        self._chrome_args.add(override_arg)
        self._logger.info('Added Chrome flag. %s', override_arg)
    # Always add the flag that allows histograms to be queried in javascript.
    self._chrome_args.add('--enable-stats-collection-bindings')

  def _StartDriver(self):
    """Parses the flags to pass to Chromium, then starts the ChromeDriver.

    If running Android, the Android package name is passed to ChromeDriver here.
    """
    self._OverrideChromeArgs()
    capabilities = {
      'loggingPrefs': {'performance': 'INFO'}
    }
    chrome_options = Options()
    for arg in self._chrome_args:
      chrome_options.add_argument(arg)
    self._logger.info('Starting Chrome with these flags: %s',
      str(self._chrome_args))
    if self._flags.android:
      chrome_options.add_experimental_option('androidPackage',
        self._flags.android_package)
      self._logger.debug('Will use Chrome on Android')
    elif self._flags.chrome_exec:
      chrome_options.binary_location = self._flags.chrome_exec
      self._logger.info('Using the Chrome binary at this path: %s',
        self._flags.chrome_exec)
    self._logger.debug('ChromeOptions will be parsed into these capabilities: '
      '%s', json.dumps(chrome_options.to_capabilities()))
    driver = webdriver.Chrome(executable_path=self._flags.chrome_driver,
      desired_capabilities=capabilities, chrome_options=chrome_options)
    driver.command_executor._commands.update({
      'getAvailableLogTypes': ('GET', '/session/$sessionId/log/types'),
      'getLog': ('POST', '/session/$sessionId/log')})
    self._driver = driver

  def _StopDriver(self):
    """Nicely stops the ChromeDriver.
    """
    self._logger.debug('Stopping ChromeDriver')
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
    self._logger.debug('Adding Chrome arg: %s', arg)

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
    self._logger.debug('Removing Chrome arg: %s', arg)

  def ClearChromeArgs(self):
    """Removes all arguments from Chromium at start.
    """
    self._chrome_args.clear()
    self._logger.debug('Clearing all Chrome args')

  def ClearCache(self):
    """Clears the browser cache.

    Important note: ChromeDriver automatically starts
    a clean copy of Chrome on every instantiation.
    """
    res = self.ExecuteJavascript('if(window.chrome && chrome.benchmarking && '
      'chrome.benchmarking.clearCache){chrome.benchmarking.clearCache(); '
      'chrome.benchmarking.clearPredictorCache();chrome.benchmarking.'
      'clearHostResolverCache();}')
    self._logger.info('Cleared browser cache. Returned=%s', str(res))

  def LoadURL(self, url, timeout=30):
    """Starts Chromium with any arguments previously given and navigates to the
    given URL.

    Args:
      url: The URL to navigate to.
      timeout: The time in seconds to load the page before timing out.
    """
    self._url = url
    if (len(urlparse.urlparse(url).netloc) == 0 and
        len(urlparse.urlparse(url).scheme) == 0):
      self._logger.warn('Invalid URL: "%s". Did you forget to prepend '
        '"http://"? See RFC 1808 for more information', url)
    if not self._driver:
      self._StartDriver()
    self._driver.set_page_load_timeout(timeout)
    self._logger.debug('Set page load timeout to %f seconds', timeout)
    self._driver.get(self._url)
    self._logger.debug('Loaded page %s', url)
    self._has_logs = True

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
    self._logger.debug('Set socket timeout to %f seconds', timeout)
    script_result = self._driver.execute_script(script)
    self._logger.debug('Executed Javascript in browser: %s', script)
    socket.setdefaulttimeout(default_timeout)
    self._logger.debug('Set socket timeout to %s', str(default_timeout))
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

  def GetHistogram(self, histogram, timeout=30):
    """Gets a Chrome histogram as a dictionary object.

    Args:
      histogram: the name of the histogram to fetch
      timeout: timeout for the underlying Javascript query.

    Returns:
      A dictionary object containing information about the histogram.
    """
    js_query = 'statsCollectionController.getBrowserHistogram("%s")' % histogram
    string_response = self.ExecuteJavascriptStatement(js_query, timeout)
    self._logger.debug('Got %s histogram=%s', histogram, string_response)
    return json.loads(string_response)

  def WaitForJavascriptExpression(self, expression, timeout, min_poll=0.1,
      max_poll=1):
    """Waits for the given Javascript expression to evaluate to True within the
    given timeout. This method polls the Javascript expression within the range
    of |min_poll| and |max_poll|.

    Args:
      expression: The Javascript expression to poll, as a string.
      min_poll: The most frequently to poll as a float.
      max_poll: The least frequently to poll as a float.
    Returns: The result of the expression.
    """
    poll_interval = max(min(max_poll, float(timeout) / 10.0), min_poll)
    self._logger.debug('Poll interval=%f seconds', poll_interval)
    result = self.ExecuteJavascriptStatement(expression)
    total_waited_time = 0
    while not result and total_waited_time < timeout:
      time.sleep(poll_interval)
      total_waited_time += poll_interval
      result = self.ExecuteJavascriptStatement(expression)
    if not result:
      self._logger.error('%s not true after %f seconds' % (expression, timeout))
      raise Exception('%s not true after %f seconds' % (expression, timeout))
    return result

  def GetPerformanceLogs(self, method_filter=r'Network\.responseReceived'):
    """Returns all logged Performance events from Chrome. Raises an Exception if
    no pages have been loaded since the last time this function was called.

    Args:
      method_filter: A regex expression to match the method of logged events
        against. Only logs who's method matches the regex will be returned.
    Returns:
      Performance logs as a list of dicts, since the last time this function was
      called.
    """
    if not self._has_logs:
      raise Exception('No pages loaded since last Network log query!')
    all_messages = []
    for log in self._driver.execute('getLog', {'type': 'performance'})['value']:
      message = json.loads(log['message'])['message']
      self._logger.debug('Got Performance log: %s', log['message'])
      if re.match(method_filter, message['method']):
        all_messages.append(message)
    self._logger.info('Got %d performance logs with filter method=%s',
      len(all_messages), method_filter)
    self._has_logs = False
    return all_messages

  def SleepUntilHistogramHasEntry(self, histogram_name, sleep_intervals=10):
    """Polls if a histogram exists in 1-6 second intervals for 10 intervals.
    Allows script to run with a timeout of 5 seconds, so the default behavior
    allows up to 60 seconds until timeout.

    Args:
      histogram_name: The name of the histogram to wait for
      sleep_intervals: The number of polling intervals, each polling cycle takes
      no more than 6 seconds.
    Returns:
      Whether the histogram exists
    """
    histogram = {}
    while(not histogram and sleep_intervals > 0):
      histogram = self.GetHistogram(histogram_name, 5)
      if (not histogram):
        time.sleep(1)
        sleep_intervals -= 1

    return bool(histogram)

  def GetHTTPResponses(self, include_favicon=False, skip_domainless_pages=True):
    """Parses the Performance Logs and returns a list of HTTPResponse objects.

    Use caution when calling this function  multiple times. Only responses
    since the last time this function was called are returned (or since Chrome
    started, whichever is later). An Exception will be raised if no page was
    loaded since the last time this function was called.

    Args:
      include_favicon: A bool that if True will include responses for favicons.
      skip_domainless_pages: If True, only responses with a net_loc as in RFC
        1808 will be included. Pages such as about:blank will be skipped.
    Returns:
      A list of HTTPResponse objects, each representing a single completed HTTP
      transaction by Chrome.
    """
    def MakeHTTPResponse(log_dict):
      params = log_dict['params']
      response_dict = params['response']
      http_response_dict = {
        'response_headers': response_dict['headers'] if 'headers' in
          response_dict else {},
        'request_headers': response_dict['requestHeaders'] if 'requestHeaders'
          in response_dict else {},
        'url': response_dict['url'] if 'url' in response_dict else '',
        'protocol': response_dict['protocol'] if 'protocol' in response_dict
          else '',
        'port': response_dict['remotePort'] if 'remotePort' in response_dict
          else -1,
        'status': response_dict['status'] if 'status' in response_dict else -1,
        'request_type': params['type'] if 'type' in params else ''
      }
      return HTTPResponse(**http_response_dict)
    all_responses = []
    for message in self.GetPerformanceLogs():
      response = MakeHTTPResponse(message)
      self._logger.debug('New HTTPResponse: %s', str(response))
      is_favicon = response.url.endswith('favicon.ico')
      has_domain = len(urlparse.urlparse(response.url).netloc) > 0
      if (not is_favicon or include_favicon) and (not skip_domainless_pages or
          has_domain):
        all_responses.append(response)
      else:
        self._logger.info("Skipping HTTPResponse with url=%s in returned logs.",
          response.url)
    self._logger.info('%d new HTTPResponse objects found in the logs %s '
      'favicons', len(all_responses), ('including' if include_favicon else
      'not including'))
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
    _protocol: The protocol used to get the response.
    _port: The remote port number used to get the response.
    _status: The integer status code of the response
    _request_type: What caused this request (Document, XHR, etc)
    _flags: A Namespace object from ParseFlags()
  """

  def __init__(self, response_headers, request_headers, url, protocol, port,
      status, request_type):
    self._response_headers = {}
    self._request_headers = {}
    self._url = url
    self._protocol = protocol
    self._port = port
    self._status = status
    self._request_type = request_type
    self._flags = ParseFlags()
    # Make all header names lower case.
    for name in response_headers:
      self._response_headers[name.lower()] = response_headers[name]
    for name in request_headers:
      self._request_headers[name.lower()] = request_headers[name]

  def __str__(self):
    self_dict = {
      'response_headers': self._response_headers,
      'request_headers': self._request_headers,
      'url': self._url,
      'protocol': self._protocol,
      'port': self._port,
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
  def protocol(self):
    return self._protocol

  @property
  def port(self):
    return self._port

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

  def UsedHTTP(self):
    return self._protocol == 'http/1.1'

  def UsedHTTP2(self):
    return self._protocol == 'h2'

class IntegrationTest(unittest.TestCase):
  """This class adds ChromeProxy-specific assertions to the generic
  unittest.TestCase class.
  """

  def assertHasChromeProxyViaHeader(self, http_response):
    """Asserts that the Via header in the given HTTPResponse matches the
    expected value as given on the command line.

    Args:
      http_response: The HTTPResponse object to check.
    """
    expected_via_header = ParseFlags().via_header_value
    self.assertIn('via', http_response.response_headers)
    self.assertEqual(expected_via_header, http_response.response_headers['via'])

  def assertNotHasChromeProxyViaHeader(self, http_response):
    """Asserts that the Via header in the given HTTPResponse does not match the
    expected value as given on the command line.

    Args:
      http_response: The HTTPResponse object to check.
    """
    expected_via_header = ParseFlags().via_header_value
    self.assertNotIn('via', http_response.response_headers)
    if 'via' in http_response.response_headers:
      self.assertNotIn(expected_via_header,
        http_response.response_headers['via'])

  def checkLoFiResponse(self, http_response, expected_lo_fi):
    """Asserts that if expected the response headers contain the Lo-Fi directive
    then the request headers do too. Also checks that the content size is less
    than 100 if |expected_lo_fi|. Otherwise, checks that the response and
    request headers don't contain the Lo-Fi directive and the content size is
    greater than 100.

    Args:
      http_response: The HTTPResponse object to check.
      expected_lo_fi: Whether the response should be Lo-Fi.

    Returns:
      Whether the response was Lo-Fi.
    """

    if (expected_lo_fi) :
      self.assertHasChromeProxyViaHeader(http_response)
      content_length = http_response.response_headers['content-length']
      cpat_request = http_response.request_headers[
                       'chrome-proxy-accept-transform']
      cpct_response = http_response.response_headers[
                        'chrome-proxy-content-transform']
      if ('empty-image' in cpct_response):
        self.assertIn('empty-image', cpat_request)
        self.assertTrue(int(content_length) < 100)
        return True;
      return False;
    else:
      self.assertNotIn('chrome-proxy-accept-transform',
        http_response.request_headers)
      self.assertNotIn('chrome-proxy-content-transform',
        http_response.response_headers)
      content_length = http_response.response_headers['content-length']
      self.assertTrue(int(content_length) > 100)
      return False;

  def checkLitePageResponse(self, http_response):
    """Asserts that if the response headers contain the Lite Page directive then
    the request headers do too.

    Args:
      http_response: The HTTPResponse object to check.

    Returns:
      Whether the response was a Lite Page.
    """

    self.assertHasChromeProxyViaHeader(http_response)
    if ('chrome-proxy-content-transform' not in http_response.response_headers):
      return False;
    cpct_response = http_response.response_headers[
                      'chrome-proxy-content-transform']
    cpat_request = http_response.request_headers[
                      'chrome-proxy-accept-transform']
    if ('lite-page' in cpct_response):
      self.assertIn('lite-page', cpat_request)
      return True;
    return False;

  @staticmethod
  def RunAllTests(run_all_tests=False):
    """A simple helper method to run all tests using unittest.main().

    Args:
      run_all_tests: If True, all tests in the directory will be run, Otherwise
        only the tests in the file given on the command line will be run.
    """
    flags = ParseFlags()
    logger = GetLogger()
    logger.debug('Command line args: %s', str(sys.argv))
    logger.info('sys.argv parsed to %s', str(flags))
    if flags.catch:
      unittest.installHandler()
    # Use python's test discovery to locate tests files that have subclasses of
    # unittest.TestCase and methods beginning with 'test'.
    pattern = '*.py' if run_all_tests else os.path.basename(sys.argv[0])
    loader = unittest.TestLoader()
    test_suite_iter = loader.discover(os.path.dirname(__file__),
      pattern=pattern)
    # Match class and method name on the given test filter from --test_filter.
    tests = unittest.TestSuite()
    test_filter_re = flags.test_filter.replace('.', r'\.').replace('*', '.*')
    for test_suite in test_suite_iter:
      for test_case in test_suite:
        for test in test_case:
          # Drop the file name in the form <filename>.<classname>.<methodname>
          test_id = test.id()[test.id().find('.') + 1:]
          if re.match(test_filter_re, test_id):
            tests.addTest(test)
    testRunner = unittest.runner.TextTestRunner(verbosity=2,
      failfast=flags.failfast, buffer=(not flags.disable_buffer))
    testRunner.run(tests)

# Platform-specific decorators.
# These decorators can be used to only run a test function for certain platforms
# by annotating the function with them.

def AndroidOnly(func):
  def wrapper(*args, **kwargs):
    if ParseFlags().android:
      func(*args, **kwargs)
    else:
      args[0].skipTest('This test runs on Android only.')
  return wrapper

def NotAndroid(func):
  def wrapper(*args, **kwargs):
    if not ParseFlags().android:
      func(*args, **kwargs)
    else:
      args[0].skipTest('This test does not run on Android.')
  return wrapper

def WindowsOnly(func):
  def wrapper(*args, **kwargs):
    if sys.platform == 'win32':
      func(*args, **kwargs)
    else:
      args[0].skipTest('This test runs on Windows only.')
  return wrapper

def NotWindows(func):
  def wrapper(*args, **kwargs):
    if sys.platform != 'win32':
      func(*args, **kwargs)
    else:
      args[0].skipTest('This test does not run on Windows.')
  return wrapper

def LinuxOnly(func):
  def wrapper(*args, **kwargs):
    if sys.platform.startswith('linux'):
      func(*args, **kwargs)
    else:
      args[0].skipTest('This test runs on Linux only.')
  return wrapper

def NotLinux(func):
  def wrapper(*args, **kwargs):
    if sys.platform.startswith('linux'):
      func(*args, **kwargs)
    else:
      args[0].skipTest('This test does not run on Linux.')
  return wrapper

def MacOnly(func):
  def wrapper(*args, **kwargs):
    if sys.platform == 'darwin':
      func(*args, **kwargs)
    else:
      args[0].skipTest('This test runs on Mac OS only.')
  return wrapper

def NotMac(func):
  def wrapper(*args, **kwargs):
    if sys.platform == 'darwin':
      func(*args, **kwargs)
    else:
      args[0].skipTest('This test does not run on Mac OS.')
  return wrapper
