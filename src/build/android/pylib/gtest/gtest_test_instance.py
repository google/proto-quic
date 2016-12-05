# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import HTMLParser
import logging
import os
import re
import tempfile
import threading
import xml.etree.ElementTree

from devil.android import apk_helper
from pylib import constants
from pylib.constants import host_paths
from pylib.base import base_test_result
from pylib.base import test_instance

with host_paths.SysPath(host_paths.BUILD_COMMON_PATH):
  import unittest_util # pylint: disable=import-error


BROWSER_TEST_SUITES = [
  'components_browsertests',
  'content_browsertests',
]

RUN_IN_SUB_THREAD_TEST_SUITES = ['net_unittests']


# Used for filtering large data deps at a finer grain than what's allowed in
# isolate files since pushing deps to devices is expensive.
# Wildcards are allowed.
_DEPS_EXCLUSION_LIST = [
    'chrome/test/data/extensions/api_test',
    'chrome/test/data/extensions/secure_shell',
    'chrome/test/data/firefox*',
    'chrome/test/data/gpu',
    'chrome/test/data/image_decoding',
    'chrome/test/data/import',
    'chrome/test/data/page_cycler',
    'chrome/test/data/perf',
    'chrome/test/data/pyauto_private',
    'chrome/test/data/safari_import',
    'chrome/test/data/scroll',
    'chrome/test/data/third_party',
    'third_party/hunspell_dictionaries/*.dic',
    # crbug.com/258690
    'webkit/data/bmp_decoder',
    'webkit/data/ico_decoder',
]


_EXTRA_NATIVE_TEST_ACTIVITY = (
    'org.chromium.native_test.NativeTestInstrumentationTestRunner.'
        'NativeTestActivity')
_EXTRA_RUN_IN_SUB_THREAD = (
    'org.chromium.native_test.NativeTest.RunInSubThread')
EXTRA_SHARD_NANO_TIMEOUT = (
    'org.chromium.native_test.NativeTestInstrumentationTestRunner.'
        'ShardNanoTimeout')
_EXTRA_SHARD_SIZE_LIMIT = (
    'org.chromium.native_test.NativeTestInstrumentationTestRunner.'
        'ShardSizeLimit')

# TODO(jbudorick): Remove these once we're no longer parsing stdout to generate
# results.
_RE_TEST_STATUS = re.compile(
    r'\[ +((?:RUN)|(?:FAILED)|(?:OK)|(?:CRASHED)) +\]'
    r' ?([^ ]+)?(?: \((\d+) ms\))?$')
# Crash detection constants.
_RE_TEST_ERROR = re.compile(r'FAILURES!!! Tests run: \d+,'
                                    r' Failures: \d+, Errors: 1')
_RE_TEST_CURRENTLY_RUNNING = re.compile(r'\[ERROR:.*?\]'
                                    r' Currently running: (.*)')

def ParseGTestListTests(raw_list):
  """Parses a raw test list as provided by --gtest_list_tests.

  Args:
    raw_list: The raw test listing with the following format:

    IPCChannelTest.
      SendMessageInChannelConnected
    IPCSyncChannelTest.
      Simple
      DISABLED_SendWithTimeoutMixedOKAndTimeout

  Returns:
    A list of all tests. For the above raw listing:

    [IPCChannelTest.SendMessageInChannelConnected, IPCSyncChannelTest.Simple,
     IPCSyncChannelTest.DISABLED_SendWithTimeoutMixedOKAndTimeout]
  """
  ret = []
  current = ''
  for test in raw_list:
    if not test:
      continue
    if test[0] != ' ':
      test_case = test.split()[0]
      if test_case.endswith('.'):
        current = test_case
    elif not 'YOU HAVE' in test:
      test_name = test.split()[0]
      ret += [current + test_name]
  return ret


def ParseGTestOutput(output):
  """Parses raw gtest output and returns a list of results.

  Args:
    output: A list of output lines.
  Returns:
    A list of base_test_result.BaseTestResults.
  """
  duration = 0
  fallback_result_type = None
  log = []
  result_type = None
  results = []
  test_name = None

  def handle_possibly_unknown_test():
    if test_name is not None:
      results.append(base_test_result.BaseTestResult(
          test_name,
          fallback_result_type or base_test_result.ResultType.UNKNOWN,
          duration, log=('\n'.join(log) if log else '')))

  for l in output:
    logging.info(l)
    matcher = _RE_TEST_STATUS.match(l)
    if matcher:
      if matcher.group(1) == 'RUN':
        handle_possibly_unknown_test()
        duration = 0
        fallback_result_type = None
        log = []
        result_type = None
      elif matcher.group(1) == 'OK':
        result_type = base_test_result.ResultType.PASS
      elif matcher.group(1) == 'FAILED':
        result_type = base_test_result.ResultType.FAIL
      elif matcher.group(1) == 'CRASHED':
        fallback_result_type = base_test_result.ResultType.CRASH
      # Be aware that test name and status might not appear on same line.
      test_name = matcher.group(2) if matcher.group(2) else test_name
      duration = int(matcher.group(3)) if matcher.group(3) else 0

    else:
      # Needs another matcher here to match crashes, like those of DCHECK.
      matcher = _RE_TEST_CURRENTLY_RUNNING.match(l)
      if matcher:
        test_name = matcher.group(1)
        result_type = base_test_result.ResultType.CRASH
        duration = 0 # Don't know.

    if log is not None:
      log.append(l)

    if result_type and test_name:
      results.append(base_test_result.BaseTestResult(
          test_name, result_type, duration,
          log=('\n'.join(log) if log else '')))
      test_name = None

  handle_possibly_unknown_test()

  return results


def ParseGTestXML(xml_content):
  """Parse gtest XML result."""
  results = []

  html = HTMLParser.HTMLParser()

  # TODO(jbudorick): Unclear how this handles crashes.
  testsuites = xml.etree.ElementTree.fromstring(xml_content)
  for testsuite in testsuites:
    suite_name = testsuite.attrib['name']
    for testcase in testsuite:
      case_name = testcase.attrib['name']
      result_type = base_test_result.ResultType.PASS
      log = []
      for failure in testcase:
        result_type = base_test_result.ResultType.FAIL
        log.append(html.unescape(failure.attrib['message']))

      results.append(base_test_result.BaseTestResult(
          '%s.%s' % (suite_name, case_name),
          result_type,
          int(float(testcase.attrib['time']) * 1000),
          log=('\n'.join(log) if log else '')))

  return results


def ConvertTestFilterFileIntoGTestFilterArgument(input_lines):
  """Converts test filter file contents into --gtest_filter argument.

  See //testing/buildbot/filters/README.md for description of the
  syntax that |input_lines| are expected to follow.

  See
  https://github.com/google/googletest/blob/master/googletest/docs/AdvancedGuide.md#running-a-subset-of-the-tests
  for description of the syntax that --gtest_filter argument should follow.

  Args:
    input_lines: An iterable (e.g. a list or a file) containing input lines.
  Returns:
    a string suitable for feeding as an argument of --gtest_filter parameter.
  """
  # Strip whitespace + skip empty lines and lines beginning with '#'.
  stripped_lines = (l.strip() for l in input_lines)
  filter_lines = list(l for l in stripped_lines if l and l[0] != '#')

  # Split the tests into positive and negative patterns (gtest treats
  # every pattern after the first '-' sign as an exclusion).
  positive_patterns = ':'.join(l for l in filter_lines if l[0] != '-')
  negative_patterns = ':'.join(l[1:] for l in filter_lines if l[0] == '-')
  if negative_patterns:
    negative_patterns = '-' + negative_patterns

  # Join the filter lines into one, big --gtest_filter argument.
  return positive_patterns + negative_patterns


class GtestTestInstance(test_instance.TestInstance):

  def __init__(self, args, data_deps_delegate, error_func):
    super(GtestTestInstance, self).__init__()
    # TODO(jbudorick): Support multiple test suites.
    if len(args.suite_name) > 1:
      raise ValueError('Platform mode currently supports only 1 gtest suite')
    self._exe_dist_dir = None
    self._extract_test_list_from_filter = args.extract_test_list_from_filter
    self._shard_timeout = args.shard_timeout
    self._store_tombstones = args.store_tombstones
    self._suite = args.suite_name[0]
    self._filter_tests_lock = threading.Lock()

    # GYP:
    if args.executable_dist_dir:
      self._exe_dist_dir = os.path.abspath(args.executable_dist_dir)
    else:
      # TODO(agrieve): Remove auto-detection once recipes pass flag explicitly.
      exe_dist_dir = os.path.join(constants.GetOutDirectory(),
                                  '%s__dist' % self._suite)

      if os.path.exists(exe_dist_dir):
        self._exe_dist_dir = exe_dist_dir

    incremental_part = ''
    if args.test_apk_incremental_install_script:
      incremental_part = '_incremental'

    apk_path = os.path.join(
        constants.GetOutDirectory(), '%s_apk' % self._suite,
        '%s-debug%s.apk' % (self._suite, incremental_part))
    self._test_apk_incremental_install_script = (
        args.test_apk_incremental_install_script)
    if not os.path.exists(apk_path):
      self._apk_helper = None
    else:
      self._apk_helper = apk_helper.ApkHelper(apk_path)
      self._extras = {
          _EXTRA_NATIVE_TEST_ACTIVITY: self._apk_helper.GetActivityName(),
      }
      if self._suite in RUN_IN_SUB_THREAD_TEST_SUITES:
        self._extras[_EXTRA_RUN_IN_SUB_THREAD] = 1
      if self._suite in BROWSER_TEST_SUITES:
        self._extras[_EXTRA_SHARD_SIZE_LIMIT] = 1
        self._extras[EXTRA_SHARD_NANO_TIMEOUT] = int(1e9 * self._shard_timeout)
        self._shard_timeout = 10 * self._shard_timeout

    if not self._apk_helper and not self._exe_dist_dir:
      error_func('Could not find apk or executable for %s' % self._suite)

    self._data_deps = []
    if args.test_filter:
      self._gtest_filter = args.test_filter
    elif args.test_filter_file:
      with open(args.test_filter_file, 'r') as f:
        self._gtest_filter = ConvertTestFilterFileIntoGTestFilterArgument(f)
    else:
      self._gtest_filter = None

    self._run_disabled = args.run_disabled

    self._data_deps_delegate = data_deps_delegate
    self._runtime_deps_path = args.runtime_deps_path
    if not self._runtime_deps_path:
      logging.warning('No data dependencies will be pushed.')

    if args.app_data_files:
      self._app_data_files = args.app_data_files
      if args.app_data_file_dir:
        self._app_data_file_dir = args.app_data_file_dir
      else:
        self._app_data_file_dir = tempfile.mkdtemp()
        logging.critical('Saving app files to %s', self._app_data_file_dir)
    else:
      self._app_data_files = None
      self._app_data_file_dir = None

    self._test_arguments = args.test_arguments

    # TODO(jbudorick): Remove this once it's deployed.
    self._enable_xml_result_parsing = args.enable_xml_result_parsing

  @property
  def activity(self):
    return self._apk_helper and self._apk_helper.GetActivityName()

  @property
  def apk(self):
    return self._apk_helper and self._apk_helper.path

  @property
  def apk_helper(self):
    return self._apk_helper

  @property
  def app_file_dir(self):
    return self._app_data_file_dir

  @property
  def app_files(self):
    return self._app_data_files

  @property
  def enable_xml_result_parsing(self):
    return self._enable_xml_result_parsing

  @property
  def exe_dist_dir(self):
    return self._exe_dist_dir

  @property
  def extras(self):
    return self._extras

  @property
  def gtest_also_run_disabled_tests(self):
    return self._run_disabled

  @property
  def gtest_filter(self):
    return self._gtest_filter

  @property
  def package(self):
    return self._apk_helper and self._apk_helper.GetPackageName()

  @property
  def permissions(self):
    return self._apk_helper and self._apk_helper.GetPermissions()

  @property
  def runner(self):
    return self._apk_helper and self._apk_helper.GetInstrumentationName()

  @property
  def shard_timeout(self):
    return self._shard_timeout

  @property
  def store_tombstones(self):
    return self._store_tombstones

  @property
  def suite(self):
    return self._suite

  @property
  def test_apk_incremental_install_script(self):
    return self._test_apk_incremental_install_script

  @property
  def test_arguments(self):
    return self._test_arguments

  @property
  def extract_test_list_from_filter(self):
    return self._extract_test_list_from_filter

  #override
  def TestType(self):
    return 'gtest'

  #override
  def SetUp(self):
    """Map data dependencies via isolate."""
    self._data_deps.extend(
        self._data_deps_delegate(self._runtime_deps_path))

  def GetDataDependencies(self):
    """Returns the test suite's data dependencies.

    Returns:
      A list of (host_path, device_path) tuples to push. If device_path is
      None, the client is responsible for determining where to push the file.
    """
    return self._data_deps

  def FilterTests(self, test_list, disabled_prefixes=None):
    """Filters |test_list| based on prefixes and, if present, a filter string.

    Args:
      test_list: The list of tests to filter.
      disabled_prefixes: A list of test prefixes to filter. Defaults to
        DISABLED_, FLAKY_, FAILS_, PRE_, and MANUAL_
    Returns:
      A filtered list of tests to run.
    """
    gtest_filter_strings = [
        self._GenerateDisabledFilterString(disabled_prefixes)]
    if self._gtest_filter:
      gtest_filter_strings.append(self._gtest_filter)

    filtered_test_list = test_list
    # This lock is required because on older versions of Python
    # |unittest_util.FilterTestNames| use of |fnmatch| is not threadsafe.
    with self._filter_tests_lock:
      for gtest_filter_string in gtest_filter_strings:
        logging.debug('Filtering tests using: %s', gtest_filter_string)
        filtered_test_list = unittest_util.FilterTestNames(
            filtered_test_list, gtest_filter_string)
    return filtered_test_list

  def _GenerateDisabledFilterString(self, disabled_prefixes):
    disabled_filter_items = []

    if disabled_prefixes is None:
      disabled_prefixes = ['FAILS_', 'PRE_', 'MANUAL_']
      if not self._run_disabled:
        disabled_prefixes += ['DISABLED_', 'FLAKY_']

    disabled_filter_items += ['%s*' % dp for dp in disabled_prefixes]
    disabled_filter_items += ['*.%s*' % dp for dp in disabled_prefixes]

    disabled_tests_file_path = os.path.join(
        host_paths.DIR_SOURCE_ROOT, 'build', 'android', 'pylib', 'gtest',
        'filter', '%s_disabled' % self._suite)
    if disabled_tests_file_path and os.path.exists(disabled_tests_file_path):
      with open(disabled_tests_file_path) as disabled_tests_file:
        disabled_filter_items += [
            '%s' % l for l in (line.strip() for line in disabled_tests_file)
            if l and not l.startswith('#')]

    return '*-%s' % ':'.join(disabled_filter_items)

  #override
  def TearDown(self):
    """Do nothing."""
    pass

