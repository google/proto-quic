# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import logging
import os
import re
import tempfile

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


_DEFAULT_ISOLATE_FILE_PATHS = {
    'base_unittests': 'base/base_unittests.isolate',
    'blink_heap_unittests':
      'third_party/WebKit/Source/platform/heap/BlinkHeapUnitTests.isolate',
    'blink_platform_unittests':
      'third_party/WebKit/Source/platform/blink_platform_unittests.isolate',
    'breakpad_unittests': 'breakpad/breakpad_unittests.isolate',
    'cc_perftests': 'cc/cc_perftests.isolate',
    'components_browsertests': 'components/components_browsertests.isolate',
    'components_unittests': 'components/components_unittests.isolate',
    'content_browsertests': 'content/content_browsertests.isolate',
    'content_unittests': 'content/content_unittests.isolate',
    'media_perftests': 'media/media_perftests.isolate',
    'media_unittests': 'media/media_unittests.isolate',
    'midi_unittests': 'media/midi/midi_unittests.isolate',
    'net_unittests': 'net/net_unittests.isolate',
    'sql_unittests': 'sql/sql_unittests.isolate',
    'sync_unit_tests': 'sync/sync_unit_tests.isolate',
    'ui_base_unittests': 'ui/base/ui_base_tests.isolate',
    'unit_tests': 'chrome/unit_tests.isolate',
    'webkit_unit_tests':
      'third_party/WebKit/Source/web/WebKitUnitTests.isolate',
}


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
    'org.chromium.native_test.NativeTestActivity.RunInSubThread')
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
_RE_TEST_RUN_STATUS = re.compile(
    r'\[ +(PASSED|RUNNER_FAILED|CRASHED) \] ?[^ ]+')
# Crash detection constants.
_RE_TEST_ERROR = re.compile(r'FAILURES!!! Tests run: \d+,'
                                    r' Failures: \d+, Errors: 1')
_RE_TEST_CURRENTLY_RUNNING = re.compile(r'\[ERROR:.*?\]'
                                    r' Currently running: (.*)')

# TODO(jbudorick): Make this a class method of GtestTestInstance once
# test_package_apk and test_package_exe are gone.
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


class GtestTestInstance(test_instance.TestInstance):

  def __init__(self, args, isolate_delegate, error_func):
    super(GtestTestInstance, self).__init__()
    # TODO(jbudorick): Support multiple test suites.
    if len(args.suite_name) > 1:
      raise ValueError('Platform mode currently supports only 1 gtest suite')
    self._extract_test_list_from_filter = args.extract_test_list_from_filter
    self._shard_timeout = args.shard_timeout
    self._skip_clear_data = args.skip_clear_data
    self._suite = args.suite_name[0]

    self._exe_path = os.path.join(constants.GetOutDirectory(),
                                  self._suite)

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
        self._shard_timeout = 900

    if not os.path.exists(self._exe_path):
      self._exe_path = None
    if not self._apk_helper and not self._exe_path:
      error_func('Could not find apk or executable for %s' % self._suite)

    self._data_deps = []
    if args.test_filter:
      self._gtest_filter = args.test_filter
    elif args.test_filter_file:
      with open(args.test_filter_file, 'r') as f:
        self._gtest_filter = ':'.join(l.strip() for l in f)
    else:
      self._gtest_filter = None

    if not args.isolate_file_path:
      default_isolate_file_path = _DEFAULT_ISOLATE_FILE_PATHS.get(self._suite)
      if default_isolate_file_path:
        args.isolate_file_path = os.path.join(
            host_paths.DIR_SOURCE_ROOT, default_isolate_file_path)

    if args.isolate_file_path:
      self._isolate_abs_path = os.path.abspath(args.isolate_file_path)
      self._isolate_delegate = isolate_delegate
      self._isolated_abs_path = os.path.join(
          constants.GetOutDirectory(), '%s.isolated' % self._suite)
    else:
      logging.warning('No isolate file provided. No data deps will be pushed.')
      self._isolate_delegate = None

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
  def exe(self):
    return self._exe_path

  @property
  def extras(self):
    return self._extras

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
  def skip_clear_data(self):
    return self._skip_clear_data

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
    if self._isolate_delegate:
      self._isolate_delegate.Remap(
          self._isolate_abs_path, self._isolated_abs_path)
      self._isolate_delegate.PurgeExcluded(_DEPS_EXCLUSION_LIST)
      self._isolate_delegate.MoveOutputDeps()
      dest_dir = None
      if self._suite == 'breakpad_unittests':
        dest_dir = '/data/local/tmp/'
      self._data_deps.extend([
          (self._isolate_delegate.isolate_deps_dir, dest_dir)])


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
    for gtest_filter_string in gtest_filter_strings:
      logging.debug('Filtering tests using: %s', gtest_filter_string)
      filtered_test_list = unittest_util.FilterTestNames(
          filtered_test_list, gtest_filter_string)
    return filtered_test_list

  def _GenerateDisabledFilterString(self, disabled_prefixes):
    disabled_filter_items = []

    if disabled_prefixes is None:
      disabled_prefixes = ['DISABLED_', 'FLAKY_', 'FAILS_', 'PRE_', 'MANUAL_']
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

  # pylint: disable=no-self-use
  def ParseGTestOutput(self, output):
    """Parses raw gtest output and returns a list of results.

    Args:
      output: A list of output lines.
    Returns:
      A list of base_test_result.BaseTestResults.
    """
    log = []
    result_type = None
    results = []
    test_name = None
    for l in output:
      logging.info(l)
      matcher = _RE_TEST_STATUS.match(l)
      if matcher:
        # Be aware that test name and status might not appear on same line.
        test_name = matcher.group(2) if matcher.group(2) else test_name
        duration = int(matcher.group(3)) if matcher.group(3) else 0
        if matcher.group(1) == 'RUN':
          log = []
        elif matcher.group(1) == 'OK':
          result_type = base_test_result.ResultType.PASS
        elif matcher.group(1) == 'FAILED':
          result_type = base_test_result.ResultType.FAIL
        elif matcher.group(1) == 'CRASHED':
          result_type = base_test_result.ResultType.CRASH

      # Needs another matcher here to match crashes, like those of DCHECK.
      matcher = _RE_TEST_CURRENTLY_RUNNING.match(l)
      if matcher:
        test_name = matcher.group(1)
        result_type = base_test_result.ResultType.CRASH
        duration = 0 # Don't know.

      if log is not None:
        log.append(l)

      if result_type:
        results.append(base_test_result.BaseTestResult(
            test_name, result_type, duration,
            log=('\n'.join(log) if log else '')))
        log = None
        result_type = None

    return results

  #override
  def TearDown(self):
    """Clear the mappings created by SetUp."""
    if self._isolate_delegate:
      self._isolate_delegate.Clear()

