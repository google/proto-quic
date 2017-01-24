# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import fnmatch
import imp
import logging
import posixpath
import signal
import thread
import threading

from devil.utils import signal_handler
from pylib import valgrind_tools
from pylib.base import base_test_result
from pylib.base import test_run
from pylib.base import test_collection
from pylib.local.device import local_device_environment


_SIGTERM_TEST_LOG = (
  '  Suite execution terminated, probably due to swarming timeout.\n'
  '  Your test may not have run.')


def IncrementalInstall(device, apk_helper, installer_script):
  """Performs an incremental install.

  Args:
    device: Device to install on.
    apk_helper: ApkHelper instance for the _incremental.apk.
    installer_script: Path to the installer script for the incremental apk.
  """
  try:
    install_wrapper = imp.load_source('install_wrapper', installer_script)
  except IOError:
    raise Exception('Incremental install script not found: %s\n' %
                    installer_script)
  params = install_wrapper.GetInstallParameters()

  from incremental_install import installer
  installer.Install(device, apk_helper, split_globs=params['splits'],
                    native_libs=params['native_libs'],
                    dex_files=params['dex_files'],
                    permissions=None)  # Auto-grant permissions from manifest.


def SubstituteDeviceRoot(device_path, device_root):
  if not device_path:
    return device_root
  elif isinstance(device_path, list):
    return posixpath.join(*(p if p else device_root for p in device_path))
  else:
    return device_path


class LocalDeviceTestRun(test_run.TestRun):

  def __init__(self, env, test_instance):
    super(LocalDeviceTestRun, self).__init__(env, test_instance)
    self._tools = {}

  #override
  def RunTests(self):
    tests = self._GetTests()

    exit_now = threading.Event()

    @local_device_environment.handle_shard_failures
    def run_tests_on_device(dev, tests, results):
      for test in tests:
        if exit_now.isSet():
          thread.exit()

        result = None
        rerun = None
        try:
          result, rerun = self._RunTest(dev, test)
          if isinstance(result, base_test_result.BaseTestResult):
            results.AddResult(result)
          elif isinstance(result, list):
            results.AddResults(result)
          else:
            raise Exception(
                'Unexpected result type: %s' % type(result).__name__)
        except:
          if isinstance(tests, test_collection.TestCollection):
            rerun = test
          raise
        finally:
          if isinstance(tests, test_collection.TestCollection):
            if rerun:
              tests.add(rerun)
            tests.test_completed()

      logging.info('Finished running tests on this device.')

    class TestsTerminated(Exception):
      pass

    def stop_tests(_signum, _frame):
      logging.critical('Received SIGTERM. Stopping test execution.')
      exit_now.set()
      raise TestsTerminated()

    try:
      with signal_handler.SignalHandler(signal.SIGTERM, stop_tests):
        tries = 0
        results = []
        while tries < self._env.max_tries and tests:
          logging.info('STARTING TRY #%d/%d', tries + 1, self._env.max_tries)
          logging.info('Will run %d tests on %d devices: %s',
                       len(tests), len(self._env.devices),
                       ', '.join(str(d) for d in self._env.devices))
          for t in tests:
            logging.debug('  %s', t)

          try_results = base_test_result.TestRunResults()
          test_names = (self._GetUniqueTestName(t) for t in tests)
          try_results.AddResults(
              base_test_result.BaseTestResult(
                  t, base_test_result.ResultType.NOTRUN)
              for t in test_names if not t.endswith('*'))

          try:
            if self._ShouldShard():
              tc = test_collection.TestCollection(self._CreateShards(tests))
              self._env.parallel_devices.pMap(
                  run_tests_on_device, tc, try_results).pGet(None)
            else:
              self._env.parallel_devices.pMap(
                  run_tests_on_device, tests, try_results).pGet(None)
          except TestsTerminated:
            for unknown_result in try_results.GetUnknown():
              try_results.AddResult(
                  base_test_result.BaseTestResult(
                      unknown_result.GetName(),
                      base_test_result.ResultType.TIMEOUT,
                      log=_SIGTERM_TEST_LOG))
            raise
          finally:
            results.append(try_results)

          tries += 1
          tests = self._GetTestsToRetry(tests, try_results)

          logging.info('FINISHED TRY #%d/%d', tries, self._env.max_tries)
          if tests:
            logging.info('%d failed tests remain.', len(tests))
          else:
            logging.info('All tests completed.')
    except TestsTerminated:
      pass

    return results

  def _GetTestsToRetry(self, tests, try_results):

    def is_failure_result(test_result):
      return (
          test_result is None
          or test_result.GetType() not in (
              base_test_result.ResultType.PASS,
              base_test_result.ResultType.SKIP))

    all_test_results = {r.GetName(): r for r in try_results.GetAll()}

    def test_failed(name):
      # When specifying a test filter, names can contain trailing wildcards.
      # See local_device_gtest_run._ExtractTestsFromFilter()
      if name.endswith('*'):
        return any(fnmatch.fnmatch(n, name) and is_failure_result(t)
                   for n, t in all_test_results.iteritems())
      return is_failure_result(all_test_results.get(name))

    failed_tests = (t for t in tests if test_failed(self._GetUniqueTestName(t)))

    return [t for t in failed_tests if self._ShouldRetry(t)]

  def GetTool(self, device):
    if not str(device) in self._tools:
      self._tools[str(device)] = valgrind_tools.CreateTool(
          self._env.tool, device)
    return self._tools[str(device)]

  def _CreateShards(self, tests):
    raise NotImplementedError

  def _GetUniqueTestName(self, test):
    # pylint: disable=no-self-use
    return test

  def _ShouldRetry(self, test):
    # pylint: disable=no-self-use,unused-argument
    return True

  def _GetTests(self):
    raise NotImplementedError

  def _RunTest(self, device, test):
    raise NotImplementedError

  def _ShouldShard(self):
    raise NotImplementedError


class NoTestsError(Exception):
  """Error for when no tests are found."""
