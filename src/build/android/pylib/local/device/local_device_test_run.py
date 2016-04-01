# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import fnmatch
import functools
import imp
import logging

from devil import base_error
from devil.android import device_errors
from pylib import valgrind_tools
from pylib.base import base_test_result
from pylib.base import test_run
from pylib.base import test_collection


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


def handle_shard_failures(f):
  """A decorator that handles device failures for per-device functions.

  Args:
    f: the function being decorated. The function must take at least one
      argument, and that argument must be the device.
  """
  return handle_shard_failures_with(None)(f)


def handle_shard_failures_with(on_failure):
  """A decorator that handles device failures for per-device functions.

  This calls on_failure in the event of a failure.

  Args:
    f: the function being decorated. The function must take at least one
      argument, and that argument must be the device.
    on_failure: A binary function to call on failure.
  """
  def decorator(f):
    @functools.wraps(f)
    def wrapper(dev, *args, **kwargs):
      try:
        return f(dev, *args, **kwargs)
      except device_errors.CommandTimeoutError:
        logging.exception('Shard timed out: %s(%s)', f.__name__, str(dev))
      except device_errors.DeviceUnreachableError:
        logging.exception('Shard died: %s(%s)', f.__name__, str(dev))
      except base_error.BaseError:
        logging.exception('Shard failed: %s(%s)', f.__name__,
                          str(dev))
      if on_failure:
        on_failure(dev, f.__name__)
      return None

    return wrapper

  return decorator


class LocalDeviceTestRun(test_run.TestRun):

  def __init__(self, env, test_instance):
    super(LocalDeviceTestRun, self).__init__(env, test_instance)
    self._tools = {}

  #override
  def RunTests(self):
    tests = self._GetTests()

    @handle_shard_failures
    def run_tests_on_device(dev, tests, results):
      for test in tests:
        result = None
        try:
          result = self._RunTest(dev, test)
          if isinstance(result, base_test_result.BaseTestResult):
            results.AddResult(result)
          elif isinstance(result, list):
            results.AddResults(result)
          else:
            raise Exception(
                'Unexpected result type: %s' % type(result).__name__)
        except:
          if isinstance(tests, test_collection.TestCollection):
            tests.add(test)
          raise
        finally:
          if isinstance(tests, test_collection.TestCollection):
            tests.test_completed()


      logging.info('Finished running tests on this device.')

    tries = 0
    results = base_test_result.TestRunResults()
    all_fail_results = {}
    while tries < self._env.max_tries and tests:
      logging.info('STARTING TRY #%d/%d', tries + 1, self._env.max_tries)
      logging.info('Will run %d tests on %d devices: %s',
                   len(tests), len(self._env.devices),
                   ', '.join(str(d) for d in self._env.devices))
      for t in tests:
        logging.debug('  %s', t)

      try_results = base_test_result.TestRunResults()
      if self._ShouldShard():
        tc = test_collection.TestCollection(self._CreateShards(tests))
        self._env.parallel_devices.pMap(
            run_tests_on_device, tc, try_results).pGet(None)
      else:
        self._env.parallel_devices.pMap(
            run_tests_on_device, tests, try_results).pGet(None)

      for result in try_results.GetAll():
        if result.GetType() in (base_test_result.ResultType.PASS,
                                base_test_result.ResultType.SKIP):
          results.AddResult(result)
        else:
          all_fail_results[result.GetName()] = result

      results_names = set(r.GetName() for r in results.GetAll())

      def has_test_result(name):
        # When specifying a test filter, names can contain trailing wildcards.
        # See local_device_gtest_run._ExtractTestsFromFilter()
        if name.endswith('*'):
          return any(fnmatch.fnmatch(n, name) for n in results_names)
        return name in results_names

      tests = [t for t in tests if not has_test_result(self._GetTestName(t))]
      tries += 1
      logging.info('FINISHED TRY #%d/%d', tries, self._env.max_tries)
      if tests:
        logging.info('%d failed tests remain.', len(tests))
      else:
        logging.info('All tests completed.')

    all_unknown_test_names = set(self._GetTestName(t) for t in tests)
    all_failed_test_names = set(all_fail_results.iterkeys())

    unknown_tests = all_unknown_test_names.difference(all_failed_test_names)
    failed_tests = all_failed_test_names.intersection(all_unknown_test_names)

    if unknown_tests:
      results.AddResults(
          base_test_result.BaseTestResult(
              u, base_test_result.ResultType.UNKNOWN)
          for u in unknown_tests)
    if failed_tests:
      results.AddResults(all_fail_results[f] for f in failed_tests)

    return results

  def GetTool(self, device):
    if not str(device) in self._tools:
      self._tools[str(device)] = valgrind_tools.CreateTool(
          self._env.tool, device)
    return self._tools[str(device)]

  def _CreateShards(self, tests):
    raise NotImplementedError

  # pylint: disable=no-self-use
  def _GetTestName(self, test):
    return test

  def _GetTests(self):
    raise NotImplementedError

  def _RunTest(self, device, test):
    raise NotImplementedError

  def _ShouldShard(self):
    raise NotImplementedError
