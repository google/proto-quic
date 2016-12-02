# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import logging
import os
import posixpath
import re
import time

from devil.android import device_errors
from devil.android import flag_changer
from devil.utils import reraiser_thread
from pylib import valgrind_tools
from pylib.android import logdog_logcat_monitor
from pylib.base import base_test_result
from pylib.instrumentation import instrumentation_test_instance
from pylib.local.device import local_device_environment
from pylib.local.device import local_device_test_run
import tombstones

_TAG = 'test_runner_py'

TIMEOUT_ANNOTATIONS = [
  ('Manual', 10 * 60 * 60),
  ('IntegrationTest', 30 * 60),
  ('External', 10 * 60),
  ('EnormousTest', 10 * 60),
  ('LargeTest', 5 * 60),
  ('MediumTest', 3 * 60),
  ('SmallTest', 1 * 60),
]


# TODO(jbudorick): Make this private once the instrumentation test_runner is
# deprecated.
def DidPackageCrashOnDevice(package_name, device):
  # Dismiss any error dialogs. Limit the number in case we have an error
  # loop or we are failing to dismiss.
  try:
    for _ in xrange(10):
      package = device.DismissCrashDialogIfNeeded()
      if not package:
        return False
      # Assume test package convention of ".test" suffix
      if package in package_name:
        return True
  except device_errors.CommandFailedError:
    logging.exception('Error while attempting to dismiss crash dialog.')
  return False


_CURRENT_FOCUS_CRASH_RE = re.compile(
    r'\s*mCurrentFocus.*Application (Error|Not Responding): (\S+)}')


class LocalDeviceInstrumentationTestRun(
    local_device_test_run.LocalDeviceTestRun):
  def __init__(self, env, test_instance):
    super(LocalDeviceInstrumentationTestRun, self).__init__(env, test_instance)
    self._flag_changers = {}

  #override
  def TestPackage(self):
    return self._test_instance.suite

  #override
  def SetUp(self):
    @local_device_environment.handle_shard_failures_with(
        self._env.BlacklistDevice)
    def individual_device_set_up(dev, host_device_tuples):
      def install_apk():
        if self._test_instance.apk_under_test:
          if self._test_instance.apk_under_test_incremental_install_script:
            local_device_test_run.IncrementalInstall(
                dev,
                self._test_instance.apk_under_test,
                self._test_instance.apk_under_test_incremental_install_script)
          else:
            permissions = self._test_instance.apk_under_test.GetPermissions()
            dev.Install(self._test_instance.apk_under_test,
                        permissions=permissions)

        if self._test_instance.test_apk_incremental_install_script:
          local_device_test_run.IncrementalInstall(
              dev,
              self._test_instance.test_apk,
              self._test_instance.test_apk_incremental_install_script)
        else:
          permissions = self._test_instance.test_apk.GetPermissions()
          dev.Install(self._test_instance.test_apk, permissions=permissions)

        for apk in self._test_instance.additional_apks:
          dev.Install(apk)

        # Set debug app in order to enable reading command line flags on user
        # builds
        if self._test_instance.flags:
          if not self._test_instance.package_info:
            logging.error("Couldn't set debug app: no package info")
          elif not self._test_instance.package_info.package:
            logging.error("Couldn't set debug app: no package defined")
          else:
            dev.RunShellCommand(['am', 'set-debug-app', '--persistent',
                                  self._test_instance.package_info.package],
                                check_return=True)

      def push_test_data():
        device_root = posixpath.join(dev.GetExternalStoragePath(),
                                     'chromium_tests_root')
        host_device_tuples_substituted = [
            (h, local_device_test_run.SubstituteDeviceRoot(d, device_root))
            for h, d in host_device_tuples]
        logging.info('instrumentation data deps:')
        for h, d in host_device_tuples_substituted:
          logging.info('%r -> %r', h, d)
        dev.PushChangedFiles(host_device_tuples_substituted,
                             delete_device_stale=True)
        if not host_device_tuples_substituted:
          dev.RunShellCommand(['rm', '-rf', device_root], check_return=True)
          dev.RunShellCommand(['mkdir', '-p', device_root], check_return=True)

      def create_flag_changer():
        if self._test_instance.flags:
          if not self._test_instance.package_info:
            logging.error("Couldn't set flags: no package info")
          elif not self._test_instance.package_info.cmdline_file:
            logging.error("Couldn't set flags: no cmdline_file")
          else:
            self._CreateFlagChangerIfNeeded(dev)
            logging.debug('Attempting to set flags: %r',
                          self._test_instance.flags)
            self._flag_changers[str(dev)].AddFlags(self._test_instance.flags)

        valgrind_tools.SetChromeTimeoutScale(
            dev, self._test_instance.timeout_scale)

      steps = (install_apk, push_test_data, create_flag_changer)
      if self._env.concurrent_adb:
        reraiser_thread.RunAsync(steps)
      else:
        for step in steps:
          step()
      if self._test_instance.store_tombstones:
        tombstones.ClearAllTombstones(dev)

    self._env.parallel_devices.pMap(
        individual_device_set_up,
        self._test_instance.GetDataDependencies())

  #override
  def TearDown(self):
    @local_device_environment.handle_shard_failures_with(
        self._env.BlacklistDevice)
    def individual_device_tear_down(dev):
      if str(dev) in self._flag_changers:
        self._flag_changers[str(dev)].Restore()

      # Remove package-specific configuration
      dev.RunShellCommand(['am', 'clear-debug-app'], check_return=True)

      valgrind_tools.SetChromeTimeoutScale(dev, None)

    self._env.parallel_devices.pMap(individual_device_tear_down)

  def _CreateFlagChangerIfNeeded(self, device):
    if not str(device) in self._flag_changers:
      self._flag_changers[str(device)] = flag_changer.FlagChanger(
        device, self._test_instance.package_info.cmdline_file)

  #override
  def _CreateShards(self, tests):
    return tests

  #override
  def _GetTests(self):
    return self._test_instance.GetTests()

  #override
  def _GetUniqueTestName(self, test):
    return instrumentation_test_instance.GetUniqueTestName(test)

  #override
  def _RunTest(self, device, test):
    extras = {}

    flags = None
    test_timeout_scale = None
    if self._test_instance.coverage_directory:
      coverage_basename = '%s.ec' % ('%s_group' % test[0]['method']
          if isinstance(test, list) else test['method'])
      extras['coverage'] = 'true'
      coverage_directory = os.path.join(
          device.GetExternalStoragePath(), 'chrome', 'test', 'coverage')
      coverage_device_file = os.path.join(
          coverage_directory, coverage_basename)
      extras['coverageFile'] = coverage_device_file

    if isinstance(test, list):
      if not self._test_instance.driver_apk:
        raise Exception('driver_apk does not exist. '
                        'Please build it and try again.')

      def name_and_timeout(t):
        n = instrumentation_test_instance.GetTestName(t)
        i = self._GetTimeoutFromAnnotations(t['annotations'], n)
        return (n, i)

      test_names, timeouts = zip(*(name_and_timeout(t) for t in test))

      test_name = ','.join(test_names)
      test_display_name = test_name
      target = '%s/%s' % (
          self._test_instance.driver_package,
          self._test_instance.driver_name)
      extras.update(
          self._test_instance.GetDriverEnvironmentVars(
              test_list=test_names))
      timeout = sum(timeouts)
    else:
      test_name = instrumentation_test_instance.GetTestName(test)
      test_display_name = self._GetUniqueTestName(test)
      target = '%s/%s' % (
          self._test_instance.test_package, self._test_instance.test_runner)
      extras['class'] = test_name
      if 'flags' in test:
        flags = test['flags']
      timeout = self._GetTimeoutFromAnnotations(
        test['annotations'], test_display_name)

      test_timeout_scale = self._GetTimeoutScaleFromAnnotations(
          test['annotations'])
      if test_timeout_scale and test_timeout_scale != 1:
        valgrind_tools.SetChromeTimeoutScale(
            device, test_timeout_scale * self._test_instance.timeout_scale)

    logging.info('preparing to run %s: %s', test_display_name, test)

    if flags:
      self._CreateFlagChangerIfNeeded(device)
      self._flag_changers[str(device)].PushFlags(
        add=flags.add, remove=flags.remove)

    try:
      device.RunShellCommand(
          ['log', '-p', 'i', '-t', _TAG, 'START %s' % test_name],
          check_return=True)
      logcat_url = None
      time_ms = lambda: int(time.time() * 1e3)
      start_ms = time_ms()
      if self._test_instance.should_save_logcat:
        stream_name = 'logcat_%s_%s_%s' % (
            test_name.replace('#', '.'),
            time.strftime('%Y%m%dT%H%M%S', time.localtime()),
            device.serial)
        with logdog_logcat_monitor.LogdogLogcatMonitor(
            device.adb, stream_name) as logmon:
          output = device.StartInstrumentation(
              target, raw=True, extras=extras, timeout=timeout, retries=0)
        logcat_url = logmon.GetLogcatURL()
      else:
        output = device.StartInstrumentation(
            target, raw=True, extras=extras, timeout=timeout, retries=0)
    finally:
      device.RunShellCommand(
          ['log', '-p', 'i', '-t', _TAG, 'END %s' % test_name],
          check_return=True)
      duration_ms = time_ms() - start_ms
      if flags:
        self._flag_changers[str(device)].Restore()
      if test_timeout_scale:
        valgrind_tools.SetChromeTimeoutScale(
            device, self._test_instance.timeout_scale)

    # TODO(jbudorick): Make instrumentation tests output a JSON so this
    # doesn't have to parse the output.
    result_code, result_bundle, statuses = (
        self._test_instance.ParseAmInstrumentRawOutput(output))
    results = self._test_instance.GenerateTestResults(
        result_code, result_bundle, statuses, start_ms, duration_ms)
    for result in results:
      result.SetLogcatUrl(logcat_url)

    # Update the result name if the test used flags.
    if flags:
      for r in results:
        if r.GetName() == test_name:
          r.SetName(test_display_name)

    # Add UNKNOWN results for any missing tests.
    iterable_test = test if isinstance(test, list) else [test]
    test_names = set(self._GetUniqueTestName(t) for t in iterable_test)
    results_names = set(r.GetName() for r in results)
    results.extend(
        base_test_result.BaseTestResult(u, base_test_result.ResultType.UNKNOWN)
        for u in test_names.difference(results_names))

    # Update the result type if we detect a crash.
    if DidPackageCrashOnDevice(self._test_instance.test_package, device):
      for r in results:
        if r.GetType() == base_test_result.ResultType.UNKNOWN:
          r.SetType(base_test_result.ResultType.CRASH)

    # Handle failures by:
    #   - optionally taking a screenshot
    #   - logging the raw output at INFO level
    #   - clearing the application state while persisting permissions
    if any(r.GetType() not in (base_test_result.ResultType.PASS,
                               base_test_result.ResultType.SKIP)
           for r in results):
      if self._test_instance.screenshot_dir:
        file_name = '%s-%s.png' % (
            test_display_name,
            time.strftime('%Y%m%dT%H%M%S', time.localtime()))
        saved_dir = device.TakeScreenshot(
            os.path.join(self._test_instance.screenshot_dir, file_name))
        logging.info(
            'Saved screenshot for %s to %s.',
            test_display_name, saved_dir)
      logging.info('detected failure in %s. raw output:', test_display_name)
      for l in output:
        logging.info('  %s', l)
      if (not self._env.skip_clear_data
          and self._test_instance.package_info):
        permissions = (
            self._test_instance.apk_under_test.GetPermissions()
            if self._test_instance.apk_under_test
            else None)
        device.ClearApplicationState(self._test_instance.package_info.package,
                                     permissions=permissions)

    else:
      logging.debug('raw output from %s:', test_display_name)
      for l in output:
        logging.debug('  %s', l)
    if self._test_instance.coverage_directory:
      device.PullFile(coverage_directory,
          self._test_instance.coverage_directory)
      device.RunShellCommand('rm -f %s' % os.path.join(coverage_directory,
          '*'))
    if self._test_instance.store_tombstones:
      resolved_tombstones = None
      for result in results:
        if result.GetType() == base_test_result.ResultType.CRASH:
          if not resolved_tombstones:
            resolved_tombstones = '\n'.join(tombstones.ResolveTombstones(
                device,
                resolve_all_tombstones=True,
                include_stack_symbols=False,
                wipe_tombstones=True))
          result.SetTombstones(resolved_tombstones)
    return results, None

  #override
  def _ShouldRetry(self, test):
    if 'RetryOnFailure' in test.get('annotations', {}):
      return True

    # TODO(jbudorick): Remove this log message once @RetryOnFailure has been
    # enabled for a while. See crbug.com/619055 for more details.
    logging.error('Default retries are being phased out. crbug.com/619055')
    return False

  #override
  def _ShouldShard(self):
    return True

  @classmethod
  def _GetTimeoutScaleFromAnnotations(cls, annotations):
    try:
      return int(annotations.get('TimeoutScale', 1))
    except ValueError as e:
      logging.warning("Non-integer value of TimeoutScale ignored. (%s)", str(e))
      return 1

  @classmethod
  def _GetTimeoutFromAnnotations(cls, annotations, test_name):
    for k, v in TIMEOUT_ANNOTATIONS:
      if k in annotations:
        timeout = v
        break
    else:
      logging.warning('Using default 1 minute timeout for %s', test_name)
      timeout = 60

    timeout *= cls._GetTimeoutScaleFromAnnotations(annotations)

    return timeout

