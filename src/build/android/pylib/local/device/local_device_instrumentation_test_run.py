# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import logging
import re
import time

from devil.android import device_errors
from devil.android import flag_changer
from devil.utils import reraiser_thread
from pylib import valgrind_tools
from pylib.base import base_test_result
from pylib.local.device import local_device_test_run


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

  def TestPackage(self):
    return None

  def SetUp(self):
    def substitute_external_storage(d, external_storage):
      if not d:
        return external_storage
      elif isinstance(d, list):
        return '/'.join(p if p else external_storage for p in d)
      else:
        return d

    @local_device_test_run.handle_shard_failures_with(
        self._env.BlacklistDevice)
    def individual_device_set_up(dev, host_device_tuples):
      def install_apk():
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
        external_storage = dev.GetExternalStoragePath()
        host_device_tuples_substituted = [
            (h, substitute_external_storage(d, external_storage))
            for h, d in host_device_tuples]
        logging.info('instrumentation data deps:')
        for h, d in host_device_tuples_substituted:
          logging.info('%r -> %r', h, d)
        dev.PushChangedFiles(host_device_tuples_substituted)

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

    self._env.parallel_devices.pMap(
        individual_device_set_up,
        self._test_instance.GetDataDependencies())

  def TearDown(self):
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
  def _GetTestName(self, test):
    return '%s#%s' % (test['class'], test['method'])

  def _GetTestNameForDisplay(self, test):
    display_name = self._GetTestName(test)
    flags = test['flags']
    if flags.add:
      display_name = '%s with {%s}' % (display_name, ' '.join(flags.add))
    if flags.remove:
      display_name = '%s without {%s}' % (display_name, ' '.join(flags.remove))
    return display_name

  #override
  def _RunTest(self, device, test):
    extras = {}

    flags = None
    test_timeout_scale = None
    if isinstance(test, list):
      if not self._test_instance.driver_apk:
        raise Exception('driver_apk does not exist. '
                        'Please build it and try again.')

      def name_and_timeout(t):
        n = self._GetTestName(t)
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
      test_name = self._GetTestName(test)
      test_display_name = test_name
      target = '%s/%s' % (
          self._test_instance.test_package, self._test_instance.test_runner)
      extras['class'] = test_name
      if 'flags' in test:
        flags = test['flags']
        test_display_name = self._GetTestNameForDisplay(test)
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
      time_ms = lambda: int(time.time() * 1e3)
      start_ms = time_ms()
      output = device.StartInstrumentation(
          target, raw=True, extras=extras, timeout=timeout, retries=0)
      duration_ms = time_ms() - start_ms
    finally:
      if flags:
        self._flag_changers[str(device)].Restore()
      if test_timeout_scale:
        valgrind_tools.SetChromeTimeoutScale(
            device, self._test_instance.timeout_scale)

    # TODO(jbudorick): Make instrumentation tests output a JSON so this
    # doesn't have to parse the output.
    logging.debug('output from %s:', test_display_name)
    for l in output:
      logging.debug('  %s', l)

    result_code, result_bundle, statuses = (
        self._test_instance.ParseAmInstrumentRawOutput(output))
    results = self._test_instance.GenerateTestResults(
        result_code, result_bundle, statuses, start_ms, duration_ms)
    if flags:
      for r in results:
        if r.GetName() == test_name:
          r.SetName(test_display_name)
    if DidPackageCrashOnDevice(self._test_instance.test_package, device):
      for r in results:
        if r.GetType() == base_test_result.ResultType.UNKNOWN:
          r.SetType(base_test_result.ResultType.CRASH)
    # TODO(jbudorick): ClearApplicationState on failure before switching
    # instrumentation tests to platform mode (but respect --skip-clear-data).
    return results

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

