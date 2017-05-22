# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import logging
import os
import posixpath
import re
import tempfile
import time

from devil.android import device_errors
from devil.android import device_temp_file
from devil.android import flag_changer
from devil.android.sdk import shared_prefs
from devil.utils import reraiser_thread
from pylib import valgrind_tools
from pylib.android import logdog_logcat_monitor
from pylib.base import base_test_result
from pylib.constants import host_paths
from pylib.instrumentation import instrumentation_test_instance
from pylib.local.device import local_device_environment
from pylib.local.device import local_device_test_run
from pylib.utils import google_storage_helper
from pylib.utils import logdog_helper
from py_trace_event import trace_event
from py_utils import contextlib_ext
from py_utils import tempfile_ext
import tombstones

with host_paths.SysPath(
    os.path.join(host_paths.DIR_SOURCE_ROOT, 'third_party'), 0):
  import jinja2  # pylint: disable=import-error
  import markupsafe  # pylint: disable=import-error,unused-import


_JINJA_TEMPLATE_DIR = os.path.join(
    host_paths.DIR_SOURCE_ROOT, 'build', 'android', 'pylib', 'instrumentation')
_JINJA_TEMPLATE_FILENAME = 'render_test.html.jinja'

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

LOGCAT_FILTERS = ['*:e', 'chromium:v', 'cr_*:v', 'DEBUG:I']

EXTRA_SCREENSHOT_FILE = (
    'org.chromium.base.test.ScreenshotOnFailureStatement.ScreenshotFile')

FEATURE_ANNOTATION = 'Feature'
RENDER_TEST_FEATURE_ANNOTATION = 'RenderTest'

# This needs to be kept in sync with formatting in |RenderUtils.imageName|
RE_RENDER_IMAGE_NAME = re.compile(
      r'(?P<test_class>\w+)\.'
      r'(?P<description>\w+)\.'
      r'(?P<device_model>\w+)\.'
      r'(?P<orientation>port|land)\.png')

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
    @trace_event.traced
    def individual_device_set_up(dev, host_device_tuples):
      steps = []

      def install_helper(apk, permissions):
        @trace_event.traced("apk_path")
        def install_helper_internal(apk_path=apk.path):
          # pylint: disable=unused-argument
          dev.Install(apk, permissions=permissions)
        return install_helper_internal

      def incremental_install_helper(dev, apk, script):
        @trace_event.traced("apk_path")
        def incremental_install_helper_internal(apk_path=apk.path):
          # pylint: disable=unused-argument
          local_device_test_run.IncrementalInstall(
              dev, apk, script)
        return incremental_install_helper_internal

      if self._test_instance.apk_under_test:
        if self._test_instance.apk_under_test_incremental_install_script:
          steps.append(incremental_install_helper(
                           dev,
                           self._test_instance.apk_under_test,
                           self._test_instance.
                               apk_under_test_incremental_install_script))
        else:
          permissions = self._test_instance.apk_under_test.GetPermissions()
          steps.append(install_helper(self._test_instance.apk_under_test,
                                      permissions))

      if self._test_instance.test_apk_incremental_install_script:
        steps.append(incremental_install_helper(
                         dev,
                         self._test_instance.test_apk,
                         self._test_instance.
                             test_apk_incremental_install_script))
      else:
        permissions = self._test_instance.test_apk.GetPermissions()
        steps.append(install_helper(self._test_instance.test_apk,
                                    permissions))

      steps.extend(install_helper(apk, None)
                   for apk in self._test_instance.additional_apks)

      @trace_event.traced
      def set_debug_app():
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
      @trace_event.traced
      def edit_shared_prefs():
        for pref in self._test_instance.edit_shared_prefs:
          prefs = shared_prefs.SharedPrefs(dev, pref['package'],
                                           pref['filename'])
          prefs.Load()
          for key in pref.get('remove', []):
            try:
              prefs.Remove(key)
            except KeyError:
              logging.warning("Attempted to remove non-existent key %s", key)
          for key, value in pref.get('set', {}).iteritems():
            if isinstance(value, bool):
              prefs.SetBoolean(key, value)
            elif isinstance(value, basestring):
              prefs.SetString(key, value)
            elif isinstance(value, long) or isinstance(value, int):
              prefs.SetLong(key, value)
            elif isinstance(value, list):
              prefs.SetStringSet(key, value)
            else:
              raise ValueError("Given invalid value type %s for key %s" % (
                  str(type(value)), key))
          prefs.Commit()

      @trace_event.traced
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

      @trace_event.traced
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

      steps += [set_debug_app, edit_shared_prefs, push_test_data,
                create_flag_changer]
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
    @trace_event.traced
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
    tests = self._test_instance.GetTests()
    tests = self._ApplyExternalSharding(
        tests, self._test_instance.external_shard_index,
        self._test_instance.total_external_shards)
    return tests

  #override
  def _GetUniqueTestName(self, test):
    return instrumentation_test_instance.GetUniqueTestName(test)

  #override
  def _RunTest(self, device, test):
    extras = {}

    flags_to_add = []
    flags_to_remove = []
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
    # Save screenshot if screenshot dir is specified (save locally) or if
    # a GS bucket is passed (save in cloud).
    screenshot_device_file = None
    if (self._test_instance.screenshot_dir or
        self._test_instance.gs_results_bucket):
      screenshot_device_file = device_temp_file.DeviceTempFile(
          device.adb, suffix='.png', dir=device.GetExternalStoragePath())
      extras[EXTRA_SCREENSHOT_FILE] = screenshot_device_file.name

    if isinstance(test, list):
      if not self._test_instance.driver_apk:
        raise Exception('driver_apk does not exist. '
                        'Please build it and try again.')
      if any(t.get('is_junit4') for t in test):
        raise Exception('driver apk does not support JUnit4 tests')

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
      if test['is_junit4']:
        target = '%s/%s' % (
            self._test_instance.test_package,
            self._test_instance.test_runner_junit4)
      else:
        target = '%s/%s' % (
            self._test_instance.test_package, self._test_instance.test_runner)
      extras['class'] = test_name
      if 'flags' in test:
        flags_to_add.extend(test['flags'].add)
        flags_to_remove.extend(test['flags'].remove)
      timeout = self._GetTimeoutFromAnnotations(
        test['annotations'], test_display_name)

      test_timeout_scale = self._GetTimeoutScaleFromAnnotations(
          test['annotations'])
      if test_timeout_scale and test_timeout_scale != 1:
        valgrind_tools.SetChromeTimeoutScale(
            device, test_timeout_scale * self._test_instance.timeout_scale)

    logging.info('preparing to run %s: %s', test_display_name, test)

    render_tests_device_output_dir = None
    if _IsRenderTest(test):
      # TODO(mikecase): Add DeviceTempDirectory class and use that instead.
      render_tests_device_output_dir = posixpath.join(
          device.GetExternalStoragePath(),
          'render_test_output_dir')
      flags_to_add.append('--render-test-output-dir=%s' %
                          render_tests_device_output_dir)

    if flags_to_add or flags_to_remove:
      self._CreateFlagChangerIfNeeded(device)
      self._flag_changers[str(device)].PushFlags(
        add=flags_to_add, remove=flags_to_remove)

    try:
      device.RunShellCommand(
          ['log', '-p', 'i', '-t', _TAG, 'START %s' % test_name],
          check_return=True)
      time_ms = lambda: int(time.time() * 1e3)
      start_ms = time_ms()

      stream_name = 'logcat_%s_%s_%s' % (
          test_name.replace('#', '.'),
          time.strftime('%Y%m%dT%H%M%S-UTC', time.gmtime()),
          device.serial)
      logmon = logdog_logcat_monitor.LogdogLogcatMonitor(
          device.adb, stream_name, filter_specs=LOGCAT_FILTERS)

      with contextlib_ext.Optional(
          logmon, self._test_instance.should_save_logcat):
        with contextlib_ext.Optional(
            trace_event.trace(test_name),
            self._env.trace_output):
          output = device.StartInstrumentation(
              target, raw=True, extras=extras, timeout=timeout, retries=0)
      logcat_url = logmon.GetLogcatURL()
    finally:
      device.RunShellCommand(
          ['log', '-p', 'i', '-t', _TAG, 'END %s' % test_name],
          check_return=True)
      duration_ms = time_ms() - start_ms
      if flags_to_add or flags_to_remove:
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
      if logcat_url:
        result.SetLink('logcat', logcat_url)

    if _IsRenderTest(test):
      # Render tests do not cause test failure by default. So we have to check
      # to see if any failure images were generated even if the test does not
      # fail.
      try:
        self._ProcessRenderTestResults(
            device, render_tests_device_output_dir, results)
      finally:
        device.RemovePath(render_tests_device_output_dir,
                          recursive=True, force=True)

    # Update the result name if the test used flags.
    if flags_to_add or flags_to_remove:
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
      with contextlib_ext.Optional(
          tempfile_ext.NamedTemporaryDirectory(),
          self._test_instance.screenshot_dir is None and
              self._test_instance.gs_results_bucket) as screenshot_host_dir:
        screenshot_host_dir = (
            self._test_instance.screenshot_dir or screenshot_host_dir)
        self._SaveScreenshot(device, screenshot_host_dir,
                             screenshot_device_file, test_display_name,
                             results)

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
      device.RunShellCommand(
          'rm -f %s' % posixpath.join(coverage_directory, '*'),
          check_return=True, shell=True)
    if self._test_instance.store_tombstones:
      tombstones_url = None
      for result in results:
        if result.GetType() == base_test_result.ResultType.CRASH:
          if not tombstones_url:
            resolved_tombstones = tombstones.ResolveTombstones(
                device,
                resolve_all_tombstones=True,
                include_stack_symbols=False,
                wipe_tombstones=True)
            stream_name = 'tombstones_%s_%s' % (
                time.strftime('%Y%m%dT%H%M%S-UTC', time.gmtime()),
                device.serial)
            tombstones_url = logdog_helper.text(
                stream_name, '\n'.join(resolved_tombstones))
          result.SetLink('tombstones', tombstones_url)
    return results, None

  def _SaveScreenshot(self, device, screenshot_host_dir, screenshot_device_file,
                      test_name, results):
    if screenshot_host_dir:
      screenshot_host_file = os.path.join(
          screenshot_host_dir,
          '%s-%s.png' % (
              test_name,
              time.strftime('%Y%m%dT%H%M%S-UTC', time.gmtime())))
      if device.FileExists(screenshot_device_file.name):
        try:
          device.PullFile(screenshot_device_file.name, screenshot_host_file)
        finally:
          screenshot_device_file.close()

        logging.info(
            'Saved screenshot for %s to %s.',
            test_name, screenshot_host_file)
        if self._test_instance.gs_results_bucket:
          link = google_storage_helper.upload(
              google_storage_helper.unique_name(
                  'screenshot', device=device),
              screenshot_host_file,
              bucket=('%s/screenshots' %
                      self._test_instance.gs_results_bucket))
          for result in results:
            result.SetLink('post_test_screenshot', link)

  def _ProcessRenderTestResults(
      self, device, render_tests_device_output_dir, results):
    # If GS results bucket is specified, will archive render result images.
    # If render image dir is specified, will pull the render result image from
    # the device and leave in the directory.
    if not (bool(self._test_instance.gs_results_bucket) or
            bool(self._test_instance.render_results_dir)):
      return

    failure_images_device_dir = posixpath.join(
        render_tests_device_output_dir, 'failures')
    if not device.FileExists(failure_images_device_dir):
      return

    diff_images_device_dir = posixpath.join(
        render_tests_device_output_dir, 'diffs')

    golden_images_device_dir = posixpath.join(
        render_tests_device_output_dir, 'goldens')

    with contextlib_ext.Optional(
        tempfile_ext.NamedTemporaryDirectory(),
        not bool(self._test_instance.render_results_dir)) as render_temp_dir:
      render_host_dir = (
          self._test_instance.render_results_dir or render_temp_dir)

      if not os.path.exists(render_host_dir):
        os.makedirs(render_host_dir)

      # Pull all render test results from device.
      device.PullFile(failure_images_device_dir, render_host_dir)

      if device.FileExists(diff_images_device_dir):
        device.PullFile(diff_images_device_dir, render_host_dir)
      else:
        logging.error('Diff images not found on device.')

      if device.FileExists(golden_images_device_dir):
        device.PullFile(golden_images_device_dir, render_host_dir)
      else:
        logging.error('Golden images not found on device.')

      # Upload results to Google Storage.
      if self._test_instance.gs_results_bucket:
        self._UploadRenderTestResults(render_host_dir, results)

  def _UploadRenderTestResults(self, render_host_dir, results):
    render_tests_bucket = (
        self._test_instance.gs_results_bucket + '/render_tests')

    for failure_filename in os.listdir(
        os.path.join(render_host_dir, 'failures')):
      m = RE_RENDER_IMAGE_NAME.match(failure_filename)
      if not m:
        logging.warning('Unexpected file in render test failures: %s',
                        failure_filename)
        continue

      failure_filepath = os.path.join(
          render_host_dir, 'failures', failure_filename)
      failure_link = google_storage_helper.upload_content_addressed(
          failure_filepath, bucket=render_tests_bucket)

      golden_filepath = os.path.join(
          render_host_dir, 'goldens', failure_filename)
      if os.path.exists(golden_filepath):
        golden_link = google_storage_helper.upload_content_addressed(
            golden_filepath, bucket=render_tests_bucket)
      else:
        golden_link = ''

      diff_filepath = os.path.join(
          render_host_dir, 'diffs', failure_filename)
      if os.path.exists(diff_filepath):
        diff_link = google_storage_helper.upload_content_addressed(
            diff_filepath, bucket=render_tests_bucket)
      else:
        diff_link = ''

      with tempfile.NamedTemporaryFile(suffix='.html') as temp_html:
        jinja2_env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(_JINJA_TEMPLATE_DIR),
            trim_blocks=True)
        template = jinja2_env.get_template(_JINJA_TEMPLATE_FILENAME)
        # pylint: disable=no-member
        processed_template_output = template.render(
            test_name=failure_filename,
            failure_link=failure_link,
            golden_link=golden_link,
            diff_link=diff_link)

        temp_html.write(processed_template_output)
        temp_html.flush()
        html_results_link = google_storage_helper.upload_content_addressed(
            temp_html.name,
            bucket=render_tests_bucket,
            content_type='text/html')
        for result in results:
          result.SetLink(failure_filename, html_results_link)

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
      return int(annotations.get('TimeoutScale', {}).get('value', 1))
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

def _IsRenderTest(test):
  """Determines if a test or list of tests has a RenderTest amongst them."""
  if not isinstance(test, list):
    test = [test]
  return any([RENDER_TEST_FEATURE_ANNOTATION in t['annotations'].get(
              FEATURE_ANNOTATION, {}).get('value', ()) for t in test])
