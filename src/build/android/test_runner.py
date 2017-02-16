#!/usr/bin/env python
#
# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Runs all types of tests from one unified interface."""

import argparse
import collections
import contextlib
import itertools
import logging
import os
import signal
import sys
import threading
import traceback
import unittest

import devil_chromium
from devil import base_error
from devil.android import device_blacklist
from devil.android import device_errors
from devil.android import device_utils
from devil.android import forwarder
from devil.android import ports
from devil.utils import reraiser_thread
from devil.utils import run_tests_helper

from pylib import constants
from pylib.base import base_test_result
from pylib.base import environment_factory
from pylib.base import test_instance_factory
from pylib.base import test_run_factory
from pylib.constants import host_paths
from pylib.results import json_results
from pylib.results import report_results

from py_utils import contextlib_ext


_DEVIL_STATIC_CONFIG_FILE = os.path.abspath(os.path.join(
    host_paths.DIR_SOURCE_ROOT, 'build', 'android', 'devil_config.json'))


def AddCommonOptions(parser):
  """Adds all common options to |parser|."""

  group = parser.add_argument_group('Common Options')

  default_build_type = os.environ.get('BUILDTYPE', 'Debug')

  debug_or_release_group = group.add_mutually_exclusive_group()
  debug_or_release_group.add_argument(
      '--debug', action='store_const', const='Debug', dest='build_type',
      default=default_build_type,
      help=('If set, run test suites under out/Debug. '
            'Default is env var BUILDTYPE or Debug.'))
  debug_or_release_group.add_argument(
      '--release', action='store_const', const='Release', dest='build_type',
      help=('If set, run test suites under out/Release. '
            'Default is env var BUILDTYPE or Debug.'))

  # TODO(jbudorick): Remove --build-directory once no bots use it.
  group.add_argument('--build-directory', dest='build_directory',
                     help='DEPRECATED')
  group.add_argument('--output-directory', dest='output_directory',
                     type=os.path.realpath,
                     help=('Path to the directory in which build files are'
                           ' located (must include build type). This will take'
                           ' precedence over --debug, --release and'
                           ' --build-directory'))
  group.add_argument('--num_retries', '--num-retries',
                     '--test_launcher_retry_limit',
                     '--test-launcher-retry-limit',
                     dest='num_retries',
                     type=int, default=2,
                     help=('Number of retries for a test before '
                           'giving up (default: %(default)s).'))
  group.add_argument('--repeat', '--gtest_repeat', '--gtest-repeat',
                     dest='repeat', type=int, default=0,
                     help='Number of times to repeat the specified set of '
                          'tests.')
  group.add_argument('--break-on-failure', '--break_on_failure',
                     dest='break_on_failure', action='store_true',
                     help='Whether to break on failure.')
  group.add_argument('-v',
                     '--verbose',
                     dest='verbose_count',
                     default=0,
                     action='count',
                     help='Verbose level (multiple times for more)')
  group.add_argument('--flakiness-dashboard-server',
                     dest='flakiness_dashboard_server',
                     help=('Address of the server that is hosting the '
                           'Chrome for Android flakiness dashboard.'))
  group.add_argument('--enable-platform-mode', action='store_true',
                     help=('Run the test scripts in platform mode, which '
                           'conceptually separates the test runner from the '
                           '"device" (local or remote, real or emulated) on '
                           'which the tests are running. [experimental]'))
  group.add_argument('-e', '--environment', default='local',
                     choices=constants.VALID_ENVIRONMENTS,
                     help='Test environment to run in (default: %(default)s).')
  group.add_argument('--adb-path', type=os.path.realpath,
                     help=('Specify the absolute path of the adb binary that '
                           'should be used.'))
  group.add_argument('--json-results-file', '--test-launcher-summary-output',
                     dest='json_results_file', type=os.path.realpath,
                     help='If set, will dump results in JSON form '
                          'to specified file.')
  group.add_argument('--trace-output', metavar='FILENAME',
                     type=os.path.realpath,
                     help='Path to save test_runner trace data to. This option '
                          'has been implemented for gtest, instrumentation '
                          'test and perf test.')

  logcat_output_group = group.add_mutually_exclusive_group()
  logcat_output_group.add_argument(
      '--logcat-output-dir', type=os.path.realpath,
      help='If set, will dump logcats recorded during test run to directory. '
           'File names will be the device ids with timestamps.')
  logcat_output_group.add_argument(
      '--logcat-output-file', type=os.path.realpath,
      help='If set, will merge logcats recorded during test run and dump them '
           'to the specified file.')

  class FastLocalDevAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
      namespace.verbose_count = max(namespace.verbose_count, 1)
      namespace.num_retries = 0
      namespace.enable_device_cache = True
      namespace.enable_concurrent_adb = True
      namespace.skip_clear_data = True
      namespace.extract_test_list_from_filter = True

  group.add_argument('--fast-local-dev', type=bool, nargs=0,
                     action=FastLocalDevAction,
                     help='Alias for: --verbose --num-retries=0 '
                          '--enable-device-cache --enable-concurrent-adb '
                          '--skip-clear-data --extract-test-list-from-filter')

def ProcessCommonOptions(args):
  """Processes and handles all common options."""
  run_tests_helper.SetLogLevel(args.verbose_count)
  constants.SetBuildType(args.build_type)
  if args.build_directory:
    constants.SetBuildDirectory(args.build_directory)
  if args.output_directory:
    constants.SetOutputDirectory(args.output_directory)

  devil_chromium.Initialize(
      output_directory=constants.GetOutDirectory(),
      adb_path=args.adb_path)

  # Some things such as Forwarder require ADB to be in the environment path.
  adb_dir = os.path.dirname(constants.GetAdbPath())
  if adb_dir and adb_dir not in os.environ['PATH'].split(os.pathsep):
    os.environ['PATH'] = adb_dir + os.pathsep + os.environ['PATH']


def AddDeviceOptions(parser):
  """Adds device options to |parser|."""
  group = parser.add_argument_group(title='Device Options')
  group.add_argument('--tool',
                     dest='tool',
                     help=('Run the test under a tool '
                           '(use --tool help to list them)'))
  group.add_argument('-d', '--device', dest='test_device',
                     help=('Target device for the test suite '
                           'to run on.'))
  group.add_argument('--blacklist-file', type=os.path.realpath,
                     help='Device blacklist file.')
  group.add_argument('--enable-device-cache', action='store_true',
                     help='Cache device state to disk between runs')
  group.add_argument('--enable-concurrent-adb', action='store_true',
                     help='Run multiple adb commands at the same time, even '
                          'for the same device.')
  group.add_argument('--skip-clear-data', action='store_true',
                     help='Do not wipe app data between tests. Use this to '
                     'speed up local development and never on bots '
                     '(increases flakiness)')
  group.add_argument('--target-devices-file', type=os.path.realpath,
                     help='Path to file with json list of device serials to '
                          'run tests on. When not specified, all available '
                          'devices are used.')


def AddGTestOptions(parser):
  """Adds gtest options to |parser|."""

  group = parser.add_argument_group('GTest Options')
  group.add_argument('-s', '--suite', dest='suite_name',
                     nargs='+', metavar='SUITE_NAME', required=True,
                     help='Executable name of the test suite to run.')
  group.add_argument('--executable-dist-dir', type=os.path.realpath,
                     help="Path to executable's dist directory for native"
                          " (non-apk) tests.")
  group.add_argument('--test-apk-incremental-install-script',
                     type=os.path.realpath,
                     help='Path to install script for the test apk.')
  group.add_argument('--gtest_also_run_disabled_tests',
                     '--gtest-also-run-disabled-tests',
                     dest='run_disabled', action='store_true',
                     help='Also run disabled tests if applicable.')
  group.add_argument('-a', '--test-arguments', dest='test_arguments',
                     default='',
                     help='Additional arguments to pass to the test.')
  group.add_argument('-t', '--shard-timeout',
                     dest='shard_timeout', type=int, default=120,
                     help='Timeout to wait for each test '
                          '(default: %(default)s).')
  # TODO(jbudorick): Remove this after ensuring nothing else uses it.
  group.add_argument('--isolate_file_path',
                     '--isolate-file-path',
                     dest='isolate_file_path',
                     type=os.path.realpath,
                     help=argparse.SUPPRESS)
  group.add_argument('--runtime-deps-path',
                     dest='runtime_deps_path',
                     type=os.path.realpath,
                     help='Runtime data dependency file from GN.')
  group.add_argument('--app-data-file', action='append', dest='app_data_files',
                     help='A file path relative to the app data directory '
                          'that should be saved to the host.')
  group.add_argument('--app-data-file-dir',
                     help='Host directory to which app data files will be'
                          ' saved. Used with --app-data-file.')
  group.add_argument('--delete-stale-data', dest='delete_stale_data',
                     action='store_true',
                     help='Delete stale test data on the device.')
  group.add_argument('--extract-test-list-from-filter',
                     action='store_true',
                     help='When a test filter is specified, and the list of '
                          'tests can be determined from it, skip querying the '
                          'device for the list of all tests. Speeds up local '
                          'development, but is not safe to use on bots ('
                          'http://crbug.com/549214')
  group.add_argument('--enable-xml-result-parsing',
                     action='store_true',
                     help=argparse.SUPPRESS)
  group.add_argument('--store-tombstones', dest='store_tombstones',
                     action='store_true',
                     help='Add tombstones in results if crash.')

  filter_group = group.add_mutually_exclusive_group()
  filter_group.add_argument('-f', '--gtest_filter', '--gtest-filter',
                            dest='test_filter',
                            help='googletest-style filter string.')
  filter_group.add_argument('--gtest-filter-file', dest='test_filter_file',
                            type=os.path.realpath,
                            help='Path to file that contains googletest-style '
                                  'filter strings.  See also '
                                  '//testing/buildbot/filters/README.md.')

  AddDeviceOptions(parser)
  AddCommonOptions(parser)


def AddLinkerTestOptions(parser):
  group = parser.add_argument_group('Linker Test Options')
  group.add_argument('-f', '--gtest-filter', dest='test_filter',
                     help='googletest-style filter string.')
  group.add_argument('--test-apk', type=os.path.realpath,
                     help='Path to the linker test APK.')
  AddCommonOptions(parser)
  AddDeviceOptions(parser)


def AddJavaTestOptions(argument_group):
  """Adds the Java test options to |option_parser|."""

  argument_group.add_argument(
      '-f', '--test-filter', '--gtest_filter', '--gtest-filter',
      dest='test_filter',
      help=('Test filter (if not fully qualified, will run all matches).'))
  argument_group.add_argument(
      '-A', '--annotation', dest='annotation_str',
      help=('Comma-separated list of annotations. Run only tests with any of '
            'the given annotations. An annotation can be either a key or a '
            'key-values pair. A test that has no annotation is considered '
            '"SmallTest".'))
  argument_group.add_argument(
      '-E', '--exclude-annotation', dest='exclude_annotation_str',
      help=('Comma-separated list of annotations. Exclude tests with these '
            'annotations.'))
  argument_group.add_argument(
      '--screenshot-directory', dest='screenshot_dir', type=os.path.realpath,
      help='Capture screenshots of test failures')
  argument_group.add_argument(
      '--save-perf-json', action='store_true',
      help='Saves the JSON file for each UI Perf test.')
  argument_group.add_argument(
      '--official-build', action='store_true', help='Run official build tests.')
  argument_group.add_argument(
      '--disable-dalvik-asserts', dest='set_asserts', action='store_false',
      default=True, help='Removes the dalvik.vm.enableassertions property')
  argument_group.add_argument(
      '--gtest_also_run_disabled_tests', '--gtest-also-run-disabled-tests',
      dest='run_disabled', action='store_true',
      help='Also run disabled tests if applicable.')



def ProcessJavaTestOptions(args):
  """Processes options/arguments and populates |options| with defaults."""

  # TODO(jbudorick): Handle most of this function in argparse.
  if args.annotation_str:
    args.annotations = args.annotation_str.split(',')
  elif args.test_filter:
    args.annotations = []
  else:
    args.annotations = ['SmallTest', 'MediumTest', 'LargeTest', 'EnormousTest',
                        'IntegrationTest']

  if args.exclude_annotation_str:
    args.exclude_annotations = args.exclude_annotation_str.split(',')
  else:
    args.exclude_annotations = []


def AddInstrumentationTestOptions(parser):
  """Adds Instrumentation test options to |parser|."""

  parser.usage = '%(prog)s [options]'

  group = parser.add_argument_group('Instrumentation Test Options')
  AddJavaTestOptions(group)

  java_or_python_group = group.add_mutually_exclusive_group()
  java_or_python_group.add_argument(
      '-j', '--java-only', action='store_false',
      dest='run_python_tests', default=True, help='Run only the Java tests.')
  java_or_python_group.add_argument(
      '-p', '--python-only', action='store_false',
      dest='run_java_tests', default=True,
      help='DEPRECATED')

  group.add_argument('--host-driven-root',
                     help='DEPRECATED')
  group.add_argument('-w', '--wait_debugger', dest='wait_for_debugger',
                     action='store_true',
                     help='Wait for debugger.')
  # TODO(jbudorick): Remove support for name-style APK specification once
  # bots are no longer doing it.
  group.add_argument('--apk-under-test',
                     help='Path or name of the apk under test.')
  group.add_argument('--apk-under-test-incremental-install-script',
                     help='Path to install script for the --apk-under-test.')
  group.add_argument('--test-apk', required=True,
                     help='Path or name of the apk containing the tests '
                          '(name is without the .apk extension; '
                          'e.g. "ContentShellTest").')
  group.add_argument('--test-jar',
                     help='Path of jar containing test java files.')
  group.add_argument('--test-apk-incremental-install-script',
                     type=os.path.realpath,
                     help='Path to install script for the --test-apk.')
  group.add_argument('--additional-apk', action='append',
                     dest='additional_apks', default=[],
                     type=os.path.realpath,
                     help='Additional apk that must be installed on '
                          'the device when the tests are run')
  group.add_argument('--coverage-dir', type=os.path.realpath,
                     help=('Directory in which to place all generated '
                           'EMMA coverage files.'))
  group.add_argument('--device-flags', dest='device_flags',
                     type=os.path.realpath,
                     help='The relative filepath to a file containing '
                          'command-line flags to set on the device')
  group.add_argument('--device-flags-file', type=os.path.realpath,
                     help='The relative filepath to a file containing '
                          'command-line flags to set on the device')
  # TODO(jbudorick): Remove this after ensuring nothing else uses it.
  group.add_argument('--isolate_file_path',
                     '--isolate-file-path',
                     dest='isolate_file_path',
                     type=os.path.realpath,
                     help=argparse.SUPPRESS)
  group.add_argument('--runtime-deps-path',
                     dest='runtime_deps_path',
                     type=os.path.realpath,
                     help='Runtime data dependency file from GN.')
  group.add_argument('--delete-stale-data', dest='delete_stale_data',
                     action='store_true',
                     help='Delete stale test data on the device.')
  group.add_argument('--timeout-scale', type=float,
                     help='Factor by which timeouts should be scaled.')
  group.add_argument('--strict-mode', dest='strict_mode', default='testing',
                     help='StrictMode command-line flag set on the device, '
                          'death/testing to kill the process, off to stop '
                          'checking, flash to flash only. Default testing.')
  group.add_argument('--regenerate-goldens', dest='regenerate_goldens',
                     action='store_true',
                     help='Causes the render tests to not fail when a check'
                          'fails or the golden image is missing but to render'
                          'the view and carry on.')
  group.add_argument('--store-tombstones', dest='store_tombstones',
                     action='store_true',
                     help='Add tombstones in results if crash.')
  group.add_argument('--shared-prefs-file', dest='shared_prefs_file',
                     type=os.path.realpath,
                     help='The relative path to a file containing JSON list '
                          'of shared preference files to edit and how to do '
                          'so. Example list: '
                          '[{'
                          '  "package": "com.package.example",'
                          '  "filename": "ExampleSettings.xml",'
                          '  "set": {'
                          '    "boolean_key_in_xml": true,'
                          '    "string_key_in_xml": "string_value"'
                          '  },'
                          '  "remove": ['
                          '    "key_in_xml_to_remove"'
                          '  ]'
                          '}]')

  AddCommonOptions(parser)
  AddDeviceOptions(parser)


def AddJUnitTestOptions(parser):
  """Adds junit test options to |parser|."""

  group = parser.add_argument_group('JUnit Test Options')
  group.add_argument(
      '-s', '--test-suite', dest='test_suite', required=True,
      help=('JUnit test suite to run.'))
  group.add_argument(
      '-f', '--test-filter', dest='test_filter',
      help='Filters tests googletest-style.')
  group.add_argument(
      '--package-filter', dest='package_filter',
      help='Filters tests by package.')
  group.add_argument(
      '--runner-filter', dest='runner_filter',
      help='Filters tests by runner class. Must be fully qualified.')
  group.add_argument(
      '--coverage-dir', dest='coverage_dir', type=os.path.realpath,
      help='Directory to store coverage info.')
  AddCommonOptions(parser)


def AddMonkeyTestOptions(parser):
  """Adds monkey test options to |parser|."""

  group = parser.add_argument_group('Monkey Test Options')
  group.add_argument(
      '--browser', required=True, choices=constants.PACKAGE_INFO.keys(),
      metavar='BROWSER', help='Browser under test.')
  group.add_argument(
      '--event-count', default=10000, type=int,
      help='Number of events to generate (default: %(default)s).')
  group.add_argument(
      '--category', nargs='*', dest='categories', default=[],
      help='A list of allowed categories. Monkey will only visit activities '
           'that are listed with one of the specified categories.')
  group.add_argument(
      '--throttle', default=100, type=int,
      help='Delay between events (ms) (default: %(default)s). ')
  group.add_argument(
      '--seed', type=int,
      help='Seed value for pseudo-random generator. Same seed value generates '
           'the same sequence of events. Seed is randomized by default.')
  AddCommonOptions(parser)
  AddDeviceOptions(parser)


def AddPerfTestOptions(parser):
  """Adds perf test options to |parser|."""

  group = parser.add_argument_group('Perf Test Options')

  class SingleStepAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
      if values and not namespace.single_step:
        parser.error('single step command provided, '
                     'but --single-step not specified.')
      elif namespace.single_step and not values:
        parser.error('--single-step specified, '
                     'but no single step command provided.')
      setattr(namespace, self.dest, values)

  step_group = group.add_mutually_exclusive_group(required=True)
  # TODO(jbudorick): Revise --single-step to use argparse.REMAINDER.
  # This requires removing "--" from client calls.
  step_group.add_argument(
      '--single-step', action='store_true',
      help='Execute the given command with retries, but only print the result '
           'for the "most successful" round.')
  step_group.add_argument(
      '--steps',
      help='JSON file containing the list of commands to run.')
  step_group.add_argument(
      '--print-step',
      help='The name of a previously executed perf step to print.')

  group.add_argument(
      '--output-json-list', type=os.path.realpath,
      help='Writes a JSON list of information for each --steps into the given '
           'file. Information includes runtime and device affinity for each '
           '--steps.')
  group.add_argument(
      '--collect-chartjson-data',
      action='store_true',
      help='Cache the telemetry chartjson output from each step for later use.')
  group.add_argument(
      '--output-chartjson-data',
      type=os.path.realpath,
      help='Writes telemetry chartjson formatted output into the given file.')
  group.add_argument(
      '--collect-json-data',
      action='store_true',
      help='Cache the telemetry JSON output from each step for later use.')
  group.add_argument(
      '--output-json-data',
      type=os.path.realpath,
      help='Writes telemetry JSON formatted output into the given file.')
  # TODO(rnephew): Remove this when everything moves to new option in platform
  # mode.
  group.add_argument(
      '--get-output-dir-archive', metavar='FILENAME', type=os.path.realpath,
      help='Write the cached output directory archived by a step into the'
      ' given ZIP file.')
  group.add_argument(
      '--output-dir-archive-path', metavar='FILENAME', type=os.path.realpath,
      help='Write the cached output directory archived by a step into the'
      ' given ZIP file.')
  group.add_argument(
      '--flaky-steps', type=os.path.realpath,
      help=('A JSON file containing steps that are flaky '
            'and will have its exit code ignored.'))
  group.add_argument(
      '--no-timeout', action='store_true',
      help=('Do not impose a timeout. Each perf step is responsible for '
            'implementing the timeout logic.'))
  group.add_argument(
      '-f', '--test-filter',
      help=('Test filter (will match against the names listed in --steps).'))
  group.add_argument(
      '--dry-run', action='store_true',
      help='Just print the steps without executing.')
  # Uses 0.1 degrees C because that's what Android does.
  group.add_argument(
      '--max-battery-temp', type=int,
      help='Only start tests when the battery is at or below the given '
           'temperature (0.1 C)')
  group.add_argument(
      'single_step_command', nargs='*', action=SingleStepAction,
      help='If --single-step is specified, the command to run.')
  group.add_argument(
      '--min-battery-level', type=int,
      help='Only starts tests when the battery is charged above '
      'given level.')
  group.add_argument('--known-devices-file', help='Path to known device list.')
  group.add_argument(
      '--write-buildbot-json', action='store_true',
      help='Whether to output buildbot json.')
  AddCommonOptions(parser)
  AddDeviceOptions(parser)


def AddPythonTestOptions(parser):
  group = parser.add_argument_group('Python Test Options')
  group.add_argument(
      '-s', '--suite', dest='suite_name', metavar='SUITE_NAME',
      choices=constants.PYTHON_UNIT_TEST_SUITES.keys(),
      help='Name of the test suite to run.')
  AddCommonOptions(parser)


def _RunPythonTests(args):
  """Subcommand of RunTestsCommand which runs python unit tests."""
  suite_vars = constants.PYTHON_UNIT_TEST_SUITES[args.suite_name]
  suite_path = suite_vars['path']
  suite_test_modules = suite_vars['test_modules']

  sys.path = [suite_path] + sys.path
  try:
    suite = unittest.TestSuite()
    suite.addTests(unittest.defaultTestLoader.loadTestsFromName(m)
                   for m in suite_test_modules)
    runner = unittest.TextTestRunner(verbosity=1+args.verbose_count)
    return 0 if runner.run(suite).wasSuccessful() else 1
  finally:
    sys.path = sys.path[1:]


def _GetAttachedDevices(blacklist_file, test_device, enable_cache, num_retries):
  """Get all attached devices.

  Args:
    blacklist_file: Path to device blacklist.
    test_device: Name of a specific device to use.
    enable_cache: Whether to enable checksum caching.

  Returns:
    A list of attached devices.
  """
  blacklist = (device_blacklist.Blacklist(blacklist_file)
               if blacklist_file
               else None)

  attached_devices = device_utils.DeviceUtils.HealthyDevices(
      blacklist, enable_device_files_cache=enable_cache,
      default_retries=num_retries)
  if test_device:
    test_device = [d for d in attached_devices if d == test_device]
    if not test_device:
      raise device_errors.DeviceUnreachableError(
          'Did not find device %s among attached device. Attached devices: %s'
          % (test_device, ', '.join(attached_devices)))
    return test_device

  else:
    if not attached_devices:
      raise device_errors.NoDevicesError()
    return sorted(attached_devices)


_DEFAULT_PLATFORM_MODE_TESTS = ['gtest', 'instrumentation', 'junit',
                                'linker', 'monkey', 'perf']


def RunTestsCommand(args): # pylint: disable=too-many-return-statements
  """Checks test type and dispatches to the appropriate function.

  Args:
    args: argparse.Namespace object.

  Returns:
    Integer indicated exit code.

  Raises:
    Exception: Unknown command name passed in, or an exception from an
        individual test runner.
  """
  command = args.command

  ProcessCommonOptions(args)
  logging.info('command: %s', ' '.join(sys.argv))
  if args.enable_platform_mode or command in _DEFAULT_PLATFORM_MODE_TESTS:
    return RunTestsInPlatformMode(args)

  forwarder.Forwarder.RemoveHostLog()
  if not ports.ResetTestServerPortAllocation():
    raise Exception('Failed to reset test server port.')

  # pylint: disable=protected-access
  if os.path.exists(ports._TEST_SERVER_PORT_LOCKFILE):
    os.unlink(ports._TEST_SERVER_PORT_LOCKFILE)
  # pylint: enable=protected-access

  if command == 'python':
    return _RunPythonTests(args)
  else:
    raise Exception('Unknown test type.')


_SUPPORTED_IN_PLATFORM_MODE = [
  # TODO(jbudorick): Add support for more test types.
  'gtest',
  'instrumentation',
  'junit',
  'linker',
  'monkey',
  'perf',
]


def RunTestsInPlatformMode(args):

  def infra_error(message):
    logging.fatal(message)
    sys.exit(constants.INFRA_EXIT_CODE)

  if args.command not in _SUPPORTED_IN_PLATFORM_MODE:
    infra_error('%s is not yet supported in platform mode' % args.command)

  ### Set up sigterm handler.

  def unexpected_sigterm(_signum, _frame):
    msg = [
      'Received SIGTERM. Shutting down.',
    ]
    for live_thread in threading.enumerate():
      # pylint: disable=protected-access
      thread_stack = ''.join(traceback.format_stack(
          sys._current_frames()[live_thread.ident]))
      msg.extend([
        'Thread "%s" (ident: %s) is currently running:' % (
            live_thread.name, live_thread.ident),
        thread_stack])

    infra_error('\n'.join(msg))

  signal.signal(signal.SIGTERM, unexpected_sigterm)

  ### Set up results handling.
  # TODO(jbudorick): Rewrite results handling.

  # all_raw_results is a list of lists of
  # base_test_result.TestRunResults objects. Each instance of
  # TestRunResults contains all test results produced by a single try,
  # while each list of TestRunResults contains all tries in a single
  # iteration.
  all_raw_results = []

  # all_iteration_results is a list of base_test_result.TestRunResults
  # objects. Each instance of TestRunResults contains the last test
  # result for each test run in that iteration.
  all_iteration_results = []

  @contextlib.contextmanager
  def write_json_file():
    try:
      yield
    finally:
      json_results.GenerateJsonResultsFile(
          all_raw_results, args.json_results_file)

  json_writer = contextlib_ext.Optional(
      write_json_file(),
      args.json_results_file)

  ### Set up test objects.

  env = environment_factory.CreateEnvironment(args, infra_error)
  test_instance = test_instance_factory.CreateTestInstance(args, infra_error)
  test_run = test_run_factory.CreateTestRun(
      args, env, test_instance, infra_error)

  ### Run.

  with json_writer, env, test_instance, test_run:

    repetitions = (xrange(args.repeat + 1) if args.repeat >= 0
                   else itertools.count())
    result_counts = collections.defaultdict(
        lambda: collections.defaultdict(int))
    iteration_count = 0
    for _ in repetitions:
      raw_results = test_run.RunTests()
      if not raw_results:
        continue

      all_raw_results.append(raw_results)

      iteration_results = base_test_result.TestRunResults()
      for r in reversed(raw_results):
        iteration_results.AddTestRunResults(r)
      all_iteration_results.append(iteration_results)

      iteration_count += 1
      for r in iteration_results.GetAll():
        result_counts[r.GetName()][r.GetType()] += 1
      report_results.LogFull(
          results=iteration_results,
          test_type=test_instance.TestType(),
          test_package=test_run.TestPackage(),
          annotation=getattr(args, 'annotations', None),
          flakiness_server=getattr(args, 'flakiness_dashboard_server',
                                   None))
      if args.break_on_failure and not iteration_results.DidRunPass():
        break

    if iteration_count > 1:
      # display summary results
      # only display results for a test if at least one test did not pass
      all_pass = 0
      tot_tests = 0
      for test_name in result_counts:
        tot_tests += 1
        if any(result_counts[test_name][x] for x in (
            base_test_result.ResultType.FAIL,
            base_test_result.ResultType.CRASH,
            base_test_result.ResultType.TIMEOUT,
            base_test_result.ResultType.UNKNOWN)):
          logging.critical(
              '%s: %s',
              test_name,
              ', '.join('%s %s' % (str(result_counts[test_name][i]), i)
                        for i in base_test_result.ResultType.GetTypes()))
        else:
          all_pass += 1

      logging.critical('%s of %s tests passed in all %s runs',
                       str(all_pass),
                       str(tot_tests),
                       str(iteration_count))

  if args.command == 'perf' and (args.steps or args.single_step):
    return 0

  return (0 if all(r.DidRunPass() for r in all_iteration_results)
          else constants.ERROR_EXIT_CODE)


CommandConfigTuple = collections.namedtuple(
    'CommandConfigTuple',
    ['add_options_func', 'help_txt'])
VALID_COMMANDS = {
    'gtest': CommandConfigTuple(
        AddGTestOptions,
        'googletest-based C++ tests'),
    'instrumentation': CommandConfigTuple(
        AddInstrumentationTestOptions,
        'InstrumentationTestCase-based Java tests'),
    'junit': CommandConfigTuple(
        AddJUnitTestOptions,
        'JUnit4-based Java tests'),
    'monkey': CommandConfigTuple(
        AddMonkeyTestOptions,
        "Tests based on Android's monkey"),
    'perf': CommandConfigTuple(
        AddPerfTestOptions,
        'Performance tests'),
    'python': CommandConfigTuple(
        AddPythonTestOptions,
        'Python tests based on unittest.TestCase'),
    'linker': CommandConfigTuple(
        AddLinkerTestOptions,
        'Linker tests'),
}


def DumpThreadStacks(_signal, _frame):
  for thread in threading.enumerate():
    reraiser_thread.LogThreadStack(thread)


def main():
  signal.signal(signal.SIGUSR1, DumpThreadStacks)

  parser = argparse.ArgumentParser()
  command_parsers = parser.add_subparsers(title='test types',
                                          dest='command')

  for test_type, config in sorted(VALID_COMMANDS.iteritems(),
                                  key=lambda x: x[0]):
    subparser = command_parsers.add_parser(
        test_type, usage='%(prog)s [options]', help=config.help_txt)
    config.add_options_func(subparser)

  args = parser.parse_args()

  try:
    return RunTestsCommand(args)
  except base_error.BaseError as e:
    logging.exception('Error occurred.')
    if e.is_infra_error:
      return constants.INFRA_EXIT_CODE
    return constants.ERROR_EXIT_CODE
  except: # pylint: disable=W0702
    logging.exception('Unrecognized error occurred.')
    return constants.ERROR_EXIT_CODE


if __name__ == '__main__':
  sys.exit(main())
