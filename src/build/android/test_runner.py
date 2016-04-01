#!/usr/bin/env python
#
# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Runs all types of tests from one unified interface."""

import argparse
import collections
import itertools
import logging
import os
import signal
import sys
import threading
import unittest

import devil_chromium
from devil import base_error
from devil import devil_env
from devil.android import apk_helper
from devil.android import device_blacklist
from devil.android import device_errors
from devil.android import device_utils
from devil.android import forwarder
from devil.android import ports
from devil.utils import reraiser_thread
from devil.utils import run_tests_helper

from pylib import constants
from pylib.constants import host_paths
from pylib.base import base_test_result
from pylib.base import environment_factory
from pylib.base import test_dispatcher
from pylib.base import test_instance_factory
from pylib.base import test_run_factory
from pylib.linker import setup as linker_setup
from pylib.host_driven import setup as host_driven_setup
from pylib.instrumentation import setup as instrumentation_setup
from pylib.instrumentation import test_options as instrumentation_test_options
from pylib.junit import setup as junit_setup
from pylib.junit import test_dispatcher as junit_dispatcher
from pylib.monkey import setup as monkey_setup
from pylib.monkey import test_options as monkey_test_options
from pylib.perf import setup as perf_setup
from pylib.perf import test_options as perf_test_options
from pylib.perf import test_runner as perf_test_runner
from pylib.results import json_results
from pylib.results import report_results


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

  group.add_argument('--build-directory', dest='build_directory',
                     help=('Path to the directory in which build files are'
                           ' located (should not include build type)'))
  group.add_argument('--output-directory', dest='output_directory',
                     help=('Path to the directory in which build files are'
                           ' located (must include build type). This will take'
                           ' precedence over --debug, --release and'
                           ' --build-directory'))
  group.add_argument('--num_retries', '--num-retries', dest='num_retries',
                     type=int, default=2,
                     help=('Number of retries for a test before '
                           'giving up (default: %(default)s).'))
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
  group.add_argument('--adb-path',
                     help=('Specify the absolute path of the adb binary that '
                           'should be used.'))
  group.add_argument('--json-results-file', '--test-launcher-summary-output',
                     dest='json_results_file',
                     help='If set, will dump results in JSON form '
                          'to specified file.')

  logcat_output_group = group.add_mutually_exclusive_group()
  logcat_output_group.add_argument(
      '--logcat-output-dir',
      help='If set, will dump logcats recorded during test run to directory. '
           'File names will be the device ids with timestamps.')
  logcat_output_group.add_argument(
      '--logcat-output-file',
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

  devil_custom_deps = None
  if args.adb_path:
    devil_custom_deps = {
      'adb': {
        devil_env.GetPlatform(): [args.adb_path]
      }
    }

  devil_chromium.Initialize(
      output_directory=constants.GetOutDirectory(),
      custom_deps=devil_custom_deps)

  # Some things such as Forwarder require ADB to be in the environment path.
  adb_dir = os.path.dirname(constants.GetAdbPath())
  if adb_dir and adb_dir not in os.environ['PATH'].split(os.pathsep):
    os.environ['PATH'] = adb_dir + os.pathsep + os.environ['PATH']


def AddRemoteDeviceOptions(parser):
  group = parser.add_argument_group('Remote Device Options')

  group.add_argument('--trigger',
                     help=('Only triggers the test if set. Stores test_run_id '
                           'in given file path. '))
  group.add_argument('--collect',
                     help=('Only collects the test results if set. '
                           'Gets test_run_id from given file path.'))
  group.add_argument('--remote-device', action='append',
                     help='Device type to run test on.')
  group.add_argument('--results-path',
                     help='File path to download results to.')
  group.add_argument('--api-protocol',
                     help='HTTP protocol to use. (http or https)')
  group.add_argument('--api-address',
                     help='Address to send HTTP requests.')
  group.add_argument('--api-port',
                     help='Port to send HTTP requests to.')
  group.add_argument('--runner-type',
                     help='Type of test to run as.')
  group.add_argument('--runner-package',
                     help='Package name of test.')
  group.add_argument('--device-type',
                     choices=constants.VALID_DEVICE_TYPES,
                     help=('Type of device to run on. iOS or android'))
  group.add_argument('--device-oem', action='append',
                     help='Device OEM to run on.')
  group.add_argument('--remote-device-file',
                     help=('File with JSON to select remote device. '
                           'Overrides all other flags.'))
  group.add_argument('--remote-device-timeout', type=int,
                     help='Times to retry finding remote device')
  group.add_argument('--network-config', type=int,
                     help='Integer that specifies the network environment '
                          'that the tests will be run in.')
  group.add_argument('--test-timeout', type=int,
                     help='Test run timeout in seconds.')

  device_os_group = group.add_mutually_exclusive_group()
  device_os_group.add_argument('--remote-device-minimum-os',
                               help='Minimum OS on device.')
  device_os_group.add_argument('--remote-device-os', action='append',
                               help='OS to have on the device.')

  api_secret_group = group.add_mutually_exclusive_group()
  api_secret_group.add_argument('--api-secret', default='',
                                help='API secret for remote devices.')
  api_secret_group.add_argument('--api-secret-file', default='',
                                help='Path to file that contains API secret.')

  api_key_group = group.add_mutually_exclusive_group()
  api_key_group.add_argument('--api-key', default='',
                             help='API key for remote devices.')
  api_key_group.add_argument('--api-key-file', default='',
                             help='Path to file that contains API key.')


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
  group.add_argument('--blacklist-file', help='Device blacklist file.')
  group.add_argument('--enable-device-cache', action='store_true',
                     help='Cache device state to disk between runs')
  group.add_argument('--enable-concurrent-adb', action='store_true',
                     help='Run multiple adb commands at the same time, even '
                          'for the same device.')
  group.add_argument('--skip-clear-data', action='store_true',
                     help='Do not wipe app data between tests. Use this to '
                     'speed up local development and never on bots '
                     '(increases flakiness)')


def AddGTestOptions(parser):
  """Adds gtest options to |parser|."""

  group = parser.add_argument_group('GTest Options')
  group.add_argument('-s', '--suite', dest='suite_name',
                     nargs='+', metavar='SUITE_NAME', required=True,
                     help='Executable name of the test suite to run.')
  group.add_argument('--test-apk-incremental-install-script',
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
  group.add_argument('--isolate_file_path',
                     '--isolate-file-path',
                     dest='isolate_file_path',
                     help='.isolate file path to override the default '
                          'path')
  group.add_argument('--app-data-file', action='append', dest='app_data_files',
                     help='A file path relative to the app data directory '
                          'that should be saved to the host.')
  group.add_argument('--app-data-file-dir',
                     help='Host directory to which app data files will be'
                          ' saved. Used with --app-data-file.')
  group.add_argument('--delete-stale-data', dest='delete_stale_data',
                     action='store_true',
                     help='Delete stale test data on the device.')
  group.add_argument('--repeat', '--gtest_repeat', '--gtest-repeat',
                     dest='repeat', type=int, default=0,
                     help='Number of times to repeat the specified set of '
                          'tests.')
  group.add_argument('--break-on-failure', '--break_on_failure',
                     dest='break_on_failure', action='store_true',
                     help='Whether to break on failure.')
  group.add_argument('--extract-test-list-from-filter',
                     action='store_true',
                     help='When a test filter is specified, and the list of '
                          'tests can be determined from it, skip querying the '
                          'device for the list of all tests. Speeds up local '
                          'development, but is not safe to use on bots ('
                          'http://crbug.com/549214')

  filter_group = group.add_mutually_exclusive_group()
  filter_group.add_argument('-f', '--gtest_filter', '--gtest-filter',
                            dest='test_filter',
                            help='googletest-style filter string.')
  filter_group.add_argument('--gtest-filter-file', dest='test_filter_file',
                            help='Path to file that contains googletest-style '
                                  'filter strings. (Lines will be joined with '
                                  '":" to create a single filter string.)')

  AddDeviceOptions(parser)
  AddCommonOptions(parser)
  AddRemoteDeviceOptions(parser)


def AddLinkerTestOptions(parser):
  group = parser.add_argument_group('Linker Test Options')
  group.add_argument('-f', '--gtest-filter', dest='test_filter',
                     help='googletest-style filter string.')
  AddCommonOptions(parser)
  AddDeviceOptions(parser)


def AddJavaTestOptions(argument_group):
  """Adds the Java test options to |option_parser|."""

  argument_group.add_argument(
      '-f', '--test-filter', dest='test_filter',
      help=('Test filter (if not fully qualified, will run all matches).'))
  argument_group.add_argument(
      '--repeat', dest='repeat', type=int, default=0,
      help='Number of times to repeat the specified set of tests.')
  argument_group.add_argument(
      '--break-on-failure', '--break_on_failure',
      dest='break_on_failure', action='store_true',
      help='Whether to break on failure.')
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
      '--screenshot', dest='screenshot_failures', action='store_true',
      help='Capture screenshots of test failures')
  argument_group.add_argument(
      '--save-perf-json', action='store_true',
      help='Saves the JSON file for each UI Perf test.')
  argument_group.add_argument(
      '--official-build', action='store_true', help='Run official build tests.')
  argument_group.add_argument(
      '--test_data', '--test-data', action='append', default=[],
      help=('Each instance defines a directory of test data that should be '
            'copied to the target(s) before running the tests. The argument '
            'should be of the form <target>:<source>, <target> is relative to '
            'the device data directory, and <source> is relative to the '
            'chromium build directory.'))
  argument_group.add_argument(
      '--disable-dalvik-asserts', dest='set_asserts', action='store_false',
      default=True, help='Removes the dalvik.vm.enableassertions property')



def ProcessJavaTestOptions(args):
  """Processes options/arguments and populates |options| with defaults."""

  # TODO(jbudorick): Handle most of this function in argparse.
  if args.annotation_str:
    args.annotations = args.annotation_str.split(',')
  elif args.test_filter:
    args.annotations = []
  else:
    args.annotations = ['Smoke', 'SmallTest', 'MediumTest', 'LargeTest',
                        'EnormousTest', 'IntegrationTest']

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
      help='Run only the host-driven tests.')

  group.add_argument('--host-driven-root',
                     help='Root of the host-driven tests.')
  group.add_argument('-w', '--wait_debugger', dest='wait_for_debugger',
                     action='store_true',
                     help='Wait for debugger.')
  group.add_argument('--apk-under-test',
                     help='Path or name of the apk under test.')
  group.add_argument('--apk-under-test-incremental-install-script',
                     help='Path to install script for the --apk-under-test.')
  group.add_argument('--test-apk', required=True,
                     help='Path or name of the apk containing the tests '
                          '(name is without the .apk extension; '
                          'e.g. "ContentShellTest").')
  group.add_argument('--test-apk-incremental-install-script',
                     help='Path to install script for the --test-apk.')
  group.add_argument('--additional-apk', action='append',
                     dest='additional_apks', default=[],
                     help='Additional apk that must be installed on '
                          'the device when the tests are run')
  group.add_argument('--coverage-dir',
                     help=('Directory in which to place all generated '
                           'EMMA coverage files.'))
  group.add_argument('--device-flags', dest='device_flags', default='',
                     help='The relative filepath to a file containing '
                          'command-line flags to set on the device')
  group.add_argument('--device-flags-file', default='',
                     help='The relative filepath to a file containing '
                          'command-line flags to set on the device')
  group.add_argument('--isolate_file_path',
                     '--isolate-file-path',
                     dest='isolate_file_path',
                     help='.isolate file path to override the default '
                          'path')
  group.add_argument('--delete-stale-data', dest='delete_stale_data',
                     action='store_true',
                     help='Delete stale test data on the device.')
  group.add_argument('--timeout-scale', type=float,
                     help='Factor by which timeouts should be scaled.')
  group.add_argument('--strict-mode', dest='strict_mode', default='testing',
                     help='StrictMode command-line flag set on the device, '
                          'death/testing to kill the process, off to stop '
                          'checking, flash to flash only. Default testing.')

  AddCommonOptions(parser)
  AddDeviceOptions(parser)
  AddRemoteDeviceOptions(parser)


def ProcessInstrumentationOptions(args):
  """Processes options/arguments and populate |options| with defaults.

  Args:
    args: argparse.Namespace object.

  Returns:
    An InstrumentationOptions named tuple which contains all options relevant to
    instrumentation tests.
  """

  ProcessJavaTestOptions(args)

  if not args.host_driven_root:
    args.run_python_tests = False

  if os.path.exists(args.test_apk):
    args.test_apk_path = args.test_apk
    args.test_apk, _ = os.path.splitext(os.path.basename(args.test_apk))
  else:
    args.test_apk_path = os.path.join(
        constants.GetOutDirectory(),
        constants.SDK_BUILD_APKS_DIR,
        '%s.apk' % args.test_apk)

  jar_basename = args.test_apk
  if jar_basename.endswith('_incremental'):
    jar_basename = jar_basename[:-len('_incremental')]

  args.test_apk_jar_path = os.path.join(
      constants.GetOutDirectory(),
      constants.SDK_BUILD_TEST_JAVALIB_DIR,
      '%s.jar' % jar_basename)
  args.test_support_apk_path = '%sSupport%s' % (
      os.path.splitext(args.test_apk_path))

  args.test_runner = apk_helper.GetInstrumentationName(args.test_apk_path)

  # TODO(jbudorick): Get rid of InstrumentationOptions.
  return instrumentation_test_options.InstrumentationOptions(
      args.tool,
      args.annotations,
      args.exclude_annotations,
      args.test_filter,
      args.test_data,
      args.save_perf_json,
      args.screenshot_failures,
      args.wait_for_debugger,
      args.coverage_dir,
      args.test_apk,
      args.test_apk_path,
      args.test_apk_jar_path,
      args.test_runner,
      args.test_support_apk_path,
      args.device_flags,
      args.isolate_file_path,
      args.set_asserts,
      args.delete_stale_data,
      args.timeout_scale,
      args.apk_under_test,
      args.additional_apks,
      args.strict_mode,
      args.skip_clear_data,
      args.test_apk_incremental_install_script,
      args.apk_under_test_incremental_install_script)


def AddUIAutomatorTestOptions(parser):
  """Adds UI Automator test options to |parser|."""

  group = parser.add_argument_group('UIAutomator Test Options')
  AddJavaTestOptions(group)
  group.add_argument(
      '--package', required=True, choices=constants.PACKAGE_INFO.keys(),
      metavar='PACKAGE', help='Package under test.')
  group.add_argument(
      '--test-jar', dest='test_jar', required=True,
      help=('The name of the dexed jar containing the tests (without the '
            '.dex.jar extension). Alternatively, this can be a full path '
            'to the jar.'))

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
      '--sdk-version', dest='sdk_version', type=int,
      help='The Android SDK version.')
  AddCommonOptions(parser)


def AddMonkeyTestOptions(parser):
  """Adds monkey test options to |parser|."""

  group = parser.add_argument_group('Monkey Test Options')
  group.add_argument(
      '--package', required=True, choices=constants.PACKAGE_INFO.keys(),
      metavar='PACKAGE', help='Package under test.')
  group.add_argument(
      '--event-count', default=10000, type=int,
      help='Number of events to generate (default: %(default)s).')
  group.add_argument(
      '--category', default='',
      help='A list of allowed categories.')
  group.add_argument(
      '--throttle', default=100, type=int,
      help='Delay between events (ms) (default: %(default)s). ')
  group.add_argument(
      '--seed', type=int,
      help=('Seed value for pseudo-random generator. Same seed value generates '
            'the same sequence of events. Seed is randomized by default.'))
  group.add_argument(
      '--extra-args', default='',
      help=('String of other args to pass to the command verbatim.'))

  AddCommonOptions(parser)
  AddDeviceOptions(parser)

def ProcessMonkeyTestOptions(args):
  """Processes all monkey test options.

  Args:
    args: argparse.Namespace object.

  Returns:
    A MonkeyOptions named tuple which contains all options relevant to
    monkey tests.
  """
  # TODO(jbudorick): Handle this directly in argparse with nargs='+'
  category = args.category
  if category:
    category = args.category.split(',')

  # TODO(jbudorick): Get rid of MonkeyOptions.
  return monkey_test_options.MonkeyOptions(
      args.verbose_count,
      args.package,
      args.event_count,
      category,
      args.throttle,
      args.seed,
      args.extra_args)

def AddUirobotTestOptions(parser):
  """Adds uirobot test options to |option_parser|."""
  group = parser.add_argument_group('Uirobot Test Options')

  group.add_argument('--app-under-test', required=True,
                     help='APK to run tests on.')
  group.add_argument(
      '--repeat', dest='repeat', type=int, default=0,
      help='Number of times to repeat the uirobot test.')
  group.add_argument(
      '--minutes', default=5, type=int,
      help='Number of minutes to run uirobot test [default: %(default)s].')

  AddCommonOptions(parser)
  AddDeviceOptions(parser)
  AddRemoteDeviceOptions(parser)

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
      '--output-json-list',
      help='Write a simple list of names from --steps into the given file.')
  group.add_argument(
      '--collect-chartjson-data',
      action='store_true',
      help='Cache the chartjson output from each step for later use.')
  group.add_argument(
      '--output-chartjson-data',
      default='',
      help='Write out chartjson into the given file.')
  group.add_argument(
      '--get-output-dir-archive', metavar='FILENAME',
      help='Write the chached output directory archived by a step into the'
      ' given ZIP file.')
  group.add_argument(
      '--flaky-steps',
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
  group.add_argument('single_step_command', nargs='*', action=SingleStepAction,
                     help='If --single-step is specified, the command to run.')
  group.add_argument('--min-battery-level', type=int,
                     help='Only starts tests when the battery is charged above '
                          'given level.')
  group.add_argument('--known-devices-file', help='Path to known device list.')
  AddCommonOptions(parser)
  AddDeviceOptions(parser)


def ProcessPerfTestOptions(args):
  """Processes all perf test options.

  Args:
    args: argparse.Namespace object.

  Returns:
    A PerfOptions named tuple which contains all options relevant to
    perf tests.
  """
  # TODO(jbudorick): Move single_step handling down into the perf tests.
  if args.single_step:
    args.single_step = ' '.join(args.single_step_command)
  # TODO(jbudorick): Get rid of PerfOptions.
  return perf_test_options.PerfOptions(
      args.steps, args.flaky_steps, args.output_json_list,
      args.print_step, args.no_timeout, args.test_filter,
      args.dry_run, args.single_step, args.collect_chartjson_data,
      args.output_chartjson_data, args.get_output_dir_archive,
      args.max_battery_temp, args.min_battery_level,
      args.known_devices_file)


def AddPythonTestOptions(parser):
  group = parser.add_argument_group('Python Test Options')
  group.add_argument(
      '-s', '--suite', dest='suite_name', metavar='SUITE_NAME',
      choices=constants.PYTHON_UNIT_TEST_SUITES.keys(),
      help='Name of the test suite to run.')
  AddCommonOptions(parser)


def _RunLinkerTests(args, devices):
  """Subcommand of RunTestsCommands which runs linker tests."""
  runner_factory, tests = linker_setup.Setup(args, devices)

  results, exit_code = test_dispatcher.RunTests(
      tests, runner_factory, devices, shard=True, test_timeout=60,
      num_retries=args.num_retries)

  report_results.LogFull(
      results=results,
      test_type='Linker test',
      test_package='ChromiumLinkerTest')

  if args.json_results_file:
    json_results.GenerateJsonResultsFile([results], args.json_results_file)

  return exit_code


def _RunInstrumentationTests(args, devices):
  """Subcommand of RunTestsCommands which runs instrumentation tests."""
  logging.info('_RunInstrumentationTests(%s, %s)', str(args), str(devices))

  instrumentation_options = ProcessInstrumentationOptions(args)

  if len(devices) > 1 and args.wait_for_debugger:
    logging.warning('Debugger can not be sharded, using first available device')
    devices = devices[:1]

  results = base_test_result.TestRunResults()
  exit_code = 0

  if args.run_java_tests:
    java_runner_factory, java_tests = instrumentation_setup.Setup(
        instrumentation_options, devices)
  else:
    java_runner_factory = None
    java_tests = None

  if args.run_python_tests:
    py_runner_factory, py_tests = host_driven_setup.InstrumentationSetup(
        args.host_driven_root, args.official_build,
        instrumentation_options)
  else:
    py_runner_factory = None
    py_tests = None

  results = []
  repetitions = (xrange(args.repeat + 1) if args.repeat >= 0
                 else itertools.count())

  code_counts = {constants.INFRA_EXIT_CODE: 0,
                 constants.ERROR_EXIT_CODE: 0,
                 constants.WARNING_EXIT_CODE: 0,
                 0: 0}

  def _escalate_code(old, new):
    for x in (constants.INFRA_EXIT_CODE,
              constants.ERROR_EXIT_CODE,
              constants.WARNING_EXIT_CODE):
      if x in (old, new):
        return x
    return 0

  for _ in repetitions:
    iteration_results = base_test_result.TestRunResults()
    if java_tests:
      test_results, test_exit_code = test_dispatcher.RunTests(
          java_tests, java_runner_factory, devices, shard=True,
          test_timeout=None, num_retries=args.num_retries)
      iteration_results.AddTestRunResults(test_results)

      code_counts[test_exit_code] += 1
      exit_code = _escalate_code(exit_code, test_exit_code)

    if py_tests:
      test_results, test_exit_code = test_dispatcher.RunTests(
          py_tests, py_runner_factory, devices, shard=True, test_timeout=None,
          num_retries=args.num_retries)
      iteration_results.AddTestRunResults(test_results)

      code_counts[test_exit_code] += 1
      exit_code = _escalate_code(exit_code, test_exit_code)

    results.append(iteration_results)
    report_results.LogFull(
        results=iteration_results,
        test_type='Instrumentation',
        test_package=os.path.basename(args.test_apk),
        annotation=args.annotations,
        flakiness_server=args.flakiness_dashboard_server)


    if args.break_on_failure and exit_code in (constants.ERROR_EXIT_CODE,
                                               constants.INFRA_EXIT_CODE):
      break

  logging.critical('Instr tests: %s success, %s infra, %s errors, %s warnings',
                   str(code_counts[0]),
                   str(code_counts[constants.INFRA_EXIT_CODE]),
                   str(code_counts[constants.ERROR_EXIT_CODE]),
                   str(code_counts[constants.WARNING_EXIT_CODE]))

  if args.json_results_file:
    json_results.GenerateJsonResultsFile(results, args.json_results_file)

  return exit_code


def _RunJUnitTests(args):
  """Subcommand of RunTestsCommand which runs junit tests."""
  runner_factory, tests = junit_setup.Setup(args)
  results, exit_code = junit_dispatcher.RunTests(tests, runner_factory)

  report_results.LogFull(
      results=results,
      test_type='JUnit',
      test_package=args.test_suite)

  if args.json_results_file:
    json_results.GenerateJsonResultsFile([results], args.json_results_file)

  return exit_code


def _RunMonkeyTests(args, devices):
  """Subcommand of RunTestsCommands which runs monkey tests."""
  monkey_options = ProcessMonkeyTestOptions(args)

  runner_factory, tests = monkey_setup.Setup(monkey_options)

  results, exit_code = test_dispatcher.RunTests(
      tests, runner_factory, devices, shard=False, test_timeout=None,
      num_retries=args.num_retries)

  report_results.LogFull(
      results=results,
      test_type='Monkey',
      test_package='Monkey')

  if args.json_results_file:
    json_results.GenerateJsonResultsFile([results], args.json_results_file)

  return exit_code


def _RunPerfTests(args, active_devices):
  """Subcommand of RunTestsCommands which runs perf tests."""
  perf_options = ProcessPerfTestOptions(args)

  # Just save a simple json with a list of test names.
  if perf_options.output_json_list:
    return perf_test_runner.OutputJsonList(
        perf_options.steps, perf_options.output_json_list)

  # Just print the results from a single previously executed step.
  if perf_options.print_step:
    return perf_test_runner.PrintTestOutput(
        perf_options.print_step, perf_options.output_chartjson_data,
        perf_options.get_output_dir_archive)

  runner_factory, tests, devices = perf_setup.Setup(
      perf_options, active_devices)

  # shard=False means that each device will get the full list of tests
  # and then each one will decide their own affinity.
  # shard=True means each device will pop the next test available from a queue,
  # which increases throughput but have no affinity.
  results, _ = test_dispatcher.RunTests(
      tests, runner_factory, devices, shard=False, test_timeout=None,
      num_retries=args.num_retries)

  report_results.LogFull(
      results=results,
      test_type='Perf',
      test_package='Perf')

  if args.json_results_file:
    json_results.GenerateJsonResultsFile([results], args.json_results_file)

  if perf_options.single_step:
    return perf_test_runner.PrintTestOutput('single_step')

  perf_test_runner.PrintSummary(tests)

  # Always return 0 on the sharding stage. Individual tests exit_code
  # will be returned on the print_step stage.
  return 0


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


def _GetAttachedDevices(blacklist_file, test_device, enable_cache):
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
      blacklist, enable_device_files_cache=enable_cache)
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

  if args.enable_platform_mode:
    return RunTestsInPlatformMode(args)

  forwarder.Forwarder.RemoveHostLog()
  if not ports.ResetTestServerPortAllocation():
    raise Exception('Failed to reset test server port.')

  def get_devices():
    return _GetAttachedDevices(args.blacklist_file, args.test_device,
                               args.enable_device_cache)

  if command == 'gtest':
    return RunTestsInPlatformMode(args)
  elif command == 'linker':
    return _RunLinkerTests(args, get_devices())
  elif command == 'instrumentation':
    return _RunInstrumentationTests(args, get_devices())
  elif command == 'junit':
    return _RunJUnitTests(args)
  elif command == 'monkey':
    return _RunMonkeyTests(args, get_devices())
  elif command == 'perf':
    return _RunPerfTests(args, get_devices())
  elif command == 'python':
    return _RunPythonTests(args)
  else:
    raise Exception('Unknown test type.')


_SUPPORTED_IN_PLATFORM_MODE = [
  # TODO(jbudorick): Add support for more test types.
  'gtest',
  'instrumentation',
  'uirobot',
]


def RunTestsInPlatformMode(args):

  def infra_error(message):
    logging.fatal(message)
    sys.exit(constants.INFRA_EXIT_CODE)

  if args.command not in _SUPPORTED_IN_PLATFORM_MODE:
    infra_error('%s is not yet supported in platform mode' % args.command)

  with environment_factory.CreateEnvironment(args, infra_error) as env:
    with test_instance_factory.CreateTestInstance(args, infra_error) as test:
      with test_run_factory.CreateTestRun(
          args, env, test, infra_error) as test_run:
        results = []
        repetitions = (xrange(args.repeat + 1) if args.repeat >= 0
                       else itertools.count())
        result_counts = collections.defaultdict(
            lambda: collections.defaultdict(int))
        iteration_count = 0
        for _ in repetitions:
          iteration_results = test_run.RunTests()
          if iteration_results is not None:
            iteration_count += 1
            results.append(iteration_results)
            for r in iteration_results.GetAll():
              result_counts[r.GetName()][r.GetType()] += 1
            report_results.LogFull(
                results=iteration_results,
                test_type=test.TestType(),
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

        if args.json_results_file:
          json_results.GenerateJsonResultsFile(
              results, args.json_results_file)

  return (0 if all(r.DidRunPass() for r in results)
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
    'uirobot': CommandConfigTuple(
        AddUirobotTestOptions,
        'Uirobot test'),
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
