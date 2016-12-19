#!/usr/bin/python
#
# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Loops Custom Tabs tests and outputs the results into a CSV file."""

import collections
import contextlib
import logging
import optparse
import os
import random
import re
import subprocess
import sys
import time

_SRC_PATH = os.path.abspath(os.path.join(
    os.path.dirname(__file__), os.pardir, os.pardir, os.pardir, os.pardir))

sys.path.append(os.path.join(_SRC_PATH, 'third_party', 'catapult', 'devil'))
from devil.android import device_errors
from devil.android import device_utils
from devil.android.perf import cache_control
from devil.android.sdk import intent

sys.path.append(os.path.join(_SRC_PATH, 'build', 'android'))
import devil_chromium

sys.path.append(os.path.join(_SRC_PATH, 'tools', 'android', 'loading'))
import device_setup


# Local build of Chrome (not Chromium).
_CHROME_PACKAGE = 'com.google.android.apps.chrome'
_COMMAND_LINE_PATH = '/data/local/tmp/chrome-command-line'
_TEST_APP_PACKAGE_NAME = 'org.chromium.customtabsclient.test'
_INVALID_VALUE = -1


# Command line arguments for Chrome.
CHROME_ARGS = [
    # Disable backgound network requests that may pollute WPR archive, pollute
    # HTTP cache generation, and introduce noise in loading performance.
    '--disable-background-networking',
    '--disable-default-apps',
    '--no-proxy-server',
    # TODO(droger): Remove once crbug.com/354743 is fixed.
    '--safebrowsing-disable-auto-update',

    # Disables actions that chrome performs only on first run or each launches,
    # which can interfere with page load performance, or even block its
    # execution by waiting for user input.
    '--disable-fre',
    '--no-default-browser-check',
    '--no-first-run',
]


def ResetChromeLocalState(device):
  """Remove the Chrome Profile and the various disk caches."""
  profile_dirs = ['app_chrome/Default', 'cache', 'app_chrome/ShaderCache',
                  'app_tabs']
  cmd = ['rm', '-rf']
  cmd.extend(
      '/data/data/{}/{}'.format(_CHROME_PACKAGE, d) for d in profile_dirs)
  device.adb.Shell(subprocess.list2cmdline(cmd))


def RunOnce(device, url, warmup, speculation_mode, delay_to_may_launch_url,
            delay_to_launch_url, cold, chrome_args, reset_chrome_state):
  """Runs a test on a device once.

  Args:
    device: (DeviceUtils) device to run the tests on.
    url: (str) URL to load.
    warmup: (bool) Whether to call warmup.
    speculation_mode: (str) Speculation Mode.
    delay_to_may_launch_url: (int) Delay to mayLaunchUrl() in ms.
    delay_to_launch_url: (int) Delay to launchUrl() in ms.
    cold: (bool) Whether the page cache should be dropped.
    chrome_args: ([str]) List of arguments to pass to Chrome.
    reset_chrome_state: (bool) Whether to reset the Chrome local state before
                        the run.

  Returns:
    The output line (str), like this (one line only):
    <warmup>,<prerender_mode>,<delay_to_may_launch_url>,<delay_to_launch>,
      <intent_sent_ms>,<page_load_started_ms>,<page_load_finished_ms>,
      <first_contentful_paint>
    or None on error.
  """
  if not device.HasRoot():
    device.EnableRoot()

  timeout_s = 20
  logcat_timeout = int(timeout_s + delay_to_may_launch_url / 1000.
                       + delay_to_launch_url / 1000.) + 3;

  with device_setup.FlagReplacer(device, _COMMAND_LINE_PATH, chrome_args):
    launch_intent = intent.Intent(
        action='android.intent.action.MAIN',
        package=_TEST_APP_PACKAGE_NAME,
        activity='org.chromium.customtabs.test.MainActivity',
        extras={'url': str(url), 'warmup': warmup,
                'speculation_mode': str(speculation_mode),
                'delay_to_may_launch_url': delay_to_may_launch_url,
                'delay_to_launch_url': delay_to_launch_url,
                'timeout': timeout_s})
    result_line_re = re.compile(r'CUSTOMTABSBENCH.*: (.*)')
    logcat_monitor = device.GetLogcatMonitor(clear=True)
    logcat_monitor.Start()
    device.ForceStop(_CHROME_PACKAGE)
    device.ForceStop(_TEST_APP_PACKAGE_NAME)

    if reset_chrome_state:
      ResetChromeLocalState(device)

    if cold:
      cache_control.CacheControl(device).DropRamCaches()

    device.StartActivity(launch_intent, blocking=True)

    match = None
    try:
      match = logcat_monitor.WaitFor(result_line_re, timeout=logcat_timeout)
    except device_errors.CommandTimeoutError as _:
      logging.warning('Timeout waiting for the result line')
    logcat_monitor.Stop()
    logcat_monitor.Close()
    return match.group(1) if match is not None else None


RESULT_FIELDS = ('warmup', 'speculation_mode', 'delay_to_may_launch_url',
                 'delay_to_launch_url', 'commit', 'plt',
                 'first_contentful_paint')
Result = collections.namedtuple('Result', RESULT_FIELDS)


def ParseResult(result_line):
  """Parses a result line, and returns it.

  Args:
    result_line: (str) A result line, as returned by RunOnce().

  Returns:
    An instance of Result.
  """
  tokens = result_line.strip().split(',')
  assert len(tokens) == 8
  intent_sent_timestamp = int(tokens[4])
  return Result(bool(tokens[0]), tokens[1], int(tokens[2]), int(tokens[3]),
                max(_INVALID_VALUE, int(tokens[5]) - intent_sent_timestamp),
                max(_INVALID_VALUE, int(tokens[6]) - intent_sent_timestamp),
                max(_INVALID_VALUE, int(tokens[7]) - intent_sent_timestamp))


def LoopOnDevice(device, configs, output_filename, wpr_archive_path=None,
                 wpr_record=None, network_condition=None, wpr_log_path=None,
                 once=False, should_stop=None):
  """Loops the tests on a device.

  Args:
    device: (DeviceUtils) device to run the tests on.
    configs: ([dict])
    output_filename: (str) Output filename. '-' for stdout.
    wpr_archive_path: (str) Path to the WPR archive.
    wpr_record: (bool) Whether WPR is set to recording.
    network_condition: (str) Name of the network configuration for throttling.
    wpr_log_path: (str) Path the the WPR log.
    once: (bool) Run only once.
    should_stop: (threading.Event or None) When the event is set, stop looping.
  """
  with SetupWpr(device, wpr_archive_path, wpr_record, network_condition,
                wpr_log_path) as wpr_attributes:
    to_stdout = output_filename == '-'
    out = sys.stdout if to_stdout else open(output_filename, 'a')
    try:
      while should_stop is None or not should_stop.is_set():
        config = configs[random.randint(0, len(configs) - 1)]
        chrome_args = CHROME_ARGS + wpr_attributes.chrome_args
        if config['speculation_mode'] == 'no_state_prefetch':
          # NoStatePrefetch is enabled through an experiment.
          chrome_args.extend([
              '--force-fieldtrials=trial/group',
              '--force-fieldtrial-params=trial.group:mode/no_state_prefetch',
              '--enable-features="NoStatePrefetch<trial"'])

        result = RunOnce(device, config['url'], config['warmup'],
                         config['speculation_mode'],
                         config['delay_to_may_launch_url'],
                         config['delay_to_launch_url'], config['cold'],
                         chrome_args, reset_chrome_state=True)
        if result is not None:
          out.write(result + '\n')
          out.flush()
        if once:
          return
        if should_stop is not None:
          should_stop.wait(10.)
        else:
          time.sleep(10)
    finally:
      if not to_stdout:
        out.close()


def ProcessOutput(filename):
  """Reads an output file, and returns a processed numpy array.

  Args:
    filename: (str) file to process.

  Returns:
    A numpy structured array.
  """
  import numpy as np
  data = np.genfromtxt(filename, delimiter=',', skip_header=1)
  result = np.array(np.zeros(len(data)),
                    dtype=[('warmup', bool), ('speculation_mode', np.int32),
                           ('delay_to_may_launch_url', np.int32),
                           ('delay_to_launch_url', np.int32),
                           ('commit', np.int32), ('plt', np.int32),
                           ('first_contentful_paint', np.int32)])
  result['warmup'] = data[:, 0]
  result['speculation_mode'] = data[:, 1]
  result['delay_to_may_launch_url'] = data[:, 2]
  result['delay_to_launch_url'] = data[:, 3]
  result['commit'] = data[:, 4]
  result['plt'] = data[:, 5]
  result['first_contentful_paint'] = data[:, 6]
  return result


def _CreateOptionParser():
  parser = optparse.OptionParser(description='Loops Custom Tabs tests on a '
                                 'device, and outputs the navigation timings '
                                 'in a CSV file.')
  parser.add_option('--device', help='Device ID')
  parser.add_option('--url', help='URL to navigate to.',
                    default='https://www.android.com')
  parser.add_option('--warmup', help='Call warmup.', default=False,
                    action='store_true')
  parser.add_option('--speculation_mode', default='prerender',
                    help='The speculation mode (prerender, disabled, '
                    'speculative_prefetch or no_state_prefetch).',
                    choices=['prerender', 'disabled', 'speculative_prefetch',
                             'no_state_prefetch'])
  parser.add_option('--delay_to_may_launch_url',
                    help='Delay before calling mayLaunchUrl() in ms.',
                    type='int', default=1000)
  parser.add_option('--delay_to_launch_url',
                    help='Delay before calling launchUrl() in ms.',
                    type='int', default=-1)
  parser.add_option('--cold', help='Purge the page cache before each run.',
                    default=False, action='store_true')
  parser.add_option('--output_file', help='Output file (append). "-" for '
                    'stdout')
  parser.add_option('--once', help='Run only one iteration.',
                    action='store_true', default=False)

  # WebPageReplay-related options.
  group = optparse.OptionGroup(
      parser, 'WebPageReplay options',
      'Setting any of these enables WebPageReplay.')
  group.add_option('--record', help='Record the WPR archive.',
                   action='store_true', default=False)
  group.add_option('--wpr_archive', help='WPR archive path.')
  group.add_option('--wpr_log', help='WPR log path.')
  group.add_option('--network_condition',
                   help='Network condition for emulation.')
  parser.add_option_group(group)

  return parser


@contextlib.contextmanager
def DummyWprHost():
  """Dummy context used to run without WebPageReplay."""
  yield device_setup.WprAttribute(chrome_args=[], chrome_env_override={})


def SetupWpr(device, wpr_archive_path, record, network_condition_name,
             out_log_path):
  """Sets up the WebPageReplay server if needed."""
  if wpr_archive_path or record or network_condition_name or out_log_path:
    return device_setup.RemoteWprHost(device, wpr_archive_path, record,
                                      network_condition_name,
                                      out_log_path=out_log_path)
  # WebPageReplay disabled.
  return DummyWprHost()


def main():
  parser = _CreateOptionParser()
  options, _ = parser.parse_args()
  devil_chromium.Initialize()
  devices = device_utils.DeviceUtils.HealthyDevices()
  device = devices[0]
  if len(devices) != 1 and options.device is None:
    logging.error('Several devices attached, must specify one with --device.')
    sys.exit(0)
  if options.device is not None:
    matching_devices = [d for d in devices if str(d) == options.device]
    if not matching_devices:
      logging.error('Device not found.')
      sys.exit(0)
    device = matching_devices[0]

  config = {
      'url': options.url,
      'warmup': options.warmup,
      'speculation_mode': options.speculation_mode,
      'delay_to_may_launch_url': options.delay_to_may_launch_url,
      'delay_to_launch_url': options.delay_to_launch_url,
      'cold': options.cold,
  }
  LoopOnDevice(device, [config], options.output_file, options.wpr_archive,
               options.record, options.network_condition, options.wpr_log,
               once=options.once)


if __name__ == '__main__':
  main()
