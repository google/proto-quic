#!/usr/bin/python
#
# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Loops Custom Tabs tests and outputs the results into a CSV file."""

import contextlib
import logging
import optparse
import os
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


# Command line arguments for Chrome.
_CHROME_ARGS = [
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


def RunOnce(device, url, warmup, prerender_mode, delay_to_may_launch_url,
            delay_to_launch_url, cold):
  """Runs a test on a device once.

  Args:
    device: (DeviceUtils) device to run the tests on.
    warmup: (bool) Whether to call warmup.
    prerender_mode: (str) Prerender mode (disabled, enabled or prefetch).
    delay_to_may_launch_url: (int) Delay to mayLaunchUrl() in ms.
    delay_to_launch_url: (int) Delay to launchUrl() in ms.
    cold: (bool) Whether the page cache should be dropped.

  Returns:
    The output line (str), like this (one line only):
    <warmup>,<prerender_mode>,<delay_to_may_launch_url>,<delay_to_launch>,
      <intent_sent_ms>,<page_load_started_ms>,<page_load_finished_ms>,
      <first_contentful_paint>
    or None on error.
  """
  launch_intent = intent.Intent(
      action='android.intent.action.MAIN',
      package='org.chromium.customtabsclient.test',
      activity='org.chromium.customtabs.test.MainActivity',
      extras={'url': url, 'warmup': warmup, 'prerender_mode': prerender_mode,
              'delay_to_may_launch_url': delay_to_may_launch_url,
              'delay_to_launch_url': delay_to_launch_url})
  result_line_re = re.compile(r'CUSTOMTABSBENCH.*: (.*)')
  logcat_monitor = device.GetLogcatMonitor(clear=True)
  logcat_monitor.Start()
  device.ForceStop(_CHROME_PACKAGE)
  device.ForceStop('org.chromium.customtabsclient.test')
  ResetChromeLocalState(device)

  if cold:
    if not device.HasRoot():
      device.EnableRoot()
    cache_control.CacheControl(device).DropRamCaches()
  device.StartActivity(launch_intent, blocking=True)
  match = None
  try:
    match = logcat_monitor.WaitFor(result_line_re, timeout=20)
  except device_errors.CommandTimeoutError as e:
    logging.warning('Timeout waiting for the result line')
  return match.group(1) if match is not None else None


def LoopOnDevice(device, url, warmup, prerender_mode, delay_to_may_launch_url,
                 delay_to_launch_url, cold, output_filename, once=False):
  """Loops the tests on a device.

  Args:
    device: (DeviceUtils) device to run the tests on.
    url: (str) URL to navigate to.
    warmup: (bool) Whether to call warmup.
    prerender_mode: (str) Prerender mode (disabled, enabled or prefetch).
    delay_to_may_launch_url: (int) Delay to mayLaunchUrl() in ms.
    delay_to_launch_url: (int) Delay to launchUrl() in ms.
    cold: (bool) Whether the page cache should be dropped.
    output_filename: (str) Output filename. '-' for stdout.
    once: (bool) Run only once.
  """
  while True:
    out = sys.stdout if output_filename == '-' else open(output_filename, 'a')
    try:
      result = RunOnce(device, url, warmup, prerender_mode,
                       delay_to_may_launch_url, delay_to_launch_url, cold)
      if result is not None:
        out.write(result + '\n')
        out.flush()
      if once:
        return
      time.sleep(10)
    finally:
      if output_filename != '-':
        out.close()


def ProcessOutput(filename):
  """Reads an output file, and returns a processed numpy array.

  Args:
    filename: (str) file to process.

  Returns:
    A numpy structured array.
  """
  import numpy as np
  data = np.genfromtxt(filename, delimiter=',')
  result = np.array(np.zeros(len(data)),
                    dtype=[('warmup', bool), ('prerender_mode', np.int32),
                           ('delay_to_may_launch_url', np.int32),
                           ('delay_to_launch_url', np.int32),
                           ('commit', np.int32), ('plt', np.int32),
                           ('first_contentful_paint', np.int32)])
  result['warmup'] = data[:, 0]
  result['prerender_mode'] = data[:, 1]
  result['delay_to_may_launch_url'] = data[:, 2]
  result['delay_to_launch_url'] = data[:, 3]
  result['commit'] = data[:, 5] - data[:, 4]
  result['plt'] = data[:, 6] - data[:, 4]
  result['first_contentful_paint'] = data[7]
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
  parser.add_option('--prerender_mode', default='enabled',
                    help='The prerender mode (disabled, enabled or prefetch).',
                    choices=['disabled', 'enabled', 'prefetch'])
  parser.add_option('--delay_to_may_launch_url',
                    help='Delay before calling mayLaunchUrl() in ms.',
                    type='int')
  parser.add_option('--delay_to_launch_url',
                    help='Delay before calling launchUrl() in ms.',
                    type='int')
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
    if len(matching_devices) == 0:
      logging.error('Device not found.')
      sys.exit(0)
    device = matching_devices[0]

  with SetupWpr(device, options.wpr_archive, options.record,
                options.network_condition, options.wpr_log) as wpr_attributes:
    chrome_args = (_CHROME_ARGS + ['--prerender=' + options.prerender_mode] +
                   wpr_attributes.chrome_args)
    with device_setup.FlagReplacer(
        device, '/data/local/tmp/chrome-command-line', chrome_args):
      LoopOnDevice(device, options.url, options.warmup, options.prerender_mode,
                   options.delay_to_may_launch_url, options.delay_to_launch_url,
                   options.cold, options.output_file, options.once)


if __name__ == '__main__':
  main()
