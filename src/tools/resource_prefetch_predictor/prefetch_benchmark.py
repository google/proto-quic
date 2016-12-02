#!/usr/bin/python
#
# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Loads a web page with speculative prefetch, and collects loading metrics."""

import argparse
import logging
import os
import sys
import time

_SRC_PATH = os.path.abspath(os.path.join(
    os.path.dirname(__file__), os.pardir, os.pardir))

sys.path.append(os.path.join(
    _SRC_PATH, 'tools', 'android', 'customtabs_benchmark', 'scripts'))
import customtabs_benchmark
import device_setup

sys.path.append(os.path.join(_SRC_PATH, 'tools', 'android', 'loading'))
from options import OPTIONS

sys.path.append(os.path.join(_SRC_PATH, 'build', 'android'))
import devil_chromium

sys.path.append(os.path.join(_SRC_PATH, 'third_party', 'catapult', 'devil'))
from devil.android.sdk import intent

import prefetch_predictor_common


_EXTERNAL_PREFETCH_FLAG = (
    '--speculative-resource-prefetching=enabled-external-only')


def _CreateArgumentParser():
  """Creates and returns the argument parser."""
  parser = argparse.ArgumentParser(
      ('Loads a URL with the resource_prefetch_predictor and prints loading '
       'metrics.'), parents=[OPTIONS.GetParentParser()])
  parser.add_argument('--device', help='Device ID')
  parser.add_argument('--database',
                      help=('File containing the predictor database, as '
                            'obtained from generate_database.py.'))
  parser.add_argument('--url', help='URL to load.')
  parser.add_argument('--prefetch_delay_ms',
                      help='Prefetch delay in ms. -1 to disable prefetch.')
  return parser


def _Setup(device, database_filename):
  """Sets up a device and returns an instance of RemoteChromeController."""
  chrome_controller = prefetch_predictor_common.Setup(device, [''])
  chrome_package = OPTIONS.ChromePackage()
  device.ForceStop(chrome_package.package)
  chrome_controller.ResetBrowserState()
  device_database_filename = prefetch_predictor_common.DatabaseDevicePath()
  owner = group = None

  # Make sure that the speculative prefetch predictor is enabled to ensure
  # that the disk database is re-created.
  command_line_path = '/data/local/tmp/chrome-command-line'
  with device_setup.FlagReplacer(
      device, command_line_path, ['--disable-fre', _EXTERNAL_PREFETCH_FLAG]):
    # Launch Chrome for the first time to recreate the local state.
    launch_intent = intent.Intent(
        action='android.intent.action.MAIN',
        package=chrome_package.package,
        activity=chrome_package.activity)
    device.StartActivity(launch_intent, blocking=True)
    time.sleep(5)
    device.ForceStop(chrome_package.package)
    assert device.FileExists(device_database_filename)
    stats = device.StatPath(device_database_filename)
    owner = stats['st_owner']
    group = stats['st_group']
  # Now push the database. Needs to be done after the first launch, otherwise
  # the profile directory is owned by root. Also change the owner of the
  # database, since adb push sets it to root.
  database_content = open(database_filename, 'r').read()
  device.WriteFile(device_database_filename, database_content, force_push=True)
  command = 'chown %s:%s \'%s\'' % (owner, group, device_database_filename)
  device.RunShellCommand(command, as_root=True)


def _Go(device, url, prefetch_delay_ms):
  disable_prefetch = prefetch_delay_ms == -1
  # Startup tracing to ease debugging.
  chrome_args = (customtabs_benchmark.CHROME_ARGS
                 + ['--trace-startup', '--trace-startup-duration=20'])
  if not disable_prefetch:
    chrome_args.append(_EXTERNAL_PREFETCH_FLAG)
  prefetch_mode = 'disabled' if disable_prefetch else 'speculative_prefetch'
  result = customtabs_benchmark.RunOnce(
      device, url, warmup=True, speculation_mode=prefetch_mode,
      delay_to_may_launch_url=2000,
      delay_to_launch_url=max(0, prefetch_delay_ms), cold=False,
      chrome_args=chrome_args, reset_chrome_state=False)
  print customtabs_benchmark.ParseResult(result)


def main():
  logging.basicConfig(level=logging.INFO)
  devil_chromium.Initialize()

  parser = _CreateArgumentParser()
  args = parser.parse_args()
  OPTIONS.SetParsedArgs(args)
  device = prefetch_predictor_common.FindDevice(args.device)
  if device is None:
    logging.error('Could not find device: %s.', args.device)
    sys.exit(1)

  _Setup(device, args.database)
  _Go(device, args.url, int(args.prefetch_delay_ms))


if __name__ == '__main__':
  main()
