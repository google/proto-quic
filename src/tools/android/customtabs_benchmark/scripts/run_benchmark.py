#!/usr/bin/env python
#
# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Loops Custom Tabs tests and outputs the results into a CSV file."""

import copy
import json
import logging
import optparse
import os
import random
import sys
import threading

import customtabs_benchmark

_SRC_PATH = os.path.abspath(os.path.join(
    os.path.dirname(__file__), '..', '..', '..', '..'))

sys.path.append(os.path.join(_SRC_PATH, 'third_party', 'catapult', 'devil'))
from devil.android import device_utils

sys.path.append(os.path.join(_SRC_PATH, 'build', 'android'))
import devil_chromium


_KEYS = ['url', 'warmup', 'no_prerendering', 'delay_to_may_launch_url',
         'delay_to_launch_url', 'cold']


def _ParseConfiguration(filename):
  """Reads a JSON file and returns a list of configurations.

  Each valid value in the JSON file can be either a scalar or a list of
  values. This function expands the scalar values to be lists. All list must
  have the same length.

  Sample configuration:
  {
    "url": "https://www.android.com",
    "warmup": [false, true],
    "no_prerendering": false,
    "delay_to_may_launch_url": [-1, 1000],
    "delay_to_launch_url": [-1, 1000],
    "cold": true
  }

  Args:
    filename: (str) Point to a file containins a JSON dictionnary of config
              values.

  Returns:
    A list of configurations, where each value is specified.
  """
  config = json.load(open(filename, 'r'))
  has_all_values = all(k in config for k in _KEYS)
  assert has_all_values
  config['url'] = str(config['url']) # Intents don't like unicode.
  has_list = any(isinstance(config[k], list) for k in _KEYS)
  if not has_list:
    return [config]
  list_keys = [k for k in _KEYS if isinstance(config[k], list)]
  list_length = len(config[list_keys[0]])
  assert all(len(config[k]) == list_length for k in list_keys)
  result = []
  for i in range(list_length):
    result.append(copy.deepcopy(config))
    for k in list_keys:
      result[-1][k] = result[-1][k][i]
  return result


def _CreateOptionParser():
  parser = optparse.OptionParser(description='Loops tests on all attached '
                                 'devices, with randomly selected '
                                 'configurations, and outputs the results in '
                                 'CSV files.')
  parser.add_option('--config', help='JSON configuration file. Required.')
  parser.add_option('--output_file_prefix', help='Output file prefix. Actual '
                    'output file is prefix_<device ID>.csv', default='result')
  return parser


def _RunOnDevice(device, output_filename, configs, should_stop):
  """Loops the tests described by configs on a device.

  Args:
    device: (DeviceUtils) device to run the tests on.
    output_filename: (str) Output file name.
    configs: (list of dict) List of configurations.
    should_stop: (Event) When set, this function should return.
  """
  with open(output_filename, 'a') as f:
    while not should_stop.is_set():
      config = configs[random.randint(0, len(configs) - 1)]
      result = customtabs_benchmark.RunOnce(
          device, config['url'], config['warmup'], config['no_prerendering'],
          config['delay_to_may_launch_url'], config['delay_to_launch_url'],
          config['cold'])
      if result is not None:
        f.write(result + '\n')
        f.flush()
      should_stop.wait(10.)


def _Run(output_file_prefix, configs):
  """Loops the tests described by the configs on connected devices.

  Args:
    output_file_prefix: (str) Prefix for the output file name.
    configs: (list of dict) List of configurations.
  """
  devices = device_utils.DeviceUtils.HealthyDevices()
  should_stop = threading.Event()
  threads = []
  for device in devices:
    output_filename = '%s_%s.csv' % (output_file_prefix, str(device))
    thread = threading.Thread(
        target=_RunOnDevice,
        args=(device, output_filename, configs, should_stop))
    thread.start()
    threads.append(thread)
  for thread in threads:
    try:
      thread.join()
    except KeyboardInterrupt as e:
      should_stop.set()


def main():
  parser = _CreateOptionParser()
  options, _ = parser.parse_args()
  if options.config is None:
    logging.error('A configuration file must be provided.')
    sys.exit(0)
  devil_chromium.Initialize()
  configs = _ParseConfiguration(options.config)
  _Run(options.output_file_prefix, configs)


if __name__ == '__main__':
  main()
