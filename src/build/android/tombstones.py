#!/usr/bin/env python
#
# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# Find the most recent tombstone file(s) on all connected devices
# and prints their stacks.
#
# Assumes tombstone file was created with current symbols.

import argparse
import datetime
import logging
import multiprocessing
import os
import re
import subprocess
import sys

import devil_chromium

from devil.android import device_blacklist
from devil.android import device_errors
from devil.android import device_utils
from devil.utils import run_tests_helper
from pylib import constants


_TZ_UTC = {'TZ': 'UTC'}


def _ListTombstones(device):
  """List the tombstone files on the device.

  Args:
    device: An instance of DeviceUtils.

  Yields:
    Tuples of (tombstone filename, date time of file on device).
  """
  try:
    if not device.PathExists('/data/tombstones', as_root=True):
      return
    entries = device.StatDirectory('/data/tombstones', as_root=True)
    for entry in entries:
      if 'tombstone' in entry['filename']:
        yield (entry['filename'],
               datetime.datetime.fromtimestamp(entry['st_mtime']))
  except device_errors.CommandFailedError:
    logging.exception('Could not retrieve tombstones.')
  except device_errors.DeviceUnreachableError:
    logging.exception('Device unreachable retrieving tombstones.')
  except device_errors.CommandTimeoutError:
    logging.exception('Timed out retrieving tombstones.')


def _GetDeviceDateTime(device):
  """Determine the date time on the device.

  Args:
    device: An instance of DeviceUtils.

  Returns:
    A datetime instance.
  """
  device_now_string = device.RunShellCommand(
      ['date'], check_return=True, env=_TZ_UTC)
  return datetime.datetime.strptime(
      device_now_string[0], '%a %b %d %H:%M:%S %Z %Y')


def _GetTombstoneData(device, tombstone_file):
  """Retrieve the tombstone data from the device

  Args:
    device: An instance of DeviceUtils.
    tombstone_file: the tombstone to retrieve

  Returns:
    A list of lines
  """
  return device.ReadFile(
      '/data/tombstones/' + tombstone_file, as_root=True).splitlines()


def _EraseTombstone(device, tombstone_file):
  """Deletes a tombstone from the device.

  Args:
    device: An instance of DeviceUtils.
    tombstone_file: the tombstone to delete.
  """
  return device.RunShellCommand(
      ['rm', '/data/tombstones/' + tombstone_file],
      as_root=True, check_return=True)


def _DeviceAbiToArch(device_abi):
  # The order of this list is significant to find the more specific match (e.g.,
  # arm64) before the less specific (e.g., arm).
  arches = ['arm64', 'arm', 'x86_64', 'x86_64', 'x86', 'mips']
  for arch in arches:
    if arch in device_abi:
      return arch
  raise RuntimeError('Unknown device ABI: %s' % device_abi)


def _ResolveSymbols(tombstone_data, include_stack, device_abi):
  """Run the stack tool for given tombstone input.

  Args:
    tombstone_data: a list of strings of tombstone data.
    include_stack: boolean whether to include stack data in output.
    device_abi: the default ABI of the device which generated the tombstone.

  Yields:
    A string for each line of resolved stack output.
  """
  # Check if the tombstone data has an ABI listed, if so use this in preference
  # to the device's default ABI.
  for line in tombstone_data:
    found_abi = re.search('ABI: \'(.+?)\'', line)
    if found_abi:
      device_abi = found_abi.group(1)
  arch = _DeviceAbiToArch(device_abi)
  if not arch:
    return

  stack_tool = os.path.join(os.path.dirname(__file__), '..', '..',
                            'third_party', 'android_platform', 'development',
                            'scripts', 'stack')
  cmd = [stack_tool, '--arch', arch, '--output-directory',
         constants.GetOutDirectory()]
  proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
  output = proc.communicate(input='\n'.join(tombstone_data))[0]
  for line in output.split('\n'):
    if not include_stack and 'Stack Data:' in line:
      break
    yield line


def _ResolveTombstone(tombstone):
  lines = []
  lines += [tombstone['file'] + ' created on ' + str(tombstone['time']) +
            ', about this long ago: ' +
            (str(tombstone['device_now'] - tombstone['time']) +
            ' Device: ' + tombstone['serial'])]
  logging.info('\n'.join(lines))
  logging.info('Resolving...')
  lines += _ResolveSymbols(tombstone['data'], tombstone['stack'],
                           tombstone['device_abi'])
  return lines


def _ResolveTombstones(jobs, tombstones):
  """Resolve a list of tombstones.

  Args:
    jobs: the number of jobs to use with multiprocess.
    tombstones: a list of tombstones.
  """
  if not tombstones:
    logging.warning('No tombstones to resolve.')
    return []
  if len(tombstones) == 1:
    data = [_ResolveTombstone(tombstones[0])]
  else:
    pool = multiprocessing.Pool(processes=jobs)
    data = pool.map(_ResolveTombstone, tombstones)
  resolved_tombstones = []
  for tombstone in data:
    resolved_tombstones.extend(tombstone)
  return resolved_tombstones


def _GetTombstonesForDevice(device, resolve_all_tombstones,
                            include_stack_symbols,
                            wipe_tombstones):
  """Returns a list of tombstones on a given device.

  Args:
    device: An instance of DeviceUtils.
    resolve_all_tombstone: Whether to resolve every tombstone.
    include_stack_symbols: Whether to include symbols for stack data.
    wipe_tombstones: Whether to wipe tombstones.
  """
  ret = []
  all_tombstones = list(_ListTombstones(device))
  if not all_tombstones:
    logging.warning('No tombstones.')
    return ret

  # Sort the tombstones in date order, descending
  all_tombstones.sort(cmp=lambda a, b: cmp(b[1], a[1]))

  # Only resolve the most recent unless --all-tombstones given.
  tombstones = all_tombstones if resolve_all_tombstones else [all_tombstones[0]]

  device_now = _GetDeviceDateTime(device)
  try:
    for tombstone_file, tombstone_time in tombstones:
      ret += [{'serial': str(device),
               'device_abi': device.product_cpu_abi,
               'device_now': device_now,
               'time': tombstone_time,
               'file': tombstone_file,
               'stack': include_stack_symbols,
               'data': _GetTombstoneData(device, tombstone_file)}]
  except device_errors.CommandFailedError:
    for entry in device.StatDirectory(
        '/data/tombstones', as_root=True, timeout=60):
      logging.info('%s: %s', str(device), entry)
    raise

  # Erase all the tombstones if desired.
  if wipe_tombstones:
    for tombstone_file, _ in all_tombstones:
      _EraseTombstone(device, tombstone_file)

  return ret


def ClearAllTombstones(device):
  """Clear all tombstones in the device.

  Args:
    device: An instance of DeviceUtils.
  """
  all_tombstones = list(_ListTombstones(device))
  if not all_tombstones:
    logging.warning('No tombstones to clear.')

  for tombstone_file, _ in all_tombstones:
    _EraseTombstone(device, tombstone_file)


def ResolveTombstones(device, resolve_all_tombstones, include_stack_symbols,
                      wipe_tombstones, jobs=4):
  """Resolve tombstones in the device.

  Args:
    device: An instance of DeviceUtils.
    resolve_all_tombstone: Whether to resolve every tombstone.
    include_stack_symbols: Whether to include symbols for stack data.
    wipe_tombstones: Whether to wipe tombstones.
    jobs: Number of jobs to use when processing multiple crash stacks.

  Returns:
    A list of resolved tombstones.
  """
  return _ResolveTombstones(jobs,
                            _GetTombstonesForDevice(device,
                                                    resolve_all_tombstones,
                                                    include_stack_symbols,
                                                    wipe_tombstones))


def main():
  custom_handler = logging.StreamHandler(sys.stdout)
  custom_handler.setFormatter(run_tests_helper.CustomFormatter())
  logging.getLogger().addHandler(custom_handler)
  logging.getLogger().setLevel(logging.INFO)

  parser = argparse.ArgumentParser()
  parser.add_argument('--device',
                      help='The serial number of the device. If not specified '
                           'will use all devices.')
  parser.add_argument('--blacklist-file', help='Device blacklist JSON file.')
  parser.add_argument('-a', '--all-tombstones', action='store_true',
                      help='Resolve symbols for all tombstones, rather than '
                           'just the most recent.')
  parser.add_argument('-s', '--stack', action='store_true',
                      help='Also include symbols for stack data')
  parser.add_argument('-w', '--wipe-tombstones', action='store_true',
                      help='Erase all tombstones from device after processing')
  parser.add_argument('-j', '--jobs', type=int,
                      default=4,
                      help='Number of jobs to use when processing multiple '
                           'crash stacks.')
  parser.add_argument('--output-directory',
                      help='Path to the root build directory.')
  parser.add_argument('--adb-path', type=os.path.abspath,
                      help='Path to the adb binary.')
  args = parser.parse_args()

  devil_chromium.Initialize(adb_path=args.adb_path)

  blacklist = (device_blacklist.Blacklist(args.blacklist_file)
               if args.blacklist_file
               else None)

  if args.output_directory:
    constants.SetOutputDirectory(args.output_directory)
  # Do an up-front test that the output directory is known.
  constants.CheckOutputDirectory()

  if args.device:
    devices = [device_utils.DeviceUtils(args.device)]
  else:
    devices = device_utils.DeviceUtils.HealthyDevices(blacklist)

  # This must be done serially because strptime can hit a race condition if
  # used for the first time in a multithreaded environment.
  # http://bugs.python.org/issue7980
  for device in devices:
    resolved_tombstones = ResolveTombstones(
        device, args.all_tombstones,
        args.stack, args.wipe_tombstones, args.jobs)
    for line in resolved_tombstones:
      logging.info(line)


if __name__ == '__main__':
  sys.exit(main())
