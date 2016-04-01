#!/usr/bin/python
# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Utility for reading / writing command-line flag files on device(s)."""

import argparse
import sys

import devil_chromium

from devil.android import device_utils
from devil.android import device_errors
from devil.utils import cmd_helper


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.usage = '''%(prog)s --device-path PATH [--device SERIAL] [flags...]

No flags: Prints existing command-line file.
Empty string: Deletes command-line file.
Otherwise: Writes command-line file.

'''
  parser.add_argument('-d', '--device', dest='device',
                      help='Target device for apk to install on.')
  parser.add_argument('--device-path', required=True,
                      help='Remote path to flags file.')
  parser.add_argument('-e', '--executable', dest='executable', default='chrome',
                      help='Name of the executable.')
  args, remote_args = parser.parse_known_args()

  devil_chromium.Initialize()

  as_root = not args.device_path.startswith('/data/local/tmp/')

  if args.device:
    devices = [device_utils.DeviceUtils(args.device, default_retries=0)]
  else:
    devices = device_utils.DeviceUtils.HealthyDevices(default_retries=0)
    if not devices:
      raise device_errors.NoDevicesError()

  all_devices = device_utils.DeviceUtils.parallel(devices)

  def print_args():
    def read_flags(device):
      try:
        return device.ReadFile(args.device_path, as_root=as_root).rstrip()
      except device_errors.AdbCommandFailedError:
        return ''  # File might not exist.

    descriptions = all_devices.pMap(lambda d: d.build_description).pGet(None)
    flags = all_devices.pMap(read_flags).pGet(None)
    for d, desc, flags in zip(devices, descriptions, flags):
      print '  %s (%s): %r' % (d, desc, flags)

  # No args == print flags.
  if not remote_args:
    print 'Existing flags (in %s):' % args.device_path
    print_args()
    return 0

  # Empty string arg == delete flags file.
  if len(remote_args) == 1 and not remote_args[0]:
    def delete_flags(device):
      device.RunShellCommand(['rm', '-f', args.device_path], as_root=as_root)
    all_devices.pMap(delete_flags).pGet(None)
    print 'Deleted %s' % args.device_path
    return 0

  # Set flags.
  quoted_args = ' '.join(cmd_helper.SingleQuote(x) for x in remote_args)
  flags_str = ' '.join([args.executable, quoted_args])

  def write_flags(device):
    device.WriteFile(args.device_path, flags_str, as_root=as_root)
    device.RunShellCommand(['chmod', '0664', args.device_path], as_root=as_root)

  all_devices.pMap(write_flags).pGet(None)
  print 'Wrote flags to %s' % args.device_path
  print_args()
  return 0


if __name__ == '__main__':
  sys.exit(main())
