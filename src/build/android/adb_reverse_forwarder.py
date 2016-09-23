#!/usr/bin/env python
#
# Copyright (c) 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Command line tool for forwarding ports from a device to the host.

Allows an Android device to connect to services running on the host machine,
i.e., "adb forward" in reverse. Requires |host_forwarder| and |device_forwarder|
to be built.
"""

import optparse
import sys
import time

import devil_chromium

from devil.android import device_blacklist
from devil.android import device_utils
from devil.android import forwarder
from devil.utils import run_tests_helper

from pylib import constants


def main(argv):
  parser = optparse.OptionParser(usage='Usage: %prog [options] device_port '
                                 'host_port [device_port_2 host_port_2] ...',
                                 description=__doc__)
  parser.add_option('-v',
                    '--verbose',
                    dest='verbose_count',
                    default=0,
                    action='count',
                    help='Verbose level (multiple times for more)')
  parser.add_option('--device',
                    help='Serial number of device we should use.')
  parser.add_option('--blacklist-file', help='Device blacklist JSON file.')
  parser.add_option('--debug', action='store_const', const='Debug',
                    dest='build_type', default='Release',
                    help='Use Debug build of host tools instead of Release.')

  options, args = parser.parse_args(argv)
  run_tests_helper.SetLogLevel(options.verbose_count)

  devil_chromium.Initialize()

  if len(args) < 2 or not len(args) % 2:
    parser.error('Need even number of port pairs')
    sys.exit(1)

  try:
    port_pairs = [int(a) for a in args[1:]]
    port_pairs = zip(port_pairs[::2], port_pairs[1::2])
  except ValueError:
    parser.error('Bad port number')
    sys.exit(1)

  blacklist = (device_blacklist.Blacklist(options.blacklist_file)
               if options.blacklist_file
               else None)
  device = device_utils.DeviceUtils.HealthyDevices(
      blacklist=blacklist, device_arg=options.device)[0]
  constants.SetBuildType(options.build_type)
  try:
    forwarder.Forwarder.Map(port_pairs, device)
    while True:
      time.sleep(60)
  except KeyboardInterrupt:
    sys.exit(0)
  finally:
    forwarder.Forwarder.UnmapAllDevicePorts(device)

if __name__ == '__main__':
  main(sys.argv)
