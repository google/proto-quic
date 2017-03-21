# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Utility methods."""

import atexit
import distutils.spawn
import logging
import os
import platform
import resource
import sys


SRC_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))


def AddCommonOptionsAndParseArgs(parser):
  parser.add_argument('--no-pypy', action='store_true',
                      help='Do not automatically switch to pypy when available')
  parser.add_argument('-v',
                      '--verbose',
                      default=0,
                      action='count',
                      help='Verbose level (multiple times for more)')

  args = parser.parse_args()

  logging.basicConfig(level=logging.WARNING - args.verbose * 10,
                      format='%(levelname).1s %(relativeCreated)6d %(message)s')

  if not args.no_pypy and platform.python_implementation() == 'CPython':
    # Switch to pypy if it's available.
    pypy_path = distutils.spawn.find_executable('pypy')
    if pypy_path:
      logging.debug('Switching to pypy.')
      os.execv(pypy_path, [pypy_path] + sys.argv)
    # NOTE! Running with python: 6s. Running with pypy: 3s
    logging.warning('This script runs more than 2x faster if you install pypy.')

  if logging.getLogger().isEnabledFor(logging.DEBUG):
    atexit.register(_LogPeakRamUsage)
  return args


def _LogPeakRamUsage():
  peak_ram_usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
  peak_ram_usage += resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
  logging.info('Peak RAM usage was %d MB.', peak_ram_usage / 1024)
