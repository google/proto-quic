# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Setup for linker tests."""

import logging

from pylib.constants import host_paths
from pylib.linker import test_case
from pylib.linker import test_runner

with host_paths.SysPath(host_paths.BUILD_COMMON_PATH):
  import unittest_util # pylint: disable=import-error

# ModernLinker requires Android M (API level 23) or later.
_VERSION_SDK_PROPERTY = 'ro.build.version.sdk'
_MODERN_LINKER_MINIMUM_SDK_INT = 23

def Setup(args, devices):
  """Creates a list of test cases and a runner factory.

  Args:
    args: an argparse.Namespace object.
    devices: an iterable of available devices.
  Returns:
    A tuple of (TestRunnerFactory, tests).
  """
  legacy_linker_tests = [
      test_case.LinkerSharedRelroTest(is_modern_linker=False,
                                      is_low_memory=False),
      test_case.LinkerSharedRelroTest(is_modern_linker=False,
                                      is_low_memory=True),
  ]
  modern_linker_tests = [
      test_case.LinkerSharedRelroTest(is_modern_linker=True),
  ]

  min_sdk_int = 1 << 31
  for device in devices:
    min_sdk_int = min(min_sdk_int, device.build_version_sdk)

  if min_sdk_int >= _MODERN_LINKER_MINIMUM_SDK_INT:
    all_tests = legacy_linker_tests + modern_linker_tests
  else:
    all_tests = legacy_linker_tests
    logging.warn('Not running LinkerModern tests (requires API %d, found %d)',
                 _MODERN_LINKER_MINIMUM_SDK_INT, min_sdk_int)

  if args.test_filter:
    all_test_names = [test.qualified_name for test in all_tests]
    filtered_test_names = unittest_util.FilterTestNames(all_test_names,
                                                        args.test_filter)
    all_tests = [t for t in all_tests \
                 if t.qualified_name in filtered_test_names]

  def TestRunnerFactory(device, _shard_index):
    return test_runner.LinkerTestRunner(device, args.tool)

  return (TestRunnerFactory, all_tests)
