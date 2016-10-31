#!/usr/bin/env python
# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Runs an isolated non-Telemetry perf test .

The main contract is that the caller passes the arguments:

  --isolated-script-test-output=[FILENAME]
json is written to that file in the format produced by
common.parse_common_test_results.

  --isolated-script-test-chartjson-output=[FILE]
stdout is written to this file containing chart results for the perf dashboard

This script is intended to be the base command invoked by the isolate,
followed by a subsequent non-python executable.  It is modeled after
run_gpu_integration_test_as_gtest.py
"""

import argparse
import json
import os
import shutil
import sys
import tempfile
import traceback

import common

# Add src/testing/ into sys.path for importing xvfb.
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
import xvfb

# Unfortunately we need to copy these variables from ../test_env.py.
# Importing it and using its get_sandbox_env breaks test runs on Linux
# (it seems to unset DISPLAY).
CHROME_SANDBOX_ENV = 'CHROME_DEVEL_SANDBOX'
CHROME_SANDBOX_PATH = '/opt/chromium/chrome_sandbox'


def IsWindows():
  return sys.platform == 'cygwin' or sys.platform.startswith('win')


def main():
  parser = argparse.ArgumentParser()
  parser.add_argument(
      '--isolated-script-test-output', type=str,
      required=True)
  parser.add_argument(
      '--isolated-script-test-chartjson-output', type=str,
      required=True)
  parser.add_argument('--xvfb', help='Start xvfb.', action='store_true')

  args, rest_args = parser.parse_known_args()

  xvfb_proc = None
  openbox_proc = None
  xcompmgr_proc = None
  env = os.environ.copy()
  # Assume we want to set up the sandbox environment variables all the
  # time; doing so is harmless on non-Linux platforms and is needed
  # all the time on Linux.
  env[CHROME_SANDBOX_ENV] = CHROME_SANDBOX_PATH
  if args.xvfb and xvfb.should_start_xvfb(env):
    xvfb_proc, openbox_proc, xcompmgr_proc = xvfb.start_xvfb(env=env,
                                                             build_dir='.')
    assert xvfb_proc and openbox_proc and xcompmgr_proc, 'Failed to start xvfb'

  try:
    valid = True
    rc = 0
    try:
      executable = rest_args[0]
      if IsWindows():
        executable = '.\%s.exe' % executable
      else:
        executable = './%s' % executable

      rc = common.run_command_with_output([executable] + [
        '--write-abbreviated-json-results-to', args.isolated_script_test_output,
      ], env=env, stdoutfile=args.isolated_script_test_chartjson_output)

      # Now get the correct json format from the stdout to write to the
      # perf results file
    except Exception:
      traceback.print_exc()
      valid = False

    if not valid:
      failures = ['(entire test suite)']
      with open(args.isolated_script_test_output, 'w') as fp:
        json.dump({
            'valid': valid,
            'failures': failures,
        }, fp)

    return rc

  finally:
    xvfb.kill(xvfb_proc)
    xvfb.kill(openbox_proc)
    xvfb.kill(xcompmgr_proc)


# This is not really a "script test" so does not need to manually add
# any additional compile targets.
def main_compile_targets(args):
  json.dump([], args.output)


if __name__ == '__main__':
  # Conform minimally to the protocol defined by ScriptTest.
  if 'compile_targets' in sys.argv:
    funcs = {
      'run': None,
      'compile_targets': main_compile_targets,
    }
    sys.exit(common.run_script(sys.argv[1:], funcs))
  sys.exit(main())

