#!/usr/bin/env python
# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Runs an isolate bundled Telemetry benchmark.

This script attempts to emulate the contract of gtest-style tests
invoked via recipes. The main contract is that the caller passes the
argument:

  --isolated-script-test-output=[FILENAME]

json is written to that file in the format produced by
common.parse_common_test_results.

This script is intended to be the base command invoked by the isolate,
followed by a subsequent Python script. It could be generalized to
invoke an arbitrary executable.
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

def main():
  parser = argparse.ArgumentParser()
  parser.add_argument(
      '--isolated-script-test-output', type=argparse.FileType('w'),
      required=True)
  parser.add_argument(
      '--isolated-script-test-chartjson-output', required=False)
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
    tempfile_dir = tempfile.mkdtemp('telemetry')
    valid = True
    failures = []
    chartjson_results_present = '--output-format=chartjson' in rest_args
    chartresults = None
    try:
      rc = common.run_command([sys.executable] + rest_args + [
        '--output-dir', tempfile_dir,
        '--output-format=json'
      ], env=env)
      tempfile_name = os.path.join(tempfile_dir, 'results.json')
      with open(tempfile_name) as f:
        results = json.load(f)
      for value in results['per_page_values']:
        if value['type'] == 'failure':
          failures.append(results['pages'][str(value['page_id'])]['name'])
      valid = bool(rc == 0 or failures)
      # If we have also output chartjson read it in and return it.
      # results-chart.json is the file name output by telemetry when the
      # chartjson output format is included
      if chartjson_results_present:
        chart_tempfile_name = os.path.join(tempfile_dir, 'results-chart.json')
        with open(chart_tempfile_name) as f:
          chartresults = json.load(f)
    except Exception:
      traceback.print_exc()
      valid = False
    finally:
      shutil.rmtree(tempfile_dir)

    if not valid and not failures:
      failures = ['(entire test suite)']
      if rc == 0:
        rc = 1  # Signal an abnormal exit.

    if chartjson_results_present and args.isolated_script_test_chartjson_output:
      chartjson_output_file = \
        open(args.isolated_script_test_chartjson_output, 'w')
      json.dump(chartresults, chartjson_output_file)

    json.dump({
        'valid': valid,
        'failures': failures
    }, args.isolated_script_test_output)
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
