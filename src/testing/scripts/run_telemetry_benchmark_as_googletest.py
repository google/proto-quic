#!/usr/bin/env python
# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Runs an isolate bundled Telemetry benchmark.

This script attempts to emulate the contract of gtest-style tests
invoked via recipes. The main contract is that the caller passes the
argument:

  --isolated-script-test-output=[FILENAME]

json is written to that file in the format detailed here:
https://www.chromium.org/developers/the-json-test-results-format

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
  env = os.environ.copy()
  # Assume we want to set up the sandbox environment variables all the
  # time; doing so is harmless on non-Linux platforms and is needed
  # all the time on Linux.
  env[CHROME_SANDBOX_ENV] = CHROME_SANDBOX_PATH
  tempfile_dir = tempfile.mkdtemp('telemetry')
  valid = True
  num_failures = 0
  chartjson_results_present = '--output-format=chartjson' in rest_args
  chartresults = None
  json_test_results = None

  results = None
  try:
    cmd = [sys.executable] + rest_args + [
      '--output-dir', tempfile_dir,
      '--output-format=json-test-results',
    ]
    if args.xvfb:
      rc = xvfb.run_executable(cmd, env)
    else:
      rc = common.run_command(cmd, env=env)

    # If we have also output chartjson read it in and return it.
    # results-chart.json is the file name output by telemetry when the
    # chartjson output format is included
    if chartjson_results_present:
      chart_tempfile_name = os.path.join(tempfile_dir, 'results-chart.json')
      with open(chart_tempfile_name) as f:
        chartresults = json.load(f)

    # test-results.json is the file name output by telemetry when the
    # json-test-results format is included
    tempfile_name = os.path.join(tempfile_dir, 'test-results.json')
    with open(tempfile_name) as f:
      json_test_results = json.load(f)

    # Determine if this was a disabled benchmark that was run
    if (not chartjson_results_present or
       (chartjson_results_present and chartresults.get('enabled', True))):
      num_failures = json_test_results['num_failures_by_type'].get('FAIL', 0)
      valid = bool(rc == 0 or num_failures != 0)

  except Exception:
    traceback.print_exc()
    if results:
      print 'results, which possibly caused exception: %s' % json.dumps(
          results, indent=2)
    valid = False
  finally:
    shutil.rmtree(tempfile_dir)

  if not valid and num_failures == 0:
    if rc == 0:
      rc = 1  # Signal an abnormal exit.

  if chartjson_results_present and args.isolated_script_test_chartjson_output:
    chartjson_output_file = \
      open(args.isolated_script_test_chartjson_output, 'w')
    json.dump(chartresults, chartjson_output_file)

  json.dump(json_test_results, args.isolated_script_test_output)
  return rc


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
