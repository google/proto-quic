#!/usr/bin/env python
# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Runs isolate bundled Telemetry unittests.

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
import sys


import common

# Add src/testing/ into sys.path for importing xvfb.
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
import xvfb


def main():
  parser = argparse.ArgumentParser()
  parser.add_argument(
      '--isolated-script-test-output', type=argparse.FileType('w'),
      required=True)
  parser.add_argument(
    '--isolated-script-test-chartjson-output', type=argparse.FileType('w'),
    required=False)
  parser.add_argument('--xvfb', help='Start xvfb.', action='store_true')
  args, rest_args = parser.parse_known_args()

  xvfb_proc = None
  openbox_proc = None
  xcompmgr_proc = None
  env = os.environ.copy()
  if args.xvfb and xvfb.should_start_xvfb(env):
    xvfb_proc, openbox_proc, xcompmgr_proc = xvfb.start_xvfb(env=env,
                                                             build_dir='.')
    assert xvfb_proc and openbox_proc and xcompmgr_proc, 'Failed to start xvfb'
  # Compatibility with gtest-based sharding.
  total_shards = None
  shard_index = None
  if 'GTEST_TOTAL_SHARDS' in env:
    total_shards = int(env['GTEST_TOTAL_SHARDS'])
    del env['GTEST_TOTAL_SHARDS']
  if 'GTEST_SHARD_INDEX' in env:
    shard_index = int(env['GTEST_SHARD_INDEX'])
    del env['GTEST_SHARD_INDEX']
  sharding_args = []
  if total_shards is not None and shard_index is not None:
    sharding_args = [
      '--total-shards=%d' % total_shards,
      '--shard-index=%d' % shard_index
    ]
  try:
    with common.temporary_file() as tempfile_path:
      rc = common.run_command([sys.executable] + rest_args + sharding_args + [
        '--write-full-results-to', tempfile_path,
      ], env=env)
      with open(tempfile_path) as f:
        results = json.load(f)
      parsed_results = common.parse_common_test_results(results,
                                                        test_separator='.')
      failures = parsed_results['unexpected_failures']

      json.dump({
          'valid': bool(rc <= common.MAX_FAILURES_EXIT_STATUS and
                        ((rc == 0) or failures)),
          'failures': failures.keys(),
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
