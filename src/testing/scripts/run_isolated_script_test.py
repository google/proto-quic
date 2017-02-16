#!/usr/bin/env python
# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Runs a script that can run as an isolate (or not).

The main requirement is that

  --isolated-script-test-output=[FILENAME]

is passed on the command line to run_isolated_script_tests. This gets
remapped to the command line argument --write-full-results-to.

json is written to that file in the format produced by
common.parse_common_test_results.

This script is intended to be the base command invoked by the isolate,
followed by a subsequent Python script. It could be generalized to
invoke an arbitrary executable.
"""

# TODO(tansell): Remove this script once LayoutTests can accept the isolated
# arguments and start xvfb itself.

import argparse
import json
import os
import pprint
import sys


import common

# Add src/testing/ into sys.path for importing xvfb.
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
import xvfb


def main():
  parser = argparse.ArgumentParser()
  parser.add_argument('--isolated-script-test-output', type=str,
                      required=True)
  parser.add_argument('--xvfb', help='start xvfb', action='store_true')

  # This argument is ignored for now.
  parser.add_argument('--isolated-script-test-chartjson-output', type=str)

  args, rest_args = parser.parse_known_args()

  env = os.environ
  cmd = [sys.executable] + rest_args
  cmd += ['--write-full-results-to', args.isolated_script_test_output]
  if args.xvfb:
    return xvfb.run_executable(cmd, env)
  else:
    return common.run_command(cmd, env=env)


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
