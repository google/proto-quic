#!/usr/bin/env python
# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Invokes the Clang static analysis command using arguments provided on the
command line.
"""

import argparse
import fnmatch
import os
import shutil
import sys
import tempfile

import wrapper_utils


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument('--clang-cc-path',
                      help='Path to the clang compiler.',
                      metavar='PATH')
  parser.add_argument('--clang-cxx-path',
                      help='Path to the clang++ compiler',
                      metavar='PATH')
  parser.add_argument('--analyzer',
                      help='Path to the language-specific Clang analysis tool.',
                      required=True,
                      metavar='PATH')
  args, compile_args = parser.parse_known_args()

  # Check that only one of --clang-cc-path or --clang-cxx-path are set.
  assert ((args.clang_cc_path != None) != (args.clang_cxx_path != None))

  is_cxx = args.clang_cxx_path != None
  env = os.environ
  env['CCC_ANALYZER_FORCE_ANALYZE_DEBUG_CODE'] = '0'
  env['CCC_ANALYZER_OUTPUT_FORMAT'] = 'text'
  clang_path = args.clang_cxx_path or args.clang_cc_path
  if is_cxx:
    env['CCC_CXX'] = clang_path
    env['CLANG_CXX'] = clang_path
  else:
    env['CCC_CC'] = clang_path
    env['CLANG'] = clang_path

  # TODO(kmarshall): Place the summarized output in a useful directory.
  temp_dir = tempfile.mkdtemp()
  try:
    env['CCC_ANALYZER_HTML'] = temp_dir
    returncode, stderr = wrapper_utils.CaptureCommandStderr(
        wrapper_utils.CommandToRun([args.analyzer] + compile_args), env)
    sys.stderr.write(stderr)
    return returncode
  finally:
    shutil.rmtree(temp_dir)

if __name__ == "__main__":
  sys.exit(main())
