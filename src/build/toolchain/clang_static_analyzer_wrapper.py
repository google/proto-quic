#!/usr/bin/env python
# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Adds an analysis build step to invocations of the Clang C/C++ compiler.

Usage: clang_static_analyzer_wrapper.py <compiler> [args...]
"""

import argparse
import fnmatch
import itertools
import os
import sys
import wrapper_utils

# Flags used to enable analysis for Clang invocations.
analyzer_enable_flags = [
    '--analyze',
    '-fdiagnostics-show-option',
]

# Flags used to configure the analyzer's behavior.
analyzer_option_flags = [
    '-analyzer-checker=cplusplus',
    '-analyzer-opt-analyze-nested-blocks',
    '-analyzer-eagerly-assume',
    '-analyzer-output=text',
    '-analyzer-config',
    'suppress-c++-stdlib=true',

# List of checkers to execute.
# The full list of checkers can be found at
# https://clang-analyzer.llvm.org/available_checks.html.
    '-analyzer-checker=core',
    '-analyzer-checker=unix',
    '-analyzer-checker=deadcode',
]


def main():
  args = sys.argv[1:]
  assert args

  # Build the object file and proceed with analysis if it is buildable.
  returncode, stderr = wrapper_utils.CaptureCommandStderr(
    wrapper_utils.CommandToRun(args))
  sys.stderr.write(stderr)
  if returncode != 0:
    return returncode

  # Now run the analyzer.

  # Interleave 'analyzer_option_flags' flags w/'-Xanalyzer' so that Clang
  # passes them to the analysis tool.
  # e.g. ['-analyzer-foo', '-analyzer-bar'] => ['-Xanalyzer', '-analyzer-foo',
  #                                             '-Xanalyzer', '-analyzer-bar']
  interleaved_analyzer_flags = list(sum(zip(
      ['-Xanalyzer'] * len(analyzer_option_flags),
      analyzer_option_flags), ()))
  returncode, stderr = wrapper_utils.CaptureCommandStderr(
      wrapper_utils.CommandToRun(args + analyzer_enable_flags +
                                 interleaved_analyzer_flags))
  sys.stderr.write(stderr)
  if returncode != 0:
    sys.stderr.write(
        """WARNING! The Clang static analyzer exited with error code %d.
         Please share the error details in crbug.com/695243 if this looks like
         a new regression.\n""" % (returncode))

  return 0

if __name__ == '__main__':
  sys.exit(main())
