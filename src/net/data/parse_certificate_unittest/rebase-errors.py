#!/usr/bin/python
# Copyright (c) 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Helper script to update the test error expectations based on actual results.

This is useful for regenerating test expectations after making changes to the
error format.

To use this run the affected tests, and then pass the input to this script
(either via stdin, or as the first argument). For instance:

  $ ./out/Release/net_unittests --gtest_filter="*ParseCertificate*" | \
     net/data/parse_certificate_unittest/rebase-errors.py

The script works by scanning the stdout looking for gtest failures when
comparing "errors.ToDebugString()". The C++ test side should have been
instrumented to dump out the test file's path on mismatch.

This script will then update the corresponding .pem file
"""

import sys
sys.path += ['../verify_certificate_chain_unittest']

import common

import os
import sys
import re


# Regular expression to find the failed errors in test stdout.
#  * Group 1 of the match is the actual error text (backslash-escaped)
#  * Group 2 of the match is file path (relative to //src) where the expected
#    errors were read from.
failed_test_regex = re.compile(r"""
Value of: errors.ToDebugString\(\)
  Actual: "(.*)"
(?:.|\n)+?
Test file: (.*[.]pem)
""", re.MULTILINE)


# Regular expression to find the ERRORS block (and any text above it) in a PEM
# file. The assumption is that ERRORS is not the very first block in the file
# (since it looks for an -----END to precede it).
#  * Group 1 of the match is the ERRORS block content and any comments
#    immediately above it.
errors_block_regex = re.compile(r""".*
-----END .*?-----

(.*?
-----BEGIN ERRORS-----
.*?
-----END ERRORS-----
)""", re.MULTILINE | re.DOTALL)


def read_file_to_string(path):
  """Reads a file entirely to a string"""
  with open(path, 'r') as f:
    return f.read()


def write_string_to_file(data, path):
  """Writes a string to a file"""
  print "Writing file %s ..." % (path)
  with open(path, "w") as f:
    f.write(data)


def replace_string(original, start, end, replacement):
  """Replaces the specified range of |original| with |replacement|"""
  return original[0:start] + replacement + original[end:]


def fixup_pem_file(path, actual_errors):
  """Updates the ERRORS block in the test .pem file"""
  contents = read_file_to_string(path)

  m = errors_block_regex.search(contents)

  if not m:
    contents += '\n' + common.text_data_to_pem('ERRORS', actual_errors)
  else:
    contents = replace_string(contents, m.start(1), m.end(1),
                              common.text_data_to_pem('ERRORS', actual_errors))

  # Update the file.
  write_string_to_file(contents, path)


def get_src_root():
  """Returns the path to the enclosing //src directory. This assumes the
  current script is inside the source tree."""
  cur_dir = os.path.dirname(os.path.realpath(__file__))

  while True:
    parent_dir, dirname = os.path.split(cur_dir)
    # Check if it looks like the src/ root.
    if dirname == "src" and os.path.isdir(os.path.join(cur_dir, "net")):
      return cur_dir
    if not parent_dir or parent_dir == cur_dir:
      break
    cur_dir = parent_dir

  print "Couldn't find src dir"
  sys.exit(1)


def get_abs_path(rel_path):
  """Converts |rel_path| (relative to src) to a full path"""
  return os.path.join(get_src_root(), rel_path)


def main():
  if len(sys.argv) > 2:
    print 'Usage: %s [path-to-unittest-stdout]' % (sys.argv[0])
    sys.exit(1)

  # Read the input either from a file, or from stdin.
  test_stdout = None
  if len(sys.argv) == 2:
    test_stdout = read_file_to_string(sys.argv[1])
  else:
    print 'Reading input from stdin...'
    test_stdout = sys.stdin.read()

  for m in failed_test_regex.finditer(test_stdout):
    actual_errors = m.group(1)
    actual_errors = actual_errors.decode('string-escape')
    relative_test_path = m.group(2)
    fixup_pem_file(get_abs_path(relative_test_path), actual_errors)


if __name__ == "__main__":
  main()
