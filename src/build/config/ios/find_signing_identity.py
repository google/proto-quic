# Copyright (c) 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import argparse
import os
import subprocess
import sys
import re

def ListIdentities():
  return subprocess.check_output([
    'xcrun',
    'security',
    'find-identity',
    '-v',
    '-p',
    'codesigning',
  ])


def FindValidIdentity():
  lines = list(map(str.strip, ListIdentities().splitlines()))
  # Look for something like "2) XYZ "iPhone Developer: Name (ABC)""
  exp = re.compile('[0-9]+\) ([A-F0-9]+) "([^"]*)"')
  for line in lines:
    res = exp.match(line)
    if res is None:
      continue
    if "iPhone Developer" in res.group(2):
      return res.group(1)
  return ""


if __name__ == '__main__':
  parser = argparse.ArgumentParser('codesign iOS bundles')
  parser.add_argument('--developer_dir', required=False,
                      help='Path to Xcode.')
  args = parser.parse_args()
  if args.developer_dir:
    os.environ['DEVELOPER_DIR'] = args.developer_dir

  print FindValidIdentity()
