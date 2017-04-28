#!/usr/bin/env python
# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""Merge driver for the Blink rename merge helper."""

import hashlib
import os
import shutil
import subprocess
import sys


def main():
  if len(sys.argv) < 5:
    print('usage: %s <base> <current> <others> <path in the tree>' %
          sys.argv[0])
    sys.exit(1)

  base, current, others, file_name_in_tree = sys.argv[1:5]

  # If set, try to resolve conflicts based on the precalculated file.
  if 'BLINK_RENAME_RECORDS_PATH' in os.environ:
    file_hash = hashlib.sha256(file_name_in_tree).hexdigest()
    saved_file = os.path.join(os.environ['BLINK_RENAME_RECORDS_PATH'],
                              file_hash)
    if os.path.isfile(saved_file):
      print 'Using pre-recorded conflict resolution for  %s' % file_name_in_tree
      shutil.copyfile(saved_file, current)
      shutil.copyfile(others, base)

  return subprocess.call(['git', 'merge-file', '-Lcurrent', '-Lbase', '-Lother',
                          current, base, others])


if __name__ == '__main__':
  sys.exit(main())
