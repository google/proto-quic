#!/usr/bin/env python
# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Unpacks pre-built sanitizer-instrumented third-party libraries.
This script should only be run by gn.
"""

import os
import subprocess
import shutil
import sys


def main(archive, stamp_file, target_dir):
  shutil.rmtree(target_dir, ignore_errors=True)

  os.mkdir(target_dir)
  subprocess.check_call([
      'tar',
      '-zxf',
      archive,
      '-C',
      target_dir])
  open(stamp_file, 'w').close()
  return 0


if __name__ == '__main__':
  sys.exit(main(*sys.argv[1:]))
