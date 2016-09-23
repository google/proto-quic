#!/usr/bin/env python
#
# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""
Updates the Android support repository (m2repository).
"""

import argparse
import fnmatch
import os
import subprocess
import shutil
import sys

DIR_SOURCE_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                               '..', '..', '..'))
ANDROID_SDK_PATH = os.path.abspath(os.path.join(DIR_SOURCE_ROOT, 'third_party',
                                                'android_tools', 'sdk'))
TARGET_NAME = 'extra-android-m2repository'
# The first version we included was 23.2.1. Any folders that are older than
# that should not be included by Chrome's git repo. Unstable versions should
# also be excluded.
REMOVE_LIST = ['databinding', '13.*', '18.*', '19.*', '20.*', '21.*', '22.*',
               '23.0.*', '23.1.*', '23.2.0', '*-alpha*', '*-beta*']


def main():
  parser = argparse.ArgumentParser(description='Updates the Android support '
                                   'repository in third_party/android_tools')
  parser.add_argument('--sdk-dir',
                      help='Directory for the Android SDK.')
  args = parser.parse_args()

  sdk_path = ANDROID_SDK_PATH
  if args.sdk_dir is not None:
    sdk_path = os.path.abspath(os.path.join(DIR_SOURCE_ROOT, args.sdk_dir))

  sdk_tool = os.path.abspath(os.path.join(sdk_path, 'tools', 'android'))
  if not os.path.exists(sdk_tool):
    print 'SDK tool not found at %s' % sdk_tool
    return 1

  # Run the android sdk update tool in command line.
  subprocess.check_call([sdk_tool, 'update', 'sdk' , '--no-ui',
                         '--filter', TARGET_NAME])

  m2repo = os.path.abspath(os.path.join(sdk_path, 'extras', 'android',
                                        'm2repository'))
  # Remove obsolete folders and unused folders according to REMOVE_LIST.
  count = 0
  for folder, _, _ in os.walk(m2repo):
    for pattern in REMOVE_LIST:
      if fnmatch.fnmatch(os.path.basename(folder), pattern):
        count += 1
        print 'Removing %s' % os.path.relpath(folder, sdk_path)
        shutil.rmtree(folder)
  if count == 0:
    print ('No files were removed from the updated support library. '
           'Did you update it successfully?')
    return 1


if __name__ == '__main__':
  sys.exit(main())
