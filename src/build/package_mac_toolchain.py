#!/usr/bin/env python
# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Compress and upload Mac toolchain files."""

import argparse
import glob
import os
import plistlib
import re
import subprocess
import sys
import tarfile
import tempfile


TOOLCHAIN_URL = "gs://chrome-mac-sdk"

# It's important to at least remove unused Platform folders to cut down on the
# size of the toolchain folder.  There are other various unused folders that
# have been removed through trial and error.  If future versions of Xcode become
# problematic it's possible this list is incorrect, and can be reduced to just
# the unused platforms.  On the flip side, it's likely more directories can be
# excluded.
EXCLUDE_FOLDERS = [
'Contents/Applications',
'Contents/Developer/Documentation',
'Contents/Developer/Platforms/AppleTVOS.platform',
'Contents/Developer/Platforms/AppleTVSimulator.platform',
'Contents/Developer/Platforms/WatchOS.platform',
'Contents/Developer/Platforms/WatchSimulator.platform',
'Contents/Developer/Platforms/iPhoneOS.platform',
'Contents/Developer/Platforms/iPhoneSimulator.platform',
'Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/swift-migrator',
'Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/swift',
'Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX10.11.sdk/'
    'usr/share/man',
'Contents/Developer/Library/Xcode/Templates'
]


def main():
  """Compress |target_dir| and upload to |TOOLCHAIN_URL|"""
  parser = argparse.ArgumentParser()
  parser.add_argument('target_dir',
                      help="Xcode installation directory.")
  args = parser.parse_args()

  # Verify this looks like an Xcode directory.
  contents_dir = os.path.join(args.target_dir, 'Contents')
  plist_file = os.path.join(contents_dir, 'version.plist')
  try:
    info = plistlib.readPlist(plist_file)
  except:
    print "Invalid Xcode dir."
    return 0
  build_version = info['ProductBuildVersion']

  # Look for previous toolchain tgz files with the same |build_version|.
  wildcard_filename = '%s/toolchain-%s-*.tgz' % (TOOLCHAIN_URL, build_version)
  p = subprocess.Popen(['gsutil.py', 'ls', wildcard_filename],
                       stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE)
  output = p.communicate()[0]
  next_count = 1
  if p.returncode == 0:
    next_count = len(output.split('\n'))
    sys.stdout.write("%s already exists (%s). "
                     "Do you want to create another? [y/n] "
                     % (build_version, next_count - 1))

    if raw_input().lower() not in set(['yes','y', 'ye']):
      print "Skipping duplicate upload."
      return 0

  os.chdir(args.target_dir)
  toolchain_file_name = "toolchain-%s-%s" % (build_version, next_count)
  toolchain_name = tempfile.mktemp(suffix='toolchain.tgz')

  print "Creating %s (%s)." % (toolchain_file_name, toolchain_name)
  os.environ["COPYFILE_DISABLE"] = "1"
  args = ['tar', '-cvzf', toolchain_name]
  args.extend(map('--exclude={0}'.format, EXCLUDE_FOLDERS))
  args.extend(['.'])
  subprocess.check_call(args)

  print "Uploading %s toolchain." % toolchain_file_name
  destination_path = '%s/%s.tgz' % (TOOLCHAIN_URL, toolchain_file_name)
  subprocess.check_call(['gsutil.py', 'cp', '-n', '-a', 'public-read',
                         toolchain_name, destination_path])

  print "Done with %s upload." % toolchain_file_name
  return 0

if __name__ == '__main__':
  sys.exit(main())
