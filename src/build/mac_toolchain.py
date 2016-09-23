#!/usr/bin/env python
# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Download necessary mac toolchain files under certain conditions.  If
xcode-select is already set and points to an external folder
(e.g. /Application/Xcode.app), this script only runs if the GYP_DEFINE
|force_mac_toolchain| is set.  To override the values in
|TOOLCHAIN_REVISION|-|TOOLCHAIN_SUB_REVISION| below, GYP_DEFINE
mac_toolchain_revision can be used instead.

This script will only run on machines if /usr/bin/xcodebuild and
/usr/bin/xcode-select has been added to the sudoers list so the license can be
accepted.

Otherwise, user input would be required to complete the script.  Perhaps future
versions can be modified to allow for user input on developer machines.
"""

import os
import plistlib
import shutil
import subprocess
import sys
import tarfile
import time
import tempfile
import urllib2

# This can be changed after running /build/package_mac_toolchain.py.
TOOLCHAIN_REVISION = '5B1008'
TOOLCHAIN_SUB_REVISION = 3
TOOLCHAIN_VERSION = '%s-%s' % (TOOLCHAIN_REVISION, TOOLCHAIN_SUB_REVISION)

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
TOOLCHAIN_BUILD_DIR = os.path.join(BASE_DIR, 'mac_files', 'Xcode.app')
STAMP_FILE = os.path.join(BASE_DIR, 'mac_files', 'toolchain_build_revision')
TOOLCHAIN_URL = 'gs://chrome-mac-sdk/'


def GetToolchainDirectory():
  if sys.platform == 'darwin' and not UseLocalMacSDK():
    return TOOLCHAIN_BUILD_DIR
  else:
    return None


def SetToolchainEnvironment():
  mac_toolchain_dir = GetToolchainDirectory()
  if mac_toolchain_dir:
    os.environ['DEVELOPER_DIR'] = mac_toolchain_dir


def ReadStampFile():
  """Return the contents of the stamp file, or '' if it doesn't exist."""
  try:
    with open(STAMP_FILE, 'r') as f:
      return f.read().rstrip()
  except IOError:
    return ''


def WriteStampFile(s):
  """Write s to the stamp file."""
  EnsureDirExists(os.path.dirname(STAMP_FILE))
  with open(STAMP_FILE, 'w') as f:
    f.write(s)
    f.write('\n')


def EnsureDirExists(path):
  if not os.path.exists(path):
    os.makedirs(path)


def DownloadAndUnpack(url, output_dir):
  """Decompresses |url| into a cleared |output_dir|."""
  temp_name = tempfile.mktemp(prefix='mac_toolchain')
  try:
    print 'Downloading new toolchain.'
    subprocess.check_call(['gsutil.py', 'cp', url, temp_name])
    if os.path.exists(output_dir):
      print 'Deleting old toolchain.'
      shutil.rmtree(output_dir)
    EnsureDirExists(output_dir)
    print 'Unpacking new toolchain.'
    tarfile.open(mode='r:gz', name=temp_name).extractall(path=output_dir)
  finally:
    if os.path.exists(temp_name):
      os.unlink(temp_name)


def CanAccessToolchainBucket():
  """Checks whether the user has access to |TOOLCHAIN_URL|."""
  proc = subprocess.Popen(['gsutil.py', 'ls', TOOLCHAIN_URL],
                           stdout=subprocess.PIPE)
  proc.communicate()
  return proc.returncode == 0

def LoadPlist(path):
  """Loads Plist at |path| and returns it as a dictionary."""
  fd, name = tempfile.mkstemp()
  try:
    subprocess.check_call(['plutil', '-convert', 'xml1', '-o', name, path])
    with os.fdopen(fd, 'r') as f:
      return plistlib.readPlist(f)
  finally:
    os.unlink(name)


def AcceptLicense():
  """Use xcodebuild to accept new toolchain license if necessary.  Don't accept
  the license if a newer license has already been accepted. This only works if
  xcodebuild and xcode-select are passwordless in sudoers."""

  # Check old license
  try:
    target_license_plist_path = \
        os.path.join(TOOLCHAIN_BUILD_DIR,
                     *['Contents','Resources','LicenseInfo.plist'])
    target_license_plist = LoadPlist(target_license_plist_path)
    build_type = target_license_plist['licenseType']
    build_version = target_license_plist['licenseID']

    accepted_license_plist = LoadPlist(
        '/Library/Preferences/com.apple.dt.Xcode.plist')
    agreed_to_key = 'IDELast%sLicenseAgreedTo' % build_type
    last_license_agreed_to = accepted_license_plist[agreed_to_key]

    # Historically all Xcode build numbers have been in the format of AANNNN, so
    # a simple string compare works.  If Xcode's build numbers change this may
    # need a more complex compare.
    if build_version <= last_license_agreed_to:
      # Don't accept the license of older toolchain builds, this will break the
      # license of newer builds.
      return
  except (subprocess.CalledProcessError, KeyError):
    # If there's never been a license of type |build_type| accepted,
    # |target_license_plist_path| or |agreed_to_key| may not exist.
    pass

  print "Accepting license."
  old_path = subprocess.Popen(['/usr/bin/xcode-select', '-p'],
                               stdout=subprocess.PIPE).communicate()[0].strip()
  try:
    build_dir = os.path.join(TOOLCHAIN_BUILD_DIR, 'Contents/Developer')
    subprocess.check_call(['sudo', '/usr/bin/xcode-select', '-s', build_dir])
    subprocess.check_call(['sudo', '/usr/bin/xcodebuild', '-license', 'accept'])
  finally:
    subprocess.check_call(['sudo', '/usr/bin/xcode-select', '-s', old_path])


def UseLocalMacSDK():
  force_pull = os.environ.has_key('FORCE_MAC_TOOLCHAIN')

  # Don't update the toolchain if there's already one installed outside of the
  # expected location for a Chromium mac toolchain, unless |force_pull| is set.
  proc = subprocess.Popen(['xcode-select', '-p'], stdout=subprocess.PIPE)
  xcode_select_dir = proc.communicate()[0]
  rc = proc.returncode
  return (not force_pull and rc == 0 and
          TOOLCHAIN_BUILD_DIR not in xcode_select_dir)


def main():
  if sys.platform != 'darwin':
    return 0

  # TODO(justincohen): Add support for GN per crbug.com/570091
  if UseLocalMacSDK():
    print 'Using local toolchain.'
    return 0

  toolchain_revision = os.environ.get('MAC_TOOLCHAIN_REVISION',
                                      TOOLCHAIN_VERSION)
  if ReadStampFile() == toolchain_revision:
    print 'Toolchain (%s) is already up to date.' % toolchain_revision
    AcceptLicense()
    return 0

  if not CanAccessToolchainBucket():
    print 'Cannot access toolchain bucket.'
    return 0

  # Reset the stamp file in case the build is unsuccessful.
  WriteStampFile('')

  toolchain_file = '%s.tgz' % toolchain_revision
  toolchain_full_url = TOOLCHAIN_URL + toolchain_file

  print 'Updating toolchain to %s...' % toolchain_revision
  try:
    toolchain_file = 'toolchain-%s.tgz' % toolchain_revision
    toolchain_full_url = TOOLCHAIN_URL + toolchain_file
    DownloadAndUnpack(toolchain_full_url, TOOLCHAIN_BUILD_DIR)
    AcceptLicense()

    print 'Toolchain %s unpacked.' % toolchain_revision
    WriteStampFile(toolchain_revision)
    return 0
  except Exception as e:
    print 'Failed to download toolchain %s.' % toolchain_file
    print 'Exception %s' % e
    print 'Exiting.'
    return 1

if __name__ == '__main__':
  sys.exit(main())
