# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import subprocess
import sys

# This script prints information about the build system, the operating
# system and the iOS SDK (depending on the platform "iphonesimulator"
# or "iphoneos" generally).
#
# In the GYP build, this is done inside GYP itself based on the SDKROOT
# variable.

def FormatVersion(version):
  """Converts Xcode version to a format required for Info.plist."""
  version = version.replace('.', '')
  version = version + '0' * (3 - len(version))
  return version.zfill(4)


def FillXcodeVersion(settings):
  """Fills the Xcode version and build number into |settings|."""
  lines = subprocess.check_output(['xcodebuild', '-version']).splitlines()
  settings['xcode_version'] = FormatVersion(lines[0].split()[-1])
  settings['xcode_build'] = lines[-1].split()[-1]


def FillMachineOSBuild(settings):
  """Fills OS build number into |settings|."""
  settings['machine_os_build'] = subprocess.check_output(
      ['sw_vers', '-buildVersion']).strip()


def FillSDKPathAndVersion(settings, platform):
  """Fills the SDK path and version for |platform| into |settings|."""
  lines = subprocess.check_output(['xcodebuild', '-version', '-sdk',
      platform, 'Path', 'SDKVersion', 'ProductBuildVersion']).splitlines()
  settings['ios_sdk_path'] = lines[0]
  settings['ios_sdk_version'] = lines[1]
  settings['ios_sdk_build'] = lines[2]


if __name__ == '__main__':
  if len(sys.argv) != 2:
    sys.stderr.write(
        'usage: %s [iphoneos|iphonesimulator]\n' %
        os.path.basename(sys.argv[0]))
    sys.exit(1)

  settings = {}
  FillSDKPathAndVersion(settings, sys.argv[1])
  FillMachineOSBuild(settings)
  FillXcodeVersion(settings)

  for key in sorted(settings):
    print '%s="%s"' % (key, settings[key])
