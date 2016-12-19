#!/usr/bin/env python
# Copyright (c) 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Install Debian sysroots for building chromium.
"""

# The sysroot is needed to ensure that binaries will run on Debian Wheezy,
# the oldest supported linux distribution. For ARM64 linux, we have Debian
# Jessie sysroot as Jessie is the first version with ARM64 support. This script
# can be run manually but is more often run as part of gclient hooks. When run
# from hooks this script is a no-op on non-linux platforms.

# The sysroot image could be constructed from scratch based on the current
# state or Debian Wheezy/Jessie but for consistency we currently use a
# pre-built root image. The image will normally need to be rebuilt every time
# chrome's build dependencies are changed.

import hashlib
import json
import platform
import optparse
import os
import re
import shutil
import subprocess
import sys
import urllib2

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(os.path.dirname(SCRIPT_DIR)))
import detect_host_arch
import gyp_chromium
import gyp_environment


URL_PREFIX = 'https://commondatastorage.googleapis.com'
URL_PATH = 'chrome-linux-sysroot/toolchain'

VALID_ARCHS = ('arm', 'arm64', 'i386', 'amd64', 'mips')


class Error(Exception):
  pass


def GetSha1(filename):
  sha1 = hashlib.sha1()
  with open(filename, 'rb') as f:
    while True:
      # Read in 1mb chunks, so it doesn't all have to be loaded into memory.
      chunk = f.read(1024*1024)
      if not chunk:
        break
      sha1.update(chunk)
  return sha1.hexdigest()


def DetectHostArch():
  # Figure out host arch using build/detect_host_arch.py and
  # set target_arch to host arch
  detected_host_arch = detect_host_arch.HostArch()
  if detected_host_arch == 'x64':
    return 'amd64'
  elif detected_host_arch == 'ia32':
    return 'i386'
  elif detected_host_arch == 'arm':
    return 'arm'
  elif detected_host_arch == 'arm64':
    return 'arm64'
  elif detected_host_arch == 'mips':
    return 'mips'
  elif detected_host_arch == 'ppc':
    return 'ppc'
  elif detected_host_arch == 's390':
    return 's390'

  raise Error('Unrecognized host arch: %s' % detected_host_arch)


def DetectTargetArch():
  """Attempt for determine target architecture.

  This works by looking for target_arch in GYP_DEFINES.
  """
  # TODO(agrieve): Make this script not depend on GYP_DEFINES so that it works
  #     with GN as well.
  gyp_environment.SetEnvironment()
  supplemental_includes = gyp_chromium.GetSupplementalFiles()
  gyp_defines = gyp_chromium.GetGypVars(supplemental_includes)
  target_arch = gyp_defines.get('target_arch')
  if target_arch == 'x64':
    return 'amd64'
  elif target_arch == 'ia32':
    return 'i386'
  elif target_arch == 'arm':
    return 'arm'
  elif target_arch == 'arm64':
    return 'arm64'
  elif target_arch == 'mipsel':
    return 'mips'

  return None


def InstallDefaultSysroots(host_arch):
  """Install the default set of sysroot images.

  This includes at least the sysroot for host architecture, and the 32-bit
  sysroot for building the v8 snapshot image.  It can also include the cross
  compile sysroot for ARM/MIPS if cross compiling environment can be detected.

  Another reason we're installing this by default is so that developers can
  compile and run on our supported platforms without having to worry about
  flipping things back and forth and whether the sysroots have been downloaded
  or not.
  """
  InstallDefaultSysrootForArch(host_arch)

  if host_arch == 'amd64':
    InstallDefaultSysrootForArch('i386')

  # Desktop Chromium OS builds require the precise sysroot.
  # TODO(thomasanderson): only download this when the GN arg target_os
  # == 'chromeos', when the functionality to perform the check becomes
  # available.
  InstallSysroot('Precise', 'amd64')

  # Finally, if we can detect a non-standard target_arch such as ARM or
  # MIPS, then install the sysroot too.
  # Don't attampt to install arm64 since this is currently and android-only
  # architecture.
  target_arch = DetectTargetArch()
  if target_arch and target_arch not in (host_arch, 'i386'):
    InstallDefaultSysrootForArch(target_arch)


def main(args):
  parser = optparse.OptionParser('usage: %prog [OPTIONS]', description=__doc__)
  parser.add_option('--running-as-hook', action='store_true',
                    default=False, help='Used when running from gclient hooks.'
                                        ' Installs default sysroot images.')
  parser.add_option('--arch', type='choice', choices=VALID_ARCHS,
                    help='Sysroot architecture: %s' % ', '.join(VALID_ARCHS))
  options, _ = parser.parse_args(args)
  if options.running_as_hook and not sys.platform.startswith('linux'):
    return 0

  if options.running_as_hook:
    host_arch = DetectHostArch()
    # PPC/s390 don't use sysroot, see http://crbug.com/646169
    if host_arch in ['ppc','s390']:
      return 0
    InstallDefaultSysroots(host_arch)
  else:
    if not options.arch:
      print 'You much specify either --arch or --running-as-hook'
      return 1
    InstallDefaultSysrootForArch(options.arch)

  return 0

def InstallDefaultSysrootForArch(target_arch):
  if target_arch == 'amd64':
    InstallSysroot('Wheezy', 'amd64')
  elif target_arch == 'arm':
    InstallSysroot('Wheezy', 'arm')
  elif target_arch == 'arm64':
    InstallSysroot('Jessie', 'arm64')
  elif target_arch == 'i386':
    InstallSysroot('Wheezy', 'i386')
  elif target_arch == 'mips':
    InstallSysroot('Wheezy', 'mips')
  else:
    raise Error('Unknown architecture: %s' % target_arch)

def InstallSysroot(target_platform, target_arch):
  # The sysroot directory should match the one specified in build/common.gypi.
  # TODO(thestig) Consider putting this elsewhere to avoid having to recreate
  # it on every build.
  linux_dir = os.path.dirname(SCRIPT_DIR)

  sysroots_file = os.path.join(SCRIPT_DIR, 'sysroots.json')
  sysroots = json.load(open(sysroots_file))
  sysroot_key = '%s_%s' % (target_platform.lower(), target_arch)
  if sysroot_key not in sysroots:
    raise Error('No sysroot for: %s %s' % (target_platform, target_arch))
  sysroot_dict = sysroots[sysroot_key]
  revision = sysroot_dict['Revision']
  tarball_filename = sysroot_dict['Tarball']
  tarball_sha1sum = sysroot_dict['Sha1Sum']
  sysroot = os.path.join(linux_dir, sysroot_dict['SysrootDir'])

  url = '%s/%s/%s/%s' % (URL_PREFIX, URL_PATH, revision, tarball_filename)

  stamp = os.path.join(sysroot, '.stamp')
  if os.path.exists(stamp):
    with open(stamp) as s:
      if s.read() == url:
        print 'Debian %s %s root image already up to date: %s' % \
            (target_platform, target_arch, sysroot)
        return

  print 'Installing Debian %s %s root image: %s' % \
      (target_platform, target_arch, sysroot)
  if os.path.isdir(sysroot):
    shutil.rmtree(sysroot)
  os.mkdir(sysroot)
  tarball = os.path.join(sysroot, tarball_filename)
  print 'Downloading %s' % url
  sys.stdout.flush()
  sys.stderr.flush()
  for _ in range(3):
    try:
      response = urllib2.urlopen(url)
      with open(tarball, "wb") as f:
        f.write(response.read())
      break
    except:
      pass
  else:
    raise Error('Failed to download %s' % url)
  sha1sum = GetSha1(tarball)
  if sha1sum != tarball_sha1sum:
    raise Error('Tarball sha1sum is wrong.'
                'Expected %s, actual: %s' % (tarball_sha1sum, sha1sum))
  subprocess.check_call(['tar', 'xf', tarball, '-C', sysroot])
  os.remove(tarball)

  with open(stamp, 'w') as s:
    s.write(url)


if __name__ == '__main__':
  try:
    sys.exit(main(sys.argv[1:]))
  except Error as e:
    sys.stderr.write(str(e) + '\n')
    sys.exit(1)
