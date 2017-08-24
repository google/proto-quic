#!/usr/bin/env python

# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import shutil
import subprocess
import sys
import tarfile
import tempfile


SELF_FILE = os.path.normpath(os.path.abspath(__file__))
REPOSITORY_ROOT = os.path.abspath(os.path.join(
    os.path.dirname(__file__), '..', '..'))


def Run(*args):
  print 'Run:', ' '.join(args)
  subprocess.check_call(args)


def EnsureEmptyDir(path):
  if os.path.isdir(path):
    shutil.rmtree(path)
  if not os.path.exists(path):
    print 'Creating directory', path
    os.makedirs(path)


def main(args):
  if len(args) != 1 or not os.path.isdir(args[0]):
    print 'usage: %s <path_to_fuchsia_tree>' % SELF_FILE
    return 1

  original_dir = os.getcwd()

  fuchsia_root = args[0]

  # Switch to the Fuchsia tree and build an SDK.
  os.chdir(fuchsia_root)
  Run('scripts/build-magenta.sh', '-t', 'x86_64')
  Run('scripts/build-magenta.sh', '-t', 'aarch64')
  Run('packages/gn/gen.py', '--target_cpu=x86-64', '--modules=sdk',
      '--ignore-skia', '--release')
  Run('packages/gn/build.py', '--release')
  tempdir = tempfile.mkdtemp()
  sdk_tar = os.path.join(tempdir, 'fuchsia-sdk.tgz')
  Run('go', 'run', 'scripts/makesdk.go', '-output', sdk_tar, '.')

  # Nuke the SDK from DEPS, put our just-built one there, and set a fake .hash
  # file. This means that on next gclient runhooks, we'll restore to the
  # real DEPS-determined SDK.
  output_dir = os.path.join(REPOSITORY_ROOT, 'third_party', 'fuchsia-sdk')
  EnsureEmptyDir(output_dir)
  tarfile.open(sdk_tar, mode='r:gz').extractall(path=output_dir)
  hash_filename = os.path.join(output_dir, '.hash')
  with open(hash_filename, 'w') as f:
    f.write('locally-built-sdk')

  # Clean up.
  shutil.rmtree(tempdir)
  os.chdir(original_dir)

  return 0


if __name__ == '__main__':
  sys.exit(main(sys.argv[1:]))
