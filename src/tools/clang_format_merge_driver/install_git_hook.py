#!/usr/bin/env python
# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""Hook to install the git config for using the clang-format merge driver."""

import os
import subprocess
import sys

_VERSION = 1


def BuildGitCmd(*args):
  cmd = []
  if sys.platform == 'win32':
    cmd.append('git.bat')
  else:
    cmd.append('git')
  cmd.extend(args)
  return cmd


def main():
  # Assume that the script always lives somewhere inside the git repo.
  os.chdir(os.path.dirname(os.path.abspath(__file__)))

  try:
    current_version = subprocess.check_output(
        BuildGitCmd('config', 'merge.clang-format.version'))
    try:
      if int(current_version) >= _VERSION:
        return
    except ValueError:
      # Not parseable for whatever reason: reinstall the config.
      pass
  except subprocess.CalledProcessError:
    # git returned a non-zero return code, the config probably doesn't exist.
    pass

  print 'Installing clang-format merge driver into .git/config...'

  subprocess.check_call(
      BuildGitCmd('config', 'merge.clang-format.name',
                  'clang-format merge driver'))
  subprocess.check_call(
      BuildGitCmd('config', 'merge.clang-format.driver',
                  'clang_format_merge_driver %O %A %B %P'))
  subprocess.check_call(
      BuildGitCmd('config', 'merge.clang-format.recursive', 'binary'))
  subprocess.check_call(
      BuildGitCmd('config', 'merge.clang-format.version', str(_VERSION)))


if __name__ == '__main__':
  sys.exit(main())
