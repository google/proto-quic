#!/usr/bin/env python
# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""This script ensures that a given directory is an initialized git repo."""

import argparse
import logging
import os
import subprocess
import sys


def run_git(git_cmd, *args, **kwargs):
  """Runs git with given arguments.

  kwargs are passed through to subprocess.

  If the kwarg 'throw' is provided, this behaves as check_call, otherwise will
  return git's return value.
  """
  logging.info('Running: %s %s %s', git_cmd, args, kwargs)
  func = subprocess.check_call if kwargs.pop('throw', True) else subprocess.call
  return func((git_cmd,)+args, **kwargs)


def main():
  parser = argparse.ArgumentParser()
  parser.add_argument('--path', help='Path to prospective git repo.',
                      required=True)
  parser.add_argument('--url', help='URL of remote to make origin.',
                      required=True)
  parser.add_argument('--git_cmd_path',
                      help='Path to the git command to run.',
                      default='git')
  parser.add_argument('--remote', help='Name of the git remote.',
                      default='origin')
  parser.add_argument('-v', '--verbose', action='store_true')
  opts = parser.parse_args()

  path = opts.path
  remote = opts.remote
  url = opts.url

  logging.getLogger().setLevel(logging.DEBUG if opts.verbose else logging.WARN)

  if not os.path.exists(path):
    os.makedirs(path)

  if os.path.exists(os.path.join(path, '.git')):
    run_git(opts.git_cmd_path, 'config', '--remove-section',
            'remote.%s' % remote, cwd=path)
  else:
    run_git(opts.git_cmd_path, 'init', cwd=path)
  run_git(opts.git_cmd_path, 'remote', 'add', remote, url, cwd=path)
  return 0


if __name__ == '__main__':
  sys.exit(main())
