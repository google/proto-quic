#!/usr/bin/env python
# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Starts bisect try jobs on multiple platforms using known-good configs.

The purpose of this script is to serve as an integration test for the
auto-bisect project by starting try jobs for various config types and
various platforms.

The known-good configs are in this same directory as this script. They
are expected to all end in ".cfg" and start with the name of the platform
followed by a dot.

You can specify --full to try running each config on all applicable bots;
the default behavior is to try each config on only one bot.
"""

import argparse
import logging
import os
import subprocess
import sys

SCRIPT_DIR = os.path.abspath(os.path.dirname(__file__))
BISECT_CONFIG = os.path.join(SCRIPT_DIR, os.path.pardir, 'bisect.cfg')
PERF_TEST_CONFIG = os.path.join(
    SCRIPT_DIR, os.path.pardir, os.path.pardir, 'run-perf-test.cfg')
PLATFORM_BOT_MAP = {
    'linux': ['linux_perf_bisect'],
    'mac': ['mac_10_9_perf_bisect', 'mac_10_10_perf_bisect'],
    'win': ['win_perf_bisect', 'win_8_perf_bisect', 'win_xp_perf_bisect'],
    'winx64': ['win_x64_perf_bisect'],
    'android': [
        'android_nexus4_perf_bisect',
        'android_nexus5_perf_bisect',
        'android_nexus7_perf_bisect',
    ],
}
SVN_URL = 'svn://svn.chromium.org/chrome-try/try-perf'
AUTO_COMMIT_MESSAGE = 'Automatic commit for bisect try job.'


def main(argv):
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument('--full', action='store_true',
                      help='Run each config on all applicable bots.')
  parser.add_argument('configs', nargs='+',
                      help='One or more sample config files.')
  parser.add_argument('--verbose', '-v', action='store_true',
                      help='Output additional debugging information.')
  parser.add_argument('--dry-run', action='store_true',
                      help='Don\'t execute "git try" while running.')
  args = parser.parse_args(argv[1:])
  _SetupLogging(args.verbose)
  logging.debug('Source configs: %s', args.configs)
  try:
    _StartTryJobs(args.configs, args.full, args.dry_run)
  except subprocess.CalledProcessError as error:
    print str(error)
    print error.output


def _SetupLogging(verbose):
  level = logging.INFO
  if verbose:
    level = logging.DEBUG
  logging.basicConfig(level=level)


def _StartTryJobs(source_configs, full_mode=False, dry_run=False):
  """Tries each of the given sample configs on one or more try bots."""
  for source_config in source_configs:
    dest_config = _DestConfig(source_config)
    bot_names = _BotNames(source_config, full_mode=full_mode)
    _StartTry(source_config, dest_config, bot_names, dry_run=dry_run)


def _DestConfig(source_config):
  """Returns the path that a sample config should be copied to."""
  if 'bisect' in source_config:
    return BISECT_CONFIG
  assert 'perf_test' in source_config, source_config
  return PERF_TEST_CONFIG


def _BotNames(source_config, full_mode=False):
  """Returns try bot names to use for the given config file name."""
  platform = os.path.basename(source_config).split('.')[0]
  assert platform in PLATFORM_BOT_MAP
  bot_names = PLATFORM_BOT_MAP[platform]
  if full_mode:
    return bot_names
  return [bot_names[0]]


def _StartTry(source_config, dest_config, bot_names, dry_run=False):
  """Sends a try job with the given config to the given try bots.

  Args:
    source_config: Path of the sample config to copy over.
    dest_config: Destination path to copy sample to, e.g. "./bisect.cfg".
    bot_names: List of try bot builder names.
  """
  assert os.path.exists(source_config)
  assert os.path.exists(dest_config)
  assert _LastCommitMessage() != AUTO_COMMIT_MESSAGE

  # Copy the sample config over and commit it.
  _Run(['cp', source_config, dest_config])
  _Run(['git', 'commit', '--all', '-m', AUTO_COMMIT_MESSAGE])

  try:
    # Start the try job.
    job_name = 'Automatically-started (%s)' % os.path.basename(source_config)
    try_command = ['git', 'try', '--svn_repo', SVN_URL, '--name', job_name]
    for bot_name in bot_names:
      try_command.extend(['--bot', bot_name])
    print _Run(try_command, dry_run=dry_run)
  finally:
    # Revert the immediately-previous commit which was made just above.
    assert _LastCommitMessage() == AUTO_COMMIT_MESSAGE
    _Run(['git', 'reset', '--hard', 'HEAD~1'])


def _LastCommitMessage():
  return _Run(['git', 'log', '--format=%s', '-1']).strip()


def _Run(command, dry_run=False):
  """Runs a command in a subprocess.

  Args:
    command: The command given as an args list.

  Returns:
    The output of the command.

  Raises:
    subprocess.CalledProcessError: The return-code was non-zero.
  """
  logging.debug('Running %s', command)
  if dry_run:
    return 'Did not run command because this is a dry run.'
  return subprocess.check_output(command)


if __name__ == '__main__':
  sys.exit(main(sys.argv))
