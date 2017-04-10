#!/usr/bin/env python
# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Tool for finding the cause of APK bloat.

Run diagnose_apk_bloat.py -h for detailed usage help.
"""

import argparse
import logging
import multiprocessing
import os
import shutil
import subprocess
import sys

import helpers

_DEFAULT_OUT_DIR = os.path.join(helpers.SRC_ROOT, 'out', 'diagnose-apk-bloat')
_DEFAULT_TARGET = 'monochrome_public_apk'
_DEFAULT_ARCHIVE_DIR = os.path.join(helpers.SRC_ROOT, 'binary-size-bloat')


class _BuildHelper(object):
  """Helper class for generating and building targets."""

  def __init__(self, args):
    self.enable_chrome_android_internal = args.enable_chrome_android_internal
    self.max_jobs = args.max_jobs
    self.max_load_average = args.max_load_average
    self.output_directory = args.output_directory
    self.target = args.target
    self.target_os = args.target_os
    self.use_goma = args.use_goma
    self._SetDefaults()

  def _SetDefaults(self):
    has_goma_dir = os.path.exists(os.path.join(os.path.expanduser('~'), 'goma'))
    self.use_goma = self.use_goma or has_goma_dir
    self.max_load_average = (self.max_load_average or
                             str(multiprocessing.cpu_count()))
    if not self.max_jobs:
      self.max_jobs = '10000' if self.use_goma else '500'

  def _GenGnCmd(self):
    gn_args = 'is_official_build = true'
    # Excludes some debug info, see crbug/610994.
    gn_args += ' is_chrome_branded = true'
    gn_args += ' use_goma = %s' % str(self.use_goma).lower()
    gn_args += ' target_os = "%s"' % self.target_os
    gn_args += (' enable_chrome_android_internal = %s' %
                str(self.enable_chrome_android_internal).lower())
    return ['gn', 'gen', self.output_directory, '--args=%s' % gn_args]

  def _GenNinjaCmd(self):
    cmd = ['ninja', '-C', self.output_directory]
    cmd += ['-j', self.max_jobs] if self.max_jobs else []
    cmd += ['-l', self.max_load_average] if self.max_load_average else []
    cmd += [self.target]
    return cmd

  def Build(self):
    logging.info('Building %s. This may take a while (run with -vv for '
                 'detailed ninja output).', self.target)
    _RunCmd(self._GenGnCmd())
    _RunCmd(self._GenNinjaCmd(), print_stdout=True)


def _GetLinkerMapPath(target_os, target):
  # TODO(estevenson): Get this from GN instead of hardcoding.
  if target_os == 'linux':
    return 'chrome.map.gz'
  elif 'monochrome' in target:
    return 'lib.unstripped/libmonochrome.so.map.gz'
  else:
    return 'lib.unstripped/libchrome.so.map.gz'


def _ApkPathFromTarget(target):
  # Only works on apk targets that follow: my_great_apk naming convention.
  apk_name = ''.join(s.title() for s in target.split('_')[:-1]) + '.apk'
  return os.path.join('apks', apk_name)


def _RunCmd(cmd, print_stdout=False):
  """Convenience function for running commands.

  Args:
    cmd: the command to run.
    print_stdout: if this is True, then the stdout of the process will be
        printed (to stdout if log level is DEBUG otherwise to /dev/null).
        If false, stdout will be returned.

  Returns:
    Command stdout if |print_stdout| is False otherwise ''.
  """
  cmd_str = ' '.join(c for c in cmd)
  logging.debug('Running: %s', cmd_str)
  if not print_stdout:
    proc_stdout = subprocess.PIPE
  elif logging.getLogger().isEnabledFor(logging.DEBUG):
    proc_stdout = sys.stdout
  else:
    proc_stdout = open(os.devnull, 'wb')

  proc = subprocess.Popen(cmd, stdout=proc_stdout, stderr=subprocess.PIPE)
  stdout, stderr = proc.communicate()

  if proc.returncode != 0:
    logging.error('Command failed: %s\nstderr:\n%s' % (cmd_str, stderr))
    sys.exit(1)

  return stdout.strip() if stdout else ''


def _GitCmd(args):
  return _RunCmd(['git', '-C', helpers.SRC_ROOT] + args)


def _GclientSyncCmd(rev):
  cwd = os.getcwd()
  os.chdir(helpers.SRC_ROOT)
  logging.info('gclient sync to %s', rev)
  _RunCmd(['gclient', 'sync', '-r', 'src@' + rev], print_stdout=True)
  os.chdir(cwd)


def _ArchiveBuildResult(archive_dir, build_helper):
  """Save resulting APK and mapping file."""
  def ArchiveFile(file_path):
    file_path = os.path.join(build_helper.output_directory, file_path)
    if os.path.exists(file_path):
      if not os.path.exists(archive_dir):
        os.makedirs(archive_dir)
      shutil.copy(file_path, archive_dir)
    else:
      logging.error('Expected file: %s not found.' % file_path)
      sys.exit(1)

  logging.info('Saving build results to: %s', archive_dir)
  ArchiveFile(_GetLinkerMapPath(build_helper.target_os, build_helper.target))
  if build_helper.target_os == 'android':
    ArchiveFile(_ApkPathFromTarget(build_helper.target))


def _SyncAndBuild(rev_with_patch, rev_without_patch, archive_dir, build_helper):
  rev_with_patch = _GitCmd(['rev-parse', rev_with_patch])
  rev_without_patch = _GitCmd([
      'rev-parse', rev_without_patch or rev_with_patch + '^'])

  # Move to a detached state since gclient sync doesn't work with local commits
  # on a branch.
  _GitCmd(['checkout', '--detach'])

  _GclientSyncCmd(rev_with_patch)
  build_helper.Build()
  _ArchiveBuildResult(
      os.path.join(archive_dir, 'with_patch_%s' % rev_with_patch), build_helper)

  _GclientSyncCmd(rev_without_patch)
  build_helper.Build()
  _ArchiveBuildResult(
      os.path.join(archive_dir, 'without_patch_%s' % rev_without_patch),
      build_helper)


def _EnsureDirectoryClean():
  logging.info('Checking source directory')
  stdout = _GitCmd(['status', '--porcelain'])
  # Ignore untracked files.
  if stdout and stdout[:2] != '??':
    logging.error('Failure: please ensure working directory is clean.')
    sys.exit(1)


def main():
  parser = argparse.ArgumentParser(
      description='Find the cause of APK size bloat.',
      formatter_class=argparse.ArgumentDefaultsHelpFormatter)
  parser.add_argument('--archive-dir',
                      default=_DEFAULT_ARCHIVE_DIR,
                      help='Where results are stored.')
  parser.add_argument('--rev-with-patch',
                      default='HEAD',
                      help='Commit with patch.')
  parser.add_argument('--rev-without-patch',
                      help='Older patch to diff against. If not supplied, '
                      'the previous commit to rev_with_patch will be used.')

  build_group = parser.add_argument_group('ninja', 'Args to use with ninja/gn')
  build_group.add_argument('-j',
                           dest='max_jobs',
                           help='Run N jobs in parallel.')
  build_group.add_argument('-l',
                           dest='max_load_average',
                           help='Do not start new jobs if the load average is '
                           'greater than N.')
  build_group.add_argument('--no-goma',
                           action='store_false',
                           dest='use_goma',
                           default=True,
                           help='Use goma when building with ninja.')
  build_group.add_argument('--target-os',
                           default='android',
                           choices=['android', 'linux'],
                           help='target_os gn arg.')
  build_group.add_argument('--output-directory',
                           default=_DEFAULT_OUT_DIR,
                           help='ninja output directory.')
  build_group.add_argument('--enable_chrome_android_internal',
                           action='store_true',
                           help='Allow downstream targets to be built.')
  build_group.add_argument('--target',
                           default=_DEFAULT_TARGET,
                           help='GN APK target to build.')
  args = helpers.AddCommonOptionsAndParseArgs(parser, sys.argv, pypy_warn=False)

  _EnsureDirectoryClean()
  build_helper = _BuildHelper(args)
  _SyncAndBuild(args.rev_with_patch, args.rev_without_patch, args.archive_dir,
                build_helper)


if __name__ == '__main__':
  sys.exit(main())

