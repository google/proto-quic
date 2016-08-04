#!/usr/bin/python
# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""Builds and packages instrumented libraries for dynamic tools."""

import argparse
import contextlib
import os
import shutil
import subprocess
import tarfile

BUILD_TYPES = {
    'msan-no-origins': [
        'is_msan = true',
        'msan_track_origins = 0',
    ],
    'msan-chained-origins': [
        'is_msan = true',
        'msan_track_origins = 2',
    ],
    'tsan': ['is_tsan = true'],
    'asan': ['is_asan = true']
}
SUPPORTED_RELEASES = frozenset(['trusty'])


class Error(Exception):
  pass


class UnsupportedReleaseError(Error):
  pass


def _get_release():
  return subprocess.check_output(['lsb_release', '-cs']).strip()


def _tar_filter(tar_info):
  if tar_info.name.endswith('.txt'):
    return None
  return tar_info


def build_libraries(build_type, ubuntu_release, jobs, use_goma):
  archive_name = '%s-%s' % (build_type, ubuntu_release)
  build_dir = 'out/Instrumented-%s' % archive_name
  if not os.path.exists(build_dir):
    os.makedirs(build_dir)

  gn_args = [
      'is_debug = false',
      'use_goma = %s' % str(use_goma).lower(),
      'instrumented_libraries_jobs  = %d' % jobs,
      'use_locally_built_instrumented_libraries = true',
  ] + BUILD_TYPES[build_type]
  with open(os.path.join(build_dir, 'args.gn'), 'w') as f:
    f.write('\n'.join(gn_args))
  subprocess.check_call(['gn', 'gen', build_dir, '--check'])
  subprocess.check_call(['ninja', '-j2', '-C', build_dir,
                         'third_party/instrumented_libraries:locally_built'])
  with tarfile.open('%s.tgz' % archive_name, mode='w:gz') as f:
    prefix = build_type.split('-', 1)[0]
    f.add('%s/instrumented_libraries/%s' % (build_dir, prefix),
          arcname=prefix,
          filter=_tar_filter)
    f.add('%s/instrumented_libraries/sources' % build_dir,
          arcname='sources',
          filter=_tar_filter)
  return archive_name


def main():
  parser = argparse.ArgumentParser(
      description=__doc__,
      formatter_class=argparse.ArgumentDefaultsHelpFormatter)
  parser.add_argument(
      '--jobs',
      '-j',
      type=int,
      default=8,
      help='the default number of jobs to use when running make')
  parser.add_argument('--use_goma',
                      action='store_true',
                      default=False,
                      help='whether to use goma to compile')
  parser.add_argument('build_type',
                      nargs='*',
                      default='all',
                      choices=BUILD_TYPES.keys() + ['all'],
                      help='the type of instrumented library to build')
  args = parser.parse_args()
  if args.build_type == 'all' or 'all' in args.build_type:
    args.build_type = BUILD_TYPES.keys()

  ubuntu_release = _get_release()
  if ubuntu_release not in SUPPORTED_RELEASES:
    raise UnsupportedReleaseError('%s is not a supported release' %
                                  _get_release())
  archive_names = [
      build_libraries(build_type, ubuntu_release, args.jobs, args.use_goma)
      for build_type in sorted(set(args.build_type))
  ]
  print 'To upload, run:'
  for archive_name in archive_names:
    print('upload_to_google_storage.py -b '
          'chromium-instrumented-libraries %s.tgz') % archive_name
  print 'You should then commit the resulting .sha1 files.'


if __name__ == '__main__':
  main()
