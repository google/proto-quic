#!/usr/bin/env python
# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Creates an .isolate given a list of files.

"""

import argparse
import os
import pprint
import re
import sys


_UNIVERSAL_BLACKLIST = (
    r'.*OWNERS',  # Should never be included.
)

_ANDROID_BLACKLIST = (
    r'.*\.crx',  # Chrome extension zip files.
    r'.*external_extensions\.json',  # Chrome external extensions config file.
    r'.*\.so',  # Libraries packed into .apk.
    r'.*\.mojom\.js',  # Some test_support targets include python deps.
    r'.*Mojo.*manifest\.json',  # Some source_set()s pull these in.
    r'.*jni_generator_tests',  # Exists just to test the compile, not to be run.
)

_DEVICE_BLACKLIST = (
    r'.*\.py',  # Some test_support targets include python deps.

    # v8's blobs get packaged into APKs.
    r'.*natives_blob.*\.bin',
    r'.*snapshot_blob.*\.bin',
)

_ASSERT_WHITELIST = (
    r'.*\.pak',
    r'.*/',  # Assume directories are always included on purpose.
)


def _IsExecutable(path):
  return os.path.isfile(path) and os.access(path, os.X_OK)


def _MatchesAny(path, patterns):
  return any(re.match(p, path) for p in patterns)


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument('--command',
                      help='The command to put in the .isolate (optional)')
  parser.add_argument('--runtime-deps-file', required=True,
                      help='Input .runtime_deps file.')
  parser.add_argument('--output-directory', required=True,
                      help='Location of the ninja output directory')
  parser.add_argument('--out-file', help='Write to file rather than stdout.')
  parser.add_argument('--apply-android-filters', action='store_true',
                      help='Filter files not required for Android.')
  parser.add_argument('--apply-device-filters', action='store_true',
                      help='Filter files not required in *.device.isolate.')
  parser.add_argument('--assert-no-odd-data', action='store_true',
                      help='Fail if any data deps exist (after filtering) '
                           'that are not a part of the _ASSERT_WHITELIST. Use '
                           'this to prevent unexpected runtime_deps from '
                           'creeping in')
  options = parser.parse_args()

  deps = []
  with open(options.runtime_deps_file) as deps_file:
    for path in deps_file:
      if path.startswith('./'):
        path = path[2:]
      deps.append(path.rstrip())

  deps = (d for d in deps if not _MatchesAny(d, _UNIVERSAL_BLACKLIST))

  if options.apply_android_filters:
    deps = (d for d in deps if not _MatchesAny(d, _ANDROID_BLACKLIST))

  if options.apply_device_filters:
    deps = (d for d in deps if not _MatchesAny(d, _DEVICE_BLACKLIST))
    # Breakpad tests have a helper exe, which is packaged in the _dist.
    deps = (d for d in deps if not _IsExecutable(d))

  # Make them relative to out-file.
  if options.out_file:
    subdir = os.path.relpath(options.output_directory,
                             os.path.dirname(options.out_file))
    deps = (os.path.join(subdir, d) for d in deps)

  deps = sorted(deps)

  if options.assert_no_odd_data:
    odd_files = [d for d in deps if not _MatchesAny(d, _ASSERT_WHITELIST)]
    assert not odd_files, ('Found possibly undesired file in runtime_deps: %s' %
                           odd_files)

  isolate_dict = {
      'variables': {
          'files': deps,
      }
  }
  if options.command:
    isolate_dict['variables']['command'] = [options.command]

  isolate_data = pprint.pformat(isolate_dict)
  if options.out_file:
    with open(options.out_file, 'w') as f:
      f.write(isolate_data + '\n')
  else:
    print isolate_data


if __name__ == '__main__':
  sys.exit(main())

