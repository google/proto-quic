#! /usr/bin/env python
# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import argparse
import os
import re
import shutil
import sys
import tempfile
import zipfile

import devil_chromium
from devil.android.sdk import dexdump
from pylib.constants import host_paths

sys.path.append(os.path.join(host_paths.DIR_SOURCE_ROOT, 'build', 'util', 'lib',
                             'common'))
import perf_tests_results_helper # pylint: disable=import-error


_METHOD_IDS_SIZE_RE = re.compile(r'^method_ids_size +: +(\d+)$')

def ExtractIfZip(dexfile, tmpdir):
  if not dexfile.endswith('.zip'):
    return [dexfile]

  with zipfile.ZipFile(dexfile, 'r') as z:
    z.extractall(tmpdir)

  return [os.path.join(tmpdir, f) for f in os.listdir(tmpdir)]

def SingleMethodCount(dexfile):
  for line in dexdump.DexDump(dexfile, file_summary=True):
    m = _METHOD_IDS_SIZE_RE.match(line)
    if m:
      return m.group(1)
  raise Exception('"method_ids_size" not found in dex dump of %s' % dexfile)

def MethodCount(dexfile):
  tmpdir = tempfile.mkdtemp(suffix='_dex_extract')
  multidex_file_list = ExtractIfZip(dexfile, tmpdir)
  try:
    return sum(int(SingleMethodCount(d)) for d in multidex_file_list)
  finally:
    shutil.rmtree(tmpdir)

def main():
  parser = argparse.ArgumentParser()
  parser.add_argument(
      '--apk-name', help='Name of the APK to which the dexfile corresponds.')
  parser.add_argument('dexfile')

  args = parser.parse_args()

  devil_chromium.Initialize()

  if not args.apk_name:
    dirname, basename = os.path.split(args.dexfile)
    while basename:
      if 'apk' in basename:
        args.apk_name = basename
        break
      dirname, basename = os.path.split(dirname)
    else:
      parser.error(
          'Unable to determine apk name from %s, '
          'and --apk-name was not provided.' % args.dexfile)

  method_count = MethodCount(args.dexfile)
  perf_tests_results_helper.PrintPerfResult(
      '%s_methods' % args.apk_name, 'total', [method_count], 'methods')
  return 0

if __name__ == '__main__':
  sys.exit(main())

