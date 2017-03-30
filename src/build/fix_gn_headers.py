#!/usr/bin/env python
# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Fix header files missing in GN.

This script takes the missing header files from check_gn_headers.py, and
try to fix them by adding them to the GN files.
Manual cleaning up is likely required afterwards.
"""

import argparse
import os
import re
import subprocess
import sys


def AddHeadersNextToCC(headers, skip_ambiguous=True):
  """Add header files next to the corresponding .cc files in GN files.

  When skip_ambiguous is True, skip if multiple .cc files are found.
  Returns unhandled headers.

  Manual cleaning up is likely required, especially if not skip_ambiguous.
  """
  edits = {}
  unhandled = []
  for filename in headers:
    filename = filename.strip()
    if not (filename.endswith('.h') or filename.endswith('.hh')):
      continue
    basename = os.path.basename(filename)
    print filename
    cc = r'\b' + os.path.splitext(basename)[0] + r'\.(cc|cpp|mm)\b'
    p = subprocess.Popen(
        ['git', 'grep', '-En', cc + '"', '--', '*.gn', '*.gni'],
        stdout=subprocess.PIPE)
    out, _ = p.communicate()
    if p.returncode != 0 or not out:
      unhandled.append(filename)
      continue

    if skip_ambiguous and len(out.splitlines()) > 1:
      print '\n[WARNING] Ambiguous matching for', filename
      print out
      continue

    for gnline in out.splitlines():
      gnfile, linenr, contents = gnline.split(':')
      linenr = int(linenr)
      new = re.sub(cc, basename, contents)
      lines = open(gnfile).read().splitlines()
      # Skip if it's already there. It could be before or after the match.
      if lines[linenr] == new:
        continue
      if lines[linenr - 2] == new:
        continue
      print '  ', gnfile, linenr, new
      edits.setdefault(gnfile, {})[linenr] = new

  for gnfile in edits:
    lines = open(gnfile).read().splitlines()
    for l in sorted(edits[gnfile].keys(), reverse=True):
      lines.insert(l, edits[gnfile][l])
    open(gnfile, 'w').write('\n'.join(lines) + '\n')

  return unhandled


def AddHeadersToSources(headers, skip_ambiguous=True):
  """Add header files to the sources list in the first GN file.

  The target GN file is the first one up the parent directories.
  This usually does the wrong thing for _test files if the test and the main
  target are in the same .gn file.
  When skip_ambiguous is True, skip if multiple sources arrays are found.

  "git cl format" afterwards is required. Manually cleaning up duplicated items
  is likely required.
  """
  for filename in headers:
    filename = filename.strip()
    print filename
    dirname = os.path.dirname(filename)
    while not os.path.exists(os.path.join(dirname, 'BUILD.gn')):
      dirname = os.path.dirname(dirname)
    rel = filename[len(dirname) + 1:]
    gnfile = os.path.join(dirname, 'BUILD.gn')

    lines = open(gnfile).read().splitlines()
    matched = [i for i, l in enumerate(lines) if ' sources = [' in l]
    if skip_ambiguous and len(matched) > 1:
      print '[WARNING] Multiple sources in', gnfile
      continue

    if len(matched) < 1:
      continue
    print '  ', gnfile, rel
    index = matched[0]
    lines.insert(index + 1, '"%s",' % rel)
    open(gnfile, 'w').write('\n'.join(lines) + '\n')


def main():
  parser = argparse.ArgumentParser()
  parser.add_argument('input_file',
                      help="missing headers, output of check_gn_headers.py")
  parser.add_argument('--prefix',
                      help="only handle path name with this prefix")

  args, _extras = parser.parse_known_args()

  headers = open(args.input_file).readlines()

  if args.prefix:
    headers = [i for i in headers if i.startswith(args.prefix)]

  unhandled = AddHeadersNextToCC(headers)
  AddHeadersToSources(unhandled)


if __name__ == '__main__':
  sys.exit(main())
