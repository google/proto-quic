#!/usr/bin/env python
# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Windows ICO file crusher.

Optimizes the PNG images within a Windows ICO icon file. This extracts all of
the sub-images within the file, runs any PNG-formatted images through
optimize-png-files.sh, then packs them back into an ICO file.

NOTE: ICO files can contain both raw uncompressed BMP files and PNG files. This
script does not touch the BMP files, which means if you have a huge uncompressed
image, it will not get smaller. 256x256 icons should be PNG-formatted first.
(Smaller icons should be BMPs for compatibility with Windows XP.)
"""

import argparse
import logging
import os
import StringIO
import sys

import ico_tools

def main(args=None):
  if args is None:
    args = sys.argv[1:]

  parser = argparse.ArgumentParser(description='Crush Windows ICO files.')
  parser.add_argument('files', metavar='ICO', type=argparse.FileType('r+b'),
                      nargs='+', help='.ico files to be crushed')
  parser.add_argument('-o', dest='optimization_level', metavar='OPT', type=int,
                      help='optimization level')
  parser.add_argument('-d', '--debug', dest='debug', action='store_true',
                      help='enable debug logging')

  args = parser.parse_args()

  if args.debug:
    logging.getLogger().setLevel(logging.DEBUG)

  for file in args.files:
    buf = StringIO.StringIO()
    file.seek(0, os.SEEK_END)
    old_length = file.tell()
    file.seek(0, os.SEEK_SET)
    ico_tools.OptimizeIcoFile(file, buf, args.optimization_level)

    new_length = len(buf.getvalue())

    # Always write (even if file size not reduced), because we make other fixes
    # such as regenerating the AND mask.
    file.truncate(new_length)
    file.seek(0)
    file.write(buf.getvalue())

    if new_length >= old_length:
      logging.info('%s : Could not reduce file size.', file.name)
    else:
      saving = old_length - new_length
      saving_percent = float(saving) / old_length
      logging.info('%s : %d => %d (%d bytes : %d %%)', file.name, old_length,
                   new_length, saving, int(saving_percent * 100))

if __name__ == '__main__':
  sys.exit(main())
