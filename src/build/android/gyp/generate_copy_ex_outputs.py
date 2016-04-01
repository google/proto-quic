#!/usr/bin/env python
#
# Copyright (c) 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# Generate outputs according source files and destination path for
# copy_ex.gypi

import argparse
import os
import sys

def DoMain(argv):
  parser = argparse.ArgumentParser(prog='generate_copy_ex_outputs')
  parser.add_argument('--src-files',
                      nargs = '+',
                      help = 'a list of files to copy')
  parser.add_argument('--dest-path',
                      required = True,
                      help = 'the directory to copy file to')
  options = parser.parse_args(argv)
  # Quote each element so filename spaces don't mess up gyp's attempt to parse
  # it into a list.
  return ' '.join('"%s"' % os.path.join(options.dest_path,
                                        os.path.basename(src))
                  for src in options.src_files)

if __name__ == '__main__':
  results = DoMain(sys.argv[1:])
  if results:
    print results

