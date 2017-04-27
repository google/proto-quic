# Copyright 2017 The Chromium Authors.  All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""Generates a file describing the js_library to be used by js_binary action.

This script takes in a list of sources and dependencies as described by a
js_library action.  It creates a file listing the sources and dependencies
that can later be used by a js_binary action to compile the javascript.
"""

from argparse import ArgumentParser


def main():
  parser = ArgumentParser()
  parser.add_argument('-s', '--sources', nargs='*', default=[],
                      help='List of js source files')
  parser.add_argument('-o', '--output', help='Write list to output')
  parser.add_argument('-d', '--deps', nargs='*', default=[],
                      help='List of js_library dependencies')
  args = parser.parse_args()

  with open(args.output, 'w') as out:
    out.write('sources:\n%s\ndeps:\n%s' % ('\n'.join(args.sources),
                                           '\n'.join(args.deps)))


if __name__ == '__main__':
  main()
