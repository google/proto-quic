# Copyright 2016 The LUCI Authors. All rights reserved.
# Use of this source code is governed under the Apache License, Version 2.0
# that can be found in the LICENSE file.

"""Command line tool for creating and extracting ar files."""

from __future__ import print_function

import argparse
import io
import os
import shutil
import stat
import sys
import time

# pylint: disable=relative-import
import arfile


class ProgressReporter(object):
  def __init__(self, every):
    self.every = int(every)
    self.start = time.time()
    self.filecount = 0
    self.lastreport = 0

  def inc(self):
    self.filecount += 1
    if (self.filecount - self.lastreport) >= self.every:
      self.report()

  def report(self):
    if self.every:
      t = time.time()-self.start
      print(u'Took %f for %i files == %f files/second' % (
          t, self.filecount, self.filecount/t), file=sys.stderr)
    self.lastreport = self.filecount

  def __del__(self):
    self.report()


def create_cmd(
      filename, dirs, progress, read_ahead, verbose, dont_use_defaults):
  afw = arfile.ArFileWriter(filename)
  try:
    for path in dirs:
      for dirpath, child_dirs, filenames in os.walk(path):
        # In-place sort the child_dirs so we walk in lexicographical order
        child_dirs.sort()
        filenames.sort()
        for fn in filenames:
          fp = os.path.join(dirpath, fn)

          if verbose:
            print(fp, file=sys.stderr)

          progress.inc()

          with open(fp, 'rb') as f:
            if dont_use_defaults:
              afw.addfile(
                  arfile.ArInfo.frompath(fp[len(path)+1:], cwd=path),
                  f)
              continue

            # If a file is small, it is cheaper to just read the file rather
            # than doing a stat
            data = f.read(read_ahead)
            if len(data) < read_ahead:
              afw.addfile(arfile.ArInfo.fromdefault(
                fp[len(path)+1:], len(data)), io.BytesIO(data))
            else:
              size = os.stat(fp).st_size
              f.seek(0)
              afw.addfile(arfile.ArInfo.fromdefault(
                fp[len(path)+1:], size), f)
  finally:
    afw.close()


def list_cmd(filename, progress):
  afr = arfile.ArFileReader(filename, fullparse=False)
  for ai, _ in afr:
    print(ai.name)
    progress.inc()


def extract_cmd(
      filename, progress, verbose, dont_use_defaults, blocksize=1024*64):
  afr = arfile.ArFileReader(filename, fullparse=dont_use_defaults)
  for ai, ifd in afr:
    assert not ai.name.startswith('/')
    if verbose:
      print(ai.name, file=sys.stderr)

    try:
      os.makedirs(os.path.dirname(ai.name))
    except OSError:
      pass

    with open(ai.name, 'wb') as ofd:
      written = 0
      while written < ai.size:
        readsize = min(blocksize, ai.size-written)
        ofd.write(ifd.read(readsize))
        written += readsize

    progress.inc()


def main(name, args):
  parser = argparse.ArgumentParser(
    prog=name,
    description=sys.modules[__name__].__doc__)
  subparsers = parser.add_subparsers(
    dest='mode', help='sub-command help')

  # Create command
  parser_create = subparsers.add_parser(
    'create', help='Create a new ar file')
  parser_create.add_argument(
    '-r', '--read-ahead',
    type=int, default=1024*64,
    help='Amount of data to read-ahead before doing a stat.')
  parser_create.add_argument(
    '-f', '--filename',
    type=argparse.FileType('wb'), default=sys.stdout,
    help='ar file to use')
  parser_create.add_argument(
    'dirs', nargs='+', help='Directory or file to add to the ar file')

  # List command
  parser_list = subparsers.add_parser('list', help='List a new ar file')

  # Extract command
  parser_extract = subparsers.add_parser(
    'extract', help='Extract an existing ar file to current directory')

  # Add to output commands
  for p in parser_list, parser_extract:
    p.add_argument(
      '-f', '--filename',
      type=argparse.FileType('rb'), default=sys.stdin,
      help='ar file to use')

  for p in parser_create, parser_extract:
    p.add_argument(
      '--dont-use-defaults',
      action='store_true', default=False,
      help='Don\'t use default value for file information.')

    p.add_argument(
      '-v', '--verbose',
      action='store_true',
      help='Output file names to stderr while running.')

  # Add to all commands
  for p in parser_create, parser_list, parser_extract:
    p.add_argument(
      '-p', '--progress',
      type=ProgressReporter, default='10000',
      help='Output progress information every N files.')

  args = parser.parse_args(args)
  mode = getattr(sys.modules[__name__], args.mode + '_cmd')
  del args.mode
  return mode(**args.__dict__)


if __name__ == '__main__':
  sys.exit(main('artool', (a.decode('utf-8') for a in sys.argv[1:])))
