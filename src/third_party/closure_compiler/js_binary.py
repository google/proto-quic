# Copyright 2017 The Chromium Authors.  All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""Used by a js_binary action to compile javascript files.

This script takes in a list of sources and dependencies and compiles them all
together into a single compiled .js file.  The dependencies are ordered in a
post-order, left-to-right traversal order.  If multiple instances of the same
source file are read, only the first is kept. The script can also take in
optional --flags argument which will add custom flags to the compiler.  Any
extern files can also be passed in using the --extern flag.
"""

import argparse
import os
import sys

import compile2


def ParseDepList(dep):
  """Parses a depenency list, returns |sources, deps|."""
  assert os.path.isfile(dep), (os.path.splitext(dep) +
                               ' is not a js_library target')
  with open(dep, 'r') as dep_list:
    lines = dep_list.read().splitlines()
  assert 'deps:' in lines, dep + ' is not formated correctly, missing "deps:"'
  split = lines.index('deps:')
  return lines[1:split], lines[split+1:]


def CrawlDepsTree(deps, sources):
  """Parses the dependency tree creating a post-order listing of sources."""
  for dep in deps:
    new_sources, new_deps = ParseDepList(dep)

    sources = CrawlDepsTree(new_deps, sources)
    sources += [source for source in new_sources if source not in sources]
  return sources


def main():
  parser = argparse.ArgumentParser()
  parser.add_argument('-c', '--compiler', required=True,
                      help='Path to compiler')
  parser.add_argument('-s', '--sources', nargs='*', default=[],
                      help='List of js source files')
  parser.add_argument('-o', '--output', required=True,
                      help='Compile to output')
  parser.add_argument('-d', '--deps', nargs='*', default=[],
                      help='List of js_libarary dependencies')
  parser.add_argument('-b', '--bootstrap',
                      help='A file to include before all others')
  parser.add_argument('-cf', '--config', nargs='*', default=[],
                      help='A list of files to include after bootstrap and '
                      'before all others')
  parser.add_argument('-f', '--flags', nargs='*', default=[],
                      help='A list of custom flags to pass to the compiler. '
                      'Do not include leading dashes')
  parser.add_argument('-e', '--externs', nargs='*', default=[],
                      help='A list of extern files to pass to the compiler')

  args = parser.parse_args()
  sources = CrawlDepsTree(args.deps, []) + args.sources

  compiler_args = ['--%s' % flag for flag in args.flags]
  compiler_args += ['--externs=%s' % e for e in args.externs]
  compiler_args += [
      '--js_output_file',
      args.output,
      '--js',
  ]
  if args.bootstrap:
    compiler_args += [args.bootstrap]
  compiler_args += args.config
  compiler_args += sources

  returncode, errors = compile2.Checker().run_jar(args.compiler, compiler_args)
  if returncode != 0:
    print errors

  return returncode


if __name__ == '__main__':
  sys.exit(main())
