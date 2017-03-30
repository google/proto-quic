#!/usr/bin/env python
# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Main Python API for analyzing binary size."""

import argparse
import distutils.spawn
import logging
import os
import subprocess
import sys

import describe
import file_format
import function_signature
import helpers
import linker_map_parser
import models


def _IterLines(s):
  prev_idx = -1
  while True:
    idx = s.find('\n', prev_idx + 1)
    if idx == -1:
      return
    yield s[prev_idx + 1:idx]
    prev_idx = idx


def _UnmangleRemainingSymbols(symbol_group, tool_prefix):
  """Uses c++filt to unmangle any symbols that need it."""
  to_process = [s for s in symbol_group if s.name.startswith('_Z')]
  if not to_process:
    return

  logging.info('Unmangling %d names', len(to_process))
  proc = subprocess.Popen([tool_prefix + 'c++filt'], stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE)
  stdout = proc.communicate('\n'.join(s.name for s in to_process))[0]
  assert proc.returncode == 0

  for i, line in enumerate(_IterLines(stdout)):
    to_process[i].name = line


def _NormalizeNames(symbol_group):
  """Ensures that all names are formatted in a useful way.

  This includes:
    - Assigning of |function_signature| (for functions).
    - Stripping of return types in |function_signature| and |name|.
    - Stripping parameters from |name|.
    - Moving "vtable for" and the like to be suffixes rather than prefixes.
  """
  found_prefixes = set()
  for symbol in symbol_group:
    if symbol.name.startswith('*'):
      # See comment in _RemoveDuplicatesAndCalculatePadding() about when this
      # can happen.
      continue

    # E.g.: vtable for FOO
    idx = symbol.name.find(' for ', 0, 30)
    if idx != -1:
      found_prefixes.add(symbol.name[:idx + 4])
      symbol.name = symbol.name[idx + 5:] + ' [' + symbol.name[:idx] + ']'

    # E.g.: virtual thunk to FOO
    idx = symbol.name.find(' to ', 0, 30)
    if idx != -1:
      found_prefixes.add(symbol.name[:idx + 3])
      symbol.name = symbol.name[idx + 4:] + ' [' + symbol.name[:idx] + ']'

    # Strip out return type, and identify where parameter list starts.
    if symbol.section == 't':
      symbol.function_signature, symbol.name = (
          function_signature.Parse(symbol.name))

    # Remove anonymous namespaces (they just harm clustering).
    symbol.name = symbol.name.replace('(anonymous namespace)::', '')

  logging.debug('Found name prefixes of: %r', found_prefixes)


def _NormalizeObjectPaths(symbol_group):
  """Ensures that all paths are formatted in a useful way."""
  for symbol in symbol_group:
    if symbol.path.startswith('obj/'):
      # Convert obj/third_party/... -> third_party/...
      symbol.path = symbol.path[4:]
    elif symbol.path.startswith('../../'):
      # Convert ../../third_party/... -> third_party/...
      symbol.path = symbol.path[6:]
    if symbol.path.endswith(')'):
      # Convert foo/bar.a(baz.o) -> foo/bar.a/baz.o
      start_idx = symbol.path.index('(')
      paren_path = symbol.path[start_idx + 1:-1]
      symbol.path = symbol.path[:start_idx] + os.path.sep + paren_path


def _RemoveDuplicatesAndCalculatePadding(symbol_group):
  """Removes symbols at the same address and calculates the |padding| field.

  Symbols must already be sorted by |address|.
  """
  i = 0
  to_remove = set()
  all_symbols = symbol_group.symbols
  for i in xrange(len(all_symbols)):
    prev_symbol = all_symbols[i - 1]
    symbol = all_symbols[i]
    if prev_symbol.section_name != symbol.section_name:
      continue
    if symbol.address > 0 and prev_symbol.address > 0:
      # Fold symbols that are at the same address (happens in nm output).
      if symbol.address == prev_symbol.address:
        symbol.size = max(prev_symbol.size, symbol.size)
        to_remove.add(i)
        continue
      # Even with symbols at the same address removed, overlaps can still
      # happen. In this case, padding will be negative (and this is fine).
      padding = symbol.address - prev_symbol.end_address
      # These thresholds were found by manually auditing arm32 Chrome.
      # E.g.: Set them to 0 and see what warnings get logged.
      # TODO(agrieve): See if these thresholds make sense for architectures
      #     other than arm32.
      if (symbol.section in 'rd' and padding >= 256 or
          symbol.section in 't' and padding >= 64):
        # For nm data, this is caused by data that has no associated symbol.
        # The linker map file lists them with no name, but with a file.
        # Example:
        #   .data 0x02d42764 0x120 .../V8SharedWorkerGlobalScope.o
        # Where as most look like:
        #   .data.MANGLED_NAME...
        logging.debug('Large padding of %d between:\n  A) %r\n  B) %r' % (
                      padding, prev_symbol, symbol))
        continue
      symbol.padding = padding
      symbol.size += padding
      assert symbol.size >= 0, 'Symbol has negative size: %r' % symbol
  # Map files have no overlaps, so worth special-casing the no-op case.
  if to_remove:
    logging.info('Removing %d overlapping symbols', len(to_remove))
    symbol_group.symbols = (
        [s for i, s in enumerate(all_symbols) if i not in to_remove])


def AddOptions(parser):
  parser.add_argument('--tool-prefix', default='',
                      help='Path prefix for c++filt.')
  parser.add_argument('--output-directory',
                      help='Path to the root build directory.')


def _DetectToolPrefix(tool_prefix, input_file, output_directory=None):
  """Calls Analyze with values from args."""
  if not output_directory:
    abs_path = os.path.abspath(input_file)
    release_idx = abs_path.find('Release')
    if release_idx != -1:
      output_directory = abs_path[:release_idx] + 'Release'
      output_directory = os.path.relpath(abs_path[:release_idx] + '/Release')
      logging.debug('Detected --output-directory=%s', output_directory)

  if not tool_prefix and output_directory:
    # Auto-detect from build_vars.txt
    build_vars_path = os.path.join(output_directory, 'build_vars.txt')
    if os.path.exists(build_vars_path):
      with open(build_vars_path) as f:
        build_vars = dict(l.rstrip().split('=', 1) for l in f if '=' in l)
      logging.debug('Found --tool-prefix from build_vars.txt')
      tool_prefix = os.path.join(output_directory,
                                 build_vars['android_tool_prefix'])

  if os.path.sep not in tool_prefix:
    full_path = distutils.spawn.find_executable(tool_prefix + 'c++filt')
  else:
    full_path = tool_prefix + 'c++filt'

  if not os.path.isfile(full_path):
    raise Exception('Bad --tool-prefix. Path not found: %s' % full_path)
  logging.info('Using --tool-prefix=%s', tool_prefix)
  return tool_prefix


def AnalyzeWithArgs(args, input_path):
  return Analyze(input_path, args.output_directory, args.tool_prefix)


def Analyze(path, output_directory=None, tool_prefix=''):
  if file_format.EndsWithMaybeGz(path, '.size'):
    logging.debug('Loading results from: %s', path)
    size_info = file_format.LoadSizeInfo(path)
    # Recompute derived values (padding and function names).
    logging.info('Calculating padding')
    _RemoveDuplicatesAndCalculatePadding(size_info.symbols)
    logging.info('Deriving signatures')
    # Re-parse out function parameters.
    _NormalizeNames(size_info.symbols.WhereInSection('t'))
    return size_info
  elif not file_format.EndsWithMaybeGz(path, '.map'):
    raise Exception('Expected input to be a .map or a .size')
  else:
    # Verify tool_prefix early.
    tool_prefix = _DetectToolPrefix(tool_prefix, path, output_directory)

    with file_format.OpenMaybeGz(path) as map_file:
      size_info = linker_map_parser.MapFileParser().Parse(map_file)

    # Map file for some reason doesn't unmangle all names.
    logging.info('Calculating padding')
    _RemoveDuplicatesAndCalculatePadding(size_info.symbols)
    # Unmangle prints its own log statement.
    _UnmangleRemainingSymbols(size_info.symbols, tool_prefix)
    # Resolve paths prints its own log statement.
    logging.info('Normalizing names')
    _NormalizeNames(size_info.symbols)
    logging.info('Normalizing paths')
    _NormalizeObjectPaths(size_info.symbols)

  if logging.getLogger().isEnabledFor(logging.INFO):
    for line in describe.DescribeSizeInfoCoverage(size_info):
      logging.info(line)
  logging.info('Finished analyzing %d symbols', len(size_info.symbols))
  return size_info


def main(argv):
  parser = argparse.ArgumentParser(argv)
  parser.add_argument('input_file', help='Path to input .map file.')
  parser.add_argument('output_file', help='Path to output .size(.gz) file.')
  AddOptions(parser)
  args = helpers.AddCommonOptionsAndParseArgs(parser, argv)
  if not file_format.EndsWithMaybeGz(args.output_file, '.size'):
    parser.error('output_file must end with .size or .size.gz')

  size_info = AnalyzeWithArgs(args, args.input_file)
  logging.info('Saving result to %s', args.output_file)
  file_format.SaveSizeInfo(size_info, args.output_file)

  logging.info('Done')


if __name__ == '__main__':
  sys.exit(main(sys.argv))
