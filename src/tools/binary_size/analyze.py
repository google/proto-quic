#!/usr/bin/env python
# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Main Python API for analyzing binary size."""

import argparse
import ast
import distutils.spawn
import gzip
import logging
import os
import re
import subprocess

import function_signature
import helpers
import mapfileparser
import symbols


# File format version for .size files.
_SERIALIZATION_VERSION = 1


def _OpenMaybeGz(path, mode=None):
  """Calls `gzip.open()` if |path| ends in ".gz", otherwise calls `open()`."""
  if path.endswith('.gz'):
    if mode and 'w' in mode:
      return gzip.GzipFile(path, mode, 1)
    return gzip.open(path, mode)
  return open(path, mode or 'r')


def _EndsWithMaybeGz(path, suffix):
  return path.endswith(suffix) or path.endswith(suffix + '.gz')


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
  to_process = [s for s in symbol_group if s.name and s.name.startswith('_Z')]
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
    if not symbol.name or symbol.name.startswith('*'):
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
    if symbol.path:
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
    if prev_symbol.section_name is not symbol.section_name:
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


def _PrintStats(result, write_func):
  """Prints out how accurate |result| is."""
  for section in symbols.SECTION_TO_SECTION_NAME:
    if section == 'd':
      expected_size = sum(v for k, v in result.section_sizes.iteritems()
                          if k.startswith('.data'))
    else:
      expected_size = result.section_sizes[
          symbols.SECTION_TO_SECTION_NAME[section]]

    def one_stat(group):
      template = ('Section %s has %.1f%% of %d bytes accounted for from '
                  '%d symbols. %d bytes are unaccounted for. Padding '
                  'accounts for %d bytes\n')
      actual_size = group.size
      count = len(group)
      padding = group.padding
      size_percent = 100.0 * actual_size / expected_size
      return (template % (section, size_percent, actual_size, count,
                          expected_size - actual_size, padding))

    in_section = result.symbol_group.WhereInSection(section)
    write_func(one_stat(in_section))

    star_syms = in_section.WhereNameMatches(r'^\*')
    attributed_syms = star_syms.Inverted().WhereHasAnyAttribution()
    anonymous_syms = attributed_syms.Inverted()
    if star_syms or anonymous_syms:
      missing_size = star_syms.size + anonymous_syms.size
      write_func(('+ Without %d merge sections and %d anonymous entries ('
                  'accounting for %d bytes):\n') % (
          len(star_syms),  len(anonymous_syms), missing_size))
      write_func('+ ' + one_stat(attributed_syms))


def _SaveResult(result, file_obj):
  """Saves the result to the given file object."""
  # Store one bucket per line.
  file_obj.write('%d\n' % _SERIALIZATION_VERSION)
  file_obj.write('%r\n' % result.section_sizes)
  file_obj.write('%d\n' % len(result.symbol_group))
  prev_section_name = None
  # Store symbol fields as tab-separated.
  # Store only non-derived fields.
  for symbol in result.symbol_group:
    if symbol.section_name != prev_section_name:
      file_obj.write('%s\n' % symbol.section_name)
      prev_section_name = symbol.section_name
    # Don't write padding nor name since these are derived values.
    file_obj.write('%x\t%x\t%s\t%s\n' % (
        symbol.address, symbol.size_without_padding,
        symbol.function_signature or symbol.name or '',
        symbol.path or ''))


def _LoadResults(file_obj):
  """Loads a result from the given file."""
  lines = iter(file_obj)
  actual_version = int(next(lines))
  assert actual_version == _SERIALIZATION_VERSION, (
      'Version mismatch. Need to write some upgrade code.')

  section_sizes = ast.literal_eval(next(lines))
  num_syms = int(next(lines))
  symbol_list = [None] * num_syms
  section_name = None
  for i in xrange(num_syms):
    line = next(lines)[:-1]
    if '\t' not in line:
      section_name = intern(line)
      line = next(lines)[:-1]
    new_sym = symbols.Symbol.__new__(symbols.Symbol)
    parts = line.split('\t')
    new_sym.section_name = section_name
    new_sym.address = int(parts[0], 16)
    new_sym.size = int(parts[1], 16)
    new_sym.name = parts[2] or None
    new_sym.path = parts[3] or None
    new_sym.padding = 0  # Derived
    new_sym.function_signature = None  # Derived
    symbol_list[i] = new_sym

  # Recompute derived values (padding and function names).
  result = mapfileparser.ParseResult(symbol_list, section_sizes)
  logging.info('Calculating padding')
  _RemoveDuplicatesAndCalculatePadding(result.symbol_group)
  logging.info('Deriving signatures')
  # Re-parse out function parameters.
  _NormalizeNames(result.symbol_group.WhereInSection('t'))
  return result


def AddOptions(parser):
  parser.add_argument('input_file',
                      help='Path to input file. Can be a linker .map file, an '
                           'unstripped binary, or a saved result from '
                           'analyze.py')
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
      tool_prefix = build_vars['android_tool_prefix']

  if os.path.sep not in tool_prefix:
    full_path = distutils.spawn.find_executable(tool_prefix + 'c++filt')
  else:
    full_path = tool_prefix + 'c++filt'

  if not os.path.isfile(full_path):
    raise Exception('Bad --tool-prefix. Path not found: %s' % full_path)
  logging.info('Using --tool-prefix=%s', tool_prefix)
  return tool_prefix


def AnalyzeWithArgs(args):
  return Analyze(args.input_file, args.output_directory, args.tool_prefix)


def Analyze(path, output_directory=None, tool_prefix=''):
  if _EndsWithMaybeGz(path, '.size'):
    logging.info('Loading cached results.')
    with _OpenMaybeGz(path) as f:
      result = _LoadResults(f)
  elif not _EndsWithMaybeGz(path, '.map'):
    raise Exception('Expected input to be a .map or a .size')
  else:
    # Verify tool_prefix early.
    tool_prefix = _DetectToolPrefix(tool_prefix, path, output_directory)

    with _OpenMaybeGz(path) as map_file:
      result = mapfileparser.MapFileParser().Parse(map_file)

    # Map file for some reason doesn't unmangle all names.
    logging.info('Calculating padding')
    _RemoveDuplicatesAndCalculatePadding(result.symbol_group)
    # Unmangle prints its own log statement.
    _UnmangleRemainingSymbols(result.symbol_group, tool_prefix)
    # Resolve paths prints its own log statement.
    logging.info('Normalizing names')
    _NormalizeNames(result.symbol_group)
    logging.info('Normalizing paths')
    _NormalizeObjectPaths(result.symbol_group)

  if logging.getLogger().isEnabledFor(logging.INFO):
    _PrintStats(result, lambda l: logging.info(l.rstrip()))
  logging.info('Finished analyzing %d symbols', len(result.symbol_group))
  return result


def main():
  parser = argparse.ArgumentParser()
  parser.add_argument('--output', required=True,
                      help='Path to store results. Must end in .size or '
                           '.size.gz')
  AddOptions(parser)
  args = helpers.AddCommonOptionsAndParseArgs(parser)
  if not _EndsWithMaybeGz(args.output, '.size'):
    raise Exception('--output must end with .size or .size.gz')

  result = AnalyzeWithArgs(args)
  logging.info('Saving result to %s', args.output)
  with _OpenMaybeGz(args.output, 'wb') as f:
    _SaveResult(result, f)

  logging.info('Done')


if __name__ == '__main__':
  main()
