#!/usr/bin/env python
# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Main Python API for analyzing binary size."""

import argparse
import datetime
import distutils.spawn
import gzip
import logging
import os
import re
import subprocess
import sys

import describe
import file_format
import function_signature
import helpers
import linker_map_parser
import models
import ninja_parser


def _OpenMaybeGz(path, mode=None):
  """Calls `gzip.open()` if |path| ends in ".gz", otherwise calls `open()`."""
  if path.endswith('.gz'):
    if mode and 'w' in mode:
      return gzip.GzipFile(path, mode, 1)
    return gzip.open(path, mode)
  return open(path, mode or 'r')


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

  for i, line in enumerate(stdout.splitlines()):
    to_process[i].name = line


def _NormalizeNames(symbol_group):
  """Ensures that all names are formatted in a useful way.

  This includes:
    - Assigning of |full_name|.
    - Stripping of return types in |full_name| and |name| (for functions).
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
      symbol.full_name, symbol.name = function_signature.Parse(symbol.name)

    # Remove anonymous namespaces (they just harm clustering).
    non_anonymous = symbol.name.replace('(anonymous namespace)::', '')
    if symbol.name != non_anonymous:
      symbol.is_anonymous = True
      symbol.name = non_anonymous
      symbol.full_name = symbol.full_name.replace(
          '(anonymous namespace)::', '')

    if symbol.section != 't' and '(' in symbol.name:
      # Pretty rare. Example:
      # blink::CSSValueKeywordsHash::findValueImpl(char const*)::value_word_list
      symbol.full_name = symbol.name
      symbol.name = re.sub(r'\(.*\)', '', symbol.full_name)

  logging.debug('Found name prefixes of: %r', found_prefixes)


def _NormalizeObjectPaths(symbol_group):
  """Ensures that all paths are formatted in a useful way."""
  for symbol in symbol_group:
    path = symbol.object_path
    if path.startswith('obj/'):
      # Convert obj/third_party/... -> third_party/...
      path = path[4:]
    elif path.startswith('../../'):
      # Convert ../../third_party/... -> third_party/...
      path = path[6:]
    if path.endswith(')'):
      # Convert foo/bar.a(baz.o) -> foo/bar.a/(baz.o)
      start_idx = path.index('(')
      path = os.path.join(path[:start_idx], path[start_idx:])
    symbol.object_path = path


def _NormalizeSourcePath(path):
  if path.startswith('gen/'):
    # Convert gen/third_party/... -> third_party/...
    return path[4:]
  if path.startswith('../../'):
    # Convert ../../third_party/... -> third_party/...
    return path[6:]
  return path


def _ExtractSourcePaths(symbol_group, output_directory):
  """Fills in the .source_path attribute of all symbols."""
  mapper = ninja_parser.SourceFileMapper(output_directory)

  for symbol in symbol_group:
    object_path = symbol.object_path
    if symbol.source_path or not object_path:
      continue
    # We don't have source info for prebuilt .a files.
    if not object_path.startswith('..'):
      source_path = mapper.FindSourceForPath(object_path)
      if source_path:
        symbol.source_path = _NormalizeSourcePath(source_path)
      else:
        logging.warning('Could not find source path for %s', object_path)
  logging.debug('Parsed %d .ninja files.', mapper.GetParsedFileCount())


def _RemoveDuplicatesAndCalculatePadding(symbol_group):
  """Removes symbols at the same address and calculates the |padding| field.

  Symbols must already be sorted by |address|.
  """
  to_remove = set()
  all_symbols = symbol_group.symbols
  for i, symbol in enumerate(all_symbols[1:]):
    prev_symbol = all_symbols[i]
    if prev_symbol.section_name != symbol.section_name:
      continue
    if symbol.address > 0 and prev_symbol.address > 0:
      # Fold symbols that are at the same address (happens in nm output).
      if symbol.address == prev_symbol.address:
        symbol.size = max(prev_symbol.size, symbol.size)
        to_remove.add(i + 1)
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
      assert symbol.size >= 0, 'Symbol has negative size: ' + (
          '%r\nprev symbol: %r' % (symbol, prev_symbol))
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
  """Detects values for --tool-prefix and --output-directory."""
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

  if not full_path or not os.path.isfile(full_path):
    raise Exception('Bad --tool-prefix. Path not found: %s' % full_path)
  if not output_directory or not os.path.isdir(output_directory):
    raise Exception('Bad --output-directory. Path not found: %s' %
                    output_directory)
  logging.info('Using --output-directory=%s', output_directory)
  logging.info('Using --tool-prefix=%s', tool_prefix)
  return output_directory, tool_prefix


def AnalyzeWithArgs(args, input_path):
  return Analyze(input_path, args.output_directory, args.tool_prefix)


def Analyze(path, output_directory=None, tool_prefix=''):
  if path.endswith('.size'):
    logging.debug('Loading results from: %s', path)
    size_info = file_format.LoadSizeInfo(path)
    # Recompute derived values (padding and function names).
    logging.info('Calculating padding')
    _RemoveDuplicatesAndCalculatePadding(size_info.symbols)
    logging.info('Deriving signatures')
    # Re-parse out function parameters.
    _NormalizeNames(size_info.symbols)
    return size_info
  elif not path.endswith('.map') and not path.endswith('.map.gz'):
    raise Exception('Expected input to be a .map or a .size')
  else:
    # Verify tool_prefix early.
    output_directory, tool_prefix = (
        _DetectToolPrefix(tool_prefix, path, output_directory))

    with _OpenMaybeGz(path) as map_file:
      section_sizes, symbols = linker_map_parser.MapFileParser().Parse(map_file)
    timestamp = datetime.datetime.utcfromtimestamp(os.path.getmtime(path))
    size_info = models.SizeInfo(section_sizes, models.SymbolGroup(symbols),
                                timestamp=timestamp)

    # Map file for some reason doesn't unmangle all names.
    logging.info('Calculating padding')
    _RemoveDuplicatesAndCalculatePadding(size_info.symbols)
    # Unmangle prints its own log statement.
    _UnmangleRemainingSymbols(size_info.symbols, tool_prefix)
    logging.info('Extracting source paths from .ninja files')
    _ExtractSourcePaths(size_info.symbols, output_directory)
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


def _DetectGitRevision(path):
  try:
    git_rev = subprocess.check_output(
        ['git', '-C', os.path.dirname(path), 'rev-parse', 'HEAD'])
    return git_rev.rstrip()
  except Exception:
    logging.warning('Failed to detect git revision for file metadata.')
    return None


def main(argv):
  parser = argparse.ArgumentParser(argv)
  parser.add_argument('input_file', help='Path to input .map file.')
  parser.add_argument('output_file', help='Path to output .size(.gz) file.')
  AddOptions(parser)
  args = helpers.AddCommonOptionsAndParseArgs(parser, argv)
  if not args.output_file.endswith('.size'):
    parser.error('output_file must end with .size')

  size_info = AnalyzeWithArgs(args, args.input_file)
  if not args.input_file.endswith('.size'):
    git_rev = _DetectGitRevision(args.input_file)
    size_info.tag = 'Filename=%s git_rev=%s' % (
        os.path.basename(args.input_file), git_rev)
  logging.info('Recording metadata: %s',
               describe.DescribeSizeInfoMetadata(size_info))
  logging.info('Saving result to %s', args.output_file)
  file_format.SaveSizeInfo(size_info, args.output_file)

  logging.info('Done')


if __name__ == '__main__':
  sys.exit(main(sys.argv))
