# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Main Python API for analyzing binary size."""

import argparse
import calendar
import collections
import datetime
import gzip
import logging
import os
import posixpath
import re
import subprocess
import sys
import tempfile
import zipfile

import describe
import file_format
import function_signature
import helpers
import linker_map_parser
import models
import ninja_parser
import paths


def _OpenMaybeGz(path, mode=None):
  """Calls `gzip.open()` if |path| ends in ".gz", otherwise calls `open()`."""
  if path.endswith('.gz'):
    if mode and 'w' in mode:
      return gzip.GzipFile(path, mode, 1)
    return gzip.open(path, mode)
  return open(path, mode or 'r')


def _StripLinkerAddedSymbolPrefixes(symbols):
  """Removes prefixes sometimes added to symbol names during link

  Removing prefixes make symbol names match up with those found in .o files.
  """
  for symbol in symbols:
    name = symbol.name
    if name.startswith('startup.'):
      symbol.flags |= models.FLAG_STARTUP
      symbol.name = name[8:]
    elif name.startswith('unlikely.'):
      symbol.flags |= models.FLAG_UNLIKELY
      symbol.name = name[9:]
    elif name.startswith('rel.local.'):
      symbol.flags |= models.FLAG_REL_LOCAL
      symbol.name = name[10:]
    elif name.startswith('rel.'):
      symbol.flags |= models.FLAG_REL
      symbol.name = name[4:]


def _UnmangleRemainingSymbols(symbols, tool_prefix):
  """Uses c++filt to unmangle any symbols that need it."""
  to_process = [s for s in symbols if s.name.startswith('_Z')]
  if not to_process:
    return

  logging.info('Unmangling %d names', len(to_process))
  proc = subprocess.Popen([tool_prefix + 'c++filt'], stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE)
  stdout = proc.communicate('\n'.join(s.name for s in to_process))[0]
  assert proc.returncode == 0

  for i, line in enumerate(stdout.splitlines()):
    to_process[i].name = line


def _NormalizeNames(symbols):
  """Ensures that all names are formatted in a useful way.

  This includes:
    - Assigning of |full_name|.
    - Stripping of return types in |full_name| and |name| (for functions).
    - Stripping parameters from |name|.
    - Moving "vtable for" and the like to be suffixes rather than prefixes.
  """
  found_prefixes = set()
  for symbol in symbols:
    if symbol.name.startswith('*'):
      # See comment in _CalculatePadding() about when this
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
      symbol.flags |= models.FLAG_ANONYMOUS
      symbol.name = non_anonymous
      symbol.full_name = symbol.full_name.replace(
          '(anonymous namespace)::', '')

    if symbol.section != 't' and '(' in symbol.name:
      # Pretty rare. Example:
      # blink::CSSValueKeywordsHash::findValueImpl(char const*)::value_word_list
      symbol.full_name = symbol.name
      symbol.name = re.sub(r'\(.*\)', '', symbol.full_name)

    # Don't bother storing both if they are the same.
    if symbol.full_name == symbol.name:
      symbol.full_name = ''

  logging.debug('Found name prefixes of: %r', found_prefixes)


def _NormalizeObjectPaths(symbols):
  """Ensures that all paths are formatted in a useful way."""
  for symbol in symbols:
    path = symbol.object_path
    if path.startswith('obj/'):
      # Convert obj/third_party/... -> third_party/...
      path = path[4:]
    elif path.startswith('../../'):
      # Convert ../../third_party/... -> third_party/...
      path = path[6:]
    if path.endswith(')'):
      # Convert foo/bar.a(baz.o) -> foo/bar.a/baz.o
      start_idx = path.index('(')
      path = os.path.join(path[:start_idx], path[start_idx + 1:-1])
    symbol.object_path = path


def _NormalizeSourcePath(path):
  if path.startswith('gen/'):
    # Convert gen/third_party/... -> third_party/...
    return path[4:]
  if path.startswith('../../'):
    # Convert ../../third_party/... -> third_party/...
    return path[6:]
  return path


def _ExtractSourcePaths(symbols, source_mapper):
  """Fills in the .source_path attribute of all symbols."""
  logging.debug('Parsed %d .ninja files.', source_mapper.parsed_file_count)

  for symbol in symbols:
    object_path = symbol.object_path
    if symbol.source_path or not object_path:
      continue
    # We don't have source info for prebuilt .a files.
    if not os.path.isabs(object_path) and not object_path.startswith('..'):
      source_path = source_mapper.FindSourceForPath(object_path)
      if source_path:
        symbol.source_path = _NormalizeSourcePath(source_path)


def _CalculatePadding(symbols):
  """Populates the |padding| field based on symbol addresses.

  Symbols must already be sorted by |address|.
  """
  seen_sections = []
  for i, symbol in enumerate(symbols[1:]):
    prev_symbol = symbols[i]
    if prev_symbol.section_name != symbol.section_name:
      assert symbol.section_name not in seen_sections, (
          'Input symbols must be sorted by section, then address.')
      seen_sections.append(symbol.section_name)
      continue
    if symbol.address <= 0 or prev_symbol.address <= 0:
      continue
    # Padding-only symbols happen for ** symbol gaps.
    prev_is_padding_only = prev_symbol.size_without_padding == 0
    if symbol.address == prev_symbol.address and not prev_is_padding_only:
      assert False, 'Found duplicate symbols:\n%r\n%r' % (prev_symbol, symbol)
    # Even with symbols at the same address removed, overlaps can still
    # happen. In this case, padding will be negative (and this is fine).
    padding = symbol.address - prev_symbol.end_address
    # These thresholds were found by manually auditing arm32 Chrome.
    # E.g.: Set them to 0 and see what warnings get logged.
    # TODO(agrieve): See if these thresholds make sense for architectures
    #     other than arm32.
    if not symbol.name.startswith('*') and (
        symbol.section in 'rd' and padding >= 256 or
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
    assert symbol.size >= 0, (
        'Symbol has negative size (likely not sorted propertly): '
        '%r\nprev symbol: %r' % (symbol, prev_symbol))


def _ClusterSymbols(symbols):
  """Returns a new list of symbols with some symbols moved into groups.

  Groups include:
   * Symbols that have [clone] in their name (created by compiler optimization).
   * Star symbols (such as "** merge strings", and "** symbol gap")

  To view created groups:
    Print(size_info.symbols.Filter(lambda s: s.IsGroup()), recursive=True)
  """
  # http://unix.stackexchange.com/questions/223013/function-symbol-gets-part-suffix-after-compilation
  # Example name suffixes:
  #     [clone .part.322]  # GCC
  #     [clone .isra.322]  # GCC
  #     [clone .constprop.1064]  # GCC
  #     [clone .11064]  # clang

  # Step 1: Create name map, find clones, collect star syms into replacements.
  logging.debug('Creating name -> symbol map')
  clone_indices = []
  indices_by_full_name = {}
  # (name, full_name) -> [(index, sym),...]
  replacements_by_name = collections.defaultdict(list)
  for i, symbol in enumerate(symbols):
    if symbol.name.startswith('**'):
      # "symbol gap 3" -> "symbol gaps"
      name = re.sub(r'\s+\d+$', 's', symbol.name)
      replacements_by_name[(name, None)].append((i, symbol))
    elif symbol.full_name:
      if symbol.full_name.endswith(']') and ' [clone ' in symbol.full_name:
        clone_indices.append(i)
      else:
        indices_by_full_name[symbol.full_name] = i

  # Step 2: Collect same-named clone symbols.
  logging.debug('Grouping all clones')
  group_names_by_index = {}
  for i in clone_indices:
    symbol = symbols[i]
    # Multiple attributes could exist, so search from left-to-right.
    stripped_name = symbol.name[:symbol.name.index(' [clone ')]
    stripped_full_name = symbol.full_name[:symbol.full_name.index(' [clone ')]
    name_tup = (stripped_name, stripped_full_name)
    replacement_list = replacements_by_name[name_tup]

    if not replacement_list:
      # First occurance, check for non-clone symbol.
      non_clone_idx = indices_by_full_name.get(stripped_name)
      if non_clone_idx is not None:
        non_clone_symbol = symbols[non_clone_idx]
        replacement_list.append((non_clone_idx, non_clone_symbol))
        group_names_by_index[non_clone_idx] = stripped_name

    replacement_list.append((i, symbol))
    group_names_by_index[i] = stripped_name

  # Step 3: Undo clustering when length=1.
  # Removing these groups means Diff() logic must know about [clone] suffix.
  to_clear = []
  for name_tup, replacement_list in replacements_by_name.iteritems():
    if len(replacement_list) == 1:
      to_clear.append(name_tup)
  for name_tup in to_clear:
    del replacements_by_name[name_tup]

  # Step 4: Replace first symbol from each cluster with a SymbolGroup.
  before_symbol_count = sum(len(x) for x in replacements_by_name.itervalues())
  logging.debug('Creating %d symbol groups from %d symbols. %d clones had only '
                'one symbol.', len(replacements_by_name), before_symbol_count,
                len(to_clear))

  len_delta = len(replacements_by_name) - before_symbol_count
  grouped_symbols = [None] * (len(symbols) + len_delta)
  dest_index = 0
  src_index = 0
  seen_names = set()
  replacement_names_by_index = {}
  for name_tup, replacement_list in replacements_by_name.iteritems():
    for tup in replacement_list:
      replacement_names_by_index[tup[0]] = name_tup

  sorted_items = replacement_names_by_index.items()
  sorted_items.sort(key=lambda tup: tup[0])
  for index, name_tup in sorted_items:
    count = index - src_index
    grouped_symbols[dest_index:dest_index + count] = (
        symbols[src_index:src_index + count])
    src_index = index + 1
    dest_index += count
    if name_tup not in seen_names:
      seen_names.add(name_tup)
      group_symbols = [tup[1] for tup in replacements_by_name[name_tup]]
      grouped_symbols[dest_index] = models.SymbolGroup(
          group_symbols, name=name_tup[0], full_name=name_tup[1],
          section_name=group_symbols[0].section_name)
      dest_index += 1

  assert len(grouped_symbols[dest_index:None]) == len(symbols[src_index:None])
  grouped_symbols[dest_index:None] = symbols[src_index:None]
  logging.debug('Finished making groups.')
  return grouped_symbols


def LoadAndPostProcessSizeInfo(path):
  """Returns a SizeInfo for the given |path|."""
  logging.debug('Loading results from: %s', path)
  size_info = file_format.LoadSizeInfo(path)
  _PostProcessSizeInfo(size_info)
  return size_info


def _PostProcessSizeInfo(size_info):
  logging.info('Normalizing symbol names')
  _NormalizeNames(size_info.raw_symbols)
  logging.info('Calculating padding')
  _CalculatePadding(size_info.raw_symbols)
  logging.info('Grouping decomposed functions')
  size_info.symbols = models.SymbolGroup(
      _ClusterSymbols(size_info.raw_symbols))
  logging.info('Processed %d symbols', len(size_info.raw_symbols))


def CreateSizeInfo(map_path, lazy_paths=None, no_source_paths=False,
                   raw_only=False):
  """Creates a SizeInfo from the given map file."""
  # tool_prefix needed for c++filt.
  lazy_paths.VerifyToolPrefix()

  if not no_source_paths:
    # Parse .ninja files at the same time as parsing the .map file.
    source_mapper_result = helpers.ForkAndCall(
        ninja_parser.Parse, lazy_paths.VerifyOutputDirectory())

  with _OpenMaybeGz(map_path) as map_file:
    section_sizes, raw_symbols = (
        linker_map_parser.MapFileParser().Parse(map_file))

  if not no_source_paths:
    logging.info('Extracting source paths from .ninja files')
    source_mapper = source_mapper_result.get()
    _ExtractSourcePaths(raw_symbols, source_mapper)
    assert source_mapper.unmatched_paths_count == 0, (
        'One or more source file paths could not be found. Likely caused by '
        '.ninja files being generated at a different time than the .map file.')

  logging.info('Stripping linker prefixes from symbol names')
  _StripLinkerAddedSymbolPrefixes(raw_symbols)
  # Map file for some reason doesn't unmangle all names.
  # Unmangle prints its own log statement.
  _UnmangleRemainingSymbols(raw_symbols, lazy_paths.tool_prefix)
  logging.info('Normalizing object paths')
  _NormalizeObjectPaths(raw_symbols)
  size_info = models.SizeInfo(section_sizes, raw_symbols)

  # Name normalization not strictly required, but makes for smaller files.
  if raw_only:
    logging.info('Normalizing symbol names')
    _NormalizeNames(size_info.raw_symbols)
  else:
    _PostProcessSizeInfo(size_info)

  if logging.getLogger().isEnabledFor(logging.DEBUG):
    # Padding is reported in size coverage logs.
    if raw_only:
      _CalculatePadding(size_info.raw_symbols)
    for line in describe.DescribeSizeInfoCoverage(size_info):
      logging.info(line)
  logging.info('Recorded info for %d symbols', len(size_info.raw_symbols))
  return size_info


def _DetectGitRevision(directory):
  try:
    git_rev = subprocess.check_output(
        ['git', '-C', directory, 'rev-parse', 'HEAD'])
    return git_rev.rstrip()
  except Exception:
    logging.warning('Failed to detect git revision for file metadata.')
    return None


def BuildIdFromElf(elf_path, tool_prefix):
  args = [tool_prefix + 'readelf', '-n', elf_path]
  stdout = subprocess.check_output(args)
  match = re.search(r'Build ID: (\w+)', stdout)
  assert match, 'Build ID not found from running: ' + ' '.join(args)
  return match.group(1)


def _SectionSizesFromElf(elf_path, tool_prefix):
  args = [tool_prefix + 'readelf', '-S', '--wide', elf_path]
  stdout = subprocess.check_output(args)
  section_sizes = {}
  # Matches  [ 2] .hash HASH 00000000006681f0 0001f0 003154 04   A  3   0  8
  for match in re.finditer(r'\[[\s\d]+\] (\..*)$', stdout, re.MULTILINE):
    items = match.group(1).split()
    section_sizes[items[0]] = int(items[4], 16)
  return section_sizes


def _ArchFromElf(elf_path, tool_prefix):
  args = [tool_prefix + 'readelf', '-h', elf_path]
  stdout = subprocess.check_output(args)
  return re.search('Machine:\s*(\S+)', stdout).group(1)


def _ParseGnArgs(args_path):
  """Returns a list of normalized "key=value" strings."""
  args = {}
  with open(args_path) as f:
    for l in f:
      # Strips #s even if within string literal. Not a problem in practice.
      parts = l.split('#')[0].split('=')
      if len(parts) != 2:
        continue
      args[parts[0].strip()] = parts[1].strip()
  return ["%s=%s" % x for x in sorted(args.iteritems())]


def _ElfInfoFromApk(apk_path, apk_so_path, tool_prefix):
  """Returns a tuple of (build_id, section_sizes)."""
  with zipfile.ZipFile(apk_path) as apk, \
       tempfile.NamedTemporaryFile() as f:
    f.write(apk.read(apk_so_path))
    f.flush()
    build_id = BuildIdFromElf(f.name, tool_prefix)
    section_sizes = _SectionSizesFromElf(f.name, tool_prefix)
    return build_id, section_sizes


def AddArguments(parser):
  parser.add_argument('size_file', help='Path to output .size file.')
  parser.add_argument('--apk-file',
                      help='.apk file to measure. When set, --elf-file will be '
                            'derived (if unset). Providing the .apk allows '
                            'for the size of packed relocations to be recorded')
  parser.add_argument('--elf-file',
                      help='Path to input ELF file. Currently used for '
                           'capturing metadata.')
  parser.add_argument('--map-file',
                      help='Path to input .map(.gz) file. Defaults to '
                           '{{elf_file}}.map(.gz)?. If given without '
                           '--elf-file, no size metadata will be recorded.')
  parser.add_argument('--no-source-paths', action='store_true',
                      help='Do not use .ninja files to map '
                           'object_path -> source_path')
  parser.add_argument('--tool-prefix', default='',
                      help='Path prefix for c++filt.')
  parser.add_argument('--output-directory',
                      help='Path to the root build directory.')


def Run(args, parser):
  if not args.size_file.endswith('.size'):
    parser.error('size_file must end with .size')

  elf_path = args.elf_file
  map_path = args.map_file
  apk_path = args.apk_file
  any_input = apk_path or elf_path or map_path
  if not any_input:
    parser.error('Most pass at least one of --apk-file, --elf-file, --map-file')
  lazy_paths = paths.LazyPaths(tool_prefix=args.tool_prefix,
                               output_directory=args.output_directory,
                               any_path_within_output_directory=any_input)
  if apk_path:
    with zipfile.ZipFile(apk_path) as z:
      lib_infos = [f for f in z.infolist()
                   if f.filename.endswith('.so') and f.file_size > 0]
    assert lib_infos, 'APK has no .so files.'
    # TODO(agrieve): Add support for multiple .so files, and take into account
    #     secondary architectures.
    apk_so_path = max(lib_infos, key=lambda x:x.file_size).filename
    logging.debug('Sub-apk path=%s', apk_so_path)
    if not elf_path:
      elf_path = os.path.join(
          lazy_paths.output_directory, 'lib.unstripped',
          os.path.basename(apk_so_path.replace('crazy.', '')))
      logging.debug('Detected --elf-file=%s', elf_path)

  if map_path:
    if not map_path.endswith('.map') and not map_path.endswith('.map.gz'):
      parser.error('Expected --map-file to end with .map or .map.gz')
  else:
    map_path = elf_path + '.map'
    if not os.path.exists(map_path):
      map_path += '.gz'
    if not os.path.exists(map_path):
      parser.error('Could not find .map(.gz)? file. Use --map-file.')

  metadata = None
  if elf_path:
    logging.debug('Constructing metadata')
    git_rev = _DetectGitRevision(os.path.dirname(elf_path))
    architecture = _ArchFromElf(elf_path, lazy_paths.tool_prefix)
    build_id = BuildIdFromElf(elf_path, lazy_paths.tool_prefix)
    timestamp_obj = datetime.datetime.utcfromtimestamp(os.path.getmtime(
        elf_path))
    timestamp = calendar.timegm(timestamp_obj.timetuple())
    gn_args = _ParseGnArgs(os.path.join(lazy_paths.output_directory, 'args.gn'))

    def relative_to_out(path):
      return os.path.relpath(path, lazy_paths.VerifyOutputDirectory())

    metadata = {
        models.METADATA_GIT_REVISION: git_rev,
        models.METADATA_MAP_FILENAME: relative_to_out(map_path),
        models.METADATA_ELF_ARCHITECTURE: architecture,
        models.METADATA_ELF_FILENAME: relative_to_out(elf_path),
        models.METADATA_ELF_MTIME: timestamp,
        models.METADATA_ELF_BUILD_ID: build_id,
        models.METADATA_GN_ARGS: gn_args,
    }

    if apk_path:
      metadata[models.METADATA_APK_FILENAME] = relative_to_out(apk_path)
      # Extraction takes around 1 second, so do it in parallel.
      apk_elf_result = helpers.ForkAndCall(
          _ElfInfoFromApk, apk_path, apk_so_path, lazy_paths.tool_prefix)

  size_info = CreateSizeInfo(
      map_path, lazy_paths, no_source_paths=args.no_source_paths, raw_only=True)

  if metadata:
    size_info.metadata = metadata
    logging.debug('Validating section sizes')
    elf_section_sizes = _SectionSizesFromElf(elf_path, lazy_paths.tool_prefix)
    for k, v in elf_section_sizes.iteritems():
      assert v == size_info.section_sizes.get(k), (
          'ELF file and .map file do not match.')

    if apk_path:
      logging.debug('Extracting section sizes from .so within .apk')
      unstripped_section_sizes = size_info.section_sizes
      apk_build_id, size_info.section_sizes = apk_elf_result.get()
      assert apk_build_id == build_id, (
          'BuildID for %s within %s did not match the one at %s' %
          (apk_so_path, apk_path, elf_path))

      packed_section_name = None
      if architecture == 'ARM':
        packed_section_name = '.rel.dyn'
      elif architecture == 'AArch64':
        packed_section_name = '.rela.dyn'

      if packed_section_name:
        logging.debug('Recording size of unpacked relocations')
        if packed_section_name not in size_info.section_sizes:
          logging.warning('Packed section not present: %s', packed_section_name)
        else:
          size_info.section_sizes['%s (unpacked)' % packed_section_name] = (
              unstripped_section_sizes.get(packed_section_name))

  logging.info('Recording metadata: \n  %s',
               '\n  '.join(describe.DescribeMetadata(size_info.metadata)))
  logging.info('Saving result to %s', args.size_file)
  file_format.SaveSizeInfo(size_info, args.size_file)
  logging.info('Done')
