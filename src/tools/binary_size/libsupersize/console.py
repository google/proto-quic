# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""An interactive console for looking analyzing .size files."""

import argparse
import atexit
import code
import contextlib
import itertools
import logging
import os
import readline
import subprocess
import sys

import archive
import canned_queries
import describe
import diff
import file_format
import match_util
import models
import paths


# Number of lines before using less for Print().
_THRESHOLD_FOR_PAGER = 50


@contextlib.contextmanager
def _LessPipe():
  """Output to `less`. Yields a file object to write to."""
  try:
    proc = subprocess.Popen(['less'], stdin=subprocess.PIPE, stdout=sys.stdout)
    yield proc.stdin
    proc.stdin.close()
    proc.wait()
  except IOError:
    pass  # Happens when less is quit before all data is written.
  except KeyboardInterrupt:
    pass  # Assume used to break out of less.


def _WriteToStream(lines, use_pager=None, to_file=None):
  if to_file:
    use_pager = False
  if use_pager is None and sys.stdout.isatty():
    # Does not take into account line-wrapping... Oh well.
    first_lines = list(itertools.islice(lines, _THRESHOLD_FOR_PAGER))
    if len(first_lines) == _THRESHOLD_FOR_PAGER:
      use_pager = True
    lines = itertools.chain(first_lines, lines)

  if use_pager:
    with _LessPipe() as stdin:
      describe.WriteLines(lines, stdin.write)
  elif to_file:
    with open(to_file, 'w') as file_obj:
      describe.WriteLines(lines, file_obj.write)
  else:
    describe.WriteLines(lines, sys.stdout.write)


class _Session(object):
  _readline_initialized = False

  def __init__(self, size_infos, lazy_paths):
    self._printed_variables = []
    self._variables = {
        'Print': self._PrintFunc,
        'Diff': self._DiffFunc,
        'Disassemble': self._DisassembleFunc,
        'ExpandRegex': match_util.ExpandRegexIdentifierPlaceholder,
        'ShowExamples': self._ShowExamplesFunc,
        'canned_queries': canned_queries.CannedQueries(size_infos),
        'printed': self._printed_variables,
    }
    self._lazy_paths = lazy_paths
    self._size_infos = size_infos
    self._disassemble_prefix_len = None

    if len(size_infos) == 1:
      self._variables['size_info'] = size_infos[0]
    else:
      for i, size_info in enumerate(size_infos):
        self._variables['size_info%d' % (i + 1)] = size_info

  def _DiffFunc(self, before=None, after=None, sort=True):
    """Diffs two SizeInfo objects. Returns a DeltaSizeInfo.

    Args:
      before: Defaults to first size_infos[0].
      after: Defaults to second size_infos[1].
      sort: When True (default), calls SymbolGroup.Sorted() after diffing.
    """
    before = before if before is not None else self._size_infos[0]
    after = after if after is not None else self._size_infos[1]
    ret = diff.Diff(before, after)
    if sort:
      ret.symbols = ret.symbols.Sorted()
    return ret

  def _PrintFunc(self, obj=None, verbose=False, recursive=False, use_pager=None,
                 to_file=None):
    """Prints out the given Symbol / SymbolGroup / SizeInfo.

    For convenience, |obj| will be appended to the global "printed" list.

    Args:
      obj: The object to be printed. Defaults to size_infos[-1]. Also accepts an
          index into the |printed| array for showing previous results.
      verbose: Show more detailed output.
      recursive: Print children of nested SymbolGroups.
      use_pager: Pipe output through `less`. Ignored when |obj| is a Symbol.
          default is to automatically pipe when output is long.
      to_file: Rather than print to stdio, write to the given file.
    """
    if isinstance(obj, int):
      obj = self._printed_variables[obj]
    elif not self._printed_variables or self._printed_variables[-1] != obj:
      if not isinstance(obj, models.SymbolGroup) or len(obj) > 0:
        self._printed_variables.append(obj)
    obj = obj if obj is not None else self._size_infos[-1]
    lines = describe.GenerateLines(obj, verbose=verbose, recursive=recursive)
    _WriteToStream(lines, use_pager=use_pager, to_file=to_file)

  def _ElfPathAndToolPrefixForSymbol(self, size_info, elf_path):
    tool_prefix = self._lazy_paths.tool_prefix
    orig_tool_prefix = size_info.metadata.get(models.METADATA_TOOL_PREFIX)
    if orig_tool_prefix:
      orig_tool_prefix = paths.FromSrcRootRelative(orig_tool_prefix)
      if os.path.exists(orig_tool_prefix + 'objdump'):
        tool_prefix = orig_tool_prefix

    # TODO(agrieve): Would be even better to use objdump --info to check that
    #     the toolchain is for the correct architecture.
    assert tool_prefix is not None, (
        'Could not determine --tool-prefix. Possible fixes include setting '
        '--tool-prefix, or setting --output-directory')

    def build_id_matches(elf_path):
      found_build_id = archive.BuildIdFromElf(elf_path, tool_prefix)
      expected_build_id = size_info.metadata.get(models.METADATA_ELF_BUILD_ID)
      return found_build_id == expected_build_id

    filename = size_info.metadata.get(models.METADATA_ELF_FILENAME)
    paths_to_try = []
    if elf_path:
      paths_to_try.append(elf_path)
    else:
      auto_lazy_paths = [
          paths.LazyPaths(any_path_within_output_directory=s.size_path)
          for s in self._size_infos]
      for lazy_paths in auto_lazy_paths + [self._lazy_paths]:
        output_dir = lazy_paths.output_directory
        if output_dir:
          # Local build: File is located in output directory.
          paths_to_try.append(
              os.path.normpath(os.path.join(output_dir, filename)))
        # Downloaded build: File is located beside .size file.
        paths_to_try.append(os.path.normpath(os.path.join(
            os.path.dirname(size_info.size_path), os.path.basename(filename))))

    paths_to_try = [p for p in paths_to_try if os.path.exists(p)]

    for i, elf_path in enumerate(paths_to_try):
      if build_id_matches(elf_path):
        return elf_path, tool_prefix

      # Show an error only once all paths are tried.
      if i + 1 == len(paths_to_try):
        assert False, 'Build ID does not match for %s' % elf_path

    assert False, (
        'Could not locate ELF file. If binary was built locally, ensure '
        '--output-directory is set. If output directory is unavailable, '
        'ensure {} is located beside {}, or pass its path explicitly using '
        'elf_path=').format(os.path.basename(filename), size_info.size_path)

  def _DetectDisassemblePrefixLen(self, args):
    # Look for a line that looks like:
    # /usr/{snip}/src/out/Release/../../net/quic/core/quic_time.h:100
    output = subprocess.check_output(args)
    for line in output.splitlines():
      if line and line[0] == os.path.sep and line[-1].isdigit():
        release_idx = line.find('Release')
        if release_idx != -1:
          return line.count(os.path.sep, 0, release_idx)
        dot_dot_idx = line.find('..')
        if dot_dot_idx != -1:
          return line.count(os.path.sep, 0, dot_dot_idx) - 1
        out_idx = line.find(os.path.sep + 'out')
        if out_idx != -1:
          return line.count(os.path.sep, 0, out_idx) + 2
        logging.warning('Could not guess source path from found path.')
        return None
    logging.warning('Found no source paths in objdump output.')
    return None

  def _DisassembleFunc(self, symbol, elf_path=None, use_pager=None,
                       to_file=None):
    """Shows objdump disassembly for the given symbol.

    Args:
      symbol: Must be a .text symbol and not a SymbolGroup.
      elf_path: Path to the executable containing the symbol. Required only
          when auto-detection fails.
    """
    assert not symbol.IsGroup()
    assert symbol.address and symbol.section_name == '.text'
    assert not symbol.IsDelta(), ('Cannot disasseble a Diff\'ed symbol. Try '
                                  'passing .before_symbol or .after_symbol.')
    size_info = None
    for size_info in self._size_infos:
      if symbol in size_info.raw_symbols:
        break
    else:
      assert False, 'Symbol does not belong to a size_info.'

    elf_path, tool_prefix = self._ElfPathAndToolPrefixForSymbol(
        size_info, elf_path)

    args = [tool_prefix + 'objdump', '--disassemble', '--source',
            '--line-numbers', '--demangle',
            '--start-address=0x%x' % symbol.address,
            '--stop-address=0x%x' % symbol.end_address, elf_path]
    if self._disassemble_prefix_len is None:
      prefix_len = self._DetectDisassemblePrefixLen(args)
      if prefix_len is not None:
        self._disassemble_prefix_len = prefix_len

    if self._disassemble_prefix_len is not None:
      output_directory = self._lazy_paths.output_directory
      # Only matters for non-generated paths, so be lenient here.
      if output_directory is None:
        output_directory = os.path.join(paths.SRC_ROOT, 'out', 'Release')
        if not os.path.exists(output_directory):
          os.makedirs(output_directory)

      args += [
          '--prefix-strip', str(self._disassemble_prefix_len),
          '--prefix', os.path.normpath(os.path.relpath(output_directory))
      ]

    proc = subprocess.Popen(args, stdout=subprocess.PIPE)
    lines = itertools.chain(('Showing disassembly for %r' % symbol,
                             'Command: %s' % ' '.join(args)),
                            (l.rstrip() for l in proc.stdout))
    _WriteToStream(lines, use_pager=use_pager, to_file=to_file)
    proc.kill()

  def _ShowExamplesFunc(self):
    print self._CreateBanner()
    print '\n'.join([
        '# Show pydoc for main types:',
        'import models',
        'help(models)',
        '',
        '# Show all attributes of all symbols & per-section totals:',
        'Print(size_info, verbose=True)',
        '',
        '# Show two levels of .text, grouped by first two subdirectories',
        'text_syms = size_info.symbols.WhereInSection("t")',
        'by_path = text_syms.GroupedByPath(depth=2)',
        'Print(by_path.WherePssBiggerThan(1024))',
        '',
        '# Show all generated symbols, then show only non-vtable ones',
        'Print(size_info.symbols.WhereGeneratedByToolchain())',
        'Print(printed[-1].WhereNameMatches(r"vtable").Inverted().Sorted())',
        '',
        '# Show all symbols that have "print" in their name or path, except',
        '# those within components/.',
        '# Note: Could have also used Inverted(), as above.',
        '# Note: Use "help(ExpandRegex)" for more about what {{_print_}} does.',
        'print_syms = size_info.symbols.WhereMatches(r"{{_print_}}")',
        'Print(print_syms - print_syms.WherePathMatches(r"^components/"))',
        '',
        '# Diff two .size files and save result to a file:',
        'Print(Diff(size_info1, size_info2), to_file="output.txt")',
        '',
        '# View per-component breakdowns, then drill into the last entry.',
        'c = canned_queries.CategorizeByChromeComponent()',
        'Print(c)',
        'Print(c[-1].GroupedByPath(depth=2).Sorted())',
        '',
        '# For even more inspiration, look at canned_queries.py',
        '# (and feel free to add your own!).',
    ])

  def _CreateBanner(self):
    def keys(cls, super_keys=None):
      ret = sorted(m for m in dir(cls) if m[0] != '_')
      if super_keys:
        ret = sorted(m for m in ret if m not in super_keys)
      return ret

    symbol_info_keys = keys(models.SizeInfo)
    symbol_keys = keys(models.Symbol)
    symbol_group_keys = keys(models.SymbolGroup, symbol_keys)
    delta_size_info_keys = keys(models.DeltaSizeInfo)
    delta_symbol_keys = keys(models.DeltaSymbol, symbol_keys)
    delta_symbol_group_keys = keys(models.DeltaSymbolGroup,
                                   symbol_keys + symbol_group_keys)
    canned_queries_keys = keys(canned_queries.CannedQueries)

    functions = sorted(k for k in self._variables if k[0].isupper())
    lines = [
        '*' * 80,
        'Entering interactive Python shell. Quick reference:',
        '',
        'SizeInfo: %s' % ', '.join(symbol_info_keys),
        'Symbol: %s' % ', '.join(symbol_keys),
        '',
        'SymbolGroup (extends Symbol): %s' % ', '.join(symbol_group_keys),
        '',
        'DeltaSizeInfo: %s' % ', '.join(delta_size_info_keys),
        'DeltaSymbol (extends Symbol): %s' % ', '.join(delta_symbol_keys),
        'DeltaSymbolGroup (extends SymbolGroup): %s' % ', '.join(
            delta_symbol_group_keys),
        '',
        'canned_queries: %s' % ', '.join(canned_queries_keys),
        '',
        'Functions: %s' % ', '.join('%s()' % f for f in functions),
        'Variables: ',
        '  printed: List of objects passed to Print().',
    ]
    for key, value in self._variables.iteritems():
      if key.startswith('size_info'):
        lines.append('  {}: Loaded from {}'.format(key, value.size_path))
    lines.append('*' * 80)
    return '\n'.join(lines)


  @classmethod
  def _InitReadline(cls):
    if cls._readline_initialized:
      return
    cls._readline_initialized = True
    # Without initializing readline, arrow keys don't even work!
    readline.parse_and_bind('tab: complete')
    history_file = os.path.join(os.path.expanduser('~'),
                                '.binary_size_query_history')
    if os.path.exists(history_file):
      readline.read_history_file(history_file)
    atexit.register(lambda: readline.write_history_file(history_file))

  def Eval(self, query):
    exec query in self._variables

  def GoInteractive(self):
    _Session._InitReadline()
    code.InteractiveConsole(self._variables).interact(self._CreateBanner())


def AddArguments(parser):
  parser.add_argument(
      'inputs', nargs='+',
      help='Input .size files to load. For a single file, it will be mapped to '
           'the variable "size_info". For multiple inputs, the names will be '
           'size_info1, size_info2, etc.')
  parser.add_argument('--query',
                      help='Execute the given snippet. '
                           'Example: Print(size_info)')
  parser.add_argument('--tool-prefix',
                      help='Path prefix for objdump. Required only for '
                           'Disassemble().')
  parser.add_argument('--output-directory',
                      help='Path to the root build directory. Used only for '
                           'Disassemble().')


def Run(args, parser):
  for path in args.inputs:
    if not path.endswith('.size'):
      parser.error('All inputs must end with ".size"')

  size_infos = [archive.LoadAndPostProcessSizeInfo(p) for p in args.inputs]
  lazy_paths = paths.LazyPaths(tool_prefix=args.tool_prefix,
                               output_directory=args.output_directory,
                               any_path_within_output_directory=args.inputs[0])
  session = _Session(size_infos, lazy_paths)

  if args.query:
    logging.info('Running query from command-line.')
    session.Eval(args.query)
  else:
    logging.info('Entering interactive console.')
    session.GoInteractive()
