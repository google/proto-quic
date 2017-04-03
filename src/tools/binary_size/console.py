#!/usr/bin/env python
# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Tool for analyzing binary size of executables using nm or linker map files.

Map files can be created by passing "-Map Foo.map" to the linker. If a map file
is unavailable, this tool can also be pointed at an unstripped executable, but
the information does not seem to be as accurate in this case.

Inspired by SymbolSort for Windows:
  https://github.com/adrianstone55/SymbolSort
"""

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

import describe
import file_format
import helpers
import map2size
import models


# Number of lines before using less for Print().
_THRESHOLD_FOR_PAGER = 30


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


class _Session(object):
  _readline_initialized = False

  def __init__(self, extra_vars):
    self._variables = {
        'Print': self._PrintFunc,
        'Write': self._WriteFunc,
        'Diff': models.Diff,
    }
    self._variables.update(extra_vars)

  def _PrintFunc(self, obj, verbose=False, use_pager=None):
    """Prints out the given Symbol / SymbolGroup / SymbolDiff / SizeInfo.

    Args:
      obj: The object to be printed.
      use_pager: Whether to pipe output through `less`. Ignored when |obj| is a
          Symbol.
    """
    lines = describe.GenerateLines(obj, verbose=verbose)
    if use_pager is None and sys.stdout.isatty():
      # Does not take into account line-wrapping... Oh well.
      first_lines = list(itertools.islice(lines, _THRESHOLD_FOR_PAGER))
      if len(first_lines) == _THRESHOLD_FOR_PAGER:
        use_pager = True
      lines = itertools.chain(first_lines, lines)

    if use_pager:
      with _LessPipe() as stdin:
        describe.WriteLines(lines, stdin.write)
    else:
      describe.WriteLines(lines, sys.stdout.write)


  def _WriteFunc(self, obj, path, verbose=False):
    """Same as Print(), but writes to a file.

    Example: Write(Diff(size_info2, size_info1), 'output.txt')
    """
    parent_dir = os.path.dirname(path)
    if parent_dir and not os.path.exists(parent_dir):
      os.makedirs(parent_dir)
    with file_format.OpenMaybeGz(path, 'w') as file_obj:
      lines = describe.GenerateLines(obj, verbose=verbose)
      describe.WriteLines(lines, file_obj.write)


  def _CreateBanner(self):
    symbol_info_keys = sorted(m for m in dir(models.SizeInfo) if m[0] != '_')
    symbol_group_keys = sorted(m for m in dir(models.SymbolGroup)
                               if m[0] != '_')
    symbol_diff_keys = sorted(m for m in dir(models.SymbolDiff)
                              if m[0] != '_' and m not in symbol_group_keys)
    functions = sorted(k for k in self._variables if k[0].isupper())
    variables = sorted(k for k in self._variables if k[0].islower())
    return '\n'.join([
        '*' * 80,
        'Entering interactive Python shell. Here is some inspiration:',
        '',
        '# Show pydoc for main types:',
        'import models',
        'help(models)',
        '',
        '# Show two levels of .text, grouped by first two subdirectories',
        'text_syms = size_info1.symbols.WhereInSection("t")',
        'by_path = text_syms.GroupBySourcePath(depth=2)',
        'Print(by_path.WhereBiggerThan(1024))',
        '',
        '# Show all non-vtable generated symbols',
        'generated_syms = size_info1.symbols.WhereIsGenerated()',
        'Print(generated_syms.WhereNameMatches("vtable").Inverted())',
        '',
        '*' * 80,
        'Here is some quick reference:',
        '',
        'SizeInfo: %s' % ', '.join(symbol_info_keys),
        'SymbolGroup: %s' % ', '.join(symbol_group_keys),
        'SymbolDiff (extends SymbolGroup): %s' % ', '.join(symbol_diff_keys),
        '',
        'Functions: %s' % ', '.join('%s()' % f for f in functions),
        'Variables: %s' % ', '.join(variables),
        '',
    ])

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
    eval_result = eval(query, self._variables)
    if eval_result:
      self._PrintFunc(eval_result)

  def GoInteractive(self):
    _Session._InitReadline()
    code.InteractiveConsole(self._variables).interact(self._CreateBanner())


def main(argv):
  parser = argparse.ArgumentParser()
  parser.add_argument('inputs', nargs='*',
                      help='Input .size/.map files to load. They will be '
                           'mapped to variables as: size_info1, size_info2,'
                           ' etc.')
  parser.add_argument('--query',
                      help='Print the result of the given snippet. Example: '
                           'size_info1.symbols.WhereInSection("d").'
                           'WhereBiggerThan(100)')
  map2size.AddOptions(parser)
  args = helpers.AddCommonOptionsAndParseArgs(parser, argv)

  info_variables = {}
  for i, path in enumerate(args.inputs):
    size_info = map2size.AnalyzeWithArgs(args, path)
    info_variables['size_info%d' % (i + 1)] = size_info

  session = _Session(info_variables)

  if args.query:
    logging.info('Running query from command-line.')
    session.Eval(args.query)
  else:
    logging.info('Entering interactive console.')
    session.GoInteractive()


if __name__ == '__main__':
  sys.exit(main(sys.argv))
