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
import code
import contextlib
import logging
import readline
import subprocess
import sys

import analyze
import helpers
import symbols


# Number of lines before using less for Print().
_THRESHOLD_FOR_PAGER = 30


@contextlib.contextmanager
def _LessPipe():
  """Output to `less`. Yields the write function."""
  try:
    proc = subprocess.Popen(['less'], stdin=subprocess.PIPE, stdout=sys.stdout)
    yield proc.stdin.write
    proc.stdin.close()

    proc.wait()
  except IOError:
    pass  # Happens when less is quit before all data is written.
  except KeyboardInterrupt:
    pass  # Assume used to break out of less.


def _PrintSymbolGroup(group, show_elided=True, use_pager=None):
  """Prints out the given list of symbols.

  Args:
    show_elided: Whether to print out group.filtered_symbols.
  """
  by_size = group.Sorted()
  # TODO(agrieve): Taking line-wrapping into account for groups vs. symbols
  #     would make sense here.
  if use_pager is None:
    count = sum(1 if s.IsGroup() else 2 for s in group)
    if show_elided and group.filtered_symbols:
      count += 1
    use_pager = count > _THRESHOLD_FOR_PAGER

  def write_to_func(write):
    write('Showing {:,} results with total size: {:,} bytes\n'.format(
        len(group), group.size))
    for s in by_size:
      if s.IsGroup():
        write('{} {:<9,} {} ({})\n'.format(s.section, s.size, s.name, len(s)))
      else:
        template = '{}@0x{:<8x}  {:<7} {}\n{:22}{}\n'
        write(template.format(s.section, s.address, s.size,
                              s.path or '<no path>', '', s.name or '<no name>'))
    if show_elided and group.filtered_symbols:
      elided = group.Inverted()
      write('* Filtered out {:,} symbols comprising {:<7,} bytes.\n'.format(
          len(elided), elided.size))

  if use_pager:
    with _LessPipe() as write:
      write_to_func(write)
  else:
    write_to_func(sys.stdout.write)


def main():
  parser = argparse.ArgumentParser()
  parser.add_argument('--query',
                      help='Print the result of the given snippet. Example: '
                           'all_syms.WhereInSection("d").WhereBiggerThan(100)')
  analyze.AddOptions(parser)
  args = helpers.AddCommonOptionsAndParseArgs(parser)

  result = analyze.AnalyzeWithArgs(args)

  variables = {
      'Print': _PrintSymbolGroup,
      'all_syms': result.symbol_group,
  }

  if args.query:
    logging.info('Running query from command-line.')
    eval_result = eval(args.query, locals=variables)
    if isinstance(eval_result, symbols.SymbolGroup):
      _PrintSymbolGroup(eval_result, show_elided=False, use_pager=False)
    return

  logging.info('Entering interactive console.')

  print '*' * 80
  print 'Entering interactive Python shell. Here is some inspiration:'
  print
  print '# Show two levels of .text, grouped by first two subdirectories'
  print 'text_syms = all_syms.WhereInSection("t")'
  print 'by_path = text_syms.GroupByPath(depth=2)'
  print 'Print(by_path.WhereBiggerThan(1024, include_filtered=True))'
  print
  print '# Show all non-vtable generated symbols'
  print 'Print(all_syms.WhereNameMatches(r"(?<!vtable)(?<!\[)\]$"))'
  print
  print '*' * 80
  print
  print 'locals:', variables.keys()
  print 'method quick reference:', (
      [m for m in dir(symbols.SymbolGroup) if m[0].isupper()])
  print
  print '*' * 80

  # Without initializing readline, arrow keys don't even work!
  readline.parse_and_bind('tab: complete')
  code.InteractiveConsole(locals=variables).interact()


if __name__ == '__main__':
  main()
