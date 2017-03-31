# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""Methods for converting model objects to human-readable formats."""

import itertools

import models


class Describer(object):
  def __init__(self, verbose=False):
    self.verbose = verbose

  def _DescribeSectionSizes(self, section_sizes):
    relevant_names = models.SECTION_TO_SECTION_NAME.values()
    section_names = sorted(k for k in section_sizes.iterkeys()
                           if k in relevant_names or k.startswith('.data'))
    total_bytes = sum(v for k, v in section_sizes.iteritems()
                      if k in section_names and k != '.bss')
    yield 'Section Sizes (Total={:,} bytes):'.format(total_bytes)
    for name in section_names:
      size = section_sizes[name]
      if name == '.bss':
        yield '{}: {:,} bytes (not included in totals)'.format(name, size)
      else:
        percent = float(size) / total_bytes if total_bytes else 0
        yield '{}: {:,} bytes ({:.1%})'.format(name, size, percent)

  def _DescribeSymbol(self, sym):
    # SymbolGroups are passed here when we don't want to expand them.
    if sym.IsGroup():
      yield '{} {:<8} {} (count={})'.format(sym.section, sym.size, sym.name,
                                            len(sym))
      return

    yield '{}@0x{:<8x}  {:<7} {}'.format(
        sym.section, sym.address, sym.size, sym.path or '<no path>')
    if sym.name:
      yield '{:22}{}'.format('', sym.name)

  def _DescribeSymbolGroup(self, group, prefix_func=None):
    yield 'Showing {:,} symbols with total size: {:} bytes'.format(
        len(group), group.size)
    yield 'First columns are: running total, type, size'

    running_total = 0
    prefix = ''

    for s in group.Sorted():
      if group.IsBss() or not s.IsBss():
        running_total += s.size
      if prefix_func:
        prefix = prefix_func(s)
      for l in self._DescribeSymbol(s):
        yield '{}{:8} {}'.format(prefix, running_total, l)

  def _DescribeSymbolDiff(self, diff):
    template = ('{} symbols added (+), {} changed (~), {} removed (-), '
                '{} unchanged ({})')
    unchanged_msg = '=' if self.verbose else 'not shown'
    header_str = (template.format(
            diff.added_count, diff.changed_count, diff.removed_count,
            diff.unchanged_count, unchanged_msg))

    def prefix_func(sym):
      if diff.IsAdded(sym):
        return '+ '
      if diff.IsRemoved(sym):
        return '- '
      if sym.size:
        return '~ '
      return '= '

    diff = diff if self.verbose else diff.WhereNotUnchanged()
    group_desc = self._DescribeSymbolGroup(diff, prefix_func=prefix_func)
    return itertools.chain((header_str,), group_desc)

  def GenerateLines(self, obj):
    if isinstance(obj, models.SizeInfo):
      section_desc = self._DescribeSectionSizes(obj.section_sizes)
      group_desc = self.GenerateLines(obj.symbols)
      return itertools.chain(section_desc, ('',), group_desc)

    if isinstance(obj, models.SymbolDiff):
      return self._DescribeSymbolDiff(obj)

    if isinstance(obj, models.SymbolGroup):
      return self._DescribeSymbolGroup(obj)

    if isinstance(obj, models.Symbol):
      return self._DescribeSymbol(obj)

    return (repr(obj),)


def DescribeSizeInfoCoverage(size_info):
  """Yields lines describing how accurate |size_info| is."""
  for section in models.SECTION_TO_SECTION_NAME:
    if section == 'd':
      expected_size = sum(v for k, v in size_info.section_sizes.iteritems()
                          if k.startswith('.data'))
    else:
      expected_size = size_info.section_sizes[
          models.SECTION_TO_SECTION_NAME[section]]

    def one_stat(group):
      template = ('Section %s has %.1f%% of %d bytes accounted for from '
                  '%d symbols. %d bytes are unaccounted for. Padding '
                  'accounts for %d bytes')
      actual_size = group.size
      count = len(group)
      padding = group.padding
      size_percent = 100.0 * actual_size / expected_size
      return (template % (section, size_percent, actual_size, count,
                          expected_size - actual_size, padding))

    in_section = size_info.symbols.WhereInSection(section)
    yield one_stat(in_section)

    star_syms = in_section.WhereNameMatches(r'^\*')
    attributed_syms = star_syms.Inverted().WhereHasAnyAttribution()
    anonymous_syms = attributed_syms.Inverted()
    if star_syms or anonymous_syms:
      missing_size = star_syms.size + anonymous_syms.size
      yield ('+ Without %d merge sections and %d anonymous entries ('
                  'accounting for %d bytes):') % (
          len(star_syms),  len(anonymous_syms), missing_size)
      yield '+ ' + one_stat(attributed_syms)


def GenerateLines(obj, verbose=False):
  return Describer(verbose).GenerateLines(obj)


def WriteLines(lines, func):
  for l in lines:
    func(l)
    func('\n')
