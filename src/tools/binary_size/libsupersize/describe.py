# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""Methods for converting model objects to human-readable formats."""

import datetime
import itertools
import time

import models


_DIFF_PREFIX_BY_STATUS = ['= ', '~ ', '+ ', '- ']


def _PrettySize(size):
  # Arbitrarily chosen cut-off.
  if abs(size) < 2000:
    return '%d bytes' % size
  # Always show 3 digits.
  size /= 1024.0
  if abs(size) < 10:
    return '%.2fkb' % size
  elif abs(size) < 100:
    return '%.1fkb' % size
  elif abs(size) < 1024:
    return '%dkb' % size
  size /= 1024.0
  if abs(size) < 10:
    return '%.2fmb' % size
  # We shouldn't be seeing sizes > 100mb.
  return '%.1fmb' % size


def _FormatPss(pss):
  # Shows a decimal for small numbers to make it clear that a shared symbol has
  # a non-zero pss.
  if pss > 10:
    return str(int(pss))
  ret = str(round(pss, 1))
  if ret.endswith('.0'):
    ret = ret[:-2]
    if ret == '0' and pss:
      ret = '~0'
  return ret


def _Divide(a, b):
  return float(a) / b if b else 0


class Describer(object):
  def __init__(self, verbose=False, recursive=False):
    self.verbose = verbose
    self.recursive = recursive

  def _DescribeSectionSizes(self, section_sizes):
    relevant_names = models.SECTION_TO_SECTION_NAME.values()
    section_names = sorted(k for k in section_sizes.iterkeys()
                           if k in relevant_names or k.startswith('.data'))
    total_bytes = sum(v for k, v in section_sizes.iteritems()
                      if k in section_names and k != '.bss')
    yield ''
    yield 'Section Sizes (Total={} ({} bytes)):'.format(
        _PrettySize(total_bytes), total_bytes)
    for name in section_names:
      size = section_sizes[name]
      if name == '.bss':
        yield '    {}: {} ({} bytes) (not included in totals)'.format(
            name, _PrettySize(size), size)
      else:
        percent = _Divide(size, total_bytes)
        yield '    {}: {} ({} bytes) ({:.1%})'.format(
            name, _PrettySize(size), size, percent)

    if self.verbose:
      yield ''
      yield 'Other section sizes:'
      section_names = sorted(k for k in section_sizes.iterkeys()
                             if k not in section_names)
      for name in section_names:
        yield '    {}: {} ({} bytes)'.format(
            name, _PrettySize(section_sizes[name]), section_sizes[name])

  def _DescribeSymbol(self, sym, single_line=False):
    if sym.IsGroup():
      address = 'Group'
    else:
      address = hex(sym.address)
    if self.verbose:
      count_part = '  count=%d' % len(sym) if sym.IsGroup() else ''
      yield '{}@{:<9s}  pss={}  padding={}  size_without_padding={}{}'.format(
          sym.section, address, _FormatPss(sym.pss), sym.padding,
          sym.size_without_padding, count_part)
      yield '    source_path={} \tobject_path={}'.format(
          sym.source_path, sym.object_path)
      if sym.name:
        yield '    flags={}  name={}'.format(sym.FlagsString(), sym.name)
        if sym.full_name is not sym.name:
          yield '         full_name={}'.format(sym.full_name)
      elif sym.full_name:
        yield '    flags={}  full_name={}'.format(
            sym.FlagsString(), sym.full_name)
    elif single_line:
      count_part = ' (count=%d)' % len(sym) if sym.IsGroup() else ''
      yield '{}@{:<9s}  {:<7} {}{}'.format(
          sym.section, address, _FormatPss(sym.pss), sym.name, count_part)
    else:
      yield '{}@{:<9s}  {:<7} {}'.format(
          sym.section, address, _FormatPss(sym.pss),
          sym.source_path or sym.object_path or '{no path}')
      if sym.name:
        count_part = ' (count=%d)' % len(sym) if sym.IsGroup() else ''
        yield '    {}{}'.format(sym.name, count_part)

  def _DescribeSymbolGroupChildren(self, group, indent=0):
    running_total = 0
    running_percent = 0
    is_diff = isinstance(group, models.SymbolDiff)
    all_groups = all(s.IsGroup() for s in group)

    indent_prefix = '> ' * indent
    diff_prefix = ''
    total = group.pss
    for index, s in enumerate(group):
      if group.IsBss() or not s.IsBss():
        running_total += s.pss
        running_percent = _Divide(running_total, total)
      for l in self._DescribeSymbol(s, single_line=all_groups):
        if l[:4].isspace():
          indent_size = 8 + len(indent_prefix) + len(diff_prefix)
          yield '{} {}'.format(' ' * indent_size, l)
        else:
          if is_diff:
            diff_prefix = _DIFF_PREFIX_BY_STATUS[group.DiffStatus(s)]
          yield '{}{}{:<4} {:>8} {:7} {}'.format(
              indent_prefix, diff_prefix, str(index) + ')',
              _FormatPss(running_total), '({:.1%})'.format(running_percent), l)

      if self.recursive and s.IsGroup():
        for l in self._DescribeSymbolGroupChildren(s, indent=indent + 1):
          yield l

  def _DescribeSymbolGroup(self, group):
    total_size = group.pss
    code_size = 0
    ro_size = 0
    data_size = 0
    bss_size = 0
    unique_paths = set()
    for s in group.IterLeafSymbols():
      if s.section == 't':
        code_size += s.pss
      elif s.section == 'r':
        ro_size += s.pss
      elif s.section == 'd':
        data_size += s.pss
      elif s.section == 'b':
        bss_size += s.pss
      # Ignore paths like foo/{shared}/2
      if '{' not in s.object_path:
        unique_paths.add(s.object_path)
    header_desc = [
        'Showing {:,} symbols ({:,} unique) with total pss: {} bytes'.format(
            len(group), group.CountUniqueSymbols(), int(total_size)),
        '.text={:<10} .rodata={:<10} .data*={:<10} .bss={:<10} total={}'.format(
            _PrettySize(int(code_size)), _PrettySize(int(ro_size)),
            _PrettySize(int(data_size)), _PrettySize(int(bss_size)),
            _PrettySize(int(total_size))),
        'Number of unique paths: {}'.format(len(unique_paths)),
        '',
        'Index, Running Total, Section@Address, PSS',
        '-' * 60
    ]
    children_desc = self._DescribeSymbolGroupChildren(group)
    return itertools.chain(header_desc, children_desc)

  def _DescribeDiffObjectPaths(self, diff):
    paths_by_status = [set(), set(), set(), set()]
    def helper(group):
      for s in group:
        if s.IsGroup():
          helper(s)
        else:
          status = group.DiffStatus(s)
          paths_by_status[status].add(s.source_path or s.object_path)
    helper(diff)
    # Show only paths that have no changed symbols (pure adds / removes).
    unchanged, changed, added, removed = paths_by_status
    added.difference_update(unchanged)
    added.difference_update(changed)
    removed.difference_update(unchanged)
    removed.difference_update(changed)
    yield '{} paths added, {} removed, {} changed'.format(
        len(added), len(removed), len(changed))

    if self.verbose and len(added):
      yield 'Added files:'
      for p in sorted(added):
        yield '  ' + p
    if self.verbose and len(removed):
      yield 'Removed files:'
      for p in sorted(removed):
        yield '  ' + p
    if self.verbose and len(changed):
      yield 'Changed files:'
      for p in sorted(changed):
        yield '  ' + p

  def _DescribeSymbolDiff(self, diff):
    header_template = ('{} symbols added (+), {} changed (~), {} removed (-), '
                       '{} unchanged ({})')
    unchanged_msg = '=' if self.verbose else 'not shown'
    symbol_delta_desc = [header_template.format(
        diff.added_count, diff.changed_count, diff.removed_count,
        diff.unchanged_count, unchanged_msg)]
    path_delta_desc = self._DescribeDiffObjectPaths(diff)

    diff = diff if self.verbose else diff.WhereNotUnchanged()
    group_desc = self._DescribeSymbolGroup(diff)
    return itertools.chain(symbol_delta_desc, path_delta_desc, ('',),
                           group_desc)

  def _DescribeSizeInfoDiff(self, diff):
    common_metadata = {k: v for k, v in diff.before_metadata.iteritems()
                       if diff.after_metadata[k] == v}
    before_metadata = {k: v for k, v in diff.before_metadata.iteritems()
                       if k not in common_metadata}
    after_metadata = {k: v for k, v in diff.after_metadata.iteritems()
                      if k not in common_metadata}
    metadata_desc = itertools.chain(
        ('Common Metadata:',),
        ('    %s' % line for line in DescribeMetadata(common_metadata)),
        ('Old Metadata:',),
        ('    %s' % line for line in DescribeMetadata(before_metadata)),
        ('New Metadata:',),
        ('    %s' % line for line in DescribeMetadata(after_metadata)))
    section_desc = self._DescribeSectionSizes(diff.section_sizes)
    group_desc = self.GenerateLines(diff.symbols)
    return itertools.chain(metadata_desc, section_desc, ('',), group_desc)

  def _DescribeSizeInfo(self, size_info):
    metadata_desc = itertools.chain(
        ('Metadata:',),
        ('    %s' % line for line in DescribeMetadata(size_info.metadata)))
    section_desc = self._DescribeSectionSizes(size_info.section_sizes)
    coverage_desc = ()
    if self.verbose:
      coverage_desc = itertools.chain(
          ('',), DescribeSizeInfoCoverage(size_info))
    group_desc = self.GenerateLines(size_info.symbols)
    return itertools.chain(metadata_desc, section_desc, coverage_desc, ('',),
                           group_desc)

  def GenerateLines(self, obj):
    if isinstance(obj, models.SizeInfoDiff):
      return self._DescribeSizeInfoDiff(obj)
    if isinstance(obj, models.SizeInfo):
      return self._DescribeSizeInfo(obj)
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

    in_section = size_info.raw_symbols.WhereInSection(section)
    actual_size = in_section.size
    size_percent = _Divide(actual_size, expected_size)
    yield ('Section {}: has {:.1%} of {} bytes accounted for from '
           '{} symbols. {} bytes are unaccounted for.').format(
               section, size_percent, actual_size, len(in_section),
               expected_size - actual_size)
    star_syms = in_section.WhereNameMatches(r'^\*')
    padding = in_section.padding - star_syms.padding
    anonymous_syms = star_syms.Inverted().WhereHasAnyAttribution().Inverted()
    yield '* Padding accounts for {} bytes ({:.1%})'.format(
        padding, _Divide(padding, in_section.size))
    if len(star_syms):
      yield ('* {} placeholders (symbols that start with **) account for '
             '{} bytes ({:.1%})').format(
                 len(star_syms), star_syms.size,
                 _Divide(star_syms.size,  in_section.size))
    if anonymous_syms:
      yield '* {} anonymous symbols account for {} bytes ({:.1%})'.format(
          len(anonymous_syms), int(anonymous_syms.pss),
          _Divide(star_syms.size, in_section.size))

    aliased_symbols = in_section.Filter(lambda s: s.aliases)
    if section == 't':
      if len(aliased_symbols):
        uniques = sum(1 for s in aliased_symbols.IterUniqueSymbols())
        yield ('* Contains {} aliases, mapped to {} unique addresses '
               '({} bytes)').format(
                   len(aliased_symbols), uniques, aliased_symbols.size)
      else:
        yield '* Contains 0 aliases'

    inlined_symbols = in_section.WhereObjectPathMatches('{shared}')
    if len(inlined_symbols):
      yield '* {} symbols have shared ownership ({} bytes)'.format(
          len(inlined_symbols), inlined_symbols.size)
    else:
      yield '* 0 symbols have shared ownership'



def _UtcToLocal(utc):
  epoch = time.mktime(utc.timetuple())
  offset = (datetime.datetime.fromtimestamp(epoch) -
            datetime.datetime.utcfromtimestamp(epoch))
  return utc + offset


def DescribeMetadata(metadata):
  display_dict = metadata.copy()
  timestamp = display_dict.get(models.METADATA_ELF_MTIME)
  if timestamp:
    timestamp_obj = datetime.datetime.utcfromtimestamp(timestamp)
    display_dict[models.METADATA_ELF_MTIME] = (
        _UtcToLocal(timestamp_obj).strftime('%Y-%m-%d %H:%M:%S'))
  gn_args = display_dict.get(models.METADATA_GN_ARGS)
  if gn_args:
    display_dict[models.METADATA_GN_ARGS] = ' '.join(gn_args)
  return sorted('%s=%s' % t for t in display_dict.iteritems())


def GenerateLines(obj, verbose=False, recursive=False):
  """Returns an iterable of lines (without \n) that describes |obj|."""
  return Describer(verbose=verbose, recursive=recursive).GenerateLines(obj)


def WriteLines(lines, func):
  for l in lines:
    func(l)
    func('\n')
