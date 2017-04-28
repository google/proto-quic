# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""Classes that comprise the data model for binary size analysis.

The primary classes are Symbol, and SymbolGroup.

Description of common properties:
  * address: The start address of the symbol.
        May be 0 (e.g. for .bss or for SymbolGroups).
  * size: The number of bytes this symbol takes up, including padding that comes
       before |address|.
  * padding: The number of bytes of padding before |address| due to this symbol.
  * name: Symbol names with parameter list removed.
        Never None, but will be '' for anonymous symbols.
  * full_name: Symbols names with parameter list left in.
       Never None, but will be '' for anonymous symbols, and for symbols that do
       not contain a parameter list.
  * is_anonymous: True when the symbol exists in an anonymous namespace (which
       are removed from both full_name and name during normalization).
  * section_name: E.g. ".text", ".rodata", ".data.rel.local"
  * section: The second character of |section_name|. E.g. "t", "r", "d".
"""

import collections
import copy
import os
import re

import match_util


METADATA_GIT_REVISION = 'git_revision'
METADATA_APK_FILENAME = 'apk_file_name'  # Path relative to output_directory.
METADATA_MAP_FILENAME = 'map_file_name'  # Path relative to output_directory.
METADATA_ELF_ARCHITECTURE = 'elf_arch'  # "Machine" field from readelf -h
METADATA_ELF_FILENAME = 'elf_file_name'  # Path relative to output_directory.
METADATA_ELF_MTIME = 'elf_mtime'  # int timestamp in utc.
METADATA_ELF_BUILD_ID = 'elf_build_id'
METADATA_GN_ARGS = 'gn_args'


SECTION_TO_SECTION_NAME = {
    'b': '.bss',
    'd': '.data',
    'r': '.rodata',
    't': '.text',
}

FLAG_ANONYMOUS = 1
FLAG_STARTUP = 2
FLAG_UNLIKELY = 4
FLAG_REL = 8
FLAG_REL_LOCAL = 16


class SizeInfo(object):
  """Represents all size information for a single binary.

  Fields:
    section_sizes: A dict of section_name -> size.
    raw_symbols: A flat list of all symbols.
    symbols: A SymbolGroup containing raw_symbols, but with some Symbols grouped
        into sub-SymbolGroups.
    metadata: A dict.
  """
  __slots__ = (
      'section_sizes',
      'raw_symbols',
      'symbols',
      'metadata',
  )

  """Root size information."""
  def __init__(self, section_sizes, raw_symbols, grouped_symbols=None,
               metadata=None):
    self.section_sizes = section_sizes  # E.g. {'.text': 0}
    # List of symbols sorted by address per-section.
    self.raw_symbols = raw_symbols
    # Root SymbolGroup. Cloned symbols grouped together within sub-SymbolGroups.
    self.symbols = grouped_symbols
    self.metadata = metadata or {}


class SizeInfoDiff(object):
  """What you get when you Diff() two SizeInfo objects.

  Fields:
    section_sizes: A dict of section_name -> size delta.
    symbols: A SymbolDiff with all symbols in it.
    before_metadata: metadata of the "before" SizeInfo.
    after_metadata: metadata of the "after" SizeInfo.
  """
  __slots__ = (
      'section_sizes',
      'symbols',
      'before_metadata',
      'after_metadata',
  )

  def __init__(self, section_sizes, symbols, before_metadata, after_metadata):
    self.section_sizes = section_sizes
    self.symbols = symbols
    self.before_metadata = before_metadata
    self.after_metadata = after_metadata


class BaseSymbol(object):
  """Base class for Symbol and SymbolGroup.

  Refer to module docs for field descriptions.
  """
  __slots__ = ()

  @property
  def section(self):
    """Returns the one-letter section.

    E.g. If section_name == '.rodata', then section == 'r'.
    """
    return self.section_name[1]

  @property
  def size_without_padding(self):
    return self.size - self.padding

  @property
  def end_address(self):
    return self.address + self.size_without_padding

  @property
  def is_anonymous(self):
    return bool(self.flags & FLAG_ANONYMOUS)

  def FlagsString(self):
    # Most flags are 0.
    flags = self.flags
    if not flags:
      return '{}'
    parts = []
    if flags & FLAG_ANONYMOUS:
      parts.append('anon')
    if flags & FLAG_STARTUP:
      parts.append('startup')
    if flags & FLAG_UNLIKELY:
      parts.append('unlikely')
    if flags & FLAG_REL:
      parts.append('rel')
    if flags & FLAG_REL_LOCAL:
      parts.append('rel.loc')
    return '{%s}' % ','.join(parts)

  def IsBss(self):
    return self.section_name == '.bss'

  def IsGroup(self):
    return False

  def IsGenerated(self):
    # TODO(agrieve): Also match generated functions such as:
    #     startup._GLOBAL__sub_I_page_allocator.cc
    return self.name.endswith(']') and not self.name.endswith('[]')

  def _Key(self):
    """Returns a tuple that can be used to see if two Symbol are the same.

    Keys are not guaranteed to be unique within a SymbolGroup. For example, it
    is common to have multiple "** merge strings" symbols, which will have a
    common key."""
    stripped_full_name = self.full_name
    if stripped_full_name:
      clone_idx = stripped_full_name.find(' [clone ')
      if clone_idx != -1:
        stripped_full_name = stripped_full_name[:clone_idx]
    return (self.section_name, stripped_full_name or self.name)


class Symbol(BaseSymbol):
  """Represents a single symbol within a binary.

  Refer to module docs for field descriptions.
  """

  __slots__ = (
      'address',
      'full_name',
      'flags',
      'object_path',
      'name',
      'padding',
      'section_name',
      'source_path',
      'size',
  )

  def __init__(self, section_name, size_without_padding, address=None,
               name=None, source_path=None, object_path=None, full_name=None,
               flags=0):
    self.section_name = section_name
    self.address = address or 0
    self.name = name or ''
    self.full_name = full_name or ''
    self.source_path = source_path or ''
    self.object_path = object_path or ''
    self.size = size_without_padding
    self.flags = flags
    self.padding = 0

  def __repr__(self):
    return ('%s@%x(size_without_padding=%d,padding=%d,name=%s,path=%s,flags=%s)'
            % (self.section_name, self.address, self.size_without_padding,
               self.padding, self.name, self.source_path or self.object_path,
               self.FlagsString()))


class SymbolGroup(BaseSymbol):
  """Represents a group of symbols using the same interface as Symbol.

  SymbolGroups are immutable. All filtering / sorting will return new
  SymbolGroups objects.

  Overrides many __functions__. E.g. the following are all valid:
  * len(group)
  * iter(group)
  * group[0]
  * group['0x1234']  # By symbol address
  * without_group2 = group1 - group2
  * unioned = group1 + group2
  """

  __slots__ = (
      '_padding',
      '_size',
      '_symbols',
      '_filtered_symbols',
      'full_name',
      'name',
      'section_name',
      'is_sorted',
  )

  def __init__(self, symbols, filtered_symbols=None, name=None,
               full_name=None, section_name=None, is_sorted=False):
    self._padding = None
    self._size = None
    self._symbols = symbols
    self._filtered_symbols = filtered_symbols or []
    self.name = name or ''
    self.full_name = full_name
    self.section_name = section_name or '.*'
    self.is_sorted = is_sorted

  def __repr__(self):
    return 'Group(name=%s,count=%d,size=%d)' % (
        self.name, len(self), self.size)

  def __iter__(self):
    return iter(self._symbols)

  def __len__(self):
    return len(self._symbols)

  def __eq__(self, other):
    return self._symbols == other._symbols

  def __getitem__(self, key):
    """|key| can be an index or an address.

    Raises if multiple symbols map to the address.
    """
    if isinstance(key, slice):
      return self._symbols.__getitem__(key)
    if isinstance(key, basestring) or key > len(self._symbols):
      found = self.WhereAddressInRange(key)
      if len(found) != 1:
        raise KeyError('%d symbols found at address %s.' % (len(found), key))
      return found[0]
    return self._symbols[key]

  def __sub__(self, other):
    other_ids = set(id(s) for s in other)
    after_symbols = [s for s in self if id(s) not in other_ids]
    return self._CreateTransformed(after_symbols,
                                   section_name=self.section_name)

  def __add__(self, other):
    self_ids = set(id(s) for s in self)
    after_symbols = self._symbols + [s for s in other if id(s) not in self_ids]
    return self._CreateTransformed(
        after_symbols, section_name=self.section_name, is_sorted=False)

  @property
  def address(self):
    first = self._symbols[0].address
    return first if all(s.address == first for s in self._symbols) else 0

  @property
  def flags(self):
    first = self._symbols[0].flags
    return first if all(s.flags == first for s in self._symbols) else 0

  @property
  def object_path(self):
    first = self._symbols[0].object_path
    return first if all(s.object_path == first for s in self._symbols) else None

  @property
  def source_path(self):
    first = self._symbols[0].source_path
    return first if all(s.source_path == first for s in self._symbols) else None

  @property
  def size(self):
    if self._size is None:
      if self.IsBss():
        self._size = sum(s.size for s in self)
      self._size = sum(s.size for s in self if not s.IsBss())
    return self._size

  @property
  def padding(self):
    if self._padding is None:
      self._padding = sum(s.padding for s in self)
    return self._padding

  def IsGroup(self):
    return True

  def _CreateTransformed(self, symbols, filtered_symbols=None, name=None,
                         section_name=None, is_sorted=None):
    if is_sorted is None:
      is_sorted = self.is_sorted
    return SymbolGroup(symbols, filtered_symbols=filtered_symbols, name=name,
                       section_name=section_name, is_sorted=is_sorted)

  def Sorted(self, cmp_func=None, key=None, reverse=False):
    # Default to sorting by abs(size) then name.
    if cmp_func is None and key is None:
      cmp_func = lambda a, b: cmp((a.IsBss(), abs(b.size), a.name),
                                  (b.IsBss(), abs(a.size), b.name))

    after_symbols = sorted(self._symbols, cmp_func, key, reverse)
    return self._CreateTransformed(
        after_symbols, filtered_symbols=self._filtered_symbols,
        section_name=self.section_name, is_sorted=True)

  def SortedByName(self, reverse=False):
    return self.Sorted(key=(lambda s:s.name), reverse=reverse)

  def SortedByAddress(self, reverse=False):
    return self.Sorted(key=(lambda s:s.address), reverse=reverse)

  def SortedByCount(self, reverse=False):
    return self.Sorted(key=(lambda s:len(s) if s.IsGroup() else 1),
                       reverse=not reverse)

  def Filter(self, func):
    filtered_and_kept = ([], [])
    for symbol in self:
      filtered_and_kept[int(bool(func(symbol)))].append(symbol)
    return self._CreateTransformed(filtered_and_kept[1],
                                   filtered_symbols=filtered_and_kept[0],
                                   section_name=self.section_name)

  def WhereBiggerThan(self, min_size):
    return self.Filter(lambda s: s.size >= min_size)

  def WhereInSection(self, section):
    if len(section) == 1:
      ret = self.Filter(lambda s: s.section == section)
      ret.section_name = SECTION_TO_SECTION_NAME[section]
    else:
      ret = self.Filter(lambda s: s.section_name == section)
      ret.section_name = section
    return ret

  def WhereIsGenerated(self):
    return self.Filter(lambda s: s.IsGenerated())

  def WhereNameMatches(self, pattern):
    regex = re.compile(match_util.ExpandRegexIdentifierPlaceholder(pattern))
    return self.Filter(lambda s: regex.search(s.name))

  def WhereObjectPathMatches(self, pattern):
    regex = re.compile(match_util.ExpandRegexIdentifierPlaceholder(pattern))
    return self.Filter(lambda s: regex.search(s.object_path))

  def WhereSourcePathMatches(self, pattern):
    regex = re.compile(match_util.ExpandRegexIdentifierPlaceholder(pattern))
    return self.Filter(lambda s: regex.search(s.source_path))

  def WherePathMatches(self, pattern):
    regex = re.compile(match_util.ExpandRegexIdentifierPlaceholder(pattern))
    return self.Filter(lambda s: (regex.search(s.source_path) or
                                  regex.search(s.object_path)))

  def WhereMatches(self, pattern):
    """Looks for |pattern| within all paths & names."""
    regex = re.compile(match_util.ExpandRegexIdentifierPlaceholder(pattern))
    return self.Filter(lambda s: (regex.search(s.source_path) or
                                  regex.search(s.object_path) or
                                  regex.search(s.full_name or '') or
                                  regex.search(s.name)))

  def WhereAddressInRange(self, start, end=None):
    """Searches for addesses within [start, end).

    Args may be ints or hex strings. Default value for |end| is |start| + 1.
    """
    if isinstance(start, basestring):
      start = int(start, 16)
    if end is None:
      end = start + 1
    return self.Filter(lambda s: s.address >= start and s.address < end)

  def WhereHasAnyAttribution(self):
    return self.Filter(lambda s: s.name or s.source_path or s.object_path)

  def Inverted(self):
    """Returns the symbols that were filtered out by the previous filter.

    Applies only when the previous call was a filter.

    Example:
        # Symbols that do not have "third_party" in their path.
        symbols.WherePathMatches(r'third_party').Inverted()
        # Symbols within third_party that do not contain the string "foo".
        symbols.WherePathMatches(r'third_party').WhereMatches('foo').Inverted()
    """
    return self._CreateTransformed(
        self._filtered_symbols, filtered_symbols=self._symbols, is_sorted=False)

  def GroupBy(self, func, min_count=0):
    """Returns a SymbolGroup of SymbolGroups, indexed by |func|.

    Args:
      func: Grouping function. Passed a symbol and returns a string for the
            name of the subgroup to put the symbol in. If None is returned, the
            symbol is omitted.
      min_count: Miniumum number of symbols for a group. If fewer than this many
                 symbols end up in a group, they will not be put within a group.
                 Use a negative value to omit symbols entirely rather than
                 include them outside of a group.
    """
    after_syms = []
    filtered_symbols = []
    symbols_by_token = collections.defaultdict(list)
    # Index symbols by |func|.
    for symbol in self:
      token = func(symbol)
      if token is None:
        filtered_symbols.append(symbol)
      symbols_by_token[token].append(symbol)
    # Create the subgroups.
    include_singles = min_count >= 0
    min_count = abs(min_count)
    for token, symbols in symbols_by_token.iteritems():
      if len(symbols) >= min_count:
        after_syms.append(self._CreateTransformed(
            symbols, name=token, section_name=self.section_name,
            is_sorted=False))
      elif include_singles:
        after_syms.extend(symbols)
      else:
        filtered_symbols.extend(symbols)
    return self._CreateTransformed(
        after_syms, filtered_symbols=filtered_symbols,
        section_name=self.section_name, is_sorted=False)

  def GroupBySectionName(self):
    return self.GroupBy(lambda s: s.section_name)

  def GroupByNamespace(self, depth=0, fallback='{global}', min_count=0):
    """Groups by symbol namespace (as denoted by ::s).

    Does not differentiate between C++ namespaces and C++ classes.

    Args:
      depth: When 0 (default), groups by entire namespace. When 1, groups by
             top-level name, when 2, groups by top 2 names, etc.
      fallback: Use this value when no namespace exists.
      min_count: Miniumum number of symbols for a group. If fewer than this many
                 symbols end up in a group, they will not be put within a group.
                 Use a negative value to omit symbols entirely rather than
                 include them outside of a group.
    """
    def extract_namespace(symbol):
      # Remove template params.
      name = symbol.name
      template_idx = name.find('<')
      if template_idx:
        name = name[:template_idx]

      # Remove after the final :: (not part of the namespace).
      colon_idx = name.rfind('::')
      if colon_idx == -1:
        return fallback
      name = name[:colon_idx]

      return _ExtractPrefixBeforeSeparator(name, '::', depth)
    return self.GroupBy(extract_namespace, min_count=min_count)

  def GroupBySourcePath(self, depth=0, fallback='{no path}',
                        fallback_to_object_path=True, min_count=0):
    """Groups by source_path.

    Args:
      depth: When 0 (default), groups by entire path. When 1, groups by
             top-level directory, when 2, groups by top 2 directories, etc.
      fallback: Use this value when no namespace exists.
      fallback_to_object_path: When True (default), uses object_path when
             source_path is missing.
      min_count: Miniumum number of symbols for a group. If fewer than this many
                 symbols end up in a group, they will not be put within a group.
                 Use a negative value to omit symbols entirely rather than
                 include them outside of a group.
    """
    def extract_path(symbol):
      path = symbol.source_path
      if fallback_to_object_path and not path:
        path = symbol.object_path
      path = path or fallback
      return _ExtractPrefixBeforeSeparator(path, os.path.sep, depth)
    return self.GroupBy(extract_path, min_count=min_count)

  def GroupByObjectPath(self, depth=0, fallback='{no path}', min_count=0):
    """Groups by object_path.

    Args:
      depth: When 0 (default), groups by entire path. When 1, groups by
             top-level directory, when 2, groups by top 2 directories, etc.
      fallback: Use this value when no namespace exists.
      min_count: Miniumum number of symbols for a group. If fewer than this many
                 symbols end up in a group, they will not be put within a group.
                 Use a negative value to omit symbols entirely rather than
                 include them outside of a group.
    """
    def extract_path(symbol):
      path = symbol.object_path or fallback
      return _ExtractPrefixBeforeSeparator(path, os.path.sep, depth)
    return self.GroupBy(extract_path, min_count=min_count)


class SymbolDiff(SymbolGroup):
  """A SymbolGroup subclass representing a diff of two other SymbolGroups.

  All Symbols contained within have a |size| which is actually the size delta.
  Additionally, metadata is kept about which symbols were added / removed /
  changed.
  """
  __slots__ = (
      '_added_ids',
      '_removed_ids',
  )

  def __init__(self, added, removed, similar, name=None, full_name=None,
               section_name=None):
    self._added_ids = set(id(s) for s in added)
    self._removed_ids = set(id(s) for s in removed)
    symbols = []
    symbols.extend(added)
    symbols.extend(removed)
    symbols.extend(similar)
    super(SymbolDiff, self).__init__(symbols, name=name, full_name=full_name,
                                     section_name=section_name)

  def __repr__(self):
    return '%s(%d added, %d removed, %d changed, %d unchanged, size=%d)' % (
        'SymbolGroup', self.added_count, self.removed_count, self.changed_count,
        self.unchanged_count, self.size)

  def _CreateTransformed(self, symbols, filtered_symbols=None, name=None,
                         section_name=None, is_sorted=None):
    ret = SymbolDiff.__new__(SymbolDiff)
    # Printing sorts, so fast-path the same symbols case.
    if len(symbols) == len(self._symbols):
      ret._added_ids = self._added_ids
      ret._removed_ids = self._removed_ids
    else:
      ret._added_ids = set(id(s) for s in symbols if self.IsAdded(s))
      ret._removed_ids = set(id(s) for s in symbols if self.IsRemoved(s))
    super(SymbolDiff, ret).__init__(
        symbols, filtered_symbols=filtered_symbols, name=name,
        section_name=section_name, is_sorted=is_sorted)
    return ret

  @property
  def added_count(self):
    return len(self._added_ids)

  @property
  def removed_count(self):
    return len(self._removed_ids)

  @property
  def changed_count(self):
    not_changed = self.unchanged_count + self.added_count + self.removed_count
    return len(self) - not_changed

  @property
  def unchanged_count(self):
    return sum(1 for s in self if self.IsSimilar(s) and s.size == 0)

  def IsAdded(self, sym):
    return id(sym) in self._added_ids

  def IsSimilar(self, sym):
    key = id(sym)
    return key not in self._added_ids and key not in self._removed_ids

  def IsRemoved(self, sym):
    return id(sym) in self._removed_ids

  def WhereNotUnchanged(self):
    return self.Filter(lambda s: not self.IsSimilar(s) or s.size)


def Diff(before, after):
  """Diffs two SizeInfo or SymbolGroup objects.

  When diffing SizeInfos, a SizeInfoDiff is returned.
  When diffing SymbolGroups, a SymbolDiff is returned.

  Returns:
    Returns a SizeInfo when args are of type SizeInfo.
    Returns a SymbolDiff when args are of type SymbolGroup.
  """
  if isinstance(after, SizeInfo):
    assert isinstance(before, SizeInfo)
    section_sizes = {k: after.section_sizes[k] - v
                     for k, v in before.section_sizes.iteritems()}
    symbol_diff = _DiffSymbols(before.symbols, after.symbols)
    return SizeInfoDiff(section_sizes, symbol_diff, before.metadata,
                        after.metadata)

  assert isinstance(after, SymbolGroup) and isinstance(before, SymbolGroup)
  return _DiffSymbols(before, after)


def _NegateAll(symbols):
  ret = []
  for symbol in symbols:
    if symbol.IsGroup():
      duped = SymbolDiff([], _NegateAll(symbol), [], name=symbol.name,
                         full_name=symbol.full_name,
                         section_name=symbol.section_name)
    else:
      duped = copy.copy(symbol)
      duped.size = -duped.size
      duped.padding = -duped.padding
    ret.append(duped)
  return ret


def _DiffSymbols(before, after):
  symbols_by_key = collections.defaultdict(list)
  for s in before:
    symbols_by_key[s._Key()].append(s)

  added = []
  similar = []
  # For similar symbols, padding is zeroed out. In order to not lose the
  # information entirely, store it in aggregate.
  padding_by_section_name = collections.defaultdict(int)
  for after_sym in after:
    matching_syms = symbols_by_key.get(after_sym._Key())
    if matching_syms:
      before_sym = matching_syms.pop(0)
      if before_sym.IsGroup() and after_sym.IsGroup():
        merged_sym = _DiffSymbols(before_sym, after_sym)
      else:
        size_diff = (after_sym.size_without_padding -
                     before_sym.size_without_padding)
        merged_sym = Symbol(after_sym.section_name, size_diff,
                            address=after_sym.address, name=after_sym.name,
                            source_path=after_sym.source_path,
                            object_path=after_sym.object_path,
                            full_name=after_sym.full_name,
                            flags=after_sym.flags)

        # Diffs are more stable when comparing size without padding, except when
        # the symbol is a padding-only symbol.
        if after_sym.size_without_padding == 0 and size_diff == 0:
          merged_sym.padding = after_sym.padding - before_sym.padding
        else:
          padding_by_section_name[after_sym.section_name] += (
              after_sym.padding - before_sym.padding)

      similar.append(merged_sym)
    else:
      added.append(after_sym)

  removed = []
  for remaining_syms in symbols_by_key.itervalues():
    if remaining_syms:
      removed.extend(_NegateAll(remaining_syms))

  for section_name, padding in padding_by_section_name.iteritems():
    if padding != 0:
      similar.append(Symbol(section_name, padding,
                            name="** aggregate padding of diff'ed symbols"))
  return SymbolDiff(added, removed, similar, name=after.name,
                    full_name=after.full_name,
                    section_name=after.section_name)


def _ExtractPrefixBeforeSeparator(string, separator, count=1):
  idx = -len(separator)
  prev_idx = None
  for _ in xrange(count):
    idx = string.find(separator, idx + len(separator))
    if idx < 0:
      break
    prev_idx = idx
  return string[:prev_idx]
