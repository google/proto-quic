# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""Classes that comprise the data model for binary size analysis."""

import collections
import copy
import re


SECTION_TO_SECTION_NAME = {
    'b': '.bss',
    'd': '.data',
    'r': '.rodata',
    't': '.text',
}


class SizeInfo(object):
  """Represents all size information for a single binary.

  Fields:
    section_sizes: A dict of section_name -> size.
    symbols: A SymbolGroup (or SymbolDiff) with all symbols in it.
  """
  __slots__ = (
      'symbols',
      'section_sizes',
  )

  """Root size information."""
  def __init__(self, symbols, section_sizes):
    self.symbols = symbols
    self.section_sizes = section_sizes  # E.g. {'.text': 0}


class BaseSymbol(object):
  """Base class for Symbol and SymbolGroup."""
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
    return (self.section_name, self.function_signature or self.name)


class Symbol(BaseSymbol):
  """Represents a single symbol within a binary."""

  __slots__ = (
      'section_name',
      'address',
      'size',
      'padding',
      'name',
      'function_signature',
      'path',
  )

  def __init__(self, section_name, size_without_padding, address=None,
               name=None, path=None, function_signature=None):
    self.section_name = section_name
    self.address = address or 0
    self.name = name or ''
    self.function_signature = function_signature or ''
    self.path = path or ''
    self.size = size_without_padding
    self.padding = 0

  def __repr__(self):
    return '%s@%x(size=%d,padding=%d,name=%s,path=%s)' % (
        self.section_name, self.address, self.size_without_padding,
        self.padding, self.name, self.path)


class SymbolGroup(BaseSymbol):
  """Represents a group of symbols using the same interface as Symbol.

  SymbolGroups are immutable. All filtering / sorting will return new
  SymbolGroups objects.
  """

  __slots__ = (
      'symbols',
      'filtered_symbols',
      'name',
      'section_name',
  )

  def __init__(self, symbols, filtered_symbols=None, name=None,
               section_name=None):
    self.symbols = symbols
    self.filtered_symbols = filtered_symbols or []
    self.name = name or ''
    self.section_name = section_name or '.*'

  def __repr__(self):
    return 'Group(name=%s,count=%d,size=%d)' % (
        self.name, len(self), self.size)

  def __iter__(self):
    return iter(self.symbols)

  def __len__(self):
    return len(self.symbols)

  def __getitem__(self, index):
    return self.symbols[index]

  def __sub__(self, other):
    other_ids = set(id(s) for s in other)
    new_symbols = [s for s in self if id(s) not in other_ids]
    return self._CreateTransformed(new_symbols, section_name=self.section_name)

  def __add__(self, other):
    self_ids = set(id(s) for s in self)
    new_symbols = self.symbols + [s for s in other if id(s) not in self_ids]
    return self._CreateTransformed(new_symbols, section_name=self.section_name)

  @property
  def address(self):
    return 0

  @property
  def function_signature(self):
    return None

  @property
  def path(self):
    return None

  @property
  def size(self):
    if self.IsBss():
      return sum(s.size for s in self)
    return sum(s.size for s in self if not s.IsBss())

  @property
  def padding(self):
    return sum(s.padding for s in self)

  def IsGroup(self):
    return True

  def _CreateTransformed(self, symbols, filtered_symbols=None, name=None,
                         section_name=None):
    return SymbolGroup(symbols, filtered_symbols=filtered_symbols, name=name,
                       section_name=section_name)

  def Sorted(self, cmp_func=None, key=None, reverse=False):
    # Default to sorting by abs(size) then name.
    if cmp_func is None and key is None:
      cmp_func = lambda a, b: cmp((a.IsBss(), abs(b.size), a.name),
                                  (b.IsBss(), abs(a.size), b.name))

    new_symbols = sorted(self.symbols, cmp_func, key, reverse)
    return self._CreateTransformed(new_symbols,
                                   filtered_symbols=self.filtered_symbols,
                                   section_name=self.section_name)

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
    regex = re.compile(pattern)
    return self.Filter(lambda s: regex.search(s.name))

  def WherePathMatches(self, pattern):
    regex = re.compile(pattern)
    return self.Filter(lambda s: s.path and regex.search(s.path))

  def WhereAddressInRange(self, start, end):
    return self.Filter(lambda s: s.address >= start and s.address <= end)

  def WhereHasAnyAttribution(self):
    return self.Filter(lambda s: s.name or s.path)

  def Inverted(self):
    return self._CreateTransformed(self.filtered_symbols,
                                   filtered_symbols=self.symbols)

  def GroupBy(self, func):
    new_syms = []
    filtered_symbols = []
    symbols_by_token = collections.defaultdict(list)
    for symbol in self:
      token = func(symbol)
      if not token:
        filtered_symbols.append(symbol)
        continue
      symbols_by_token[token].append(symbol)
    for token, symbols in symbols_by_token.iteritems():
      new_syms.append(self._CreateTransformed(symbols, name=token,
                                              section_name=self.section_name))
    return self._CreateTransformed(new_syms, filtered_symbols=filtered_symbols,
                                   section_name=self.section_name)

  def GroupByNamespace(self, depth=1):
    def extract_namespace(symbol):
      # Does not distinguish between classes and namespaces.
      idx = -2
      for _ in xrange(depth):
        idx = symbol.name.find('::', idx + 2)
      if idx != -1:
        ret = symbol.name[:idx]
        if '<' not in ret:
          return ret
      return '{global}'
    return self.GroupBy(extract_namespace)

  def GroupByPath(self, depth=1):
    def extract_path(symbol):
      idx = -1
      for _ in xrange(depth):
        idx = symbol.path.find('/', idx + 1)
      if idx != -1:
        return symbol.path[:idx]
      return '{path unknown}'
    return self.GroupBy(extract_path)


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

  def __init__(self, added, removed, similar):
    self._added_ids = set(id(s) for s in added)
    self._removed_ids = set(id(s) for s in removed)
    symbols = []
    symbols.extend(added)
    symbols.extend(removed)
    symbols.extend(similar)
    super(SymbolDiff, self).__init__(symbols)

  def __repr__(self):
    return '%s(%d added, %d removed, %d changed, %d unchanged, size=%d)' % (
        'SymbolGroup', self.added_count, self.removed_count, self.changed_count,
        self.unchanged_count, self.size)

  def _CreateTransformed(self, symbols, filtered_symbols=None, name=None,
                         section_name=None):
    ret = SymbolDiff.__new__(SymbolDiff)
    # Printing sorts, so fast-path the same symbols case.
    if len(symbols) == len(self.symbols):
      ret._added_ids = self._added_ids
      ret._removed_ids = self._removed_ids
    else:
      ret._added_ids = set(id(s) for s in symbols if self.IsAdded(s))
      ret._removed_ids = set(id(s) for s in symbols if self.IsRemoved(s))
    super(SymbolDiff, ret).__init__(symbols, filtered_symbols=filtered_symbols,
                                    name=name, section_name=section_name)

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


def Diff(new, old):
  """Diffs two SizeInfo or SymbolGroup objects.

  When diffing SizeInfos, ret.section_sizes are the result of |new| - |old|, and
  ret.symbols will be a SymbolDiff.

  When diffing SymbolGroups, a SymbolDiff is returned.

  Returns:
    Returns a SizeInfo when args are of type SizeInfo.
    Returns a SymbolDiff when args are of type SymbolGroup.
  """
  if isinstance(new, SizeInfo):
    assert isinstance(old, SizeInfo)
    section_sizes = {
        k:new.section_sizes[k] - v for k, v in old.section_sizes.iteritems()}
    symbol_diff = Diff(new.symbols, old.symbols)
    return SizeInfo(symbol_diff, section_sizes)

  assert isinstance(new, SymbolGroup) and isinstance(old, SymbolGroup)
  symbols_by_key = collections.defaultdict(list)
  for s in old:
    symbols_by_key[s._Key()].append(s)

  added = []
  removed = []
  similar = []
  # For similar symbols, padding is zeroed out. In order to not lose the
  # information entirely, store it in aggregate.
  padding_by_section_name = collections.defaultdict(int)
  for new_sym in new:
    matching_syms = symbols_by_key.get(new_sym._Key())
    if matching_syms:
      old_sym = matching_syms.pop(0)
      # More stable/useful to compare size without padding.
      size_diff = (new_sym.size_without_padding -
                   old_sym.size_without_padding)
      merged_sym = Symbol(old_sym.section_name, size_diff,
                          address=old_sym.address, name=old_sym.name,
                          path=old_sym.path,
                          function_signature=old_sym.function_signature)
      similar.append(merged_sym)
      padding_by_section_name[new_sym.section_name] += (
          new_sym.padding - old_sym.padding)
    else:
      added.append(new_sym)

  for remaining_syms in symbols_by_key.itervalues():
    for old_sym in remaining_syms:
      duped = copy.copy(old_sym)
      duped.size = -duped.size
      duped.padding = -duped.padding
      removed.append(duped)

  for section_name, padding in padding_by_section_name.iteritems():
    similar.append(Symbol(section_name, padding,
                          name='** aggregate padding of delta symbols'))
  return SymbolDiff(added, removed, similar)
