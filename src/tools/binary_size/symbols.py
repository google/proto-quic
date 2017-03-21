# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import collections
import re


SECTION_TO_SECTION_NAME = {
    'b': '.bss',
    'd': '.data',
    'r': '.rodata',
    't': '.text',
}


class BaseSymbol(object):
  """Base class for Symbol and SymbolGroup."""
  __slots__ = ()

  def __repr__(self):
    return '%s@%x(size=%d,padding=%d,name=%s,path=%s)' % (
        self.section_name, self.address, self.size_without_padding,
        self.size - self.size_without_padding, self.name, self.path)

  @property
  def section(self):
    return self.section_name[1]

  @property
  def size_without_padding(self):
    return self.size - self.padding

  @property
  def end_address(self):
    return self.address + self.size_without_padding

  def IsGroup(self):
    return False

  def IsGenerated(self):
    return self.name and self.name.endswith(']') and (
        not self.name.endswith('[]'))


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

  def __init__(self, section_name, address, size_without_padding, name, path):
    self.section_name = intern(section_name)
    self.address = address
    self.size = size_without_padding
    self.padding = 0
    self.name = name
    self.function_signature = None
    self.path = path


class SymbolGroup(BaseSymbol):
  """Represents a group of symbols using the same interface as Symbol."""

  __slots__ = (
      'symbols',
      'filtered_symbols',
      'name',
      'section_name',
  )

  def __init__(self, symbols, filtered_symbols=None, name=None,
               section_name='**'):
    self.symbols = symbols
    self.filtered_symbols = filtered_symbols or []
    self.name = name
    self.section_name = section_name

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
    return sum(s.size for s in self)

  @property
  def padding(self):
    return sum(s.padding for s in self)

  def __iter__(self):
    return iter(self.symbols)

  def __len__(self):
    return len(self.symbols)

  def IsGroup(self):
    return True

  def Sorted(self, cmp_func=None, key=None, reverse=False):
    # Default to sorting by size then name.
    if cmp_func is None and key is None:
      cmp_func = lambda a, b: cmp((b.size, a.name), (a.size, b.name))

    new_symbols = sorted(self.symbols, cmp_func, key, reverse)
    return self.__class__(new_symbols, filtered_symbols=self.filtered_symbols,
                          section_name=self.section_name)

  def Filter(self, func, include_filtered=False):
    filtered_and_kept = ([], [])
    for symbol in self:
      filtered_and_kept[int(bool(func(symbol)))].append(symbol)

    if include_filtered:
      filtered_and_kept[0].extend(self.filtered_symbols)
    return self.__class__(filtered_and_kept[1],
                          filtered_symbols=filtered_and_kept[0],
                          section_name=self.section_name)

  def WhereBiggerThan(self, min_size, include_filtered=False):
    return self.Filter(lambda s: s.size >= min_size,
                       include_filtered=include_filtered)

  def WhereInSection(self, section, include_filtered=False):
    ret = self.Filter(lambda s: s.section == section,
                      include_filtered=include_filtered)
    ret.section_name = SECTION_TO_SECTION_NAME[section]
    return ret

  def WhereNameMatches(self, pattern, include_filtered=False):
    regex = re.compile(pattern)
    return self.Filter(lambda s: s.name and regex.search(s.name),
                       include_filtered=include_filtered)

  def WherePathMatches(self, pattern, include_filtered=False):
    regex = re.compile(pattern)
    return self.Filter(lambda s: s.path and regex.search(s.path),
                       include_filtered=include_filtered)

  def WhereAddressInRange(self, start, end, include_filtered=False):
    return self.Filter(lambda s: s.address >= start and s.address <= end,
                       include_filtered=include_filtered)

  def WhereHasAnyAttribution(self, include_filtered=False):
    return self.Filter(lambda s: s.name or s.path,
                       include_filtered=include_filtered)

  def Inverted(self):
    return self.__class__(self.filtered_symbols, filtered_symbols=self.symbols)

  def GroupBy(self, func, include_filtered=False):
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
      new_syms.append(self.__class__(symbols, name=token,
                                     section_name=self.section_name))
    if include_filtered:
      filtered_symbols.extend(self.filtered_symbols)
    return self.__class__(new_syms, filtered_symbols=filtered_symbols,
                          section_name=self.section_name)

  def GroupByNamespace(self, depth=1, include_filtered=False):
    def extract_namespace(symbol):
      # Does not distinguish between classes and namespaces.
      if symbol.name:
        idx = -2
        for _ in xrange(depth):
          idx = symbol.name.find('::', idx + 2)
        if idx != -1:
          ret = symbol.name[:idx]
          if '<' not in ret:
            return ret
      return '{global}'
    return self.GroupBy(extract_namespace, include_filtered=include_filtered)

  def GroupByPath(self, depth=1, include_filtered=False):
    def extract_path(symbol):
      if symbol.path:
        idx = -1
        for _ in xrange(depth):
          idx = symbol.path.find('/', idx + 1)
        if idx != -1:
          return symbol.path[:idx]
      return None
    return self.GroupBy(extract_path, include_filtered=include_filtered)
