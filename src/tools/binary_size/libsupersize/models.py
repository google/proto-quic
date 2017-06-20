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
  * num_aliases: The number of symbols with the same address (including self).
  * pss: size / num_aliases.
  * padding: The number of bytes of padding before |address| due to this symbol.
  * padding_pss: padding / num_aliases.
  * name: Names with templates and parameter list removed.
        Never None, but will be '' for anonymous symbols.
  * template_name: Name with parameter list removed (but templates left in).
        Never None, but will be '' for anonymous symbols.
  * full_name: Name with template and parameter list left in.
        Never None, but will be '' for anonymous symbols.
  * is_anonymous: True when the symbol exists in an anonymous namespace (which
        are removed from both full_name and name during normalization).
  * section_name: E.g. ".text", ".rodata", ".data.rel.local"
  * section: The second character of |section_name|. E.g. "t", "r", "d".
"""

import collections
import logging
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
METADATA_TOOL_PREFIX = 'tool_prefix'  # Path relative to SRC_ROOT.


SECTION_TO_SECTION_NAME = {
    'b': '.bss',
    'd': '.data',
    'r': '.rodata',
    't': '.text',
}
# Used by SymbolGroup when they contain a mix of sections.
SECTION_NAME_MULTIPLE = '.*'

FLAG_ANONYMOUS = 1
FLAG_STARTUP = 2
FLAG_UNLIKELY = 4
FLAG_REL = 8
FLAG_REL_LOCAL = 16
FLAG_GENERATED_SOURCE = 32
FLAG_CLONE = 64

DIFF_STATUS_UNCHANGED = 0
DIFF_STATUS_CHANGED = 1
DIFF_STATUS_ADDED = 2
DIFF_STATUS_REMOVED = 3
DIFF_PREFIX_BY_STATUS = ['= ', '~ ', '+ ', '- ']


class SizeInfo(object):
  """Represents all size information for a single binary.

  Fields:
    section_sizes: A dict of section_name -> size.
    raw_symbols: A SymbolGroup containing all top-level symbols (no groups).
    symbols: A SymbolGroup where symbols have been grouped by full_name (where
        applicable). May be re-assigned when it is desirable to show custom
        groupings while still printing metadata and section_sizes.
    metadata: A dict.
    size_path: Path to .size file this was loaded from (or None).
  """
  __slots__ = (
      'section_sizes',
      'raw_symbols',
      '_symbols',
      'metadata',
      'size_path',
  )

  """Root size information."""
  def __init__(self, section_sizes, raw_symbols, metadata=None, symbols=None,
               size_path=None):
    if isinstance(raw_symbols, list):
      raw_symbols = SymbolGroup(raw_symbols)
    self.section_sizes = section_sizes  # E.g. {'.text': 0}
    self.raw_symbols = raw_symbols
    self._symbols = symbols
    self.metadata = metadata or {}
    self.size_path = size_path

  @property
  def symbols(self):
    if self._symbols is None:
      self._symbols = self.raw_symbols._Clustered()
    return self._symbols

  @symbols.setter
  def symbols(self, value):
    self._symbols = value


class DeltaSizeInfo(object):
  """What you get when you Diff() two SizeInfo objects.

  Fields:
    section_sizes: A dict of section_name -> size delta.
    raw_symbols: A DeltaSymbolGroup with all top-level symbols in it
        (no groups).
    symbols: A DeltaSymbolGroup where symbols have been grouped by full_name
        (where applicable). May be re-assigned when it is desirable to show
        custom groupings while still printing metadata and section_sizes.
    before_metadata: metadata of the "before" SizeInfo.
    after_metadata: metadata of the "after" SizeInfo.
  """
  __slots__ = (
      'section_sizes',
      'raw_symbols',
      '_symbols',
      'before_metadata',
      'after_metadata',
  )

  def __init__(self, section_sizes, raw_symbols, before_metadata,
               after_metadata):
    self.section_sizes = section_sizes
    self.raw_symbols = raw_symbols
    self.before_metadata = before_metadata
    self.after_metadata = after_metadata
    self._symbols = None

  @property
  def symbols(self):
    if self._symbols is None:
      self._symbols = self.raw_symbols._Clustered()
    return self._symbols

  @symbols.setter
  def symbols(self, value):
    self._symbols = value


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

  @property
  def generated_source(self):
    return bool(self.flags & FLAG_GENERATED_SOURCE)

  @generated_source.setter
  def generated_source(self, value):
    if value:
      self.flags |= FLAG_GENERATED_SOURCE
    else:
      self.flags &= ~FLAG_GENERATED_SOURCE

  @property
  def num_aliases(self):
    return len(self.aliases) if self.aliases else 1

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
    if flags & FLAG_GENERATED_SOURCE:
      parts.append('gen')
    if flags & FLAG_CLONE:
      parts.append('clone')
    return '{%s}' % ','.join(parts)

  def IsBss(self):
    return self.section_name == '.bss'

  def IsGroup(self):
    return False

  def IsDelta(self):
    return False

  def IsGeneratedByToolchain(self):
    return '.' in self.name or (
        self.name.endswith(']') and not self.name.endswith('[]'))


class Symbol(BaseSymbol):
  """Represents a single symbol within a binary.

  Refer to module docs for field descriptions.
  """

  __slots__ = (
      'address',
      'full_name',
      'template_name',
      'name',
      'flags',
      'object_path',
      'aliases',
      'padding',
      'section_name',
      'source_path',
      'size',
  )

  def __init__(self, section_name, size_without_padding, address=None,
               full_name=None, template_name=None, name=None, source_path=None,
               object_path=None, flags=0, aliases=None):
    self.section_name = section_name
    self.address = address or 0
    self.full_name = full_name or ''
    self.template_name = template_name or ''
    self.name = name or ''
    self.source_path = source_path or ''
    self.object_path = object_path or ''
    self.size = size_without_padding
    self.flags = flags
    self.aliases = aliases
    self.padding = 0

  def __repr__(self):
    template = ('{}@{:x}(size_without_padding={},padding={},full_name={},'
                'object_path={},source_path={},flags={},num_aliases={})')
    return template.format(
        self.section_name, self.address, self.size_without_padding,
        self.padding, self.full_name, self.object_path, self.source_path,
        self.FlagsString(), self.num_aliases)

  @property
  def pss(self):
    return float(self.size) / self.num_aliases

  @property
  def pss_without_padding(self):
    return float(self.size_without_padding) / self.num_aliases

  @property
  def padding_pss(self):
    return float(self.padding) / self.num_aliases


class DeltaSymbol(BaseSymbol):
  """Represents a changed symbol.

  PSS is not just size / num_aliases, because aliases information is not
  directly tracked. It is not directly tracked because a symbol may be an alias
  to one symbol in the |before|, and then be an alias to another in |after|.
  """

  __slots__ = (
      'before_symbol',
      'after_symbol',
  )

  def __init__(self, before_symbol, after_symbol):
    self.before_symbol = before_symbol
    self.after_symbol = after_symbol

  def __repr__(self):
    template = ('{}{}@{:x}(size_without_padding={},padding={},full_name={},'
                'object_path={},source_path={},flags={})')
    return template.format(
        DIFF_PREFIX_BY_STATUS[self.diff_status], self.section_name,
        self.address, self.size_without_padding, self.padding,
        self.full_name, self.object_path, self.source_path,
        self.FlagsString())

  def IsDelta(self):
    return True

  @property
  def diff_status(self):
    if self.before_symbol is None:
      return DIFF_STATUS_ADDED
    if self.after_symbol is None:
      return DIFF_STATUS_REMOVED
    if self.size == 0:
      return DIFF_STATUS_UNCHANGED
    return DIFF_STATUS_CHANGED

  @property
  def address(self):
    return self.after_symbol.address if self.after_symbol else 0

  @property
  def full_name(self):
    return (self.after_symbol or self.before_symbol).full_name

  @property
  def template_name(self):
    return (self.after_symbol or self.before_symbol).template_name

  @property
  def name(self):
    return (self.after_symbol or self.before_symbol).name

  @property
  def flags(self):
    before_flags = self.before_symbol.flags if self.before_symbol else 0
    after_flags = self.after_symbol.flags if self.after_symbol else 0
    return before_flags ^ after_flags

  @property
  def object_path(self):
    return (self.after_symbol or self.before_symbol).object_path

  @property
  def source_path(self):
    return (self.after_symbol or self.before_symbol).source_path

  @property
  def aliases(self):
    return None

  @property
  def section_name(self):
    return (self.after_symbol or self.before_symbol).section_name

  @property
  def padding_pss(self):
    if self.after_symbol is None:
      return -self.before_symbol.padding_pss
    if self.before_symbol is None:
      return self.after_symbol.padding_pss
    # Padding tracked in aggregate, except for padding-only symbols.
    if self.before_symbol.size_without_padding == 0:
      return self.after_symbol.padding_pss - self.before_symbol.padding_pss
    return 0

  @property
  def padding(self):
    if self.after_symbol is None:
      return -self.before_symbol.padding
    if self.before_symbol is None:
      return self.after_symbol.padding
    # Padding tracked in aggregate, except for padding-only symbols.
    if self.before_symbol.size_without_padding == 0:
      return self.after_symbol.padding - self.before_symbol.padding
    return 0

  @property
  def pss(self):
    if self.after_symbol is None:
      return -self.before_symbol.pss
    if self.before_symbol is None:
      return self.after_symbol.pss
    # Padding tracked in aggregate, except for padding-only symbols.
    if self.before_symbol.size_without_padding == 0:
      return self.after_symbol.pss - self.before_symbol.pss
    return (self.after_symbol.pss_without_padding -
            self.before_symbol.pss_without_padding)

  @property
  def size(self):
    if self.after_symbol is None:
      return -self.before_symbol.size
    if self.before_symbol is None:
      return self.after_symbol.size
    # Padding tracked in aggregate, except for padding-only symbols.
    if self.before_symbol.size_without_padding == 0:
      return self.after_symbol.padding - self.before_symbol.padding
    return (self.after_symbol.size_without_padding -
            self.before_symbol.size_without_padding)

  @property
  def pss_without_padding(self):
    return self.pss - self.padding_pss


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
      '_pss',
      '_symbols',
      '_filtered_symbols',
      'full_name',
      'template_name',
      'name',
      'section_name',
      'is_sorted',
  )

  # template_name and full_name are useful when clustering symbol clones.
  def __init__(self, symbols, filtered_symbols=None, full_name=None,
               template_name=None, name='', section_name=None, is_sorted=False):
    self._padding = None
    self._size = None
    self._pss = None
    self._symbols = symbols
    self._filtered_symbols = filtered_symbols or []
    self.full_name = full_name if full_name is not None else name
    self.template_name = template_name if template_name is not None else name
    self.name = name or ''
    self.section_name = section_name or SECTION_NAME_MULTIPLE
    self.is_sorted = is_sorted

  def __repr__(self):
    return 'Group(full_name=%s,count=%d,size=%d)' % (
        self.full_name, len(self), self.size)

  def __iter__(self):
    return iter(self._symbols)

  def __len__(self):
    return len(self._symbols)

  def __eq__(self, other):
    return isinstance(other, SymbolGroup) and self._symbols == other._symbols

  def __contains__(self, sym):
    return sym in self._symbols

  def __getitem__(self, key):
    """|key| can be an index or an address.

    Raises if multiple symbols map to the address.
    """
    if isinstance(key, slice):
      return self._CreateTransformed(self._symbols.__getitem__(key))
    if isinstance(key, basestring) or key > len(self._symbols):
      found = self.WhereAddressInRange(key)
      if len(found) != 1:
        raise KeyError('%d symbols found at address %s.' % (len(found), key))
      return found[0]
    return self._symbols[key]

  def __sub__(self, other):
    other_ids = set(id(s) for s in other)
    after_symbols = [s for s in self if id(s) not in other_ids]
    return self._CreateTransformed(after_symbols)

  def __add__(self, other):
    self_ids = set(id(s) for s in self)
    after_symbols = self._symbols + [s for s in other if id(s) not in self_ids]
    return self._CreateTransformed(after_symbols, is_sorted=False)

  def index(self, item):
    return self._symbols.index(item)

  @property
  def address(self):
    first = self._symbols[0].address if self else 0
    return first if all(s.address == first for s in self._symbols) else 0

  @property
  def flags(self):
    first = self._symbols[0].flags if self else 0
    return first if all(s.flags == first for s in self._symbols) else 0

  @property
  def object_path(self):
    first = self._symbols[0].object_path if self else ''
    return first if all(s.object_path == first for s in self._symbols) else ''

  @property
  def source_path(self):
    first = self._symbols[0].source_path if self else ''
    return first if all(s.source_path == first for s in self._symbols) else ''

  @property
  def size(self):
    if self._size is None:
      if self.IsBss():
        self._size = sum(s.size for s in self.IterUniqueSymbols())
      else:
        self._size = sum(
            s.size for s in self.IterUniqueSymbols() if not s.IsBss())
    return self._size

  @property
  def pss(self):
    if self._pss is None:
      if self.IsBss():
        self._pss = sum(s.pss for s in self)
      else:
        self._pss = sum(s.pss for s in self if not s.IsBss())
    return self._pss

  @property
  def padding(self):
    if self._padding is None:
      self._padding = sum(s.padding for s in self.IterUniqueSymbols())
    return self._padding

  @property
  def aliases(self):
    return None

  def IsGroup(self):
    return True

  def SetName(self, full_name, template_name=None, name=None):
    self.full_name = full_name
    self.template_name = full_name if template_name is None else template_name
    self.name = full_name if name is None else name

  def IterUniqueSymbols(self):
    """Yields all symbols, but only one from each alias group."""
    seen_aliases_lists = set()
    for s in self:
      if not s.aliases:
        yield s
      elif id(s.aliases) not in seen_aliases_lists:
        seen_aliases_lists.add(id(s.aliases))
        yield s

  def IterLeafSymbols(self):
    """Yields all symbols, recursing into subgroups."""
    for s in self:
      if s.IsGroup():
        for x in s.IterLeafSymbols():
          yield x
      else:
        yield s

  def CountUniqueSymbols(self):
    return sum(1 for s in self.IterUniqueSymbols())

  def _CreateTransformed(self, symbols, filtered_symbols=None, full_name=None,
                         template_name=None, name=None, section_name=None,
                         is_sorted=None):
    if is_sorted is None:
      is_sorted = self.is_sorted
    if section_name is None:
      section_name = self.section_name
    return self.__class__(symbols, filtered_symbols=filtered_symbols,
                          full_name=full_name, template_name=template_name,
                          name=name, section_name=section_name,
                          is_sorted=is_sorted)

  def Sorted(self, cmp_func=None, key=None, reverse=False):
    if cmp_func is None and key is None:
      cmp_func = lambda a, b: cmp((a.IsBss(), abs(b.pss), a.name),
                                  (b.IsBss(), abs(a.pss), b.name))

    after_symbols = sorted(self._symbols, cmp_func, key, reverse)
    return self._CreateTransformed(
        after_symbols, filtered_symbols=self._filtered_symbols,
        is_sorted=True)

  def SortedByName(self, reverse=False):
    return self.Sorted(key=(lambda s:s.name), reverse=reverse)

  def SortedByAddress(self, reverse=False):
    return self.Sorted(key=(lambda s:(s.address, s.object_path, s.name)),
                       reverse=reverse)

  def SortedByCount(self, reverse=False):
    return self.Sorted(key=(lambda s:len(s) if s.IsGroup() else 1),
                       reverse=not reverse)

  def Filter(self, func):
    filtered_and_kept = ([], [])
    symbol = None
    try:
      for symbol in self:
        filtered_and_kept[int(bool(func(symbol)))].append(symbol)
    except:
      logging.warning('Filter failed on symbol %r', symbol)
      raise

    return self._CreateTransformed(filtered_and_kept[1],
                                   filtered_symbols=filtered_and_kept[0])

  def WhereIsGroup(self):
    return self.Filter(lambda s: s.IsGroup())

  def WhereSizeBiggerThan(self, min_size):
    return self.Filter(lambda s: s.size >= min_size)

  def WherePssBiggerThan(self, min_pss):
    return self.Filter(lambda s: s.pss >= min_pss)

  def WhereInSection(self, section):
    if len(section) == 1:
      ret = self.Filter(lambda s: s.section == section)
      ret.section_name = SECTION_TO_SECTION_NAME[section]
    else:
      ret = self.Filter(lambda s: s.section_name == section)
      ret.section_name = section
    return ret

  def WhereIsTemplate(self):
    return self.Filter(lambda s: s.template_name is not s.name)

  def WhereSourceIsGenerated(self):
    return self.Filter(lambda s: s.generated_source)

  def WhereGeneratedByToolchain(self):
    return self.Filter(lambda s: s.IsGeneratedByToolchain())

  def WhereFullNameMatches(self, pattern):
    regex = re.compile(match_util.ExpandRegexIdentifierPlaceholder(pattern))
    return self.Filter(lambda s: regex.search(s.full_name))

  def WhereTemplateNameMatches(self, pattern):
    regex = re.compile(match_util.ExpandRegexIdentifierPlaceholder(pattern))
    return self.Filter(lambda s: regex.search(s.template_name))

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
    return self.Filter(lambda s: (
        regex.search(s.source_path) or
        regex.search(s.object_path) or
        regex.search(s.full_name) or
        s.full_name is not s.template_name and regex.search(s.template_name) or
        s.full_name is not s.name and regex.search(s.name)))

  def WhereAddressInRange(self, start, end=None):
    """Searches for addesses within [start, end).

    Args may be ints or hex strings. Default value for |end| is |start| + 1.
    """
    if isinstance(start, basestring):
      start = int(start, 16)
    if end is None:
      end = start + 1
    return self.Filter(lambda s: s.address >= start and s.address < end)

  def WhereHasPath(self):
    return self.Filter(lambda s: s.source_path or s.object_path)

  def WhereHasAnyAttribution(self):
    return self.Filter(lambda s: s.full_name or s.source_path or s.object_path)

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
        self._filtered_symbols, filtered_symbols=self._symbols,
        section_name=SECTION_NAME_MULTIPLE, is_sorted=False)

  def GroupedBy(self, func, min_count=0, group_factory=None):
    """Returns a SymbolGroup of SymbolGroups, indexed by |func|.

    Symbols within each subgroup maintain their relative ordering.

    Args:
      func: Grouping function. Passed a symbol and returns a string for the
          name of the subgroup to put the symbol in. If None is returned, the
          symbol is omitted.
      min_count: Miniumum number of symbols for a group. If fewer than this many
          symbols end up in a group, they will not be put within a group.
          Use a negative value to omit symbols entirely rather than
          include them outside of a group.
      group_factory: Function to create SymbolGroup from a list of Symbols.
    """
    if group_factory is None:
      group_factory = lambda token, symbols: self._CreateTransformed(
            symbols, full_name=token, template_name=token, name=token)

    after_syms = []
    filtered_symbols = []
    symbols_by_token = collections.OrderedDict()
    # Index symbols by |func|.
    for symbol in self:
      token = func(symbol)
      if token is None:
        filtered_symbols.append(symbol)
      else:
        # Optimization: Store a list only when >1 symbol.
        # Saves 200-300ms for _Clustered().
        prev = symbols_by_token.setdefault(token, symbol)
        if prev is not symbol:
          if prev.__class__ == list:
            prev.append(symbol)
          else:
            symbols_by_token[token] = [prev, symbol]
    # Create the subgroups.
    include_singles = min_count >= 0
    min_count = abs(min_count)
    for token, symbol_or_list in symbols_by_token.iteritems():
      count = 1
      if symbol_or_list.__class__ == list:
        count = len(symbol_or_list)

      if count >= min_count:
        if count == 1:
          symbol_or_list = [symbol_or_list]
        after_syms.append(group_factory(token, symbol_or_list))
      else:
        target_list = after_syms if include_singles else filtered_symbols
        if count == 1:
          target_list.append(symbol_or_list)
        else:
          target_list.extend(symbol_or_list)

    return self._CreateTransformed(
        after_syms, filtered_symbols=filtered_symbols)

  def _Clustered(self):
    """Returns a new SymbolGroup with some symbols moved into subgroups.

    Method is private since it only ever makes sense to call it from
    SizeInfo.symbols.

    The main function of clustering is to put symbols that were broken into
    multiple parts under a group so that they once again look like a single
    symbol. It also groups together symbols like "** merge strings".

    To view created groups:
      Print(size_info.symbols.WhereIsGroup())
    """
    def cluster_func(symbol):
      name = symbol.full_name
      if not name:
        # min_count=2 will ensure order is maintained while not being grouped.
        # "&" to distinguish from real symbol names, id() to ensure uniqueness.
        name = '&' + hex(id(symbol))
      elif name.startswith('*'):
        # "symbol gap 3" -> "symbol gaps"
        name = re.sub(r'\s+\d+( \(.*\))?$', 's', name)
      # Never cluster symbols that span multiple paths so that all groups return
      # non-None path information.
      return (symbol.object_path, name)

    # Use a custom factory to fill in name & template_name.
    def group_factory(token, symbols):
      full_name = token[1]
      sym = symbols[0]
      if token[1].startswith('*'):
        return self._CreateTransformed(
            symbols, full_name=full_name, template_name=full_name,
            name=full_name, section_name=sym.section_name)
      return self._CreateTransformed(
          symbols, full_name=full_name, template_name=sym.template_name,
          name=sym.name, section_name=sym.section_name)

    # A full second faster to cluster per-section. Plus, don't need create
    # (section_name, name) tuples in cluster_func.
    ret = []
    for section in self.GroupedBySectionName():
      ret.extend(section.GroupedBy(
          cluster_func, min_count=2, group_factory=group_factory))

    return self._CreateTransformed(ret)

  def GroupedBySectionName(self):
    return self.GroupedBy(lambda s: s.section_name)

  def GroupedByFullName(self, min_count=2):
    """Groups by symbol.full_name.

    Does not differentiate between namespaces/classes/functions.

    Args:
      min_count: Miniumum number of symbols for a group. If fewer than this many
                 symbols end up in a group, they will not be put within a group.
                 Use a negative value to omit symbols entirely rather than
                 include them outside of a group.
    """
    return self.GroupedBy(lambda s: s.full_name, min_count=min_count)

  def GroupedByName(self, depth=0, min_count=0):
    """Groups by symbol.name, where |depth| controls how many ::s to include.

    Does not differentiate between namespaces/classes/functions.

    Args:
      depth: 0 (default): Groups by entire name. Useful for grouping templates.
             >0: Groups by this many name parts.
                 Example: 1 -> std::, 2 -> std::map
             <0: Groups by entire name minus this many name parts
                 Example: -1 -> std::map, -2 -> std::
      min_count: Miniumum number of symbols for a group. If fewer than this many
                 symbols end up in a group, they will not be put within a group.
                 Use a negative value to omit symbols entirely rather than
                 include them outside of a group.
    """
    if depth >= 0:
      extract_namespace = (
          lambda s: _ExtractPrefixBeforeSeparator(s.name, '::', depth))
    else:
      depth = -depth
      extract_namespace = (
          lambda s: _ExtractSuffixAfterSeparator(s.name, '::', depth))
    return self.GroupedBy(extract_namespace, min_count=min_count)

  def GroupedByPath(self, depth=0, fallback='{no path}',
                  fallback_to_object_path=True, min_count=0):
    """Groups by source_path.

    Due to path sharing (symbols where path looks like foo/bar/{shared}/3),
    grouping by path will not show 100% of they bytes consumed by each path.

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
      # Group by base of foo/bar/{shared}/2
      shared_idx = path.find('{shared}')
      if shared_idx != -1:
        path = path[:shared_idx + 8]
      return _ExtractPrefixBeforeSeparator(path, os.path.sep, depth)
    return self.GroupedBy(extract_path, min_count=min_count)


class DeltaSymbolGroup(SymbolGroup):
  """A SymbolGroup subclass representing a diff of two other SymbolGroups.

  Contains a list of DeltaSymbols.
  """
  __slots__ = ()

  def __repr__(self):
    counts = self.CountsByDiffStatus()
    return '%s(%d added, %d removed, %d changed, %d unchanged, size=%d)' % (
        'DeltaSymbolGroup', counts[DIFF_STATUS_ADDED],
        counts[DIFF_STATUS_REMOVED], counts[DIFF_STATUS_CHANGED],
        counts[DIFF_STATUS_UNCHANGED], self.size)

  def IsDelta(self):
    return True

  def CountsByDiffStatus(self):
    """Returns a map of diff_status -> count of children with that status."""
    ret = [0, 0, 0, 0]
    for sym in self:
      ret[sym.diff_status] += 1
    return ret

  def CountUniqueSymbols(self):
    """Returns (num_unique_before_symbols, num_unique_after_symbols)."""
    syms = (s.before_symbol for s in self.IterLeafSymbols() if s.before_symbol)
    before_count = SymbolGroup(syms).CountUniqueSymbols()
    syms = (s.after_symbol for s in self.IterLeafSymbols() if s.after_symbol)
    after_count = SymbolGroup(syms).CountUniqueSymbols()
    return before_count, after_count

  @property
  def diff_status(self):
    if not self:
      return DIFF_STATUS_UNCHANGED
    ret = self._symbols[0].diff_status
    for sym in self._symbols[1:]:
      if sym.diff_status != ret:
        return DIFF_STATUS_CHANGED
    return ret

  def WhereDiffStatusIs(self, diff_status):
    return self.Filter(lambda s: s.diff_status == diff_status)


def _ExtractPrefixBeforeSeparator(string, separator, count):
  idx = -len(separator)
  prev_idx = None
  for _ in xrange(count):
    idx = string.find(separator, idx + len(separator))
    if idx < 0:
      break
    prev_idx = idx
  return string[:prev_idx]


def _ExtractSuffixAfterSeparator(string, separator, count):
  prev_idx = len(string) + 1
  for _ in xrange(count):
    idx = string.rfind(separator, 0, prev_idx - 1)
    if idx < 0:
      break
    prev_idx = idx
  return string[:prev_idx]
