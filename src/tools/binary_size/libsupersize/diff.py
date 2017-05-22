# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""Logic for diffing two SizeInfo objects."""

import collections
import re

import models


def _SymbolKey(symbol):
  """Returns a tuple that can be used to see if two Symbol are the same.

  Keys are not guaranteed to be unique within a SymbolGroup. When multiple
  symbols have the same key, they will be matched up in order of appearance.
  We do this because the numbering of these generated symbols is not stable.

  Examples of symbols with shared keys:
    "** merge strings"
    "** symbol gap 3", "** symbol gap 5"
    "foo() [clone ##]"
    "CSWTCH.61", "CSWTCH.62"
    "._468", "._467"
    ".L__unnamed_1193", ".L__unnamed_712"
  """
  name = symbol.full_name
  clone_idx = name.find(' [clone ')
  if clone_idx != -1:
    name = name[:clone_idx]
  if name.startswith('*'):
    # "symbol gap 3 (bar)" -> "symbol gaps"
    name = re.sub(r'\s+\d+( \(.*\))?$', 's', name)

  if '.' not in name:
    return (symbol.section_name, name)
  # Compiler or Linker generated symbol.
  name = re.sub(r'[.0-9]', '', name)  # Strip out all numbers and dots.
  return (symbol.section_name, name, symbol.object_path)


def _CloneSymbol(sym, size):
  """Returns a copy of |sym| with an updated |size|.

  Padding and aliases are not copied.
  """
  return models.Symbol(
      sym.section_name, size, address=sym.address, full_name=sym.full_name,
      template_name=sym.template_name, name=sym.name,
      source_path=sym.source_path, object_path=sym.object_path, flags=sym.flags)


def _CloneAlias(sym, diffed_alias):
  """Returns a copy of |sym| and making it an alias of |diffed_alias|."""
  ret = _CloneSymbol(sym, diffed_alias.size_without_padding)
  ret.padding = diffed_alias.padding
  ret.aliases = diffed_alias.aliases
  ret.aliases.append(ret)
  return ret


def _DiffSymbol(before_sym, after_sym, diffed_symbol_by_after_aliases,
                padding_by_section_name):
  diffed_alias = None
  if after_sym.aliases:
    diffed_alias = diffed_symbol_by_after_aliases.get(id(after_sym.aliases))

  if diffed_alias:
    ret = _CloneAlias(after_sym, diffed_alias)
  else:
    size_diff = (after_sym.size_without_padding -
                 before_sym.size_without_padding)
    ret = _CloneSymbol(after_sym, size_diff)
    # Diffs are more stable when comparing size without padding, except when
    # the symbol is a padding-only symbol.
    if after_sym.size_without_padding == 0 and size_diff == 0:
      ret.padding = after_sym.padding - before_sym.padding
    else:
      padding_diff = after_sym.padding - before_sym.padding
      padding_by_section_name[ret.section_name] += padding_diff

    # If this is the first matched symbol of an alias group, initialize its
    # aliases list. The remaining aliases will be appended when diff'ed.
    if after_sym.aliases:
      ret.aliases = [ret]
      diffed_symbol_by_after_aliases[id(after_sym.aliases)] = ret
  return ret


def _CloneUnmatched(after_symbols, diffed_symbol_by_after_aliases):
  ret = [None] * len(after_symbols)
  for i, sym in enumerate(after_symbols):
    cloned = sym
    if sym.aliases:
      diffed_alias = diffed_symbol_by_after_aliases.get(id(sym.aliases))
      if diffed_alias:
        # At least one alias was diffed.
        cloned = _CloneAlias(sym, diffed_alias)
    ret[i] = cloned
  return ret


def _NegateAndClone(before_symbols, matched_before_aliases,
                    negated_symbol_by_before_aliases):
  ret = [None] * len(before_symbols)
  for i, sym in enumerate(before_symbols):
    if sym.aliases:
      negated_alias = negated_symbol_by_before_aliases.get(id(sym.aliases))
      if negated_alias:
        cloned = _CloneAlias(sym, negated_alias)
      else:
        all_aliases_removed = id(sym.aliases) not in matched_before_aliases
        # If all alises are removed, then given them negative size to reflect
        # the savings.
        if all_aliases_removed:
          cloned = _CloneSymbol(sym, -sym.size_without_padding)
          cloned.padding = -sym.padding
        else:
          # But if only a subset of aliases are removed, do not actually treat
          # them as aliases anymore, or else they will weigh down the PSS of
          # the symbols that were not removed.
          cloned = _CloneSymbol(sym, 0)
        cloned.aliases = [cloned]
        negated_symbol_by_before_aliases[id(sym.aliases)] = cloned
    else:
      cloned = _CloneSymbol(sym, -sym.size_without_padding)
      cloned.padding = -sym.padding
    ret[i] = cloned
  return ret


def _DiffSymbolGroups(before, after):
  before_symbols_by_key = collections.defaultdict(list)
  for s in before:
    before_symbols_by_key[_SymbolKey(s)].append(s)

  similar = []
  diffed_symbol_by_after_aliases = {}
  matched_before_aliases = set()
  unmatched_after_syms = []
  # For similar symbols, padding is zeroed out. In order to not lose the
  # information entirely, store it in aggregate.
  padding_by_section_name = collections.defaultdict(int)

  # Step 1: Create all delta symbols and record unmatched symbols.
  for after_sym in after:
    matching_syms = before_symbols_by_key.get(_SymbolKey(after_sym))
    if matching_syms:
      before_sym = matching_syms.pop(0)
      if before_sym.IsGroup() and after_sym.IsGroup():
        similar.append(_DiffSymbolGroups(before_sym, after_sym))
      else:
        if before_sym.aliases:
          matched_before_aliases.add(id(before_sym.aliases))
        similar.append(
            _DiffSymbol(before_sym, after_sym, diffed_symbol_by_after_aliases,
                        padding_by_section_name))
    else:
      unmatched_after_syms.append(after_sym)
      continue

  # Step 2: Copy symbols only in "after" (being careful with aliases).
  added = _CloneUnmatched(unmatched_after_syms, diffed_symbol_by_after_aliases)

  # Step 3: Negate symbols only in "before" (being careful with aliases).
  removed = []
  negated_symbol_by_before_aliases = {}
  for remaining_syms in before_symbols_by_key.itervalues():
    removed.extend(_NegateAndClone(remaining_syms, matched_before_aliases,
                                   negated_symbol_by_before_aliases))

  # Step 4: Create ** symbols to represent padding differences.
  for section_name, padding in padding_by_section_name.iteritems():
    if padding != 0:
      similar.append(models.Symbol(
          section_name, padding,
          name="** aggregate padding of diff'ed symbols"))
  return models.SymbolDiff(added, removed, similar)


def Diff(before, after):
  """Diffs two SizeInfo objects. Returns a SizeInfoDiff."""
  assert isinstance(before, models.SizeInfo)
  assert isinstance(after, models.SizeInfo)
  section_sizes = {k: after.section_sizes[k] - v
                   for k, v in before.section_sizes.iteritems()}
  symbol_diff = _DiffSymbolGroups(before.raw_symbols, after.raw_symbols)
  return models.SizeInfoDiff(section_sizes, symbol_diff, before.metadata,
                             after.metadata)
