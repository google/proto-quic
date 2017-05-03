# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Logic for clustering similar symbols."""

import collections
import logging
import re


# Refer to models.SymbolGroup.Cluster() for pydoc
def ClusterSymbols(symbols):
  # http://unix.stackexchange.com/questions/223013/function-symbol-gets-part-suffix-after-compilation
  # Example name suffixes:
  #     [clone .part.322]  # GCC
  #     [clone .isra.322]  # GCC
  #     [clone .constprop.1064]  # GCC
  #     [clone .11064]  # clang

  # Step 1: Create name map, find clones, collect star syms into replacements.
  logging.debug('Creating name -> symbol map')
  clone_indices = []
  indices_by_full_name = {}
  # (section_name, name, full_name) -> [(index, sym),...]
  replacements_by_tup = collections.defaultdict(list)
  for i, symbol in enumerate(symbols):
    if symbol.name.startswith('**'):
      # "symbol gap 3" -> "symbol gaps"
      name = re.sub(r'\s+\d+( \(.*\))?$', 's', symbol.name)
      replacements_by_tup[(symbol.section_name, name, None)].append((i, symbol))
    elif symbol.full_name:
      if symbol.full_name.endswith(']') and ' [clone ' in symbol.full_name:
        clone_indices.append(i)
      else:
        indices_by_full_name[symbol.full_name] = i

  # Step 2: Collect same-named clone symbols.
  logging.debug('Grouping all clones')
  group_names_by_index = {}
  for i in clone_indices:
    symbol = symbols[i]
    # Multiple attributes could exist, so search from left-to-right.
    stripped_name = symbol.name[:symbol.name.index(' [clone ')]
    stripped_full_name = symbol.full_name[:symbol.full_name.index(' [clone ')]
    name_tup = (symbol.section_name, stripped_name, stripped_full_name)
    replacement_list = replacements_by_tup[name_tup]

    if not replacement_list:
      # First occurance, check for non-clone symbol.
      non_clone_idx = indices_by_full_name.get(stripped_name)
      if non_clone_idx is not None:
        non_clone_symbol = symbols[non_clone_idx]
        replacement_list.append((non_clone_idx, non_clone_symbol))
        group_names_by_index[non_clone_idx] = stripped_name

    replacement_list.append((i, symbol))
    group_names_by_index[i] = stripped_name

  # Step 3: Undo clustering when length=1.
  # Removing these groups means Diff() logic must know about [clone] suffix.
  to_clear = []
  for name_tup, replacement_list in replacements_by_tup.iteritems():
    if len(replacement_list) == 1:
      to_clear.append(name_tup)
  for name_tup in to_clear:
    del replacements_by_tup[name_tup]

  # Step 4: Replace first symbol from each cluster with a SymbolGroup.
  before_symbol_count = sum(len(x) for x in replacements_by_tup.itervalues())
  logging.debug('Creating %d symbol groups from %d symbols. %d clones had only '
                'one symbol.', len(replacements_by_tup), before_symbol_count,
                len(to_clear))

  len_delta = len(replacements_by_tup) - before_symbol_count
  grouped_symbols = [None] * (len(symbols) + len_delta)
  dest_index = 0
  src_index = 0
  seen_tups = set()
  replacement_tup_by_index = {}
  for name_tup, replacement_list in replacements_by_tup.iteritems():
    for tup in replacement_list:
      replacement_tup_by_index[tup[0]] = name_tup

  sorted_items = replacement_tup_by_index.items()
  sorted_items.sort(key=lambda tup: tup[0])
  for index, name_tup in sorted_items:
    count = index - src_index
    grouped_symbols[dest_index:dest_index + count] = (
        symbols[src_index:src_index + count])
    src_index = index + 1
    dest_index += count
    if name_tup not in seen_tups:
      seen_tups.add(name_tup)
      group_symbols = [tup[1] for tup in replacements_by_tup[name_tup]]
      grouped_symbols[dest_index] = symbols._CreateTransformed(
          group_symbols, name=name_tup[1], full_name=name_tup[2],
          section_name=name_tup[0])
      dest_index += 1

  assert len(grouped_symbols[dest_index:None]) == len(symbols[src_index:None])
  grouped_symbols[dest_index:None] = symbols[src_index:None]
  logging.debug('Finished clustering symbols.')
  return grouped_symbols
