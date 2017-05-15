# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Logic for clustering similar symbols."""

import collections
import logging
import re

import function_signature


def _StripCloneSuffix(name):
  # Multiple attributes could exist, so search from left-to-right.
  idx = name.find(' [clone ')
  if idx != -1:
    return name[:idx]
  return name


# Refer to models.SymbolGroup.Clustered() for pydoc
# TODO(agrieve): This logic should likely be combined with
#    SymbolGroup.GroupedBy(), as it conceptually does the same thing.
#    One could also thing of this as GroupedByFullName().
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
  # (section_name, full_name_no_attr) -> [(index, sym),...]
  replacements_by_tup = collections.defaultdict(list)
  for i, symbol in enumerate(symbols):
    name = symbol.full_name
    if not name:
      continue
    if name.startswith('*'):
      # "symbol gap 3" -> "symbol gaps"
      name = re.sub(r'\s+\d+( \(.*\))?$', 's', name)
      replacements_by_tup[(symbol.section_name, name)].append((i, symbol))
    elif name.endswith(']') and ' [clone ' in name:
      clone_indices.append(i)
    else:
      indices_by_full_name[name] = i

  # Step 2: Collect same-named clone symbols.
  logging.debug('Grouping all clones')
  group_names_by_index = {}
  for i in clone_indices:
    symbol = symbols[i]
    stripped_full_name = _StripCloneSuffix(symbol.full_name)
    name_tup = (symbol.section_name, stripped_full_name)
    replacement_list = replacements_by_tup[name_tup]

    if not replacement_list:
      # First occurance, check for non-clone symbol.
      non_clone_idx = indices_by_full_name.get(stripped_full_name)
      if non_clone_idx is not None:
        non_clone_symbol = symbols[non_clone_idx]
        replacement_list.append((non_clone_idx, non_clone_symbol))
        group_names_by_index[non_clone_idx] = stripped_full_name

    replacement_list.append((i, symbol))
    group_names_by_index[i] = stripped_full_name

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
  index_and_name_tups = []
  for name_tup, replacement_list in replacements_by_tup.iteritems():
    for symbol_tup in replacement_list:
      index_and_name_tups.append((symbol_tup[0], name_tup))

  index_and_name_tups.sort(key=lambda tup: tup[0])
  for index, name_tup in index_and_name_tups:
    count = index - src_index
    grouped_symbols[dest_index:dest_index + count] = (
        symbols[src_index:src_index + count])
    src_index = index + 1
    dest_index += count
    if name_tup not in seen_tups:
      seen_tups.add(name_tup)
      group_symbols = [tup[1] for tup in replacements_by_tup[name_tup]]
      section_name, stripped_full_name = name_tup
      if stripped_full_name.startswith('*'):
        stripped_template_name = stripped_full_name
        stripped_name = stripped_full_name
      else:
        stripped_template_name = _StripCloneSuffix(
            group_symbols[0].template_name)
        stripped_name = _StripCloneSuffix(group_symbols[0].name)
      cluster = symbols._CreateTransformed(
          group_symbols, full_name=stripped_full_name,
          template_name=stripped_template_name, name=stripped_name,
          section_name=section_name)
      function_signature.InternSameNames(cluster)
      grouped_symbols[dest_index] = cluster
      dest_index += 1

  assert len(grouped_symbols[dest_index:None]) == len(symbols[src_index:None])
  grouped_symbols[dest_index:None] = symbols[src_index:None]
  logging.debug('Finished clustering symbols.')
  return grouped_symbols
