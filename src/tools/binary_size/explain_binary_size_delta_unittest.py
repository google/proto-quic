#!/usr/bin/env python
# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Check that explain_binary_size_delta seems to work."""

import cStringIO
import sys
import unittest

import explain_binary_size_delta


class ExplainBinarySizeDeltaTest(unittest.TestCase):

  def testCompare(self):
    # List entries have form:
    # symbol_name, symbol_type, symbol_size, file_path, memory_address
    symbol_list1 = (
      # File with one symbol, left as-is.
      ( 'unchanged', 't', 1000, '/file_unchanged', 0x1 ),
      # File with one symbol, changed.
      ( 'changed', 't', 1000, '/file_all_changed', 0x2 ),
      # File with one symbol, deleted.
      ( 'removed', 't', 1000, '/file_all_deleted', 0x3 ),
      # File with two symbols, one unchanged, one changed, same bucket
      ( 'unchanged', 't', 1000, '/file_pair_unchanged_changed', 0x4 ),
      ( 'changed', 't', 1000, '/file_pair_unchanged_changed', 0x5 ),
      # File with two symbols, one unchanged, one deleted, same bucket
      ( 'unchanged', 't', 1000, '/file_pair_unchanged_removed', 0x6 ),
      ( 'removed', 't', 1000, '/file_pair_unchanged_removed', 0x7 ),
      # File with two symbols, one unchanged, one added, same bucket
      ( 'unchanged', 't', 1000, '/file_pair_unchanged_added', 0x8 ),
      # File with two symbols, one unchanged, one changed, different bucket
      ( 'unchanged', 't', 1000, '/file_pair_unchanged_diffbuck_changed', 0x9 ),
      ( 'changed', '@', 1000, '/file_pair_unchanged_diffbuck_changed', 0xa ),
      # File with two symbols, one unchanged, one deleted, different bucket
      ( 'unchanged', 't', 1000, '/file_pair_unchanged_diffbuck_removed', 0xb ),
      ( 'removed', '@', 1000, '/file_pair_unchanged_diffbuck_removed', 0xc ),
      # File with two symbols, one unchanged, one added, different bucket
      ( 'unchanged', 't', 1000, '/file_pair_unchanged_diffbuck_added', 0xd ),
      # File with four symbols, one added, one removed,
      # one changed, one unchanged
      ( 'size_changed', 't', 1000, '/file_tetra', 0xe ),
      ( 'removed', 't', 1000, '/file_tetra', 0xf ),
      ( 'unchanged', 't', 1000, '/file_tetra', 0x10 ),
    )

    symbol_list2 = (
      # File with one symbol, left as-is.
      ( 'unchanged', 't', 1000, '/file_unchanged', 0x1 ),
      # File with one symbol, changed.
      ( 'changed', 't', 2000, '/file_all_changed', 0x2 ),
      # File with two symbols, one unchanged, one changed, same bucket
      ( 'unchanged', 't', 1000, '/file_pair_unchanged_changed', 0x3 ),
      ( 'changed', 't', 2000, '/file_pair_unchanged_changed', 0x4 ),
      # File with two symbols, one unchanged, one deleted, same bucket
      ( 'unchanged', 't', 1000, '/file_pair_unchanged_removed', 0x5 ),
      # File with two symbols, one unchanged, one added, same bucket
      ( 'unchanged', 't', 1000, '/file_pair_unchanged_added', 0x6 ),
      ( 'added', 't', 1000, '/file_pair_unchanged_added', 0x7 ),
      # File with two symbols, one unchanged, one changed, different bucket
      ( 'unchanged', 't', 1000, '/file_pair_unchanged_diffbuck_changed', 0x8 ),
      ( 'changed', '@', 2000, '/file_pair_unchanged_diffbuck_changed', 0x9 ),
      # File with two symbols, one unchanged, one deleted, different bucket
      ( 'unchanged', 't', 1000, '/file_pair_unchanged_diffbuck_removed', 0xa ),
      # File with two symbols, one unchanged, one added, different bucket
      ( 'unchanged', 't', 1000, '/file_pair_unchanged_diffbuck_added', 0xb ),
      ( 'added', '@', 1000, '/file_pair_unchanged_diffbuck_added', 0xc ),
      # File with four symbols, one added, one removed,
      # one changed, one unchanged
      ( 'size_changed', 't', 2000, '/file_tetra', 0xd ),
      ( 'unchanged', 't', 1000, '/file_tetra', 0xe ),
      ( 'added', 't', 1000, '/file_tetra', 0xf ),
      # New file with one symbol added
      ( 'added', 't', 1000, '/file_new', 0x10 ),
    )

    # Here we go
    (added, removed, changed, unchanged) = \
        explain_binary_size_delta.Compare(symbol_list1, symbol_list2)

    def delta(file_path, symbol_type, symbol_name, old_size, new_size):
      delta_info = explain_binary_size_delta.DeltaInfo(
        file_path, symbol_type, symbol_name, False)
      delta_info.old_size = old_size
      delta_info.new_size = new_size
      return delta_info

    # File with one symbol, left as-is.
    assert delta('/file_unchanged', 't', 'unchanged', 1000, 1000) in unchanged
    # File with one symbol, changed.
    assert delta('/file_all_changed', 't', 'changed', 1000, 2000) in changed
    # File with one symbol, deleted.
    assert delta('/file_all_deleted', 't', 'removed', 1000, None) in removed
    # New file with one symbol added
    assert delta('/file_new', 't', 'added', None, 1000) in added
    # File with two symbols, one unchanged, one changed, same bucket
    assert delta('/file_pair_unchanged_changed',
            't', 'unchanged', 1000, 1000) in unchanged
    assert delta('/file_pair_unchanged_changed',
            't', 'changed', 1000, 2000) in changed
    # File with two symbols, one unchanged, one removed, same bucket
    assert delta('/file_pair_unchanged_removed',
            't', 'unchanged', 1000, 1000) in unchanged
    assert delta('/file_pair_unchanged_removed',
            't', 'removed', 1000, None) in removed
    # File with two symbols, one unchanged, one added, same bucket
    assert delta('/file_pair_unchanged_added',
            't', 'unchanged', 1000, 1000) in unchanged
    assert delta('/file_pair_unchanged_added',
            't', 'added', None, 1000) in added
    # File with two symbols, one unchanged, one changed, different bucket
    assert delta('/file_pair_unchanged_diffbuck_changed',
            't', 'unchanged', 1000, 1000) in unchanged
    assert delta('/file_pair_unchanged_diffbuck_changed',
            '@', 'changed', 1000, 2000) in changed
    # File with two symbols, one unchanged, one removed, different bucket
    assert delta('/file_pair_unchanged_diffbuck_removed',
            't', 'unchanged', 1000, 1000) in unchanged
    assert delta('/file_pair_unchanged_diffbuck_removed',
            '@', 'removed', 1000, None) in removed
    # File with two symbols, one unchanged, one added, different bucket
    assert delta('/file_pair_unchanged_diffbuck_added',
            't', 'unchanged', 1000, 1000) in unchanged
    assert delta('/file_pair_unchanged_diffbuck_added',
            '@', 'added', None, 1000) in added
    # File with four symbols, one added, one removed, one changed, one unchanged
    assert delta('/file_tetra', 't', 'size_changed', 1000, 2000) in changed
    assert delta('/file_tetra', 't', 'unchanged', 1000, 1000) in unchanged
    assert delta('/file_tetra', 't', 'added', None, 1000) in added
    assert delta('/file_tetra', 't', 'removed', 1000, None) in removed

    # Now check final stats.
    orig_stdout = sys.stdout
    output_collector = cStringIO.StringIO()
    sys.stdout = output_collector
    try:
      explain_binary_size_delta.CrunchStats(added, removed, changed,
                                            unchanged, True, True)
    finally:
      sys.stdout = orig_stdout
    result = output_collector.getvalue()

    expected_output = """\
Total change: +4000 bytes
=========================
  4 added, totalling +4000 bytes across 4 sources
  4 removed, totalling -4000 bytes across 4 sources
  4 grown, for a net change of +4000 bytes \
(4000 bytes before, 8000 bytes after) across 4 sources
  8 unchanged, totalling 8000 bytes
Source stats:
  11 sources encountered.
  1 completely new.
  1 removed completely.
  8 partially changed.
  1 completely unchanged.
Per-source Analysis:

--------------------------------------------------
 +1000 - Source: /file_new - (gained 1000, lost 0)
--------------------------------------------------
  New symbols:
      +1000: added type=t, size=1000 bytes

---------------------------------------------------------------------
 +1000 - Source: /file_pair_unchanged_changed - (gained 1000, lost 0)
---------------------------------------------------------------------
  Grown symbols:
      +1000: changed type=t, (was 1000 bytes, now 2000 bytes)

----------------------------------------------------------------------------
 +1000 - Source: /file_pair_unchanged_diffbuck_added - (gained 1000, lost 0)
----------------------------------------------------------------------------
  New symbols:
      +1000: added type=@, size=1000 bytes

-------------------------------------------------------------------
 +1000 - Source: /file_pair_unchanged_added - (gained 1000, lost 0)
-------------------------------------------------------------------
  New symbols:
      +1000: added type=t, size=1000 bytes

------------------------------------------------------------------------------
 +1000 - Source: /file_pair_unchanged_diffbuck_changed - (gained 1000, lost 0)
------------------------------------------------------------------------------
  Grown symbols:
      +1000: changed type=@, (was 1000 bytes, now 2000 bytes)

----------------------------------------------------------
 +1000 - Source: /file_all_changed - (gained 1000, lost 0)
----------------------------------------------------------
  Grown symbols:
      +1000: changed type=t, (was 1000 bytes, now 2000 bytes)

-------------------------------------------------------
 +1000 - Source: /file_tetra - (gained 2000, lost 1000)
-------------------------------------------------------
  New symbols:
      +1000: added type=t, size=1000 bytes
  Removed symbols:
      -1000: removed type=t, size=1000 bytes
  Grown symbols:
      +1000: size_changed type=t, (was 1000 bytes, now 2000 bytes)

------------------------------------------------------------------------------
 -1000 - Source: /file_pair_unchanged_diffbuck_removed - (gained 0, lost 1000)
------------------------------------------------------------------------------
  Removed symbols:
      -1000: removed type=@, size=1000 bytes

----------------------------------------------------------
 -1000 - Source: /file_all_deleted - (gained 0, lost 1000)
----------------------------------------------------------
  Removed symbols:
      -1000: removed type=t, size=1000 bytes

---------------------------------------------------------------------
 -1000 - Source: /file_pair_unchanged_removed - (gained 0, lost 1000)
---------------------------------------------------------------------
  Removed symbols:
      -1000: removed type=t, size=1000 bytes
"""

    self.maxDiff = None
    self.assertMultiLineEqual(expected_output, result)


  def testCompareStringEntries(self):
    # List entries have form:
    # symbol_name, symbol_type, symbol_size, file_path, memory_address
    symbol_list1 = (
      # File with one string.
      ( '.L.str107', 'r', 8, '/file_with_strs', 0x1 ),
    )

    symbol_list2 = (
      # Two files with one string each, same name.
      ( '.L.str107', 'r', 8, '/file_with_strs', 0x1 ),
      ( '.L.str107', 'r', 7, '/other_file_with_strs', 0x2 ),
    )

    # Here we go
    (added, removed, changed, unchanged) = \
        explain_binary_size_delta.Compare(symbol_list1, symbol_list2)


    # Now check final stats.
    orig_stdout = sys.stdout
    output_collector = cStringIO.StringIO()
    sys.stdout = output_collector
    try:
      explain_binary_size_delta.CrunchStats(added, removed, changed,
                                            unchanged, True, True)
    finally:
      sys.stdout = orig_stdout
    result = output_collector.getvalue()

    expected_output = """\
Total change: +7 bytes
======================
  1 added, totalling +7 bytes across 1 sources
  1 unchanged, totalling 8 bytes
Source stats:
  2 sources encountered.
  1 completely new.
  0 removed completely.
  0 partially changed.
  1 completely unchanged.
Per-source Analysis:

--------------------------------------------------------
 +7 - Source: /other_file_with_strs - (gained 7, lost 0)
--------------------------------------------------------
  New symbols:
         +7: .L.str107 type=r, size=7 bytes
"""

    self.maxDiff = None
    self.assertMultiLineEqual(expected_output, result)

  def testCompareStringEntriesWithNoFile(self):
    # List entries have form:
    # symbol_name, symbol_type, symbol_size, file_path, memory_address
    symbol_list1 = (
      ( '.L.str104', 'r', 21, '??', 0x1 ), # Will change size.
      ( '.L.str105', 'r', 17, '??', 0x2 ), # Same.
      ( '.L.str106', 'r', 13, '??', 0x3 ), # Will be removed.
      ( '.L.str106', 'r', 3, '??', 0x4 ), # Same.
      ( '.L.str106', 'r', 3, '??', 0x5 ), # Will be removed.
      ( '.L.str107', 'r', 8, '??', 0x6 ), # Will be removed (other sizes).
    )

    symbol_list2 = (
      # Two files with one string each, same name.
      ( '.L.str104', 'r', 19, '??', 0x1 ), # Changed.
      ( '.L.str105', 'r', 11, '??', 0x2 ), # New size for multi-symbol.
      ( '.L.str105', 'r', 17, '??', 0x3 ), # New of same size for multi-symbol.
      ( '.L.str105', 'r', 17, '??', 0x4 ), # Same.
      ( '.L.str106', 'r', 3, '??', 0x5 ), # Same.
      ( '.L.str107', 'r', 5, '??', 0x6 ), # New size for symbol.
      ( '.L.str107', 'r', 7, '??', 0x7 ), # New size for symbol.
      ( '.L.str108', 'r', 8, '??', 0x8 ), # New symbol.
    )

    # Here we go
    (added, removed, changed, unchanged) = \
        explain_binary_size_delta.Compare(symbol_list1, symbol_list2)


    # Now check final stats.
    orig_stdout = sys.stdout
    output_collector = cStringIO.StringIO()
    sys.stdout = output_collector
    try:
      explain_binary_size_delta.CrunchStats(added, removed, changed,
                                            unchanged, True, True)
    finally:
      sys.stdout = orig_stdout
    result = output_collector.getvalue()

    expected_output = """\
Total change: +22 bytes
=======================
  5 added, totalling +48 bytes across 1 sources
  3 removed, totalling -24 bytes across 1 sources
  1 shrunk, for a net change of -2 bytes (21 bytes before, 19 bytes after) \
across 1 sources
  2 unchanged, totalling 20 bytes
Source stats:
  1 sources encountered.
  0 completely new.
  0 removed completely.
  1 partially changed.
  0 completely unchanged.
Per-source Analysis:

----------------------------------------
 +22 - Source: ?? - (gained 48, lost 26)
----------------------------------------
  New symbols:
        +17: .L.str105 type=r, size=17 bytes
        +11: .L.str105 type=r, size=11 bytes
         +8: .L.str108 type=r, size=8 bytes
         +7: .L.str107 type=r, size=7 bytes
         +5: .L.str107 type=r, size=5 bytes
  Removed symbols:
         -3: .L.str106 type=r, size=3 bytes
         -8: .L.str107 type=r, size=8 bytes
        -13: .L.str106 type=r, size=13 bytes
  Shrunk symbols:
         -2: .L.str104 type=r, (was 21 bytes, now 19 bytes)
"""

    self.maxDiff = None
    self.assertMultiLineEqual(expected_output, result)

  def testCompareSharedSpace(self):
    # List entries have form:
    # symbol_name, symbol_type, symbol_size, file_path, memory_address
    symbol_list1 = (
      # File with two symbols, same address.
      ( 'sym1', 'r', 8, '/file', 0x1 ),
      ( 'sym2', 'r', 8, '/file', 0x1 ),
    )

    symbol_list2 = (
      # File with two symbols, same address.
      ( 'sym1', 'r', 4, '/file', 0x1 ),
      ( 'sym2', 'r', 4, '/file', 0x1 ),
    )

    # Here we go
    (added, removed, changed, unchanged) = \
        explain_binary_size_delta.Compare(symbol_list1, symbol_list2)


    # Now check final stats.
    orig_stdout = sys.stdout
    output_collector = cStringIO.StringIO()
    sys.stdout = output_collector
    try:
      explain_binary_size_delta.CrunchStats(added, removed, changed,
                                            unchanged, True, True)
    finally:
      sys.stdout = orig_stdout
    result = output_collector.getvalue()

    expected_output = """\
Total change: -4 bytes
======================
  2 shrunk, for a net change of -4 bytes (8 bytes before, 4 bytes after) \
across 1 sources
  0 unchanged, totalling 0 bytes
Source stats:
  1 sources encountered.
  0 completely new.
  0 removed completely.
  1 partially changed.
  0 completely unchanged.
Per-source Analysis:

----------------------------------------
 -4 - Source: /file - (gained 0, lost 4)
----------------------------------------
  Shrunk symbols:
         -2: sym1 type=r, (was 4 bytes, now 2 bytes) (adjusted sizes because \
of memory sharing)
         -2: sym2 type=r, (was 4 bytes, now 2 bytes) (adjusted sizes because \
of memory sharing)
"""

    self.maxDiff = None
    self.assertMultiLineEqual(expected_output, result)


  def testCompareSharedSpaceDuplicateSymbols(self):
    # List entries have form:
    # symbol_name, symbol_type, symbol_size, file_path, memory_address
    symbol_list1 = (
      # File with two symbols, same address.
      ( 'sym1', 'r', 7, '/file', 0x2 ),
      ( 'sym1', 'r', 8, '/file', 0x1 ),
      ( 'sym2', 'r', 8, '/file', 0x1 ),
    )

    symbol_list2 = (
      # File with two symbols, same address.
      ( 'sym1', 'r', 7, '/file', 0x2 ),
      ( 'sym1', 'r', 4, '/file', 0x1 ),
      ( 'sym2', 'r', 4, '/file', 0x1 ),
    )

    # Here we go
    (added, removed, changed, unchanged) = \
        explain_binary_size_delta.Compare(symbol_list1, symbol_list2)


    # Now check final stats.
    orig_stdout = sys.stdout
    output_collector = cStringIO.StringIO()
    sys.stdout = output_collector
    try:
      explain_binary_size_delta.CrunchStats(added, removed, changed,
                                            unchanged, True, True)
    finally:
      sys.stdout = orig_stdout
    result = output_collector.getvalue()

    expected_output = """\
Total change: -4 bytes
======================
  1 added, totalling +2 bytes across 1 sources
  1 removed, totalling -4 bytes across 1 sources
  1 shrunk, for a net change of -2 bytes (4 bytes before, 2 bytes after) \
across 1 sources
  1 unchanged, totalling 7 bytes
Source stats:
  1 sources encountered.
  0 completely new.
  0 removed completely.
  1 partially changed.
  0 completely unchanged.
Per-source Analysis:

----------------------------------------
 -4 - Source: /file - (gained 2, lost 6)
----------------------------------------
  New symbols:
         +2: sym1 type=r, size=2 bytes (adjusted sizes because of memory \
sharing)
  Removed symbols:
         -4: sym1 type=r, size=4 bytes (adjusted sizes because of memory \
sharing)
  Shrunk symbols:
         -2: sym2 type=r, (was 4 bytes, now 2 bytes) (adjusted sizes because \
of memory sharing)
"""

    self.maxDiff = None
    self.assertMultiLineEqual(expected_output, result)

  def testCompareSharedSpaceBecomingUnshared(self):
    # List entries have form:
    # symbol_name, symbol_type, symbol_size, file_path, memory_address
    symbol_list1 = (
      # File with two symbols, same address.
      ( 'sym1', 'r', 8, '/file', 0x1 ),
      ( 'sym2', 'r', 8, '/file', 0x1 ),
    )

    symbol_list2 = (
      # File with two symbols, not the same address.
      ( 'sym1', 'r', 8, '/file', 0x1 ),
      ( 'sym2', 'r', 6, '/file', 0x2 ),
    )

    # Here we go
    (added, removed, changed, unchanged) = \
        explain_binary_size_delta.Compare(symbol_list1, symbol_list2)


    # Now check final stats.
    orig_stdout = sys.stdout
    output_collector = cStringIO.StringIO()
    sys.stdout = output_collector
    try:
      explain_binary_size_delta.CrunchStats(added, removed, changed,
                                            unchanged, True, True)
    finally:
      sys.stdout = orig_stdout
    result = output_collector.getvalue()

    expected_output = """\
Total change: +6 bytes
======================
  2 grown, for a net change of +6 bytes (8 bytes before, 14 bytes after) \
across 1 sources
  0 unchanged, totalling 0 bytes
Source stats:
  1 sources encountered.
  0 completely new.
  0 removed completely.
  1 partially changed.
  0 completely unchanged.
Per-source Analysis:

----------------------------------------
 +6 - Source: /file - (gained 6, lost 0)
----------------------------------------
  Grown symbols:
         +4: sym1 type=r, (was 4 bytes, now 8 bytes) (adjusted sizes because \
of memory sharing)
         +2: sym2 type=r, (was 4 bytes, now 6 bytes) (adjusted sizes because \
of memory sharing)
"""

    self.maxDiff = None
    self.assertMultiLineEqual(expected_output, result)

  def testCompareSymbolsBecomingUnshared(self):
    # List entries have form:
    # symbol_name, symbol_type, symbol_size, file_path, memory_address
    symbol_list1 = (
      # File with two symbols, not the same address.
      ( 'sym1', 'r', 8, '/file', 0x1 ),
      ( 'sym2', 'r', 6, '/file', 0x2 ),
    )

    symbol_list2 = (
      # File with two symbols, same address.
      ( 'sym1', 'r', 8, '/file', 0x1 ),
      ( 'sym2', 'r', 8, '/file', 0x1 ),
    )

    # Here we go
    (added, removed, changed, unchanged) = \
        explain_binary_size_delta.Compare(symbol_list1, symbol_list2)


    # Now check final stats.
    orig_stdout = sys.stdout
    output_collector = cStringIO.StringIO()
    sys.stdout = output_collector
    try:
      explain_binary_size_delta.CrunchStats(added, removed, changed,
                                            unchanged, True, True)
    finally:
      sys.stdout = orig_stdout
    result = output_collector.getvalue()

    expected_output = """\
Total change: -6 bytes
======================
  2 shrunk, for a net change of -6 bytes (14 bytes before, 8 bytes after) \
across 1 sources
  0 unchanged, totalling 0 bytes
Source stats:
  1 sources encountered.
  0 completely new.
  0 removed completely.
  1 partially changed.
  0 completely unchanged.
Per-source Analysis:

----------------------------------------
 -6 - Source: /file - (gained 0, lost 6)
----------------------------------------
  Shrunk symbols:
         -2: sym2 type=r, (was 6 bytes, now 4 bytes) (adjusted sizes because \
of memory sharing)
         -4: sym1 type=r, (was 8 bytes, now 4 bytes) (adjusted sizes because \
of memory sharing)
"""

    self.maxDiff = None
    self.assertMultiLineEqual(expected_output, result)

  def testDeltaInfo(self):
    x = explain_binary_size_delta.DeltaInfo("path", "t", "sym_name", False)
    assert x == x
    y = explain_binary_size_delta.DeltaInfo("path", "t", "sym_name", False)
    assert x == y

    y.new_size = 12
    assert x != y

    x.new_size = 12
    assert x == y

    z = explain_binary_size_delta.DeltaInfo("path", "t", "sym_name", True)
    assert not (x == z)
    assert x != z

    w = explain_binary_size_delta.DeltaInfo("other_path", "t", "sym_name", True)
    assert w != z

if __name__ == '__main__':
  unittest.main()
