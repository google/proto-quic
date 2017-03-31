#!/usr/bin/env python
# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import copy
import difflib
import itertools
import logging
import os
import unittest
import subprocess
import sys
import tempfile

import describe
import map2size
import models


_SCRIPT_DIR = os.path.dirname(__file__)
_TEST_DATA_DIR = os.path.join(_SCRIPT_DIR, 'testdata')
_TEST_MAP_PATH = os.path.join(_TEST_DATA_DIR, 'test.map')

update_goldens = False


def _AssertGolden(expected_lines, actual_lines):
  expected = list(expected_lines)
  actual = list(l + '\n' for l in actual_lines)
  assert actual == expected, ('Did not match .golden.\n' +
      ''.join(difflib.unified_diff(expected, actual, 'expected', 'actual')))


def _CompareWithGolden(func):
  name = func.__name__.replace('test_', '')
  golden_path = os.path.join(_TEST_DATA_DIR, name + '.golden')

  def inner(self):
    actual_lines = func(self)

    if update_goldens:
      with open(golden_path, 'w') as file_obj:
        describe.WriteLines(actual_lines, file_obj.write)
      logging.info('Wrote %s', golden_path)
    else:
      with open(golden_path) as file_obj:
        _AssertGolden(file_obj, actual_lines)
  return inner


def _RunApp(name, *args):
  argv = [os.path.join(_SCRIPT_DIR, name), '--no-pypy']
  argv.extend(args)
  return subprocess.check_output(argv).splitlines()


class IntegrationTest(unittest.TestCase):
  size_info = None

  def _GetParsedMap(self):
    if not IntegrationTest.size_info:
      IntegrationTest.size_info = map2size.Analyze(_TEST_MAP_PATH)
    return copy.deepcopy(IntegrationTest.size_info)

  @_CompareWithGolden
  def test_Map2Size(self):
    with tempfile.NamedTemporaryFile(suffix='.size') as temp_file:
      _RunApp('map2size.py', _TEST_MAP_PATH, temp_file.name)
      size_info = map2size.Analyze(temp_file.name)
    sym_strs = (repr(sym) for sym in size_info.symbols)
    stats = describe.DescribeSizeInfoCoverage(size_info)
    return itertools.chain(stats, sym_strs)

  @_CompareWithGolden
  def test_ConsoleNullDiff(self):
    return _RunApp('console.py', '--query', 'Diff(size_info1, size_info2)',
                   _TEST_MAP_PATH, _TEST_MAP_PATH)

  @_CompareWithGolden
  def test_ActualDiff(self):
    map1 = self._GetParsedMap()
    map2 = self._GetParsedMap()
    map1.symbols.symbols.pop(-1)
    map2.symbols.symbols.pop(0)
    map1.symbols[1].size -= 10
    diff = models.Diff(map1, map2)
    return describe.GenerateLines(diff)

  def test_SymbolGroupMethods(self):
    all_syms = self._GetParsedMap().symbols
    global_syms = all_syms.WhereNameMatches('GLOBAL')
    # Tests Filter(), Inverted(), and __sub__().
    non_global_syms = global_syms.Inverted()
    self.assertEqual(non_global_syms.symbols, (all_syms - global_syms).symbols)
    # Tests Sorted() and __add__().
    self.assertEqual(all_syms.Sorted().symbols,
                     (global_syms + non_global_syms).Sorted().symbols)
    # Tests GroupByPath() and __len__().
    self.assertEqual(6, len(all_syms.GroupByPath()))


def main():
  argv = sys.argv
  if len(argv) > 1 and argv[1] == '--update':
    argv.pop(0)
    global update_goldens
    update_goldens = True

  unittest.main(argv=argv, verbosity=2)


if __name__ == '__main__':
  main()
