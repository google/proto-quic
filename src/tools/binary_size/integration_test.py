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
import file_format
import map2size
import models
import paths


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

  def _CloneSizeInfo(self):
    if not IntegrationTest.size_info:
      lazy_paths = paths.LazyPaths(output_directory=_TEST_DATA_DIR)
      IntegrationTest.size_info = map2size.Analyze(_TEST_MAP_PATH, lazy_paths)
    return copy.deepcopy(IntegrationTest.size_info)

  @_CompareWithGolden
  def test_Map2Size(self):
    with tempfile.NamedTemporaryFile(suffix='.size') as temp_file:
      _RunApp('map2size.py', '--output-directory', _TEST_DATA_DIR,
              '--map-file', _TEST_MAP_PATH, '', temp_file.name)
      size_info = map2size.Analyze(temp_file.name)
    sym_strs = (repr(sym) for sym in size_info.symbols)
    stats = describe.DescribeSizeInfoCoverage(size_info)
    return itertools.chain(stats, sym_strs)

  @_CompareWithGolden
  def test_ConsoleNullDiff(self):
    with tempfile.NamedTemporaryFile(suffix='.size') as temp_file:
      file_format.SaveSizeInfo(self._CloneSizeInfo(), temp_file.name)
      return _RunApp('console.py', '--query', 'Diff(size_info1, size_info2)',
                     temp_file.name, temp_file.name)

  @_CompareWithGolden
  def test_ActualDiff(self):
    size_info1 = self._CloneSizeInfo()
    size_info2 = self._CloneSizeInfo()
    size_info1.metadata = {"foo": 1, "bar": [1,2,3], "baz": "yes"}
    size_info2.metadata = {"foo": 1, "bar": [1,3], "baz": "yes"}
    size_info1.symbols -= size_info1.symbols[:2]
    size_info2.symbols -= size_info2.symbols[-3:]
    size_info1.symbols[1].size -= 10
    diff = models.Diff(size_info1, size_info2)
    return describe.GenerateLines(diff, verbose=True)

  @_CompareWithGolden
  def test_SymbolGroupMethods(self):
    all_syms = self._CloneSizeInfo().symbols
    global_syms = all_syms.WhereNameMatches('GLOBAL')
    # Tests Filter(), Inverted(), and __sub__().
    non_global_syms = global_syms.Inverted()
    self.assertEqual(non_global_syms, (all_syms - global_syms))
    # Tests Sorted() and __add__().
    self.assertEqual(all_syms.Sorted(),
                     (global_syms + non_global_syms).Sorted())
    # Tests GroupByNamespace() and __len__().
    return itertools.chain(
        ['GroupByNamespace()'],
        describe.GenerateLines(all_syms.GroupByNamespace()),
        ['GroupByNamespace(depth=1)'],
        describe.GenerateLines(all_syms.GroupByNamespace(depth=1)),
        ['GroupByNamespace(depth=1, fallback=None)'],
        describe.GenerateLines(all_syms.GroupByNamespace(depth=1,
                                                         fallback=None)),
        ['GroupByNamespace(depth=1, min_count=2)'],
        describe.GenerateLines(all_syms.GroupByNamespace(depth=1, min_count=2)),
    )


def main():
  argv = sys.argv
  if len(argv) > 1 and argv[1] == '--update':
    argv.pop(0)
    global update_goldens
    update_goldens = True

  unittest.main(argv=argv, verbosity=2)


if __name__ == '__main__':
  main()
