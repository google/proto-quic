#!/usr/bin/python
# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import unittest

import cyglog_to_orderfile
import os
import symbol_extractor
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(__file__), os.pardir, os.pardir,
                    'third_party', 'android_platform', 'development',
                    'scripts'))
import symbol


class TestCyglogToOrderfile(unittest.TestCase):
  def testParseLogLines(self):
    lines = """5086e000-52e92000 r-xp 00000000 b3:02 51276      libchromeview.so
secs       usecs      pid:threadid    func
START
1314897086 795828     3587:1074648168 0x509e105c
1314897086 795874     3587:1074648168 0x509e0eb4
END""".split('\n')
    offsets = cyglog_to_orderfile._ParseLogLines(lines)
    self.assertListEqual(
        offsets, [0x509e105c - 0x5086e000, 0x509e0eb4 - 0x5086e000])

  def testFindSymbolInfosAtOffsetExactMatch(self):
    offset_map = {0x10: [symbol_extractor.SymbolInfo(
        name='Symbol', offset=0x10, size=0x13, section='.text')]}
    functions = cyglog_to_orderfile._FindSymbolInfosAtOffset(offset_map, 0x10)
    self.assertEquals(len(functions), 1)
    self.assertEquals(functions[0], offset_map[0x10][0])

  def testFindSymbolInfosAtOffsetInexactMatch(self):
    offset_map = {0x10: [symbol_extractor.SymbolInfo(
        name='Symbol', offset=0x10, size=0x13, section='.text')]}
    functions = cyglog_to_orderfile._FindSymbolInfosAtOffset(offset_map, 0x11)
    self.assertEquals(len(functions), 1)
    self.assertEquals(functions[0], offset_map[0x10][0])

  def testFindSymbolInfosAtOffsetNoMatch(self):
    offset_map = {0x10: [symbol_extractor.SymbolInfo(
        name='Symbol', offset=0x10, size=0x13, section='.text')]}
    self.assertRaises(
        cyglog_to_orderfile.SymbolNotFoundException,
        cyglog_to_orderfile._FindSymbolInfosAtOffset, offset_map, 0x12)

  def testWarnAboutDuplicates(self):
    offsets = [0x1, 0x2, 0x3]
    self.assertTrue(cyglog_to_orderfile._WarnAboutDuplicates(offsets))
    offsets.append(0x1)
    self.assertFalse(cyglog_to_orderfile._WarnAboutDuplicates(offsets))

  def testSameCtorOrDtorNames(self):
    if not os.path.exists(symbol.ToolPath('c++filt')):
      print 'Skipping test dependent on missing c++filt binary.'
      return
    self.assertTrue(cyglog_to_orderfile._SameCtorOrDtorNames(
        '_ZNSt3__119istreambuf_iteratorIcNS_11char_traitsIcEEEC1Ev',
        '_ZNSt3__119istreambuf_iteratorIcNS_11char_traitsIcEEEC2Ev'))
    self.assertTrue(cyglog_to_orderfile._SameCtorOrDtorNames(
        '_ZNSt3__119istreambuf_iteratorIcNS_11char_traitsIcEEED1Ev',
        '_ZNSt3__119istreambuf_iteratorIcNS_11char_traitsIcEEED2Ev'))
    self.assertFalse(cyglog_to_orderfile._SameCtorOrDtorNames(
        '_ZNSt3__119istreambuf_iteratorIcNS_11char_traitsIcEEEC1Ev',
        '_ZNSt3__119foo_iteratorIcNS_11char_traitsIcEEEC1Ev'))
    self.assertFalse(cyglog_to_orderfile._SameCtorOrDtorNames(
        '_ZNSt3__119istreambuf_iteratorIcNS_11char_traitsIcEEE',
        '_ZNSt3__119istreambuf_iteratorIcNS_11char_traitsIcEEE'))

  def testOutputOrderfile(self):
    class FakeOutputFile(object):
      def __init__(self):
        self.writes = []

      def write(self, data):
        self.writes.append(data)

    # One symbol not matched, one with an odd address, one regularly matched
    # And two symbols aliased to the same address
    offsets = [0x12, 0x17]
    offset_to_symbol_infos = {
        0x10: [symbol_extractor.SymbolInfo(
            name='Symbol', offset=0x10, size=0x13, section='dummy')],
        0x12: [symbol_extractor.SymbolInfo(
            name='Symbol2', offset=0x12, size=0x13, section='dummy')],
        0x16: [symbol_extractor.SymbolInfo(
                   name='Symbol3', offset=0x16, size=0x13, section='dummy'),
               symbol_extractor.SymbolInfo(
                   name='Symbol32', offset=0x16, size=0x13, section='dummy'),]}
    symbol_to_sections_map = {
        'Symbol': ['.text.Symbol'],
        'Symbol2': ['.text.Symbol2', '.text.hot.Symbol2'],
        'Symbol3': ['.text.Symbol3'],
        'Symbol32': ['.text.Symbol32']}
    fake_output = FakeOutputFile()
    cyglog_to_orderfile._OutputOrderfile(
        offsets, offset_to_symbol_infos, symbol_to_sections_map, fake_output)
    expected = """.text.Symbol2
.text.hot.Symbol2
.text.Symbol3
.text.Symbol32
"""
    self.assertEquals(expected, ''.join(fake_output.writes))


if __name__ == '__main__':
  unittest.main()
