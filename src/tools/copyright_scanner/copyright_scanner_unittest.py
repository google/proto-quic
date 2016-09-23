#!/usr/bin/env python
# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Unit tests for Copyright Scanner utilities."""

import os
import re
import sys
import unittest

test_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.extend([
    os.path.normpath(os.path.join(test_dir, '..', '..', 'build')),
    os.path.join(test_dir),
])

import find_depot_tools
from testing_support.super_mox import SuperMoxTestBase

import copyright_scanner

class FindCopyrightsTest(SuperMoxTestBase):
  def setUp(self):
    SuperMoxTestBase.setUp(self)
    self.input_api = self.mox.CreateMockAnything()
    self.input_api.re = re
    self.input_api.os_path = os.path
    self.input_api.os_walk = os.walk

  def ShouldMatchReferenceOutput(self, test_data, expected_output):
    for data in test_data:
      self.input_api.ReadFile = lambda _1, _2: data
      actual_output = copyright_scanner.FindCopyrights(self.input_api, '', [''])
      self.assertEqual(
        expected_output,
        actual_output,
        'Input """\n%s""", expected output: "%s", actual: "%s"' % \
            (data, expected_output, actual_output));

  def testCopyrightedFiles(self):
    test_data = [
      '// (c) 2014 Google Inc.\n//\n//  (a) One\n//\n//  (b) Two\n//\n',
      'Copyright 2014 Google Inc.\n',
      'Copr. 2014 Google Inc.',
      '\xc2\xa9 2014 Google Inc.',
      'Copyright 2014    Google  Inc.'
    ]
    self.ShouldMatchReferenceOutput(test_data, [['2014 Google Inc.']])

  def testGeneratedFiles(self):
    test_data = [
      'ALL CHANGES MADE IN THIS FILE WILL BE LOST\nCopyright 2014 Google\n',
      'GENERATED FILE. DO NOT EDIT\nCopyright 2014 Google\n',
      'GENERATED. DO NOT DELETE THIS FILE.\nCopyright 2014 Google\n',
      'DO NOT EDIT\nCopyright 2014 Google\n',
      'DO NOT DELETE THIS FILE\nCopyright 2014 Google\n',
      'All changes made in this file will be lost\nCopyright 2014 Google\n',
      'Automatically generated file\nCopyright 2014 Google\n',
      'Synthetically generated dummy file\nCopyright 2014 Google\n',
      'Generated data (by gnugnu)\nCopyright 2014 Google\n'
    ]
    self.ShouldMatchReferenceOutput(test_data, [['GENERATED FILE']])

  def testNonCopyrightedFiles(self):
    test_data = [
      'std::cout << "Copyright 2014 Google"\n',
      '// Several points can be made:\n//\n//  (a) One\n//\n//  (b) Two\n'
      '//\n//  (c) Three\n//\n',
      'See \'foo\' for copyright information.\n',
      'See \'foo\' for the copyright notice.\n',
      'See \'foo\' for the copyright and other things.\n'
    ]
    self.ShouldMatchReferenceOutput(test_data, [['*No copyright*']])

  def testNonGeneratedFiles(self):
    test_data = [
      'This file was prohibited from being generated.\n',
      'Please do not delete our files! They are valuable to us.\n',
      'Manually generated from dice rolls.\n',
      '"""This Python script produces generated data\n"""\n',
      '\'\'\'This Python script produces generated data\n\'\'\'\n'
    ]
    self.ShouldMatchReferenceOutput(test_data, [['*No copyright*']])


class FindFilesTest(SuperMoxTestBase):
  def setUp(self):
    SuperMoxTestBase.setUp(self)
    self.input_api = self.mox.CreateMockAnything()
    self.input_api.re = re
    self.input_api.os_path = os.path

  def testFilesAsStartPaths(self):
    join = self.input_api.os_path.join
    self.input_api.os_path.isfile = lambda _: True
    input_files = [
      'a',
      'a.cc',
      'a.txt',
      join('foo', 'a'),
      join('foo', 'a.cc'),
      join('foo', 'a.txt'),
      join('third_party', 'a'),
      join('third_party', 'a.cc'),
      join('third_party', 'a.txt'),
      join('foo', 'third_party', 'a'),
      join('foo', 'third_party', 'a.cc'),
      join('foo', 'third_party', 'a.txt'),
    ]
    root_dir = os.path.sep + 'src'
    actual = copyright_scanner.FindFiles(
      self.input_api, root_dir, input_files, [''])
    self.assertEqual(['a.cc', join('foo', 'a.cc')], actual)
    actual = copyright_scanner.FindFiles(
      self.input_api, root_dir, input_files, ['third_party'])
    self.assertEqual(['a.cc', join('foo', 'a.cc')], actual)
    actual = copyright_scanner.FindFiles(
      self.input_api, root_dir, input_files, ['foo'])
    self.assertEqual(['a.cc'], actual)
    actual = copyright_scanner.FindFiles(
      self.input_api, root_dir, input_files, ['foo', 'third_party'])
    self.assertEqual(['a.cc'], actual)
    actual = copyright_scanner.FindFiles(
      self.input_api, root_dir, input_files, [join('foo', 'third_party')])
    self.assertEqual(['a.cc', join('foo', 'a.cc')], actual)

  def testDirAsStartPath(self):
    self.input_api.os_path.isfile = lambda _: False
    join = self.input_api.os_path.join
    normpath = self.input_api.os_path.normpath
    root_dir = os.path.sep + 'src'
    scan_from = '.'
    base_path = join(root_dir, scan_from)

    def mock_os_walk(path):
      return lambda _: [(join(base_path, path), [''], ['a', 'a.cc', 'a.txt'])]

    self.input_api.os_walk = mock_os_walk('')
    actual = map(normpath, copyright_scanner.FindFiles(
      self.input_api, root_dir, [scan_from], ['']))
    self.assertEqual(['a.cc'], actual)

    self.input_api.os_walk = mock_os_walk('third_party')
    actual = map(normpath, copyright_scanner.FindFiles(
      self.input_api, root_dir, [scan_from], ['']))
    self.assertEqual([], actual)

    self.input_api.os_walk = mock_os_walk('foo')
    actual = map(normpath, copyright_scanner.FindFiles(
      self.input_api, root_dir, [scan_from], ['']))
    self.assertEqual([join('foo', 'a.cc')], actual)

    self.input_api.os_walk = mock_os_walk('foo')
    actual = map(normpath, copyright_scanner.FindFiles(
      self.input_api, root_dir, [scan_from], ['foo']))
    self.assertEqual([], actual)

    self.input_api.os_walk = mock_os_walk(join('foo', 'bar'))
    actual = map(normpath, copyright_scanner.FindFiles(
      self.input_api, root_dir, [scan_from], ['foo']))
    self.assertEqual([], actual)

    self.input_api.os_walk = mock_os_walk(join('foo', 'third_party'))
    actual = map(normpath, copyright_scanner.FindFiles(
      self.input_api, root_dir, [scan_from], ['']))
    self.assertEqual([], actual)

    self.input_api.os_walk = mock_os_walk(join('foo', 'third_party'))
    actual = map(normpath, copyright_scanner.FindFiles(
      self.input_api, root_dir, [scan_from], [join('foo', 'third_party')]))
    self.assertEqual([], actual)


class AnalyzeScanResultsTest(SuperMoxTestBase):
  def setUp(self):
    SuperMoxTestBase.setUp(self)
    self.input_api = self.mox.CreateMockAnything()
    self.input_api.os_path = os.path
    self.input_api.change = self.mox.CreateMockAnything()
    self.input_api.change.RepositoryRoot = lambda: ''

  def testAnalyzeScanResults(self):
    # Tests whitelisted vs. current files state logic.
    #
    # Whitelisted - in whitelist, and contains 3rd party code => OK
    # Missing - in whitelist, but doesn't exist
    # Stale - in whitelist, but is clean
    # Unknown - not in whitelist, but contains 3rd party code
    self.input_api.os_path.isfile = lambda x: x != 'Missing'
    self.assertEqual(
      (['Unknown'], ['Missing'], ['Stale']),
      copyright_scanner.AnalyzeScanResults(self.input_api, \
          ['Whitelisted', 'Missing', 'Stale'], ['Whitelisted', 'Unknown']))


class ScanAtPresubmitTest(SuperMoxTestBase):
  def setUp(self):
    SuperMoxTestBase.setUp(self)
    self.input_api = self.mox.CreateMockAnything()
    self.input_api.re = re
    self.input_api.os_path = os.path
    self.output_api = self.mox.CreateMockAnything()
  def tearDown(self):
    self.mox.UnsetStubs()
    SuperMoxTestBase.tearDown(self)

  class AffectedFileMock(object):
    def __init__(self, local_path, action):
      self._local_path = local_path
      self._action = action
    def LocalPath(self):
      return self._local_path
    def Action(self):
      return self._action

  def CreateAffectedFilesFunc(self, paths_and_actions):
    result = []
    for i in range(0, len(paths_and_actions), 2):
      result.append(ScanAtPresubmitTest.AffectedFileMock(
        paths_and_actions[i], paths_and_actions[i + 1]))
    return lambda: result

  def CreateDoScanAtPresubmitFunc(self):
    self._whitelisted_files = None
    self._files_to_check = None
    def ScanAtPresubmitStub(_, whitelisted, to_check):
      self._whitelisted_files = whitelisted
      self._files_to_check = to_check
      return ([], [], [])
    return ScanAtPresubmitStub

  def GetWhitelistedFiles(self):
    return sorted(self._whitelisted_files)

  def GetFilesToCheck(self):
    return sorted(self._files_to_check)

  def testWhitelistedUntouched(self):
    # When a change doesn't touch the whitelist file, any updated files
    # (except deleted) must be checked. The whitelist used for analysis
    # must be trimmed to the changed files subset.
    #
    # A_NW.cc - added, not whitelisted => check
    # A_W.cc - added, whitelisted => check, remain on the trimmed whitelist
    # D_NW.cc - deleted, not whitelisted => ignore
    # D_W.cc - deleted and whitelisted => remain on w/l
    # M_NW.cc - modified, not whitelisted => check
    # M_W.cc - modified and whitelisted => check, remain on w/l
    # NM_W.cc - not modified, whitelisted => trim from w/l
    # W - the whitelist file

    self.input_api.AffectedFiles = self.CreateAffectedFilesFunc(
      ['A_NW.cc', 'A', 'A_W.cc', 'A', 'D_NW.cc', 'D', 'D_W.cc', 'D',
       'M_NW.cc', 'M', 'M_W.cc', 'M'])
    self.mox.StubOutWithMock(copyright_scanner, '_GetWhitelistFileName')
    copyright_scanner._GetWhitelistFileName = lambda _: 'W'
    self.mox.StubOutWithMock(copyright_scanner, 'LoadWhitelistedFilesList')
    copyright_scanner.LoadWhitelistedFilesList = \
        lambda _: ['A_W.cc', 'D_W.cc', 'M_W.cc', 'NM_W.cc']
    self.mox.StubOutWithMock(copyright_scanner, '_DoScanAtPresubmit')
    copyright_scanner._DoScanAtPresubmit = self.CreateDoScanAtPresubmitFunc()
    self.mox.ReplayAll()
    copyright_scanner.ScanAtPresubmit(self.input_api, self.output_api)
    self.assertEqual(
      ['A_W.cc', 'D_W.cc', 'M_W.cc'], self.GetWhitelistedFiles())
    self.assertEqual(
      ['A_NW.cc', 'A_W.cc', 'M_NW.cc', 'M_W.cc'], self.GetFilesToCheck())

  def testWhitelistTouched(self):
    # When the whitelist file is touched by the change, all the files listed in
    # it, including deleted entries, must be re-checked. All modified files
    # (including the deleted ones) must be checked as well. The current contents
    # of the whitelist are used for analysis.
    # Whitelist addition or deletion are not considered.
    #
    # All the files from names testWhitelistedUntouched are re-used, but now
    # action for all of them is 'check' (except for the w/l file itself).
    # A_DW.cc - added, deleted from w/l => check
    # D_DW.cc - deleted from repo and w/l => check
    # M_DW.cc - modified, deleted from w/l => check
    self.input_api.AffectedFiles = self.CreateAffectedFilesFunc(
      ['A_DW.cc', 'A', 'A_NW.cc', 'A', 'A_W.cc', 'A',
       'D_DW.cc', 'D', 'D_NW.cc', 'D', 'D_W.cc', 'D',
       'M_DW.cc', 'M', 'M_NW.cc', 'M', 'M_W.cc', 'M', 'W', 'M'])
    self.mox.StubOutWithMock(copyright_scanner, '_GetWhitelistFileName')
    copyright_scanner._GetWhitelistFileName = lambda _: 'W'
    self.mox.StubOutWithMock(copyright_scanner, '_GetDeletedContents')
    def GetDeletedContentsStub(affected_file):
      self.assertEqual('W', affected_file.LocalPath())
      return ['A_DW.cc', 'D_DW.cc', 'M_DW.cc']
    copyright_scanner._GetDeletedContents = GetDeletedContentsStub
    self.mox.StubOutWithMock(copyright_scanner, 'LoadWhitelistedFilesList')
    copyright_scanner.LoadWhitelistedFilesList = \
        lambda _: ['A_W.cc', 'D_W.cc', 'M_W.cc', 'NM_W.cc']
    self.mox.StubOutWithMock(copyright_scanner, '_DoScanAtPresubmit')
    copyright_scanner._DoScanAtPresubmit = self.CreateDoScanAtPresubmitFunc()
    self.mox.ReplayAll()
    copyright_scanner.ScanAtPresubmit(self.input_api, self.output_api)
    self.assertEqual(
      ['A_W.cc', 'D_W.cc', 'M_W.cc', 'NM_W.cc'], self.GetWhitelistedFiles())
    self.assertEqual(
      ['A_DW.cc', 'A_NW.cc', 'A_W.cc', 'D_DW.cc', 'D_NW.cc', 'D_W.cc',
       'M_DW.cc', 'M_NW.cc', 'M_W.cc', 'NM_W.cc' ], self.GetFilesToCheck())

if __name__ == '__main__':
  unittest.main()
