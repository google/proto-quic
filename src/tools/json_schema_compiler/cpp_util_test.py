#!/usr/bin/env python
# Copyright (c) 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import unittest

from cpp_util import (
    Classname, CloseNamespace, GenerateIfndefName, OpenNamespace)

class CppUtilTest(unittest.TestCase):
  def testClassname(self):
    self.assertEquals('Permissions', Classname('permissions'))
    self.assertEquals('UpdateAllTheThings',
        Classname('updateAllTheThings'))
    self.assertEquals('Aa_Bb_Cc', Classname('aa.bb.cc'))

  def testNamespaceDeclaration(self):
    self.assertEquals('namespace foo {',
                      OpenNamespace('foo').Render())
    self.assertEquals('}  // namespace foo',
                      CloseNamespace('foo').Render())

    self.assertEquals(
        'namespace extensions {\n'
        'namespace foo {',
        OpenNamespace('extensions::foo').Render())
    self.assertEquals(
        '}  // namespace foo\n'
        '}  // namespace extensions',
        CloseNamespace('extensions::foo').Render())

    self.assertEquals(
        'namespace extensions {\n'
        'namespace gen {\n'
        'namespace api {',
        OpenNamespace('extensions::gen::api').Render())
    self.assertEquals(
        '}  // namespace api\n'
        '}  // namespace gen\n'
        '}  // namespace extensions',
        CloseNamespace('extensions::gen::api').Render())

    self.assertEquals(
        'namespace extensions {\n'
        'namespace gen {\n'
        'namespace api {\n'
        'namespace foo {',
        OpenNamespace('extensions::gen::api::foo').Render())
    self.assertEquals(
        '}  // namespace foo\n'
        '}  // namespace api\n'
        '}  // namespace gen\n'
        '}  // namespace extensions',
        CloseNamespace('extensions::gen::api::foo').Render())

  def testGenerateIfndefName(self):
    self.assertEquals('FOO_BAR_BAZ_H__', GenerateIfndefName('foo\\bar\\baz.h'))
    self.assertEquals('FOO_BAR_BAZ_H__', GenerateIfndefName('foo/bar/baz.h'))


if __name__ == '__main__':
  unittest.main()
