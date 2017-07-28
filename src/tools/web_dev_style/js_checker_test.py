#!/usr/bin/env python
# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import js_checker
from os import path as os_path
import re
from sys import path as sys_path
import test_util
import unittest

_HERE = os_path.dirname(os_path.abspath(__file__))
sys_path.append(os_path.join(_HERE, '..', '..', 'build'))

import find_depot_tools  # pylint: disable=W0611
from testing_support.super_mox import SuperMoxTestBase


class JsCheckerTest(SuperMoxTestBase):
  def setUp(self):
    SuperMoxTestBase.setUp(self)

    input_api = self.mox.CreateMockAnything()
    input_api.re = re
    output_api = self.mox.CreateMockAnything()
    self.checker = js_checker.JSChecker(input_api, output_api)

  def ShouldFailCommentCheck(self, line):
    """Checks that uncommented '<if>' and '<include>' are a style error."""
    error = self.checker.CommentIfAndIncludeCheck(1, line)
    self.assertNotEqual('', error, 'Should be flagged as style error: ' + line)
    highlight = test_util.GetHighlight(line, error).strip()
    self.assertTrue(highlight.startswith(('<if', '<include')))

  def ShouldPassCommentCheck(self, line):
    """Checks that commented '<if>' and '<include>' are allowed."""
    self.assertEqual('', self.checker.CommentIfAndIncludeCheck(1, line),
        'Should not be flagged as style error: ' + line)

  def testCommentFails(self):
    lines = [
        '<include src="blah.js">',
        # Currently, only "// " is accepted (not just "//" or "//\s+") as Python
        # can't do variable-length lookbehind.
        '//<include src="blah.js">',
        '//  <include src="blah.js">',
        '             <include src="blee.js">',
        '  <if expr="chromeos">',
        '<if expr="lang == \'de\'">',
        '//<if expr="bitness == 64">',
    ]
    for line in lines:
      self.ShouldFailCommentCheck(line)

  def testCommentPasses(self):
    lines = [
        '// <include src="assert.js">',
        '             // <include src="util.js"/>',
        '// <if expr="chromeos">',
        '           // <if expr="not chromeos">',
        "   '<iframe src=blah.html>';",
    ]
    for line in lines:
      self.ShouldPassCommentCheck(line)

  def ShouldFailChromeSendCheck(self, line):
    """Checks that the 'chrome.send' checker flags |line| as a style error."""
    error = self.checker.ChromeSendCheck(1, line)
    self.assertNotEqual('', error,
        'Should be flagged as style error: ' + line)
    self.assertEqual(test_util.GetHighlight(line, error), ', []')

  def ShouldPassChromeSendCheck(self, line):
    """Checks that the 'chrome.send' checker doesn't flag |line| as a style
       error.
    """
    self.assertEqual('', self.checker.ChromeSendCheck(1, line),
        'Should not be flagged as style error: ' + line)

  def testChromeSendFails(self):
    lines = [
        "chrome.send('message', []);",
        "  chrome.send('message', []);",
    ]
    for line in lines:
      self.ShouldFailChromeSendCheck(line)

  def testChromeSendPasses(self):
    lines = [
        "chrome.send('message', constructArgs('foo', []));",
        "  chrome.send('message', constructArgs('foo', []));",
        "chrome.send('message', constructArgs([]));",
        "  chrome.send('message', constructArgs([]));",
    ]
    for line in lines:
      self.ShouldPassChromeSendCheck(line)

  def ShouldFailEndJsDocCommentCheck(self, line):
    """Checks that the **/ checker flags |line| as a style error."""
    error = self.checker.EndJsDocCommentCheck(1, line)
    self.assertNotEqual('', error,
        'Should be flagged as style error: ' + line)
    self.assertEqual(test_util.GetHighlight(line, error), '**/')

  def ShouldPassEndJsDocCommentCheck(self, line):
    """Checks that the **/ checker doesn't flag |line| as a style error."""
    self.assertEqual('', self.checker.EndJsDocCommentCheck(1, line),
        'Should not be flagged as style error: ' + line)

  def testEndJsDocCommentFails(self):
    lines = [
        "/** @override **/",
        "/** @type {number} @const **/",
        "  **/",
        "**/  ",
    ]
    for line in lines:
      self.ShouldFailEndJsDocCommentCheck(line)

  def testEndJsDocCommentPasses(self):
    lines = [
        "/***************/",  # visual separators
        "  */",  # valid JSDoc comment ends
        "*/  ",
        "/**/",  # funky multi-line comment enders
        "/** @override */",  # legit JSDoc one-liners
    ]
    for line in lines:
      self.ShouldPassEndJsDocCommentCheck(line)

  def ShouldFailExtraDotInGenericCheck(self, line):
    """Checks that Array.< or Object.< is flagged as a style nit."""
    error = self.checker.ExtraDotInGenericCheck(1, line)
    self.assertNotEqual('', error)
    self.assertTrue(test_util.GetHighlight(line, error).endswith(".<"))

  def testExtraDotInGenericFails(self):
    lines = [
        "/** @private {!Array.<!Frobber>} */",
        "var a = /** @type {Object.<number>} */({});",
        "* @return {!Promise.<Change>}"
    ]
    for line in lines:
      self.ShouldFailExtraDotInGenericCheck(line)

  def ShouldFailInheritDocCheck(self, line):
    """Checks that the '@inheritDoc' checker flags |line| as a style error."""
    error = self.checker.InheritDocCheck(1, line)
    self.assertNotEqual('', error,
        msg='Should be flagged as style error: ' + line)
    self.assertEqual(test_util.GetHighlight(line, error), '@inheritDoc')

  def ShouldPassInheritDocCheck(self, line):
    """Checks that the '@inheritDoc' checker doesn't flag |line| as a style
       error.
    """
    self.assertEqual('', self.checker.InheritDocCheck(1, line),
        msg='Should not be flagged as style error: ' + line)

  def testInheritDocFails(self):
    lines = [
        " /** @inheritDoc */",
        "   * @inheritDoc",
    ]
    for line in lines:
      self.ShouldFailInheritDocCheck(line)

  def testInheritDocPasses(self):
    lines = [
        "And then I said, but I won't @inheritDoc! Hahaha!",
        " If your dad's a doctor, do you inheritDoc?",
        "  What's up, inherit doc?",
        "   this.inheritDoc(someDoc)",
    ]
    for line in lines:
      self.ShouldPassInheritDocCheck(line)

  def ShouldFailPolymerLocalIdCheck(self, line):
    """Checks that element.$.localId check marks |line| as a style error."""
    error = self.checker.PolymerLocalIdCheck(1, line)
    self.assertNotEqual('', error,
        msg='Should be flagged as a style error: ' + line)
    self.assertTrue('.$' in test_util.GetHighlight(line, error))

  def ShouldPassPolymerLocalIdCheck(self, line):
    """Checks that element.$.localId check doesn't mark |line| as a style
       error."""
    self.assertEqual('', self.checker.PolymerLocalIdCheck(1, line),
        msg='Should not be flagged as a style error: ' + line)

  def testPolymerLocalIdFails(self):
    lines = [
        "cat.$.dog",
        "thing1.$.thing2",
        "element.$.localId",
        "element.$['fancy-hyphenated-id']",
    ]
    for line in lines:
      self.ShouldFailPolymerLocalIdCheck(line)

  def testPolymerLocalIdPasses(self):
    lines = [
        "this.$.id",
        "this.$.localId",
        "this.$['fancy-id']",
    ]
    for line in lines:
      self.ShouldPassPolymerLocalIdCheck(line)

  def ShouldFailVarNameCheck(self, line):
    """Checks that var unix_hacker, $dollar are style errors."""
    error = self.checker.VarNameCheck(1, line)
    self.assertNotEqual('', error,
        msg='Should be flagged as style error: ' + line)
    highlight = test_util.GetHighlight(line, error)
    self.assertFalse('var ' in highlight);

  def ShouldPassVarNameCheck(self, line):
    """Checks that variableNamesLikeThis aren't style errors."""
    self.assertEqual('', self.checker.VarNameCheck(1, line),
        msg='Should not be flagged as style error: ' + line)

  def testVarNameFails(self):
    lines = [
        "var private_;",
        "var hostName_ = 'https://google.com';",
        " var _super_private",
        "  var unix_hacker = someFunc();",
    ]
    for line in lines:
      self.ShouldFailVarNameCheck(line)

  def testVarNamePasses(self):
    lines = [
        "  var namesLikeThis = [];",
        " for (var i = 0; i < 10; ++i) { ",
        "for (var i in obj) {",
        " var one, two, three;",
        "  var magnumPI = {};",
        " var g_browser = 'da browzer';",
        "/** @const */ var Bla = options.Bla;",  # goog.scope() replacement.
        " var $ = function() {",                 # For legacy reasons.
        "  var StudlyCaps = cr.define('bla')",   # Classes.
        " var SCARE_SMALL_CHILDREN = [",         # TODO(dbeam): add @const in
                                                 # front of all these vars like
        "/** @const */ CONST_VAR = 1;",          # this line has (<--).
    ]
    for line in lines:
      self.ShouldPassVarNameCheck(line)


if __name__ == '__main__':
  unittest.main()
