#!/usr/bin/env python
# Copyright (c) 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import glob
import unittest

from idl_lexer import IDLLexer
from idl_parser import IDLParser, ParseFile


def ParseCommentTest(comment):
  comment = comment.strip()
  comments = comment.split(None, 1)
  return comments[0], comments[1]


class WebIDLParser(unittest.TestCase):

  def setUp(self):
    self.parser = IDLParser(IDLLexer(), mute_error=True)
    self.filenames = glob.glob('test_parser/*_web.idl')

  def _TestNode(self, node):
    comments = node.GetListOf('SpecialComment')
    for comment in comments:
      check, value = ParseCommentTest(comment.GetName())
      if check == 'BUILD':
        msg = 'Expecting %s, but found %s.\n' % (value, str(node))
        self.assertEqual(value, str(node), msg)

      if check == 'ERROR':
        msg = node.GetLogLine('Expecting\n\t%s\nbut found \n\t%s\n' % (
                              value, str(node)))
        self.assertEqual(value, node.GetName(), msg)

      if check == 'TREE':
        quick = '\n'.join(node.Tree())
        lineno = node.GetProperty('LINENO')
        msg = 'Mismatched tree at line %d:\n%sVS\n%s' % (
            lineno, value, quick)
        self.assertEqual(value, quick, msg)

  def testExpectedNodes(self):
    for filename in self.filenames:
      filenode = ParseFile(self.parser, filename)
      children = filenode.GetChildren()
      self.assertTrue(len(children) > 2, 'Expecting children in %s.' %
                      filename)

      for node in filenode.GetChildren():
        self._TestNode(node)


class TestImplements(unittest.TestCase):

  def setUp(self):
    self.parser = IDLParser(IDLLexer(), mute_error=True)

  def _ParseImplements(self, idl_text):
    filenode = self.parser.ParseText(filename='', data=idl_text)
    self.assertEqual(1, len(filenode.GetChildren()))
    return filenode.GetChildren()[0]

  def testAImplementsB(self):
    idl_text = 'A implements B;'
    implements_node = self._ParseImplements(idl_text)
    self.assertEqual('Implements(A)', str(implements_node))
    reference_node = implements_node.GetProperty('REFERENCE')
    self.assertEqual('B', str(reference_node))

  def testBImplementsC(self):
    idl_text = 'B implements C;'
    implements_node = self._ParseImplements(idl_text)
    self.assertEqual('Implements(B)', str(implements_node))
    reference_node = implements_node.GetProperty('REFERENCE')
    self.assertEqual('C', str(reference_node))

  def testUnexpectedSemicolon(self):
    idl_text = 'A implements;'
    node = self._ParseImplements(idl_text)
    self.assertEqual('Error', node.GetClass())
    error_message = node.GetName()
    self.assertEqual('Unexpected ";" after keyword "implements".',
                     error_message)

  def testUnexpectedImplements(self):
    idl_text = 'implements C;'
    node = self._ParseImplements(idl_text)
    self.assertEqual('Error', node.GetClass())
    error_message = node.GetName()
    self.assertEqual('Unexpected implements.',
                     error_message)

  def testUnexpectedImplementsAfterBracket(self):
    idl_text = '[foo] implements B;'
    node = self._ParseImplements(idl_text)
    self.assertEqual('Error', node.GetClass())
    error_message = node.GetName()
    self.assertEqual('Unexpected keyword "implements" after "]".',
                     error_message)


class TestEnums(unittest.TestCase):

  def setUp(self):
    self.parser = IDLParser(IDLLexer(), mute_error=True)

  def _ParseEnums(self, idl_text):
    filenode = self.parser.ParseText(
        filename='', data=idl_text)
    self.assertEqual(1, len(filenode.GetChildren()))
    return filenode.GetChildren()[0]

  def testBasic(self):
    idl_text = 'enum MealType { "rice", "noodles", "other" };'
    node = self._ParseEnums(idl_text)
    children = node.GetChildren()
    self.assertEqual('Enum', node.GetClass())
    self.assertEqual(3, len(children))
    self.assertEqual('EnumItem', children[0].GetClass())
    self.assertEqual('rice', children[0].GetName())
    self.assertEqual('EnumItem', children[1].GetClass())
    self.assertEqual('noodles', children[1].GetName())
    self.assertEqual('EnumItem', children[2].GetClass())
    self.assertEqual('other', children[2].GetName())

  def testErrorMissingName(self):
    idl_text = 'enum {"rice","noodles","other"};'
    node = self._ParseEnums(idl_text)
    self.assertEqual('Error', node.GetClass())
    error_message = node.GetName()
    self.assertEqual('Enum missing name.', error_message)

  def testTrailingCommaIsAllowed(self):
    idl_text = 'enum TrailingComma { "rice", "noodles", "other",};'
    node = self._ParseEnums(idl_text)
    children = node.GetChildren()
    self.assertEqual('Enum', node.GetClass())
    self.assertEqual(3, len(children))
    self.assertEqual('EnumItem', children[0].GetClass())
    self.assertEqual('rice', children[0].GetName())
    self.assertEqual('EnumItem', children[1].GetClass())
    self.assertEqual('noodles', children[1].GetName())
    self.assertEqual('EnumItem', children[2].GetClass())
    self.assertEqual('other', children[2].GetName())

  def testErrorMissingCommaBetweenIdentifiers(self):
    idl_text = 'enum MissingComma { "rice" "noodles", "other" };'
    node = self._ParseEnums(idl_text)
    self.assertEqual('Error', node.GetClass())
    error_message = node.GetName()
    self.assertEqual('Unexpected string "noodles" after string "rice".',
      error_message)

  def testErrorExtraCommaBetweenIdentifiers(self):
    idl_text = 'enum ExtraComma {"rice", "noodles",, "other"};'
    node = self._ParseEnums(idl_text)
    self.assertEqual('Error', node.GetClass())
    error_message = node.GetName()
    self.assertEqual('Unexpected "," after ",".', error_message)

  def testErrorUnexpectedKeyword(self):
    idl_text = 'enum TestEnum { interface, "noodles", "other"};'
    node = self._ParseEnums(idl_text)
    self.assertEqual('Error', node.GetClass())
    error_message = node.GetName()
    self.assertEqual('Unexpected keyword "interface" after "{".',
      error_message)

  def testErrorUnexpectedIdentifier(self):
    idl_text = 'enum TestEnum { somename, "noodles", "other"};'
    node = self._ParseEnums(idl_text)
    self.assertEqual('Error', node.GetClass())
    error_message = node.GetName()
    self.assertEqual('Unexpected identifier "somename" after "{".',
      error_message)


if __name__ == '__main__':
  unittest.main(verbosity=2)
