#!/usr/bin/env python
# Copyright (c) 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from struct_generator import GenerateField
from struct_generator import GenerateStruct
import unittest

class StructGeneratorTest(unittest.TestCase):
  def testGenerateIntField(self):
    self.assertEquals('const int foo_bar',
        GenerateField({'type': 'int', 'field': 'foo_bar'}))

  def testGenerateStringField(self):
    self.assertEquals('const char* const bar_foo',
        GenerateField({'type': 'string', 'field': 'bar_foo'}))

  def testGenerateString16Field(self):
    self.assertEquals('const wchar_t* const foo_bar',
        GenerateField({'type': 'string16', 'field': 'foo_bar'}))

  def testGenerateEnumField(self):
    self.assertEquals('const MyEnumType foo_foo',
        GenerateField({'type': 'enum',
                       'field': 'foo_foo',
                       'ctype': 'MyEnumType'}))

  def testGenerateArrayField(self):
    self.assertEquals('const int * bar_bar;\n'
                      '  const size_t bar_bar_size',
        GenerateField({'type': 'array',
                       'field': 'bar_bar',
                       'contents': {'type': 'int'}}))

  def testGenerateStruct(self):
    schema = [
      {'type': 'int', 'field': 'foo_bar'},
      {'type': 'string', 'field': 'bar_foo', 'default': 'dummy'},
      {
        'type': 'array',
        'field': 'bar_bar',
        'contents': {
          'type': 'enum',
          'ctype': 'MyEnumType'
        }
      }
    ]
    struct = ('struct MyTypeName {\n'
        '  const int foo_bar;\n'
        '  const char* const bar_foo;\n'
        '  const MyEnumType * bar_bar;\n'
        '  const size_t bar_bar_size;\n'
        '};\n')
    self.assertEquals(struct, GenerateStruct('MyTypeName', schema))

  def testGenerateArrayOfStruct(self):
    schema = [
      {
        'type': 'array',
        'field': 'bar_bar',
        'contents': {
          'type': 'struct',
          'type_name': 'InnerTypeName',
          'fields': [
            {'type': 'string', 'field': 'key'},
            {'type': 'string', 'field': 'value'},
          ]
        }
      }
    ]
    struct = (
        'struct InnerTypeName {\n'
        '  const char* const key;\n'
        '  const char* const value;\n'
        '};\n'
        '\n'
        'struct MyTypeName {\n'
        '  const InnerTypeName * bar_bar;\n'
        '  const size_t bar_bar_size;\n'
        '};\n')
    self.assertEquals(struct, GenerateStruct('MyTypeName', schema))

if __name__ == '__main__':
  unittest.main()
