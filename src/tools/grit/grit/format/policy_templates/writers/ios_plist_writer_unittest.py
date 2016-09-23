#!/usr/bin/env python
# Copyright (c) 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

'''Unit tests for grit.format.policy_templates.writers.ios_plist_writer'''


import base64
import functools
import os
import plistlib
import sys
if __name__ == '__main__':
  sys.path.append(os.path.join(os.path.dirname(__file__), '../../../..'))

import unittest

try:
  import Cocoa
except:
  Cocoa = None

from grit.format.policy_templates.writers import writer_unittest_common


class IOSPListWriterUnittest(writer_unittest_common.WriterUnittestCommon):
  '''Unit tests for IOSPListWriter.'''

  def _ParseWithPython(self, decode, text):
    '''Parses a serialized Plist, using Python's plistlib.

    If |decode| is true then |text| is decoded as Base64 before being
    deserialized as a Plist.'''
    if decode:
      text = base64.b64decode(text)
    return plistlib.readPlistFromString(text)

  def _ParseWithCocoa(self, decode, text):
    '''Parses a serialized Plist, using Cocoa's python bindings.

    If |decode| is true then |text| is decoded as Base64 before being
    deserialized as a Plist.'''
    if decode:
      data = Cocoa.NSData.alloc().initWithBase64EncodedString_options_(text, 0)
    else:
      data = Cocoa.NSData.alloc().initWithBytes_length_(text, len(text))
    result = Cocoa.NSPropertyListSerialization. \
        propertyListFromData_mutabilityOption_format_errorDescription_(
            data, Cocoa.NSPropertyListImmutable, None, None)
    return result[0]

  def _VerifyGeneratedOutputWithParsers(self,
                                        templates,
                                        expected_output,
                                        parse,
                                        decode_and_parse):


    _defines = { '_chromium': '1',
                 'mac_bundle_id': 'com.example.Test',
                 'version': '39.0.0.0' }

    # Generate the grit output for |templates|.
    output = self.GetOutput(
        self.PrepareTest(templates),
        'fr',
        _defines,
        'ios_plist',
        'en')

    # Parse it as a Plist.
    plist = parse(output)
    self.assertEquals(len(plist), 2)
    self.assertTrue('ChromePolicy' in plist)
    self.assertTrue('EncodedChromePolicy' in plist)

    # Get the 2 expected fields.
    chrome_policy = plist['ChromePolicy']
    encoded_chrome_policy = plist['EncodedChromePolicy']

    # Verify the ChromePolicy.
    self.assertEquals(chrome_policy, expected_output)

    # Decode the EncodedChromePolicy and verify it.
    decoded_chrome_policy = decode_and_parse(encoded_chrome_policy)
    self.assertEquals(decoded_chrome_policy, expected_output)

  def _VerifyGeneratedOutput(self, templates, expected):
    # plistlib is available on all Python platforms.
    parse = functools.partial(self._ParseWithPython, False)
    decode_and_parse = functools.partial(self._ParseWithPython, True)
    self._VerifyGeneratedOutputWithParsers(
        templates, expected, parse, decode_and_parse)

    # The Cocoa bindings are available on Mac OS X only.
    if Cocoa:
      parse = functools.partial(self._ParseWithCocoa, False)
      decode_and_parse = functools.partial(self._ParseWithCocoa, True)
      self._VerifyGeneratedOutputWithParsers(
          templates, expected, parse, decode_and_parse)

  def _MakeTemplate(self, name, type, example, extra=''):
    return '''
    {
      'policy_definitions': [
        {
          'name': '%s',
          'type': '%s',
          'desc': '',
          'caption': '',
          'supported_on': ['ios:35-'],
          'example_value': %s,
          %s
        },
      ],
      'placeholders': [],
      'messages': {},
    }
    ''' % (name, type, example, extra)

  def testEmpty(self):
    templates = '''
    {
      'policy_definitions': [],
      'placeholders': [],
      'messages': {},
    }
    '''
    expected = {}
    self._VerifyGeneratedOutput(templates, expected)

  def testEmptyVersion(self):
    templates = '''
    {
      'policy_definitions': [],
      'placeholders': [],
      'messages': {},
    }
    '''
    expected = {}
    self._VerifyGeneratedOutput(templates, expected)

  def testBoolean(self):
    templates = self._MakeTemplate('BooleanPolicy', 'main', 'True')
    expected = {
      'BooleanPolicy': True,
    }
    self._VerifyGeneratedOutput(templates, expected)

  def testString(self):
    templates = self._MakeTemplate('StringPolicy', 'string', '"Foo"')
    expected = {
      'StringPolicy': 'Foo',
    }
    self._VerifyGeneratedOutput(templates, expected)

  def testStringEnum(self):
    templates = self._MakeTemplate(
        'StringEnumPolicy', 'string-enum', '"Foo"',
        '''
          'items': [
            { 'name': 'Foo', 'value': 'Foo', 'caption': '' },
            { 'name': 'Bar', 'value': 'Bar', 'caption': '' },
          ],
        ''')
    expected = {
      'StringEnumPolicy': 'Foo',
    }
    self._VerifyGeneratedOutput(templates, expected)

  def testInt(self):
    templates = self._MakeTemplate('IntPolicy', 'int', '42')
    expected = {
      'IntPolicy': 42,
    }
    self._VerifyGeneratedOutput(templates, expected)

  def testIntEnum(self):
    templates = self._MakeTemplate(
        'IntEnumPolicy', 'int-enum', '42',
        '''
          'items': [
            { 'name': 'Foo', 'value': 100, 'caption': '' },
            { 'name': 'Bar', 'value': 42, 'caption': '' },
          ],
        ''')
    expected = {
      'IntEnumPolicy': 42,
    }
    self._VerifyGeneratedOutput(templates, expected)

  def testStringList(self):
    templates = self._MakeTemplate('StringListPolicy', 'list', '["a", "b"]')
    expected = {
      'StringListPolicy': [ "a", "b" ],
    }
    self._VerifyGeneratedOutput(templates, expected)

  def testStringEnumList(self):
    templates = self._MakeTemplate('StringEnumListPolicy',
                                   'string-enum-list', '["a", "b"]',
        '''
          'items': [
            { 'name': 'Foo', 'value': 'a', 'caption': '' },
            { 'name': 'Bar', 'value': 'b', 'caption': '' },
          ],
        ''')

    expected = {
      'StringEnumListPolicy': [ "a", "b" ],
    }
    self._VerifyGeneratedOutput(templates, expected)

  def testListOfDictionary(self):
    templates = self._MakeTemplate(
        'ManagedBookmarks', 'dict',
        '''
        [
          {
            "name": "Google Search",
            "url": "www.google.com",
          },
          {
            "name": "Youtube",
            "url": "www.youtube.com",
          }
        ]
        ''')
    expected = {
      'ManagedBookmarks': [
        { "name": "Google Search", "url": "www.google.com" },
        { "name": "Youtube", "url": "www.youtube.com" },
      ],
    }
    self._VerifyGeneratedOutput(templates, expected)


if __name__ == '__main__':
  unittest.main()
