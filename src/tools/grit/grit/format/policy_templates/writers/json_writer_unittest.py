#!/usr/bin/env python
# Copyright (c) 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

'''Unit tests for grit.format.policy_templates.writers.json_writer'''


import os
import sys
if __name__ == '__main__':
  sys.path.append(os.path.join(os.path.dirname(__file__), '../../../..'))

import unittest

from grit.format.policy_templates.writers import writer_unittest_common


TEMPLATE_HEADER="""\
// Policy template for Linux.
// Uncomment the policies you wish to activate and change their values to
// something useful for your case. The provided values are for reference only
// and do not provide meaningful defaults!
{
"""

TEMPLATE_HEADER_WITH_VERSION="""\
// chromium version: 39.0.0.0
// Policy template for Linux.
// Uncomment the policies you wish to activate and change their values to
// something useful for your case. The provided values are for reference only
// and do not provide meaningful defaults!
{
"""


HEADER_DELIMETER="""\
  //-------------------------------------------------------------------------
"""


class JsonWriterUnittest(writer_unittest_common.WriterUnittestCommon):
  '''Unit tests for JsonWriter.'''

  def CompareOutputs(self, output, expected_output):
    '''Compares the output of the json_writer with its expected output.

    Args:
      output: The output of the json writer as returned by grit.
      expected_output: The expected output.

    Raises:
      AssertionError: if the two strings are not equivalent.
    '''
    self.assertEquals(
        output.strip(),
        expected_output.strip())

  def testEmpty(self):
    # Test the handling of an empty policy list.
    grd = self.PrepareTest(
        '{'
        '  "policy_definitions": [],'
        '  "placeholders": [],'
        '  "messages": {},'
        '}')
    output = self.GetOutput(grd, 'fr', {'_chromium': '1'}, 'json', 'en')
    expected_output = TEMPLATE_HEADER + '}'
    self.CompareOutputs(output, expected_output)

  def testEmptyWithVersion(self):
    # Test the handling of an empty policy list.
    grd = self.PrepareTest(
        '{'
        '  "policy_definitions": [],'
        '  "placeholders": [],'
        '  "messages": {},'
        '}')
    output = self.GetOutput(
        grd, 'fr', {'_chromium': '1', 'version':'39.0.0.0'}, 'json', 'en')
    expected_output = TEMPLATE_HEADER_WITH_VERSION + '}'
    self.CompareOutputs(output, expected_output)

  def testMainPolicy(self):
    # Tests a policy group with a single policy of type 'main'.
    grd = self.PrepareTest(
        '{'
        '  "policy_definitions": ['
        '    {'
        '      "name": "MainPolicy",'
        '      "type": "main",'
        '      "caption": "Example Main Policy",'
        '      "desc": "Example Main Policy",'
        '      "supported_on": ["chrome.linux:8-"],'
        '      "example_value": True'
        '    },'
        '  ],'
        '  "placeholders": [],'
        '  "messages": {},'
        '}')
    output = self.GetOutput(grd, 'fr', {'_google_chrome' : '1'}, 'json', 'en')
    expected_output = (
        TEMPLATE_HEADER +
        '  // Example Main Policy\n' +
        HEADER_DELIMETER +
        '  // Example Main Policy\n\n'
        '  //"MainPolicy": true\n\n'
        '}')
    self.CompareOutputs(output, expected_output)

  def testRecommendedOnlyPolicy(self):
    # Tests a policy group with a single policy of type 'main'.
    grd = self.PrepareTest(
        '{'
        '  "policy_definitions": ['
        '    {'
        '      "name": "MainPolicy",'
        '      "type": "main",'
        '      "caption": "Example Main Policy",'
        '      "desc": "Example Main Policy",'
        '      "features": {'
        '        "can_be_recommended": True,'
        '        "can_be_mandatory": False'
        '      },'
        '      "supported_on": ["chrome.linux:8-"],'
        '      "example_value": True'
        '    },'
        '  ],'
        '  "placeholders": [],'
        '  "messages": {},'
        '}')
    output = self.GetOutput(grd, 'fr', {'_google_chrome' : '1'}, 'json', 'en')
    expected_output = (
        TEMPLATE_HEADER +
        '  // Note: this policy is supported only in recommended mode.\n' +
        '  // The JSON file should be placed in' +
        ' /etc/opt/chrome/policies/recommended.\n' +
        '  // Example Main Policy\n' +
        HEADER_DELIMETER +
        '  // Example Main Policy\n\n'
        '  //"MainPolicy": true\n\n'
        '}')
    self.CompareOutputs(output, expected_output)

  def testStringPolicy(self):
    # Tests a policy group with a single policy of type 'string'.
    grd = self.PrepareTest(
        '{'
        '  "policy_definitions": ['
        '    {'
        '      "name": "StringPolicy",'
        '      "type": "string",'
        '      "caption": "Example String Policy",'
        '      "desc": "Example String Policy",'
        '      "supported_on": ["chrome.linux:8-"],'
        '      "example_value": "hello, world!"'
        '    },'
        '  ],'
        '  "placeholders": [],'
        '  "messages": {},'
        '}')
    output = self.GetOutput(grd, 'fr', {'_chromium' : '1'}, 'json', 'en')
    expected_output = (
        TEMPLATE_HEADER +
        '  // Example String Policy\n' +
        HEADER_DELIMETER +
        '  // Example String Policy\n\n'
        '  //"StringPolicy": "hello, world!"\n\n'
        '}')
    self.CompareOutputs(output, expected_output)

  def testIntPolicy(self):
    # Tests a policy group with a single policy of type 'string'.
    grd = self.PrepareTest(
        '{'
        '  "policy_definitions": ['
        '    {'
        '      "name": "IntPolicy",'
        '      "type": "int",'
        '      "caption": "Example Int Policy",'
        '      "desc": "Example Int Policy",'
        '      "supported_on": ["chrome.linux:8-"],'
        '      "example_value": 15'
        '    },'
        '  ],'
        '  "placeholders": [],'
        '  "messages": {},'
        '}')
    output = self.GetOutput(grd, 'fr', {'_chromium' : '1'}, 'json', 'en')
    expected_output = (
        TEMPLATE_HEADER +
        '  // Example Int Policy\n' +
        HEADER_DELIMETER +
        '  // Example Int Policy\n\n'
        '  //"IntPolicy": 15\n\n'
        '}')
    self.CompareOutputs(output, expected_output)

  def testIntEnumPolicy(self):
    # Tests a policy group with a single policy of type 'int-enum'.
    grd = self.PrepareTest(
        '{'
        '  "policy_definitions": ['
        '    {'
        '      "name": "EnumPolicy",'
        '      "type": "int-enum",'
        '      "caption": "Example Int Enum",'
        '      "desc": "Example Int Enum",'
        '      "items": ['
        '        {"name": "ProxyServerDisabled", "value": 0, "caption": ""},'
        '        {"name": "ProxyServerAutoDetect", "value": 1, "caption": ""},'
        '      ],'
        '      "supported_on": ["chrome.linux:8-"],'
        '      "example_value": 1'
        '    },'
        '  ],'
        '  "placeholders": [],'
        '  "messages": {},'
        '}')
    output = self.GetOutput(grd, 'fr', {'_google_chrome': '1'}, 'json', 'en')
    expected_output = (
        TEMPLATE_HEADER +
        '  // Example Int Enum\n' +
        HEADER_DELIMETER +
        '  // Example Int Enum\n\n'
        '  //"EnumPolicy": 1\n\n'
        '}')
    self.CompareOutputs(output, expected_output)

  def testStringEnumPolicy(self):
    # Tests a policy group with a single policy of type 'string-enum'.
    grd = self.PrepareTest(
        '{'
        '  "policy_definitions": ['
        '    {'
        '      "name": "EnumPolicy",'
        '      "type": "string-enum",'
        '      "caption": "Example String Enum",'
        '      "desc": "Example String Enum",'
        '      "items": ['
        '        {"name": "ProxyServerDisabled", "value": "one",'
        '         "caption": ""},'
        '        {"name": "ProxyServerAutoDetect", "value": "two",'
        '         "caption": ""},'
        '      ],'
        '      "supported_on": ["chrome.linux:8-"],'
        '      "example_value": "one"'
        '    },'
        '  ],'
        '  "placeholders": [],'
        '  "messages": {},'
        '}')
    output = self.GetOutput(grd, 'fr', {'_google_chrome': '1'}, 'json', 'en')
    expected_output = (
        TEMPLATE_HEADER +
        '  // Example String Enum\n' +
        HEADER_DELIMETER +
        '  // Example String Enum\n\n'
        '  //"EnumPolicy": "one"\n\n'
        '}')
    self.CompareOutputs(output, expected_output)

  def testListPolicy(self):
    # Tests a policy group with a single policy of type 'list'.
    grd = self.PrepareTest(
        '{'
        '  "policy_definitions": ['
        '    {'
        '      "name": "ListPolicy",'
        '      "type": "list",'
        '      "caption": "Example List",'
        '      "desc": "Example List",'
        '      "supported_on": ["chrome.linux:8-"],'
        '      "example_value": ["foo", "bar"]'
        '    },'
        '  ],'
        '  "placeholders": [],'
        '  "messages": {},'
        '}')
    output = self.GetOutput(grd, 'fr', {'_chromium' : '1'}, 'json', 'en')
    expected_output = (
        TEMPLATE_HEADER +
        '  // Example List\n' +
        HEADER_DELIMETER +
        '  // Example List\n\n'
        '  //"ListPolicy": ["foo", "bar"]\n\n'
        '}')
    self.CompareOutputs(output, expected_output)

  def testStringEnumListPolicy(self):
    # Tests a policy group with a single policy of type 'string-enum-list'.
    grd = self.PrepareTest(
        '{'
        '  "policy_definitions": ['
        '    {'
        '      "name": "ListPolicy",'
        '      "type": "string-enum-list",'
        '      "caption": "Example List",'
        '      "desc": "Example List",'
        '      "items": ['
        '        {"name": "ProxyServerDisabled", "value": "one",'
        '         "caption": ""},'
        '        {"name": "ProxyServerAutoDetect", "value": "two",'
        '         "caption": ""},'
        '      ],'
        '      "supported_on": ["chrome.linux:8-"],'
        '      "example_value": ["one", "two"]'
        '    },'
        '  ],'
        '  "placeholders": [],'
        '  "messages": {},'
        '}')
    output = self.GetOutput(grd, 'fr', {'_chromium' : '1'}, 'json', 'en')
    expected_output = (
        TEMPLATE_HEADER +
        '  // Example List\n' +
        HEADER_DELIMETER +
        '  // Example List\n\n'
        '  //"ListPolicy": ["one", "two"]\n\n'
        '}')
    self.CompareOutputs(output, expected_output)

  def testDictionaryPolicy(self):
    # Tests a policy group with a single policy of type 'dict'.
    example = {
      'bool': True,
      'dict': {
        'a': 1,
        'b': 2,
      },
      'int': 10,
      'list': [1, 2, 3],
      'string': 'abc',
    }
    grd = self.PrepareTest(
        '{'
        '  "policy_definitions": ['
        '    {'
        '      "name": "DictionaryPolicy",'
        '      "type": "dict",'
        '      "caption": "Example Dictionary Policy",'
        '      "desc": "Example Dictionary Policy",'
        '      "supported_on": ["chrome.linux:8-"],'
        '      "example_value": ' + str(example) +
        '    },'
        '  ],'
        '  "placeholders": [],'
        '  "messages": {},'
        '}')
    output = self.GetOutput(grd, 'fr', {'_chromium' : '1'}, 'json', 'en')
    expected_output = (
        TEMPLATE_HEADER +
        '  // Example Dictionary Policy\n' +
        HEADER_DELIMETER +
        '  // Example Dictionary Policy\n\n'
        '  //"DictionaryPolicy": {"bool": true, "dict": {"a": 1, '
        '"b": 2}, "int": 10, "list": [1, 2, 3], "string": "abc"}\n\n'
        '}')
    self.CompareOutputs(output, expected_output)

  def testNonSupportedPolicy(self):
    # Tests a policy that is not supported on Linux, so it shouldn't
    # be included in the JSON file.
    grd = self.PrepareTest(
        '{'
        '  "policy_definitions": ['
        '    {'
        '      "name": "NonLinuxPolicy",'
        '      "type": "list",'
        '      "caption": "",'
        '      "desc": "",'
        '      "supported_on": ["chrome.mac:8-"],'
        '      "example_value": ["a"]'
        '    },'
        '  ],'
        '  "placeholders": [],'
        '  "messages": {},'
        '}')
    output = self.GetOutput(grd, 'fr', {'_chromium' : '1'}, 'json', 'en')
    expected_output = TEMPLATE_HEADER + '}'
    self.CompareOutputs(output, expected_output)

  def testPolicyGroup(self):
    # Tests a policy group that has more than one policies.
    grd = self.PrepareTest(
        '{'
        '  "policy_definitions": ['
        '    {'
        '      "name": "Group1",'
        '      "type": "group",'
        '      "caption": "",'
        '      "desc": "",'
        '      "policies": [{'
        '        "name": "Policy1",'
        '        "type": "list",'
        '        "caption": "Policy One",'
        '        "desc": "Policy One",'
        '        "supported_on": ["chrome.linux:8-"],'
        '        "example_value": ["a", "b"]'
        '      },{'
        '        "name": "Policy2",'
        '        "type": "string",'
        '        "caption": "Policy Two",'
        '        "desc": "Policy Two",'
        '        "supported_on": ["chrome.linux:8-"],'
        '        "example_value": "c"'
        '      }],'
        '    },'
        '  ],'
        '  "placeholders": [],'
        '  "messages": {},'
        '}')
    output = self.GetOutput(grd, 'fr', {'_chromium' : '1'}, 'json', 'en')
    expected_output = (
        TEMPLATE_HEADER +
        '  // Policy One\n' +
        HEADER_DELIMETER +
        '  // Policy One\n\n'
        '  //"Policy1": ["a", "b"],\n\n'
        '  // Policy Two\n' +
        HEADER_DELIMETER +
        '  // Policy Two\n\n'
        '  //"Policy2": "c"\n\n'
        '}')
    self.CompareOutputs(output, expected_output)


if __name__ == '__main__':
  unittest.main()
