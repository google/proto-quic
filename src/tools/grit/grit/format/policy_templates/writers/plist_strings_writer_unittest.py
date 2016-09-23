#!/usr/bin/env python
# Copyright (c) 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

'''Unit tests for grit.format.policy_templates.writers.plist_strings_writer'''


import os
import sys
if __name__ == '__main__':
  sys.path.append(os.path.join(os.path.dirname(__file__), '../../../..'))

import unittest

from grit.format.policy_templates.writers import writer_unittest_common


class PListStringsWriterUnittest(writer_unittest_common.WriterUnittestCommon):
  '''Unit tests for PListStringsWriter.'''

  def testEmpty(self):
    # Test PListStringsWriter in case of empty polices.
    grd = self.PrepareTest('''
      {
        'policy_definitions': [],
        'placeholders': [],
        'messages': {
          'mac_chrome_preferences': {
            'text': '$1 preferen"ces',
            'desc': 'blah'
          }
        }
      }''')
    output = self.GetOutput(
        grd,
        'fr',
        {'_chromium': '1', 'mac_bundle_id': 'com.example.Test'},
        'plist_strings',
        'en')
    expected_output = (
        'Chromium.pfm_title = "Chromium";\n'
        'Chromium.pfm_description = "Chromium preferen\\"ces";')
    self.assertEquals(output.strip(), expected_output.strip())

  def testEmptyVersion(self):
    # Test PListStringsWriter in case of empty polices.
    grd = self.PrepareTest('''
      {
        'policy_definitions': [],
        'placeholders': [],
        'messages': {
          'mac_chrome_preferences': {
            'text': '$1 preferen"ces',
            'desc': 'blah'
          }
        }
      }''')
    output = self.GetOutput(
        grd,
        'fr',
        {'_chromium': '1',
         'mac_bundle_id': 'com.example.Test',
         'version': '39.0.0.0'},
        'plist_strings',
        'en')
    expected_output = (
        '/* chromium version: 39.0.0.0 */\n'
        'Chromium.pfm_title = "Chromium";\n'
        'Chromium.pfm_description = "Chromium preferen\\"ces";')
    self.assertEquals(output.strip(), expected_output.strip())

  def testMainPolicy(self):
    # Tests a policy group with a single policy of type 'main'.
    grd = self.PrepareTest('''
      {
        'policy_definitions': [
          {
            'name': 'MainGroup',
            'type': 'group',
            'caption': 'Caption of main.',
            'desc': 'Description of main.',
            'policies': [{
              'name': 'MainPolicy',
              'type': 'main',
              'supported_on': ['chrome.mac:8-'],
              'caption': 'Caption of main policy.',
              'desc': 'Description of main policy.',
            }],
          },
        ],
        'placeholders': [],
        'messages': {
          'mac_chrome_preferences': {
            'text': 'Preferences of $1',
            'desc': 'blah'
          }
        }
      }''')
    output = self.GetOutput(
        grd,
        'fr',
        {'_google_chrome' : '1', 'mac_bundle_id': 'com.example.Test'},
        'plist_strings',
        'en')
    expected_output = (
        'Google_Chrome.pfm_title = "Google Chrome";\n'
        'Google_Chrome.pfm_description = "Preferences of Google Chrome";\n'
        'MainPolicy.pfm_title = "Caption of main policy.";\n'
        'MainPolicy.pfm_description = "Description of main policy.";')
    self.assertEquals(output.strip(), expected_output.strip())

  def testStringPolicy(self):
    # Tests a policy group with a single policy of type 'string'. Also test
    # inheriting group description to policy description.
    grd = self.PrepareTest('''
      {
        'policy_definitions': [
          {
            'name': 'StringGroup',
            'type': 'group',
            'caption': 'Caption of group.',
            'desc': """Description of group.
With a newline.""",
            'policies': [{
              'name': 'StringPolicy',
              'type': 'string',
              'caption': 'Caption of policy.',
              'desc': """Description of policy.
With a newline.""",
              'supported_on': ['chrome.mac:8-'],
            }],
          },
        ],
        'placeholders': [],
        'messages': {
          'mac_chrome_preferences': {
            'text': 'Preferences of $1',
            'desc': 'blah'
          }
        }
      }''')
    output = self.GetOutput(
        grd,
        'fr',
        {'_chromium' : '1', 'mac_bundle_id': 'com.example.Test'},
        'plist_strings',
        'en')
    expected_output = (
        'Chromium.pfm_title = "Chromium";\n'
        'Chromium.pfm_description = "Preferences of Chromium";\n'
        'StringPolicy.pfm_title = "Caption of policy.";\n'
        'StringPolicy.pfm_description = '
            '"Description of policy.\\nWith a newline.";')
    self.assertEquals(output.strip(), expected_output.strip())

  def testStringListPolicy(self):
    # Tests a policy group with a single policy of type 'list'.
    grd = self.PrepareTest('''
      {
        'policy_definitions': [
          {
            'name': 'ListGroup',
            'type': 'group',
            'caption': '',
            'desc': '',
            'policies': [{
              'name': 'ListPolicy',
              'type': 'list',
              'caption': 'Caption of policy.',
              'desc': """Description of policy.
With a newline.""",
              'schema': {
                  'type': 'array',
                  'items': { 'type': 'string' },
              },
              'supported_on': ['chrome.mac:8-'],
            }],
          },
        ],
        'placeholders': [],
        'messages': {
          'mac_chrome_preferences': {
            'text': 'Preferences of $1',
            'desc': 'blah'
          }
        }
      }''')
    output = self.GetOutput(
        grd,
        'fr',
        {'_chromium' : '1', 'mac_bundle_id': 'com.example.Test'},
        'plist_strings',
        'en')
    expected_output = (
        'Chromium.pfm_title = "Chromium";\n'
        'Chromium.pfm_description = "Preferences of Chromium";\n'
        'ListPolicy.pfm_title = "Caption of policy.";\n'
        'ListPolicy.pfm_description = '
            '"Description of policy.\\nWith a newline.";')
    self.assertEquals(output.strip(), expected_output.strip())

  def testStringEnumListPolicy(self):
    # Tests a policy group with a single policy of type 'string-enum-list'.
    grd = self.PrepareTest('''
      {
        'policy_definitions': [
          {
            'name': 'EnumGroup',
            'type': 'group',
            'caption': '',
            'desc': '',
            'policies': [{
              'name': 'EnumPolicy',
              'type': 'string-enum-list',
              'caption': 'Caption of policy.',
              'desc': """Description of policy.
With a newline.""",
              'schema': {
                  'type': 'array',
                  'items': { 'type': 'string' },
              },
              'items': [
                {
                  'name': 'ProxyServerDisabled',
                  'value': 'one',
                  'caption': 'Option1'
                },
                {
                  'name': 'ProxyServerAutoDetect',
                  'value': 'two',
                  'caption': 'Option2'
                },
              ],
              'supported_on': ['chrome.mac:8-'],
            }],
          },
        ],
        'placeholders': [],
        'messages': {
          'mac_chrome_preferences': {
            'text': 'Preferences of $1',
            'desc': 'blah'
          }
        }
      }''')
    output = self.GetOutput(
        grd,
        'fr',
        {'_chromium' : '1', 'mac_bundle_id': 'com.example.Test'},
        'plist_strings',
        'en')
    expected_output = (
        'Chromium.pfm_title = "Chromium";\n'
        'Chromium.pfm_description = "Preferences of Chromium";\n'
        'EnumPolicy.pfm_title = "Caption of policy.";\n'
        'EnumPolicy.pfm_description = '
            '"one - Option1\\ntwo - Option2\\n'
            'Description of policy.\\nWith a newline.";')
    self.assertEquals(output.strip(), expected_output.strip())

  def testIntEnumPolicy(self):
    # Tests a policy group with a single policy of type 'int-enum'.
    grd = self.PrepareTest('''
      {
        'policy_definitions': [
          {
            'name': 'EnumGroup',
            'type': 'group',
            'desc': '',
            'caption': '',
            'policies': [{
              'name': 'EnumPolicy',
              'type': 'int-enum',
              'desc': 'Description of policy.',
              'caption': 'Caption of policy.',
              'items': [
                {
                  'name': 'ProxyServerDisabled',
                  'value': 0,
                  'caption': 'Option1'
                },
                {
                  'name': 'ProxyServerAutoDetect',
                  'value': 1,
                  'caption': 'Option2'
                },
              ],
              'supported_on': ['chrome.mac:8-'],
            }],
          },
        ],
        'placeholders': [],
        'messages': {
          'mac_chrome_preferences': {
            'text': '$1 preferences',
            'desc': 'blah'
          }
        }
      }''')
    output = self.GetOutput(
        grd,
        'fr',
        {'_google_chrome': '1', 'mac_bundle_id': 'com.example.Test2'},
        'plist_strings',
        'en')
    expected_output = (
        'Google_Chrome.pfm_title = "Google Chrome";\n'
        'Google_Chrome.pfm_description = "Google Chrome preferences";\n'
        'EnumPolicy.pfm_title = "Caption of policy.";\n'
        'EnumPolicy.pfm_description = '
            '"0 - Option1\\n1 - Option2\\nDescription of policy.";\n')

    self.assertEquals(output.strip(), expected_output.strip())

  def testStringEnumPolicy(self):
    # Tests a policy group with a single policy of type 'string-enum'.
    grd = self.PrepareTest('''
      {
        'policy_definitions': [
          {
            'name': 'EnumGroup',
            'type': 'group',
            'desc': '',
            'caption': '',
            'policies': [{
              'name': 'EnumPolicy',
              'type': 'string-enum',
              'desc': 'Description of policy.',
              'caption': 'Caption of policy.',
              'items': [
                {
                  'name': 'ProxyServerDisabled',
                  'value': 'one',
                  'caption': 'Option1'
                },
                {
                  'name': 'ProxyServerAutoDetect',
                  'value': 'two',
                  'caption': 'Option2'
                },
              ],
              'supported_on': ['chrome.mac:8-'],
            }],
          },
        ],
        'placeholders': [],
        'messages': {
          'mac_chrome_preferences': {
            'text': '$1 preferences',
            'desc': 'blah'
          }
        }
      }''')
    output = self.GetOutput(
        grd,
        'fr',
        {'_google_chrome': '1', 'mac_bundle_id': 'com.example.Test2'},
        'plist_strings',
        'en')
    expected_output = (
        'Google_Chrome.pfm_title = "Google Chrome";\n'
        'Google_Chrome.pfm_description = "Google Chrome preferences";\n'
        'EnumPolicy.pfm_title = "Caption of policy.";\n'
        'EnumPolicy.pfm_description = '
            '"one - Option1\\ntwo - Option2\\nDescription of policy.";\n')

    self.assertEquals(output.strip(), expected_output.strip())

  def testNonSupportedPolicy(self):
    # Tests a policy that is not supported on Mac, so its strings shouldn't
    # be included in the plist string table.
    grd = self.PrepareTest('''
      {
        'policy_definitions': [
          {
            'name': 'NonMacGroup',
            'type': 'group',
            'caption': '',
            'desc': '',
            'policies': [{
              'name': 'NonMacPolicy',
              'type': 'string',
              'caption': '',
              'desc': '',
              'supported_on': ['chrome_os:8-'],
            }],
          },
        ],
        'placeholders': [],
        'messages': {
          'mac_chrome_preferences': {
            'text': '$1 preferences',
            'desc': 'blah'
          }
        }
      }''')
    output = self.GetOutput(
        grd,
        'fr',
        {'_google_chrome': '1', 'mac_bundle_id': 'com.example.Test2'},
        'plist_strings',
        'en')
    expected_output = (
        'Google_Chrome.pfm_title = "Google Chrome";\n'
        'Google_Chrome.pfm_description = "Google Chrome preferences";')
    self.assertEquals(output.strip(), expected_output.strip())


if __name__ == '__main__':
  unittest.main()
