#!/usr/bin/env python
# Copyright (c) 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

'''Unit tests for grit.format.policy_templates.writers.adm_writer'''


import os
import sys
if __name__ == '__main__':
  sys.path.append(os.path.join(os.path.dirname(__file__), '../../../..'))

import unittest

from grit.format.policy_templates.writers import writer_unittest_common


class AdmWriterUnittest(writer_unittest_common.WriterUnittestCommon):
  '''Unit tests for AdmWriter.'''

  def ConstructOutput(self, classes, body, strings):
    result = []
    for clazz in classes:
      result.append('CLASS ' + clazz)
      result.append(body)
    result.append(strings)
    return ''.join(result)

  def CompareOutputs(self, output, expected_output):
    '''Compares the output of the adm_writer with its expected output.

    Args:
      output: The output of the adm writer as returned by grit.
      expected_output: The expected output.

    Raises:
      AssertionError: if the two strings are not equivalent.
    '''
    self.assertEquals(
        output.strip(),
        expected_output.strip().replace('\n', '\r\n'))

  def testEmpty(self):
    # Test PListWriter in case of empty polices.
    grd = self.PrepareTest('''
      {
        'policy_definitions': [],
        'placeholders': [],
        'messages': {
          'win_supported_winxpsp2': {
            'text': 'At least "Windows 3.11', 'desc': 'blah'
          },
          'doc_recommended': {
            'text': 'Recommended', 'desc': 'bleh'
          }
        }
      }''')
    output = self.GetOutput(grd, 'fr', {'_chromium': '1',}, 'adm', 'en')
    expected_output = self.ConstructOutput(
        ['MACHINE', 'USER'], '''
  CATEGORY !!chromium
    KEYNAME "Software\\Policies\\Chromium"

  END CATEGORY

  CATEGORY !!chromium_recommended
    KEYNAME "Software\\Policies\\Chromium\\Recommended"

  END CATEGORY


''', '''[Strings]
SUPPORTED_WINXPSP2="At least "Windows 3.11"
chromium="Chromium"
chromium_recommended="Chromium - Recommended"''')
    self.CompareOutputs(output, expected_output)

  def testVersionAnnotation(self):
    # Test PListWriter in case of empty polices.
    grd = self.PrepareTest('''
      {
        'policy_definitions': [],
        'placeholders': [],
        'messages': {
          'win_supported_winxpsp2': {
            'text': 'At least "Windows 3.11', 'desc': 'blah'
          },
          'doc_recommended': {
            'text': 'Recommended', 'desc': 'bleh'
          }
        }
      }''')
    output = self.GetOutput(
        grd, 'fr', {'_chromium': '1', 'version':'39.0.0.0'}, 'adm', 'en')
    expected_output = '; chromium version: 39.0.0.0\n' + \
        self.ConstructOutput(['MACHINE', 'USER'], '''
  CATEGORY !!chromium
    KEYNAME "Software\\Policies\\Chromium"

  END CATEGORY

  CATEGORY !!chromium_recommended
    KEYNAME "Software\\Policies\\Chromium\\Recommended"

  END CATEGORY


''', '''[Strings]
SUPPORTED_WINXPSP2="At least "Windows 3.11"
chromium="Chromium"
chromium_recommended="Chromium - Recommended"''')
    self.CompareOutputs(output, expected_output)

  def testMainPolicy(self):
    # Tests a policy group with a single policy of type 'main'.
    grd = self.PrepareTest('''
      {
        'policy_definitions': [
          {
            'name': 'MainPolicy',
            'type': 'main',
            'supported_on': ['chrome.win:8-'],
            'features': { 'can_be_recommended': True },
            'caption': 'Caption of main.',
            'desc': 'Description of main.',
          },
        ],
        'placeholders': [],
        'messages': {
          'win_supported_winxpsp2': {
            'text': 'At least Windows 3.12', 'desc': 'blah'
          },
          'doc_recommended': {
            'text': 'Recommended', 'desc': 'bleh'
          }
        }
      }''')
    output = self.GetOutput(grd, 'fr', {'_google_chrome' : '1'}, 'adm', 'en')
    expected_output = self.ConstructOutput(
        ['MACHINE', 'USER'], '''
  CATEGORY !!google
    CATEGORY !!googlechrome
      KEYNAME "Software\\Policies\\Google\\Chrome"

      POLICY !!MainPolicy_Policy
        #if version >= 4
          SUPPORTED !!SUPPORTED_WINXPSP2
        #endif
        EXPLAIN !!MainPolicy_Explain
        VALUENAME "MainPolicy"
        VALUEON NUMERIC 1
        VALUEOFF NUMERIC 0
      END POLICY

    END CATEGORY
  END CATEGORY

  CATEGORY !!google
    CATEGORY !!googlechrome_recommended
      KEYNAME "Software\\Policies\\Google\\Chrome\\Recommended"

      POLICY !!MainPolicy_Policy
        #if version >= 4
          SUPPORTED !!SUPPORTED_WINXPSP2
        #endif
        EXPLAIN !!MainPolicy_Explain
        VALUENAME "MainPolicy"
        VALUEON NUMERIC 1
        VALUEOFF NUMERIC 0
      END POLICY

    END CATEGORY
  END CATEGORY


''', '''[Strings]
SUPPORTED_WINXPSP2="At least Windows 3.12"
google="Google"
googlechrome="Google Chrome"
googlechrome_recommended="Google Chrome - Recommended"
MainPolicy_Policy="Caption of main."
MainPolicy_Explain="Description of main."''')
    self.CompareOutputs(output, expected_output)

  def testMainPolicyRecommendedOnly(self):
    # Tests a policy group with a single policy of type 'main'.
    grd = self.PrepareTest('''
      {
        'policy_definitions': [
          {
            'name': 'MainPolicy',
            'type': 'main',
            'supported_on': ['chrome.win:8-'],
            'features': {
              'can_be_recommended': True,
              'can_be_mandatory': False
            },
            'caption': 'Caption of main.',
            'desc': 'Description of main.',
          },
        ],
        'placeholders': [],
        'messages': {
          'win_supported_winxpsp2': {
            'text': 'At least Windows 3.12', 'desc': 'blah'
          },
          'doc_recommended': {
            'text': 'Recommended', 'desc': 'bleh'
          }
        }
      }''')
    output = self.GetOutput(grd, 'fr', {'_google_chrome' : '1'}, 'adm', 'en')
    expected_output = self.ConstructOutput(
        ['MACHINE', 'USER'], '''
  CATEGORY !!google
    CATEGORY !!googlechrome
      KEYNAME "Software\\Policies\\Google\\Chrome"

    END CATEGORY
  END CATEGORY

  CATEGORY !!google
    CATEGORY !!googlechrome_recommended
      KEYNAME "Software\\Policies\\Google\\Chrome\\Recommended"

      POLICY !!MainPolicy_Policy
        #if version >= 4
          SUPPORTED !!SUPPORTED_WINXPSP2
        #endif
        EXPLAIN !!MainPolicy_Explain
        VALUENAME "MainPolicy"
        VALUEON NUMERIC 1
        VALUEOFF NUMERIC 0
      END POLICY

    END CATEGORY
  END CATEGORY


''', '''[Strings]
SUPPORTED_WINXPSP2="At least Windows 3.12"
google="Google"
googlechrome="Google Chrome"
googlechrome_recommended="Google Chrome - Recommended"
MainPolicy_Policy="Caption of main."
MainPolicy_Explain="Description of main."''')
    self.CompareOutputs(output, expected_output)

  def testStringPolicy(self):
    # Tests a policy group with a single policy of type 'string'.
    grd = self.PrepareTest('''
      {
        'policy_definitions': [
          {
            'name': 'StringPolicy',
            'type': 'string',
            'supported_on': ['chrome.win:8-'],
            'features': { 'can_be_recommended': True },
            'desc': """Description of group.
With a newline.""",
            'caption': 'Caption of policy.',
          },
        ],
        'placeholders': [],
        'messages': {
          'win_supported_winxpsp2': {
            'text': 'At least Windows 3.13', 'desc': 'blah'
          },
          'doc_recommended': {
            'text': 'Recommended', 'desc': 'bleh'
          }
        }
      }''')
    output = self.GetOutput(grd, 'fr', {'_chromium' : '1'}, 'adm', 'en')
    expected_output = self.ConstructOutput(
        ['MACHINE', 'USER'], '''
  CATEGORY !!chromium
    KEYNAME "Software\\Policies\\Chromium"

    POLICY !!StringPolicy_Policy
      #if version >= 4
        SUPPORTED !!SUPPORTED_WINXPSP2
      #endif
      EXPLAIN !!StringPolicy_Explain

      PART !!StringPolicy_Part  EDITTEXT
        VALUENAME "StringPolicy"
        MAXLEN 1000000
      END PART
    END POLICY

  END CATEGORY

  CATEGORY !!chromium_recommended
    KEYNAME "Software\\Policies\\Chromium\\Recommended"

    POLICY !!StringPolicy_Policy
      #if version >= 4
        SUPPORTED !!SUPPORTED_WINXPSP2
      #endif
      EXPLAIN !!StringPolicy_Explain

      PART !!StringPolicy_Part  EDITTEXT
        VALUENAME "StringPolicy"
        MAXLEN 1000000
      END PART
    END POLICY

  END CATEGORY


''', '''[Strings]
SUPPORTED_WINXPSP2="At least Windows 3.13"
chromium="Chromium"
chromium_recommended="Chromium - Recommended"
StringPolicy_Policy="Caption of policy."
StringPolicy_Explain="Description of group.\\nWith a newline."
StringPolicy_Part="Caption of policy."
''')
    self.CompareOutputs(output, expected_output)

  def testIntPolicy(self):
    # Tests a policy group with a single policy of type 'string'.
    grd = self.PrepareTest('''
      {
        'policy_definitions': [
          {
            'name': 'IntPolicy',
            'type': 'int',
            'caption': 'Caption of policy.',
            'features': { 'can_be_recommended': True },
            'desc': 'Description of policy.',
            'supported_on': ['chrome.win:8-']
          },
        ],
        'placeholders': [],
        'messages': {
          'win_supported_winxpsp2': {
            'text': 'At least Windows 3.13', 'desc': 'blah'
          },
          'doc_recommended': {
            'text': 'Recommended', 'desc': 'bleh'
          }
        }
      }''')
    output = self.GetOutput(grd, 'fr', {'_chromium' : '1'}, 'adm', 'en')
    expected_output = self.ConstructOutput(
        ['MACHINE', 'USER'], '''
  CATEGORY !!chromium
    KEYNAME "Software\\Policies\\Chromium"

    POLICY !!IntPolicy_Policy
      #if version >= 4
        SUPPORTED !!SUPPORTED_WINXPSP2
      #endif
      EXPLAIN !!IntPolicy_Explain

      PART !!IntPolicy_Part  NUMERIC
        VALUENAME "IntPolicy"
        MIN 0 MAX 2000000000
      END PART
    END POLICY

  END CATEGORY

  CATEGORY !!chromium_recommended
    KEYNAME "Software\\Policies\\Chromium\\Recommended"

    POLICY !!IntPolicy_Policy
      #if version >= 4
        SUPPORTED !!SUPPORTED_WINXPSP2
      #endif
      EXPLAIN !!IntPolicy_Explain

      PART !!IntPolicy_Part  NUMERIC
        VALUENAME "IntPolicy"
        MIN 0 MAX 2000000000
      END PART
    END POLICY

  END CATEGORY


''', '''[Strings]
SUPPORTED_WINXPSP2="At least Windows 3.13"
chromium="Chromium"
chromium_recommended="Chromium - Recommended"
IntPolicy_Policy="Caption of policy."
IntPolicy_Explain="Description of policy."
IntPolicy_Part="Caption of policy."
''')
    self.CompareOutputs(output, expected_output)

  def testIntEnumPolicy(self):
    # Tests a policy group with a single policy of type 'int-enum'.
    grd = self.PrepareTest('''
      {
        'policy_definitions': [
          {
            'name': 'EnumPolicy',
            'type': 'int-enum',
            'items': [
              {
                'name': 'ProxyServerDisabled',
                'value': 0,
                'caption': 'Option1',
              },
              {
                'name': 'ProxyServerAutoDetect',
                'value': 1,
                'caption': 'Option2',
              },
            ],
            'desc': 'Description of policy.',
            'caption': 'Caption of policy.',
            'supported_on': ['chrome.win:8-'],
            'features': { 'can_be_recommended': True },
          },
        ],
        'placeholders': [],
        'messages': {
          'win_supported_winxpsp2': {
            'text': 'At least Windows 3.14', 'desc': 'blah'
          },
          'doc_recommended': {
            'text': 'Recommended', 'desc': 'bleh'
          }
        }
      }''')
    output = self.GetOutput(grd, 'fr', {'_google_chrome': '1'}, 'adm', 'en')
    expected_output = self.ConstructOutput(
        ['MACHINE', 'USER'], '''
  CATEGORY !!google
    CATEGORY !!googlechrome
      KEYNAME "Software\\Policies\\Google\\Chrome"

      POLICY !!EnumPolicy_Policy
        #if version >= 4
          SUPPORTED !!SUPPORTED_WINXPSP2
        #endif
        EXPLAIN !!EnumPolicy_Explain

        PART !!EnumPolicy_Part  DROPDOWNLIST
          VALUENAME "EnumPolicy"
          ITEMLIST
            NAME !!ProxyServerDisabled_DropDown VALUE NUMERIC 0
            NAME !!ProxyServerAutoDetect_DropDown VALUE NUMERIC 1
          END ITEMLIST
        END PART
      END POLICY

    END CATEGORY
  END CATEGORY

  CATEGORY !!google
    CATEGORY !!googlechrome_recommended
      KEYNAME "Software\\Policies\\Google\\Chrome\\Recommended"

      POLICY !!EnumPolicy_Policy
        #if version >= 4
          SUPPORTED !!SUPPORTED_WINXPSP2
        #endif
        EXPLAIN !!EnumPolicy_Explain

        PART !!EnumPolicy_Part  DROPDOWNLIST
          VALUENAME "EnumPolicy"
          ITEMLIST
            NAME !!ProxyServerDisabled_DropDown VALUE NUMERIC 0
            NAME !!ProxyServerAutoDetect_DropDown VALUE NUMERIC 1
          END ITEMLIST
        END PART
      END POLICY

    END CATEGORY
  END CATEGORY


''', '''[Strings]
SUPPORTED_WINXPSP2="At least Windows 3.14"
google="Google"
googlechrome="Google Chrome"
googlechrome_recommended="Google Chrome - Recommended"
EnumPolicy_Policy="Caption of policy."
EnumPolicy_Explain="Description of policy."
EnumPolicy_Part="Caption of policy."
ProxyServerDisabled_DropDown="Option1"
ProxyServerAutoDetect_DropDown="Option2"
''')
    self.CompareOutputs(output, expected_output)

  def testStringEnumPolicy(self):
    # Tests a policy group with a single policy of type 'int-enum'.
    grd = self.PrepareTest('''
      {
        'policy_definitions': [
          {
            'name': 'EnumPolicy',
            'type': 'string-enum',
            'caption': 'Caption of policy.',
            'desc': 'Description of policy.',
            'items': [
              {'name': 'ProxyServerDisabled', 'value': 'one',
               'caption': 'Option1'},
              {'name': 'ProxyServerAutoDetect', 'value': 'two',
               'caption': 'Option2'},
            ],
            'supported_on': ['chrome.win:8-'],
            'features': { 'can_be_recommended': True },
          },
        ],
        'placeholders': [],
        'messages': {
          'win_supported_winxpsp2': {
            'text': 'At least Windows 3.14', 'desc': 'blah'
          },
          'doc_recommended': {
            'text': 'Recommended', 'desc': 'bleh'
          }
        }
      }''')
    output = self.GetOutput(grd, 'fr', {'_google_chrome': '1'}, 'adm', 'en')
    expected_output = self.ConstructOutput(
        ['MACHINE', 'USER'], '''
  CATEGORY !!google
    CATEGORY !!googlechrome
      KEYNAME "Software\\Policies\\Google\\Chrome"

      POLICY !!EnumPolicy_Policy
        #if version >= 4
          SUPPORTED !!SUPPORTED_WINXPSP2
        #endif
        EXPLAIN !!EnumPolicy_Explain

        PART !!EnumPolicy_Part  DROPDOWNLIST
          VALUENAME "EnumPolicy"
          ITEMLIST
            NAME !!ProxyServerDisabled_DropDown VALUE "one"
            NAME !!ProxyServerAutoDetect_DropDown VALUE "two"
          END ITEMLIST
        END PART
      END POLICY

    END CATEGORY
  END CATEGORY

  CATEGORY !!google
    CATEGORY !!googlechrome_recommended
      KEYNAME "Software\\Policies\\Google\\Chrome\\Recommended"

      POLICY !!EnumPolicy_Policy
        #if version >= 4
          SUPPORTED !!SUPPORTED_WINXPSP2
        #endif
        EXPLAIN !!EnumPolicy_Explain

        PART !!EnumPolicy_Part  DROPDOWNLIST
          VALUENAME "EnumPolicy"
          ITEMLIST
            NAME !!ProxyServerDisabled_DropDown VALUE "one"
            NAME !!ProxyServerAutoDetect_DropDown VALUE "two"
          END ITEMLIST
        END PART
      END POLICY

    END CATEGORY
  END CATEGORY


''', '''[Strings]
SUPPORTED_WINXPSP2="At least Windows 3.14"
google="Google"
googlechrome="Google Chrome"
googlechrome_recommended="Google Chrome - Recommended"
EnumPolicy_Policy="Caption of policy."
EnumPolicy_Explain="Description of policy."
EnumPolicy_Part="Caption of policy."
ProxyServerDisabled_DropDown="Option1"
ProxyServerAutoDetect_DropDown="Option2"
''')
    self.CompareOutputs(output, expected_output)

  def testListPolicy(self):
    # Tests a policy group with a single policy of type 'list'.
    grd = self.PrepareTest('''
      {
        'policy_definitions': [
          {
            'name': 'ListPolicy',
            'type': 'list',
            'supported_on': ['chrome.win:8-'],
            'features': { 'can_be_recommended': True },
            'desc': """Description of list policy.
With a newline.""",
            'caption': 'Caption of list policy.',
            'label': 'Label of list policy.'
          },
        ],
        'placeholders': [],
        'messages': {
          'win_supported_winxpsp2': {
            'text': 'At least Windows 3.15', 'desc': 'blah'
          },
          'doc_recommended': {
            'text': 'Recommended', 'desc': 'bleh'
          }
        },
      }''')
    output = self.GetOutput(grd, 'fr', {'_chromium' : '1'}, 'adm', 'en')
    expected_output = self.ConstructOutput(
        ['MACHINE', 'USER'], '''
  CATEGORY !!chromium
    KEYNAME "Software\\Policies\\Chromium"

    POLICY !!ListPolicy_Policy
      #if version >= 4
        SUPPORTED !!SUPPORTED_WINXPSP2
      #endif
      EXPLAIN !!ListPolicy_Explain

      PART !!ListPolicy_Part  LISTBOX
        KEYNAME "Software\\Policies\\Chromium\\ListPolicy"
        VALUEPREFIX ""
      END PART
    END POLICY

  END CATEGORY

  CATEGORY !!chromium_recommended
    KEYNAME "Software\\Policies\\Chromium\\Recommended"

    POLICY !!ListPolicy_Policy
      #if version >= 4
        SUPPORTED !!SUPPORTED_WINXPSP2
      #endif
      EXPLAIN !!ListPolicy_Explain

      PART !!ListPolicy_Part  LISTBOX
        KEYNAME "Software\\Policies\\Chromium\\Recommended\\ListPolicy"
        VALUEPREFIX ""
      END PART
    END POLICY

  END CATEGORY


''', '''[Strings]
SUPPORTED_WINXPSP2="At least Windows 3.15"
chromium="Chromium"
chromium_recommended="Chromium - Recommended"
ListPolicy_Policy="Caption of list policy."
ListPolicy_Explain="Description of list policy.\\nWith a newline."
ListPolicy_Part="Label of list policy."
''')
    self.CompareOutputs(output, expected_output)

  def testStringEnumListPolicy(self):
    # Tests a policy group with a single policy of type 'string-enum-list'.
    grd = self.PrepareTest('''
      {
        'policy_definitions': [
          {
            'name': 'ListPolicy',
            'type': 'string-enum-list',
            'supported_on': ['chrome.win:8-'],
            'features': { 'can_be_recommended': True },
            'desc': """Description of list policy.
With a newline.""",
            'items': [
              {'name': 'ProxyServerDisabled', 'value': 'one',
               'caption': 'Option1'},
              {'name': 'ProxyServerAutoDetect', 'value': 'two',
               'caption': 'Option2'},
            ],
            'caption': 'Caption of list policy.',
            'label': 'Label of list policy.'
          },
        ],
        'placeholders': [],
        'messages': {
          'win_supported_winxpsp2': {
            'text': 'At least Windows 3.15', 'desc': 'blah'
          },
          'doc_recommended': {
            'text': 'Recommended', 'desc': 'bleh'
          }
        },
      }''')
    output = self.GetOutput(grd, 'fr', {'_chromium' : '1'}, 'adm', 'en')
    expected_output = self.ConstructOutput(
        ['MACHINE', 'USER'], '''
  CATEGORY !!chromium
    KEYNAME "Software\\Policies\\Chromium"

    POLICY !!ListPolicy_Policy
      #if version >= 4
        SUPPORTED !!SUPPORTED_WINXPSP2
      #endif
      EXPLAIN !!ListPolicy_Explain

      PART !!ListPolicy_Part  LISTBOX
        KEYNAME "Software\\Policies\\Chromium\\ListPolicy"
        VALUEPREFIX ""
      END PART
    END POLICY

  END CATEGORY

  CATEGORY !!chromium_recommended
    KEYNAME "Software\\Policies\\Chromium\\Recommended"

    POLICY !!ListPolicy_Policy
      #if version >= 4
        SUPPORTED !!SUPPORTED_WINXPSP2
      #endif
      EXPLAIN !!ListPolicy_Explain

      PART !!ListPolicy_Part  LISTBOX
        KEYNAME "Software\\Policies\\Chromium\\Recommended\\ListPolicy"
        VALUEPREFIX ""
      END PART
    END POLICY

  END CATEGORY


''', '''[Strings]
SUPPORTED_WINXPSP2="At least Windows 3.15"
chromium="Chromium"
chromium_recommended="Chromium - Recommended"
ListPolicy_Policy="Caption of list policy."
ListPolicy_Explain="Description of list policy.\\nWith a newline."
ListPolicy_Part="Label of list policy."
''')
    self.CompareOutputs(output, expected_output)

  def testDictionaryPolicy(self):
    # Tests a policy group with a single policy of type 'dict'.
    grd = self.PrepareTest('''
      {
        'policy_definitions': [
          {
            'name': 'DictionaryPolicy',
            'type': 'dict',
            'supported_on': ['chrome.win:8-'],
            'features': { 'can_be_recommended': True },
            'desc': 'Description of group.',
            'caption': 'Caption of policy.',
          },
        ],
        'placeholders': [],
        'messages': {
          'win_supported_winxpsp2': {
            'text': 'At least Windows 3.13', 'desc': 'blah'
          },
          'doc_recommended': {
            'text': 'Recommended', 'desc': 'bleh'
          }
        }
      }''')
    output = self.GetOutput(grd, 'fr', {'_chromium' : '1'}, 'adm', 'en')
    expected_output = self.ConstructOutput(
        ['MACHINE', 'USER'], '''
  CATEGORY !!chromium
    KEYNAME "Software\\Policies\\Chromium"

    POLICY !!DictionaryPolicy_Policy
      #if version >= 4
        SUPPORTED !!SUPPORTED_WINXPSP2
      #endif
      EXPLAIN !!DictionaryPolicy_Explain

      PART !!DictionaryPolicy_Part  EDITTEXT
        VALUENAME "DictionaryPolicy"
        MAXLEN 1000000
      END PART
    END POLICY

  END CATEGORY

  CATEGORY !!chromium_recommended
    KEYNAME "Software\\Policies\\Chromium\\Recommended"

    POLICY !!DictionaryPolicy_Policy
      #if version >= 4
        SUPPORTED !!SUPPORTED_WINXPSP2
      #endif
      EXPLAIN !!DictionaryPolicy_Explain

      PART !!DictionaryPolicy_Part  EDITTEXT
        VALUENAME "DictionaryPolicy"
        MAXLEN 1000000
      END PART
    END POLICY

  END CATEGORY


''', '''[Strings]
SUPPORTED_WINXPSP2="At least Windows 3.13"
chromium="Chromium"
chromium_recommended="Chromium - Recommended"
DictionaryPolicy_Policy="Caption of policy."
DictionaryPolicy_Explain="Description of group."
DictionaryPolicy_Part="Caption of policy."
''')
    self.CompareOutputs(output, expected_output)

  def testNonSupportedPolicy(self):
    # Tests a policy that is not supported on Windows, so it shouldn't
    # be included in the ADM file.
    grd = self.PrepareTest('''
      {
        'policy_definitions': [
          {
            'name': 'NonWinGroup',
            'type': 'group',
            'policies': [{
              'name': 'NonWinPolicy',
              'type': 'list',
              'supported_on': ['chrome.linux:8-', 'chrome.mac:8-'],
              'caption': 'Caption of list policy.',
              'desc': 'Desc of list policy.',
            }],
            'caption': 'Group caption.',
            'desc': 'Group description.',
          },
        ],
        'placeholders': [],
        'messages': {
          'win_supported_winxpsp2': {
            'text': 'At least Windows 3.16', 'desc': 'blah'
          },
          'doc_recommended': {
            'text': 'Recommended', 'desc': 'bleh'
          }
        }
      }''')
    output = self.GetOutput(grd, 'fr', {'_chromium' : '1'}, 'adm', 'en')
    expected_output = self.ConstructOutput(
        ['MACHINE', 'USER'], '''
  CATEGORY !!chromium
    KEYNAME "Software\\Policies\\Chromium"

  END CATEGORY

  CATEGORY !!chromium_recommended
    KEYNAME "Software\\Policies\\Chromium\\Recommended"

  END CATEGORY


''', '''[Strings]
SUPPORTED_WINXPSP2="At least Windows 3.16"
chromium="Chromium"
chromium_recommended="Chromium - Recommended"
''')
    self.CompareOutputs(output, expected_output)

  def testNonRecommendedPolicy(self):
    # Tests a policy that is not recommended, so it should be included.
    grd = self.PrepareTest('''
      {
        'policy_definitions': [
          {
            'name': 'MainPolicy',
            'type': 'main',
            'supported_on': ['chrome.win:8-'],
            'caption': 'Caption of main.',
            'desc': 'Description of main.',
          },
        ],
        'placeholders': [],
        'messages': {
          'win_supported_winxpsp2': {
            'text': 'At least Windows 3.12', 'desc': 'blah'
          },
          'doc_recommended': {
            'text': 'Recommended', 'desc': 'bleh'
          }
        }
      }''')
    output = self.GetOutput(grd, 'fr', {'_google_chrome' : '1'}, 'adm', 'en')
    expected_output = self.ConstructOutput(
        ['MACHINE', 'USER'], '''
  CATEGORY !!google
    CATEGORY !!googlechrome
      KEYNAME "Software\\Policies\\Google\\Chrome"

      POLICY !!MainPolicy_Policy
        #if version >= 4
          SUPPORTED !!SUPPORTED_WINXPSP2
        #endif
        EXPLAIN !!MainPolicy_Explain
        VALUENAME "MainPolicy"
        VALUEON NUMERIC 1
        VALUEOFF NUMERIC 0
      END POLICY

    END CATEGORY
  END CATEGORY

  CATEGORY !!google
    CATEGORY !!googlechrome_recommended
      KEYNAME "Software\\Policies\\Google\\Chrome\\Recommended"

    END CATEGORY
  END CATEGORY


''', '''[Strings]
SUPPORTED_WINXPSP2="At least Windows 3.12"
google="Google"
googlechrome="Google Chrome"
googlechrome_recommended="Google Chrome - Recommended"
MainPolicy_Policy="Caption of main."
MainPolicy_Explain="Description of main."''')
    self.CompareOutputs(output, expected_output)

  def testPolicyGroup(self):
    # Tests a policy group that has more than one policies.
    grd = self.PrepareTest('''
      {
        'policy_definitions': [
          {
            'name': 'Group1',
            'type': 'group',
            'desc': 'Description of group.',
            'caption': 'Caption of group.',
            'policies': [{
              'name': 'Policy1',
              'type': 'list',
              'supported_on': ['chrome.win:8-'],
              'features': { 'can_be_recommended': True },
              'caption': 'Caption of policy1.',
              'desc': """Description of policy1.
With a newline."""
            },{
              'name': 'Policy2',
              'type': 'string',
              'supported_on': ['chrome.win:8-'],
              'caption': 'Caption of policy2.',
              'desc': """Description of policy2.
With a newline."""
            }],
          },
        ],
        'placeholders': [],
        'messages': {
          'win_supported_winxpsp2': {
            'text': 'At least Windows 3.16', 'desc': 'blah'
          },
          'doc_recommended': {
            'text': 'Recommended', 'desc': 'bleh'
          }
        }
      }''')
    output = self.GetOutput(grd, 'fr', {'_chromium' : '1'}, 'adm', 'en')
    expected_output = self.ConstructOutput(
        ['MACHINE', 'USER'], '''
  CATEGORY !!chromium
    KEYNAME "Software\\Policies\\Chromium"

    CATEGORY !!Group1_Category
      POLICY !!Policy1_Policy
        #if version >= 4
          SUPPORTED !!SUPPORTED_WINXPSP2
        #endif
        EXPLAIN !!Policy1_Explain

        PART !!Policy1_Part  LISTBOX
          KEYNAME "Software\\Policies\\Chromium\\Policy1"
          VALUEPREFIX ""
        END PART
      END POLICY

      POLICY !!Policy2_Policy
        #if version >= 4
          SUPPORTED !!SUPPORTED_WINXPSP2
        #endif
        EXPLAIN !!Policy2_Explain

        PART !!Policy2_Part  EDITTEXT
          VALUENAME "Policy2"
          MAXLEN 1000000
        END PART
      END POLICY

    END CATEGORY

  END CATEGORY

  CATEGORY !!chromium_recommended
    KEYNAME "Software\\Policies\\Chromium\\Recommended"

    CATEGORY !!Group1_Category
      POLICY !!Policy1_Policy
        #if version >= 4
          SUPPORTED !!SUPPORTED_WINXPSP2
        #endif
        EXPLAIN !!Policy1_Explain

        PART !!Policy1_Part  LISTBOX
          KEYNAME "Software\\Policies\\Chromium\\Recommended\\Policy1"
          VALUEPREFIX ""
        END PART
      END POLICY

    END CATEGORY

  END CATEGORY


''', '''[Strings]
SUPPORTED_WINXPSP2="At least Windows 3.16"
chromium="Chromium"
chromium_recommended="Chromium - Recommended"
Group1_Category="Caption of group."
Policy1_Policy="Caption of policy1."
Policy1_Explain="Description of policy1.\\nWith a newline."
Policy1_Part="Caption of policy1."
Policy2_Policy="Caption of policy2."
Policy2_Explain="Description of policy2.\\nWith a newline."
Policy2_Part="Caption of policy2."
''')
    self.CompareOutputs(output, expected_output)

  def testDuplicatedStringEnumPolicy(self):
    # Verifies that duplicated enum constants get merged, and that
    # string constants get escaped.
    grd = self.PrepareTest('''
      {
        'policy_definitions': [
          {
            'name': 'EnumPolicy.A',
            'type': 'string-enum',
            'caption': 'Caption of policy A.',
            'desc': 'Description of policy A.',
            'items': [
              {'name': 'tls1.2', 'value': 'tls1.2', 'caption': 'tls1.2' },
            ],
            'supported_on': ['chrome.win:39-'],
          },
          {
            'name': 'EnumPolicy.B',
            'type': 'string-enum',
            'caption': 'Caption of policy B.',
            'desc': 'Description of policy B.',
            'items': [
              {'name': 'tls1.2', 'value': 'tls1.2', 'caption': 'tls1.2' },
            ],
            'supported_on': ['chrome.win:39-'],
          },
        ],
        'placeholders': [],
        'messages': {
          'win_supported_winxpsp2': {
            'text': 'At least Windows 3.14', 'desc': 'blah'
          },
          'doc_recommended': {
            'text': 'Recommended', 'desc': 'bleh'
          }
        }
      }''')
    output = self.GetOutput(grd, 'fr', {'_google_chrome': '1'}, 'adm', 'en')
    expected_output = self.ConstructOutput(
        ['MACHINE', 'USER'], '''
  CATEGORY !!google
    CATEGORY !!googlechrome
      KEYNAME "Software\\Policies\\Google\\Chrome"

      POLICY !!EnumPolicy_A_Policy
        #if version >= 4
          SUPPORTED !!SUPPORTED_WINXPSP2
        #endif
        EXPLAIN !!EnumPolicy_A_Explain

        PART !!EnumPolicy_A_Part  DROPDOWNLIST
          VALUENAME "EnumPolicy.A"
          ITEMLIST
            NAME !!tls1_2_DropDown VALUE "tls1.2"
          END ITEMLIST
        END PART
      END POLICY

      POLICY !!EnumPolicy_B_Policy
        #if version >= 4
          SUPPORTED !!SUPPORTED_WINXPSP2
        #endif
        EXPLAIN !!EnumPolicy_B_Explain

        PART !!EnumPolicy_B_Part  DROPDOWNLIST
          VALUENAME "EnumPolicy.B"
          ITEMLIST
            NAME !!tls1_2_DropDown VALUE "tls1.2"
          END ITEMLIST
        END PART
      END POLICY

    END CATEGORY
  END CATEGORY

  CATEGORY !!google
    CATEGORY !!googlechrome_recommended
      KEYNAME "Software\\Policies\\Google\\Chrome\\Recommended"

    END CATEGORY
  END CATEGORY


''', '''[Strings]
SUPPORTED_WINXPSP2="At least Windows 3.14"
google="Google"
googlechrome="Google Chrome"
googlechrome_recommended="Google Chrome - Recommended"
EnumPolicy_A_Policy="Caption of policy A."
EnumPolicy_A_Explain="Description of policy A."
EnumPolicy_A_Part="Caption of policy A."
tls1_2_DropDown="tls1.2"
EnumPolicy_B_Policy="Caption of policy B."
EnumPolicy_B_Explain="Description of policy B."
EnumPolicy_B_Part="Caption of policy B."
''')
    self.CompareOutputs(output, expected_output)

if __name__ == '__main__':
  unittest.main()
