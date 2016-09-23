#!/usr/bin/env python
# Copyright (c) 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.


import os
import sys
if __name__ == '__main__':
  sys.path.append(os.path.join(os.path.dirname(__file__), '../../..'))

import unittest

from grit.format.policy_templates import policy_template_generator
from grit.format.policy_templates.writers import mock_writer
from grit.format.policy_templates.writers import template_writer


class PolicyTemplateGeneratorUnittest(unittest.TestCase):
  '''Unit tests for policy_template_generator.py.'''

  def do_test(self, policy_data, writer):
    '''Executes a test case.

    Creates and invokes an instance of PolicyTemplateGenerator with
    the given arguments.

    Notice: Plain comments are used in test methods instead of docstrings,
    so that method names do not get overridden by the docstrings in the
    test output.

    Args:
      policy_data: The list of policies and groups as it would be
        loaded from policy_templates.json.
      writer: A writer used for this test. It is usually derived from
        mock_writer.MockWriter.
    '''
    writer.tester = self
    config = {
      'app_name': '_app_name',
      'frame_name': '_frame_name',
      'os_name': '_os_name',
    }
    if not 'messages' in policy_data:
      policy_data['messages'] = {}
    if not 'placeholders' in policy_data:
      policy_data['placeholders'] = []
    if not 'policy_definitions' in policy_data:
      policy_data['policy_definitions'] = []
    policy_generator = policy_template_generator.PolicyTemplateGenerator(
        config,
        policy_data)
    res = policy_generator.GetTemplateText(writer)
    writer.Test()
    return res

  def testSequence(self):
    # Test the sequence of invoking the basic PolicyWriter operations,
    # in case of empty input data structures.
    class LocalMockWriter(mock_writer.MockWriter):
      def __init__(self):
        self.log = 'init;'
      def Init(self):
        self.log += 'prepare;'
      def BeginTemplate(self):
        self.log += 'begin;'
      def EndTemplate(self):
        self.log += 'end;'
      def GetTemplateText(self):
        self.log += 'get_text;'
        return 'writer_result_string'
      def Test(self):
        self.tester.assertEquals(self.log,
                                 'init;prepare;begin;end;get_text;')
    result = self.do_test({}, LocalMockWriter())
    self.assertEquals(result, 'writer_result_string')

  def testEmptyGroups(self):
    # Test that empty policy groups are not passed to the writer.
    policies_mock = {
      'policy_definitions': [
        {'name': 'Group1', 'type': 'group', 'policies': [],
         'desc': '', 'caption': ''},
        {'name': 'Group2', 'type': 'group', 'policies': [],
         'desc': '', 'caption': ''},
        {'name': 'Group3', 'type': 'group', 'policies': [],
         'desc': '', 'caption': ''},
      ]
    }
    class LocalMockWriter(mock_writer.MockWriter):
      def __init__(self):
        self.log = ''
      def BeginPolicyGroup(self, group):
        self.log += '['
      def EndPolicyGroup(self):
        self.log += ']'
      def Test(self):
        self.tester.assertEquals(self.log, '')
    self.do_test(policies_mock, LocalMockWriter())

  def testGroups(self):
    # Test that policy groups are passed to the writer in the correct order.
    policies_mock = {
      'policy_definitions': [
        {
          'name': 'Group1', 'type': 'group',
          'caption': '', 'desc': '',
          'policies': [{'name': 'TAG1', 'type': 'mock', 'supported_on': [],
                        'caption': '', 'desc': ''}]
        },
        {
          'name': 'Group2', 'type': 'group',
          'caption': '', 'desc': '',
          'policies': [{'name': 'TAG2', 'type': 'mock', 'supported_on': [],
                        'caption': '', 'desc': ''}]
        },
        {
          'name': 'Group3', 'type': 'group',
          'caption': '', 'desc': '',
          'policies': [{'name': 'TAG3', 'type': 'mock', 'supported_on': [],
                        'caption': '', 'desc': ''}]
        },
      ]
    }
    class LocalMockWriter(mock_writer.MockWriter):
      def __init__(self):
        self.log = ''
      def BeginPolicyGroup(self, group):
        self.log += '[' + group['policies'][0]['name']
      def EndPolicyGroup(self):
        self.log += ']'
      def Test(self):
        self.tester.assertEquals(self.log, '[TAG1][TAG2][TAG3]')
    self.do_test(policies_mock, LocalMockWriter())

  def testPolicies(self):
    # Test that policies are passed to the writer in the correct order.
    policy_defs_mock = {
     'policy_definitions': [
        {
          'name': 'Group1',
          'type': 'group',
          'caption': '',
          'desc': '',
          'policies': [
            {'name': 'Group1Policy1', 'type': 'string', 'supported_on': [],
             'caption': '', 'desc': ''},
            {'name': 'Group1Policy2', 'type': 'string', 'supported_on': [],
             'caption': '', 'desc': ''},
          ]
        },
        {
          'name': 'Group2',
          'type': 'group',
          'caption': '',
          'desc': '',
          'policies': [
            {'name': 'Group2Policy3', 'type': 'string', 'supported_on': [],
             'caption': '', 'desc': ''},
          ]
        }
      ]
    }
    class LocalMockWriter(mock_writer.MockWriter):
      def __init__(self):
        self.policy_name = None
        self.policy_list = []
      def BeginPolicyGroup(self, group):
        self.group = group;
      def EndPolicyGroup(self):
        self.group = None
      def WritePolicy(self, policy):
        self.tester.assertEquals(policy['name'][0:6], self.group['name'])
        self.policy_list.append(policy['name'])
      def Test(self):
        self.tester.assertEquals(
          self.policy_list,
          ['Group1Policy1', 'Group1Policy2', 'Group2Policy3'])
    self.do_test( policy_defs_mock, LocalMockWriter())

  def testPolicyTexts(self):
    # Test that GUI messages of policies all get placeholders replaced.
    policy_data_mock = {
      'policy_definitions': [
        {
          'name': 'Group1',
          'type': 'group',
          'desc': '',
          'caption': '',
          'policies': [
            {
              'name': 'Policy1',
              'caption': '1. app_name -- $1',
              'label': '2. os_name -- $2',
              'desc': '3. frame_name -- $3',
              'type': 'string',
              'supported_on': []
            },
          ]
        }
      ]
    }
    class LocalMockWriter(mock_writer.MockWriter):
      def WritePolicy(self, policy):
        if policy['name'] == 'Policy1':
          self.tester.assertEquals(policy['caption'],
                                   '1. app_name -- _app_name')
          self.tester.assertEquals(policy['label'],
                                   '2. os_name -- _os_name')
          self.tester.assertEquals(policy['desc'],
                                   '3. frame_name -- _frame_name')
        elif policy['name'] == 'Group1':
          pass
        else:
          self.tester.fail()
    self.do_test(policy_data_mock, LocalMockWriter())

  def testIntEnumTexts(self):
    # Test that GUI messages are assigned correctly to int-enums
    # (aka dropdown menus).
    policy_defs_mock = {
      'policy_definitions': [{
        'name': 'Policy1',
        'type': 'int-enum',
        'caption': '', 'desc': '',
        'supported_on': [],
        'items': [
          {'name': 'item1', 'value': 0, 'caption': 'string1', 'desc': ''},
          {'name': 'item2', 'value': 1, 'caption': 'string2', 'desc': ''},
          {'name': 'item3', 'value': 3, 'caption': 'string3', 'desc': ''},
        ]
      }]
    }

    class LocalMockWriter(mock_writer.MockWriter):
      def WritePolicy(self, policy):
        self.tester.assertEquals(policy['items'][0]['caption'], 'string1')
        self.tester.assertEquals(policy['items'][1]['caption'], 'string2')
        self.tester.assertEquals(policy['items'][2]['caption'], 'string3')
    self.do_test(policy_defs_mock, LocalMockWriter())

  def testStringEnumTexts(self):
    # Test that GUI messages are assigned correctly to string-enums
    # (aka dropdown menus).
    policy_data_mock = {
      'policy_definitions': [{
        'name': 'Policy1',
        'type': 'string-enum',
        'caption': '', 'desc': '',
        'supported_on': [],
        'items': [
          {'name': 'item1', 'value': 'one', 'caption': 'string1', 'desc': ''},
          {'name': 'item2', 'value': 'two', 'caption': 'string2', 'desc': ''},
          {'name': 'item3', 'value': 'three', 'caption': 'string3', 'desc': ''},
        ]
      }]
    }
    class LocalMockWriter(mock_writer.MockWriter):
      def WritePolicy(self, policy):
        self.tester.assertEquals(policy['items'][0]['caption'], 'string1')
        self.tester.assertEquals(policy['items'][1]['caption'], 'string2')
        self.tester.assertEquals(policy['items'][2]['caption'], 'string3')
    self.do_test(policy_data_mock, LocalMockWriter())

  def testStringEnumTexts(self):
    # Test that GUI messages are assigned correctly to string-enums
    # (aka dropdown menus).
    policy_data_mock = {
      'policy_definitions': [{
        'name': 'Policy1',
        'type': 'string-enum-list',
        'caption': '', 'desc': '',
        'supported_on': [],
        'items': [
          {'name': 'item1', 'value': 'one', 'caption': 'string1', 'desc': ''},
          {'name': 'item2', 'value': 'two', 'caption': 'string2', 'desc': ''},
          {'name': 'item3', 'value': 'three', 'caption': 'string3', 'desc': ''},
        ]
      }]
    }
    class LocalMockWriter(mock_writer.MockWriter):
      def WritePolicy(self, policy):
        self.tester.assertEquals(policy['items'][0]['caption'], 'string1')
        self.tester.assertEquals(policy['items'][1]['caption'], 'string2')
        self.tester.assertEquals(policy['items'][2]['caption'], 'string3')
    self.do_test(policy_data_mock, LocalMockWriter())

  def testPolicyFiltering(self):
    # Test that policies are filtered correctly based on their annotations.
    policy_data_mock = {
      'policy_definitions': [
         {
          'name': 'Group1',
          'type': 'group',
          'caption': '',
          'desc': '',
          'policies': [
            {
              'name': 'Group1Policy1',
              'type': 'string',
              'caption': '',
              'desc': '',
              'supported_on': [
                'chrome.aaa:8-', 'chrome.bbb:8-', 'chrome.ccc:8-'
              ]
            },
            {
              'name': 'Group1Policy2',
              'type': 'string',
              'caption': '',
              'desc': '',
              'supported_on': ['chrome.ddd:8-']
            },
          ]
        }, {
          'name': 'Group2',
          'type': 'group',
          'caption': '',
          'desc': '',
          'policies': [
            {
              'name': 'Group2Policy3',
              'type': 'string',
              'caption': '',
              'desc': '',
              'supported_on': ['chrome.eee:8-']
            },
          ]
        }, {
          'name': 'SinglePolicy',
          'type': 'int',
          'caption': '',
          'desc': '',
          'supported_on': ['chrome.eee:8-']
        }
      ]
    }
    # This writer accumulates the list of policies it is asked to write.
    # This list is stored in the result_list member variable and can
    # be used later for assertions.
    class LocalMockWriter(mock_writer.MockWriter):
      def __init__(self, platforms):
        self.platforms = platforms
        self.policy_name = None
        self.result_list = []
      def BeginPolicyGroup(self, group):
        self.group = group;
        self.result_list.append('begin_' + group['name'])
      def EndPolicyGroup(self):
        self.result_list.append('end_group')
        self.group = None
      def WritePolicy(self, policy):
        self.result_list.append(policy['name'])
      def IsPolicySupported(self, policy):
        # Call the original (non-mock) implementation of this method.
        return template_writer.TemplateWriter.IsPolicySupported(self, policy)

    local_mock_writer = LocalMockWriter(['eee'])
    self.do_test(policy_data_mock, local_mock_writer)
    # Test that only policies of platform 'eee' were written:
    self.assertEquals(
        local_mock_writer.result_list,
        ['begin_Group2', 'Group2Policy3', 'end_group', 'SinglePolicy'])

    local_mock_writer = LocalMockWriter(['ddd', 'bbb'])
    self.do_test(policy_data_mock, local_mock_writer)
    # Test that only policies of platforms 'ddd' and 'bbb' were written:
    self.assertEquals(
        local_mock_writer.result_list,
        ['begin_Group1', 'Group1Policy1', 'Group1Policy2', 'end_group'])

  def testSortingInvoked(self):
    # Tests that policy-sorting happens before passing policies to the writer.
    policy_data = {
      'policy_definitions': [
        {'name': 'zp', 'type': 'string', 'supported_on': [],
         'caption': '', 'desc': ''},
        {'name': 'ap', 'type': 'string', 'supported_on': [],
         'caption': '', 'desc': ''},
      ]
    }
    class LocalMockWriter(mock_writer.MockWriter):
      def __init__(self):
        self.result_list = []
      def WritePolicy(self, policy):
        self.result_list.append(policy['name'])
      def Test(self):
        self.tester.assertEquals(
          self.result_list,
          ['ap', 'zp'])
    self.do_test(policy_data, LocalMockWriter())


if __name__ == '__main__':
  unittest.main()
