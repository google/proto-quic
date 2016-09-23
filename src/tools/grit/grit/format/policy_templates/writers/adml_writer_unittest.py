#!/usr/bin/env python
# Copyright (c) 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.


"""Unittests for grit.format.policy_templates.writers.adml_writer."""


import os
import sys
import unittest
if __name__ == '__main__':
  sys.path.append(os.path.join(os.path.dirname(__file__), '../../../..'))


from grit.format.policy_templates.writers import adml_writer
from grit.format.policy_templates.writers import xml_writer_base_unittest


class AdmlWriterUnittest(xml_writer_base_unittest.XmlWriterBaseTest):

  def setUp(self):
    config = {
      'app_name': 'test',
      'build': 'test',
      'win_supported_os': 'SUPPORTED_TESTOS',
    }
    self.writer = adml_writer.GetWriter(config)
    self.writer.messages = {
      'win_supported_winxpsp2': {
        'text': 'Supported on Test OS or higher',
        'desc': 'blah'
      },
      'doc_recommended': {
        'text': 'Recommended',
        'desc': 'bleh'
      },
    }
    self.writer.Init()

  def _InitWriterForAddingPolicyGroups(self, writer):
    '''Initialize the writer for adding policy groups. This method must be
    called before the method "BeginPolicyGroup" can be called. It initializes
    attributes of the writer.
    '''
    writer.BeginTemplate()

  def _InitWriterForAddingPolicies(self, writer, policy):
    '''Initialize the writer for adding policies. This method must be
    called before the method "WritePolicy" can be called. It initializes
    attributes of the writer.
    '''
    self._InitWriterForAddingPolicyGroups(writer)
    policy_group = {
      'name': 'PolicyGroup',
      'caption': 'Test Caption',
      'desc': 'This is the test description of the test policy group.',
      'policies': policy,
    }
    writer.BeginPolicyGroup(policy_group)

    string_elements = \
        self.writer._string_table_elem.getElementsByTagName('string')
    for elem in string_elements:
      self.writer._string_table_elem.removeChild(elem)

  def testEmpty(self):
    self.writer.BeginTemplate()
    self.writer.EndTemplate()
    output = self.writer.GetTemplateText()
    expected_output = (
        '<?xml version="1.0" ?><policyDefinitionResources'
        ' revision="1.0" schemaVersion="1.0"><displayName/><description/>'
        '<resources><stringTable><string id="SUPPORTED_TESTOS">Supported on'
        ' Test OS or higher</string></stringTable><presentationTable/>'
        '</resources></policyDefinitionResources>')
    self.AssertXMLEquals(output, expected_output)

  def testVersionAnnotation(self):
    self.writer.config['version'] = '39.0.0.0'
    self.writer.BeginTemplate()
    self.writer.EndTemplate()
    output = self.writer.GetTemplateText()
    expected_output = (
        '<?xml version="1.0" ?><policyDefinitionResources'
        ' revision="1.0" schemaVersion="1.0"><!--test version: 39.0.0.0-->'
        '<displayName/><description/><resources><stringTable>'
        '<string id="SUPPORTED_TESTOS">Supported on'
        ' Test OS or higher</string></stringTable><presentationTable/>'
        '</resources></policyDefinitionResources>')
    self.AssertXMLEquals(output, expected_output)

  def testPolicyGroup(self):
    empty_policy_group = {
      'name': 'PolicyGroup',
      'caption': 'Test Group Caption',
      'desc': 'This is the test description of the test policy group.',
      'policies': [
          {'name': 'PolicyStub2',
           'type': 'main'},
          {'name': 'PolicyStub1',
           'type': 'main'},
      ],
    }
    self._InitWriterForAddingPolicyGroups(self.writer)
    self.writer.BeginPolicyGroup(empty_policy_group)
    self.writer.EndPolicyGroup
    # Assert generated string elements.
    output = self.GetXMLOfChildren(self.writer._string_table_elem)
    expected_output = (
        '<string id="SUPPORTED_TESTOS">'
        'Supported on Test OS or higher</string>\n'
        '<string id="PolicyGroup_group">Test Group Caption</string>')
    self.AssertXMLEquals(output, expected_output)
    # Assert generated presentation elements.
    output = self.GetXMLOfChildren(self.writer._presentation_table_elem)
    expected_output = ''
    self.AssertXMLEquals(output, expected_output)

  def testMainPolicy(self):
    main_policy = {
      'name': 'DummyMainPolicy',
      'type': 'main',
      'caption': 'Main policy caption',
      'desc': 'Main policy test description.'
    }
    self. _InitWriterForAddingPolicies(self.writer, main_policy)
    self.writer.WritePolicy(main_policy)
    # Assert generated string elements.
    output = self.GetXMLOfChildren(self.writer._string_table_elem)
    expected_output = (
        '<string id="DummyMainPolicy">Main policy caption</string>\n'
        '<string id="DummyMainPolicy_Explain">'
        'Main policy test description.</string>')
    self.AssertXMLEquals(output, expected_output)
    # Assert generated presentation elements.
    output = self.GetXMLOfChildren(self.writer._presentation_table_elem)
    expected_output = '<presentation id="DummyMainPolicy"/>'
    self.AssertXMLEquals(output, expected_output)

  def testStringPolicy(self):
    string_policy = {
      'name': 'StringPolicyStub',
      'type': 'string',
      'caption': 'String policy caption',
      'label': 'String policy label',
      'desc': 'This is a test description.',
    }
    self. _InitWriterForAddingPolicies(self.writer, string_policy)
    self.writer.WritePolicy(string_policy)
    # Assert generated string elements.
    output = self.GetXMLOfChildren(self.writer._string_table_elem)
    expected_output = (
        '<string id="StringPolicyStub">String policy caption</string>\n'
        '<string id="StringPolicyStub_Explain">'
        'This is a test description.</string>')
    self.AssertXMLEquals(output, expected_output)
    # Assert generated presentation elements.
    output = self.GetXMLOfChildren(self.writer._presentation_table_elem)
    expected_output = (
        '<presentation id="StringPolicyStub">\n'
        '  <textBox refId="StringPolicyStub">\n'
        '    <label>String policy label</label>\n'
        '  </textBox>\n'
        '</presentation>')
    self.AssertXMLEquals(output, expected_output)

  def testIntPolicy(self):
    int_policy = {
      'name': 'IntPolicyStub',
      'type': 'int',
      'caption': 'Int policy caption',
      'label': 'Int policy label',
      'desc': 'This is a test description.',
    }
    self. _InitWriterForAddingPolicies(self.writer, int_policy)
    self.writer.WritePolicy(int_policy)
    # Assert generated string elements.
    output = self.GetXMLOfChildren(self.writer._string_table_elem)
    expected_output = (
        '<string id="IntPolicyStub">Int policy caption</string>\n'
        '<string id="IntPolicyStub_Explain">'
        'This is a test description.</string>')
    self.AssertXMLEquals(output, expected_output)
    # Assert generated presentation elements.
    output = self.GetXMLOfChildren(self.writer._presentation_table_elem)
    expected_output = (
        '<presentation id="IntPolicyStub">\n'
        '  <decimalTextBox refId="IntPolicyStub">'
        'Int policy label:</decimalTextBox>\n'
        '</presentation>')
    self.AssertXMLEquals(output, expected_output)

  def testIntEnumPolicy(self):
    enum_policy = {
      'name': 'EnumPolicyStub',
      'type': 'int-enum',
      'caption': 'Enum policy caption',
      'label': 'Enum policy label',
      'desc': 'This is a test description.',
      'items': [
          {
           'name': 'item 1',
           'value': 1,
           'caption': 'Caption Item 1',
          },
          {
           'name': 'item 2',
           'value': 2,
           'caption': 'Caption Item 2',
          },
      ],
    }
    self. _InitWriterForAddingPolicies(self.writer, enum_policy)
    self.writer.WritePolicy(enum_policy)
    # Assert generated string elements.
    output = self.GetXMLOfChildren(self.writer._string_table_elem)
    expected_output = (
        '<string id="EnumPolicyStub">Enum policy caption</string>\n'
        '<string id="EnumPolicyStub_Explain">'
        'This is a test description.</string>\n'
        '<string id="item 1">Caption Item 1</string>\n'
        '<string id="item 2">Caption Item 2</string>')
    self.AssertXMLEquals(output, expected_output)
    # Assert generated presentation elements.
    output = self.GetXMLOfChildren(self.writer._presentation_table_elem)
    expected_output = (
        '<presentation id="EnumPolicyStub">\n'
        '  <dropdownList refId="EnumPolicyStub">'
        'Enum policy label</dropdownList>\n'
        '</presentation>')
    self.AssertXMLEquals(output, expected_output)

  def testStringEnumPolicy(self):
    enum_policy = {
      'name': 'EnumPolicyStub',
      'type': 'string-enum',
      'caption': 'Enum policy caption',
      'label': 'Enum policy label',
      'desc': 'This is a test description.',
      'items': [
          {
           'name': 'item 1',
           'value': 'value 1',
           'caption': 'Caption Item 1',
          },
          {
           'name': 'item 2',
           'value': 'value 2',
           'caption': 'Caption Item 2',
          },
      ],
    }
    self. _InitWriterForAddingPolicies(self.writer, enum_policy)
    self.writer.WritePolicy(enum_policy)
    # Assert generated string elements.
    output = self.GetXMLOfChildren(self.writer._string_table_elem)
    expected_output = (
        '<string id="EnumPolicyStub">Enum policy caption</string>\n'
        '<string id="EnumPolicyStub_Explain">'
        'This is a test description.</string>\n'
        '<string id="item 1">Caption Item 1</string>\n'
        '<string id="item 2">Caption Item 2</string>')
    self.AssertXMLEquals(output, expected_output)
    # Assert generated presentation elements.
    output = self.GetXMLOfChildren(self.writer._presentation_table_elem)
    expected_output = (
        '<presentation id="EnumPolicyStub">\n'
        '  <dropdownList refId="EnumPolicyStub">'
        'Enum policy label</dropdownList>\n'
        '</presentation>')
    self.AssertXMLEquals(output, expected_output)

  def testListPolicy(self):
    list_policy = {
      'name': 'ListPolicyStub',
      'type': 'list',
      'caption': 'List policy caption',
      'label': 'List policy label',
      'desc': 'This is a test description.',
    }
    self. _InitWriterForAddingPolicies(self.writer, list_policy)
    self.writer.WritePolicy(list_policy)
    # Assert generated string elements.
    output = self.GetXMLOfChildren(self.writer._string_table_elem)
    expected_output = (
        '<string id="ListPolicyStub">List policy caption</string>\n'
        '<string id="ListPolicyStub_Explain">'
        'This is a test description.</string>\n'
        '<string id="ListPolicyStubDesc">List policy caption</string>')
    self.AssertXMLEquals(output, expected_output)
    # Assert generated presentation elements.
    output = self.GetXMLOfChildren(self.writer._presentation_table_elem)
    expected_output = (
        '<presentation id="ListPolicyStub">\n'
        '  <listBox refId="ListPolicyStubDesc">List policy label</listBox>\n'
        '</presentation>')
    self.AssertXMLEquals(output, expected_output)

  def testStringEnumListPolicy(self):
    list_policy = {
      'name': 'ListPolicyStub',
      'type': 'string-enum-list',
      'caption': 'List policy caption',
      'label': 'List policy label',
      'desc': 'This is a test description.',
      'items': [
          {
           'name': 'item 1',
           'value': 'value 1',
           'caption': 'Caption Item 1',
          },
          {
           'name': 'item 2',
           'value': 'value 2',
           'caption': 'Caption Item 2',
          },
      ],
    }
    self. _InitWriterForAddingPolicies(self.writer, list_policy)
    self.writer.WritePolicy(list_policy)
    # Assert generated string elements.
    output = self.GetXMLOfChildren(self.writer._string_table_elem)
    expected_output = (
        '<string id="ListPolicyStub">List policy caption</string>\n'
        '<string id="ListPolicyStub_Explain">'
        'This is a test description.</string>\n'
        '<string id="ListPolicyStubDesc">List policy caption</string>')
    self.AssertXMLEquals(output, expected_output)
    # Assert generated presentation elements.
    output = self.GetXMLOfChildren(self.writer._presentation_table_elem)
    expected_output = (
        '<presentation id="ListPolicyStub">\n'
        '  <listBox refId="ListPolicyStubDesc">List policy label</listBox>\n'
        '</presentation>')
    self.AssertXMLEquals(output, expected_output)

  def testDictionaryPolicy(self):
    dict_policy = {
      'name': 'DictionaryPolicyStub',
      'type': 'dict',
      'caption': 'Dictionary policy caption',
      'label': 'Dictionary policy label',
      'desc': 'This is a test description.',
    }
    self. _InitWriterForAddingPolicies(self.writer, dict_policy)
    self.writer.WritePolicy(dict_policy)
    # Assert generated string elements.
    output = self.GetXMLOfChildren(self.writer._string_table_elem)
    expected_output = (
        '<string id="DictionaryPolicyStub">Dictionary policy caption</string>\n'
        '<string id="DictionaryPolicyStub_Explain">'
        'This is a test description.</string>')
    self.AssertXMLEquals(output, expected_output)
    # Assert generated presentation elements.
    output = self.GetXMLOfChildren(self.writer._presentation_table_elem)
    expected_output = (
        '<presentation id="DictionaryPolicyStub">\n'
        '  <textBox refId="DictionaryPolicyStub">\n'
        '    <label>Dictionary policy label</label>\n'
        '  </textBox>\n'
        '</presentation>')
    self.AssertXMLEquals(output, expected_output)

  def testPlatform(self):
    # Test that the writer correctly chooses policies of platform Windows.
    self.assertTrue(self.writer.IsPolicySupported({
      'supported_on': [
        {'platforms': ['win', 'zzz']}, {'platforms': ['aaa']}
      ]
    }))
    self.assertFalse(self.writer.IsPolicySupported({
      'supported_on': [
        {'platforms': ['mac', 'linux']}, {'platforms': ['aaa']}
      ]
    }))

  def testStringEncodings(self):
    enum_policy_a = {
      'name': 'EnumPolicy.A',
      'type': 'string-enum',
      'caption': 'Enum policy A caption',
      'label': 'Enum policy A label',
      'desc': 'This is a test description.',
      'items': [
          {
           'name': 'tls1.2',
           'value': 'tls1.2',
           'caption': 'tls1.2',
          }
      ],
    }
    enum_policy_b = {
      'name': 'EnumPolicy.B',
      'type': 'string-enum',
      'caption': 'Enum policy B caption',
      'label': 'Enum policy B label',
      'desc': 'This is a test description.',
      'items': [
          {
           'name': 'tls1.2',
           'value': 'tls1.2',
           'caption': 'tls1.2',
          }
      ],
    }
    self. _InitWriterForAddingPolicies(self.writer, enum_policy_a)
    self.writer.WritePolicy(enum_policy_a)
    self.writer.WritePolicy(enum_policy_b)
    # Assert generated string elements.
    output = self.GetXMLOfChildren(self.writer._string_table_elem)
    expected_output = (
        '<string id="EnumPolicy_A">Enum policy A caption</string>\n'
        '<string id="EnumPolicy_A_Explain">'
        'This is a test description.</string>\n'
        '<string id="tls1_2">tls1.2</string>\n'
        '<string id="EnumPolicy_B">Enum policy B caption</string>\n'
        '<string id="EnumPolicy_B_Explain">'
        'This is a test description.</string>\n')
    self.AssertXMLEquals(output, expected_output)
    # Assert generated presentation elements.
    output = self.GetXMLOfChildren(self.writer._presentation_table_elem)
    expected_output = (
        '<presentation id="EnumPolicy.A">\n'
        '  <dropdownList refId="EnumPolicy.A">'
        'Enum policy A label</dropdownList>\n'
        '</presentation>\n'
        '<presentation id="EnumPolicy.B">\n'
        '  <dropdownList refId="EnumPolicy.B">'
        'Enum policy B label</dropdownList>\n'
        '</presentation>')
    self.AssertXMLEquals(output, expected_output)


if __name__ == '__main__':
  unittest.main()
