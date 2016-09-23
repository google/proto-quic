#!/usr/bin/env python
# Copyright (c) 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.


"""Unittests for grit.format.policy_templates.writers.admx_writer."""


import os
import sys
import unittest
if __name__ == '__main__':
  sys.path.append(os.path.join(os.path.dirname(__file__), '../../../..'))


from grit.format.policy_templates.writers import admx_writer
from grit.format.policy_templates.writers import xml_writer_base_unittest
from xml.dom import minidom


class AdmxWriterUnittest(xml_writer_base_unittest.XmlWriterBaseTest):

  def _CreateDocumentElement(self):
    dom_impl = minidom.getDOMImplementation('')
    doc = dom_impl.createDocument(None, 'root', None)
    return doc.documentElement

  def setUp(self):
    # Writer configuration. This dictionary contains parameter used by the ADMX
    # Writer
    config = {
      'win_group_policy_class': 'TestClass',
      'win_supported_os': 'SUPPORTED_TESTOS',
      'win_reg_mandatory_key_name': 'Software\\Policies\\Test',
      'win_reg_recommended_key_name': 'Software\\Policies\\Test\\Recommended',
      'win_mandatory_category_path': ['test_category'],
      'win_recommended_category_path': ['test_recommended_category'],
      'admx_namespace': 'ADMXWriter.Test.Namespace',
      'admx_prefix': 'test_prefix',
      'build': 'test_product',
    }
    self.writer = admx_writer.GetWriter(config)
    self.writer.Init()

  def _GetPoliciesElement(self, doc):
    node_list = doc.getElementsByTagName('policies')
    self.assertTrue(node_list.length == 1)
    return node_list.item(0)

  def _GetCategoriesElement(self, doc):
    node_list = doc.getElementsByTagName('categories')
    self.assertTrue(node_list.length == 1)
    return node_list.item(0)

  def testEmpty(self):
    self.writer.BeginTemplate()
    self.writer.EndTemplate()

    output = self.writer.GetTemplateText()
    expected_output = (
        '<?xml version="1.0" ?>\n'
        '<policyDefinitions revision="1.0" schemaVersion="1.0">\n'
        '  <policyNamespaces>\n'
        '    <target namespace="ADMXWriter.Test.Namespace"'
        ' prefix="test_prefix"/>\n'
        '    <using namespace="Microsoft.Policies.Windows" prefix="windows"/>\n'
        '  </policyNamespaces>\n'
        '  <resources minRequiredRevision="1.0"/>\n'
        '  <supportedOn>\n'
        '    <definitions>\n'
        '      <definition displayName="'
        '$(string.SUPPORTED_TESTOS)" name="SUPPORTED_TESTOS"/>\n'
        '    </definitions>\n'
        '  </supportedOn>\n'
        '  <categories>\n'
        '    <category displayName="$(string.test_category)"'
        ' name="test_category"/>\n'
        '    <category displayName="$(string.test_recommended_category)"'
        ' name="test_recommended_category"/>\n'
        '  </categories>\n'
        '  <policies/>\n'
        '</policyDefinitions>')
    self.AssertXMLEquals(output, expected_output)

  def testEmptyVersion(self):
    self.writer.config['version'] = '39.0.0.0'
    self.writer.BeginTemplate()
    self.writer.EndTemplate()

    output = self.writer.GetTemplateText()
    expected_output = (
        '<?xml version="1.0" ?>\n'
        '<policyDefinitions revision="1.0" schemaVersion="1.0">\n'
        '  <!--test_product version: 39.0.0.0-->\n'
        '  <policyNamespaces>\n'
        '    <target namespace="ADMXWriter.Test.Namespace"'
        ' prefix="test_prefix"/>\n'
        '    <using namespace="Microsoft.Policies.Windows" prefix="windows"/>\n'
        '  </policyNamespaces>\n'
        '  <resources minRequiredRevision="1.0"/>\n'
        '  <supportedOn>\n'
        '    <definitions>\n'
        '      <definition displayName="'
        '$(string.SUPPORTED_TESTOS)" name="SUPPORTED_TESTOS"/>\n'
        '    </definitions>\n'
        '  </supportedOn>\n'
        '  <categories>\n'
        '    <category displayName="$(string.test_category)"'
        ' name="test_category"/>\n'
        '    <category displayName="$(string.test_recommended_category)"'
        ' name="test_recommended_category"/>\n'
        '  </categories>\n'
        '  <policies/>\n'
        '</policyDefinitions>')
    self.AssertXMLEquals(output, expected_output)

  def testEmptyPolicyGroup(self):
    empty_policy_group = {
      'name': 'PolicyGroup',
      'policies': []
    }
    # Initialize writer to write a policy group.
    self.writer.BeginTemplate()
    # Write policy group
    self.writer.BeginPolicyGroup(empty_policy_group)
    self.writer.EndPolicyGroup()

    output = self.GetXMLOfChildren(self._GetPoliciesElement(self.writer._doc))
    expected_output = ''
    self.AssertXMLEquals(output, expected_output)

    output = self.GetXMLOfChildren(
        self._GetCategoriesElement(self.writer._doc))
    expected_output = (
        '<category displayName="$(string.test_category)"'
        ' name="test_category"/>\n'
        '<category displayName="$(string.test_recommended_category)"'
        ' name="test_recommended_category"/>\n'
        '<category displayName="$(string.PolicyGroup_group)"'
        ' name="PolicyGroup">\n'
        '  <parentCategory ref="test_category"/>\n'
        '</category>')

    self.AssertXMLEquals(output, expected_output)

  def testPolicyGroup(self):
    empty_policy_group = {
      'name': 'PolicyGroup',
      'policies': [
          {'name': 'PolicyStub2',
          'type': 'main'},
          {'name': 'PolicyStub1',
          'type': 'main'},
      ]
    }
    # Initialize writer to write a policy group.
    self.writer.BeginTemplate()
    # Write policy group
    self.writer.BeginPolicyGroup(empty_policy_group)
    self.writer.EndPolicyGroup()

    output = self.GetXMLOfChildren(self._GetPoliciesElement(self.writer._doc))
    expected_output = ''
    self.AssertXMLEquals(output, expected_output)

    output = self.GetXMLOfChildren(
        self._GetCategoriesElement(self.writer._doc))
    expected_output = (
        '<category displayName="$(string.test_category)"'
        ' name="test_category"/>\n'
        '<category displayName="$(string.test_recommended_category)"'
        ' name="test_recommended_category"/>\n'
        '<category displayName="$(string.PolicyGroup_group)"'
        ' name="PolicyGroup">\n'
        '  <parentCategory ref="test_category"/>\n'
        '</category>')
    self.AssertXMLEquals(output, expected_output)


  def _initWriterForPolicy(self, writer, policy):
    '''Initializes the writer to write the given policy next.
    '''
    policy_group = {
      'name': 'PolicyGroup',
      'policies': [policy]
    }
    writer.BeginTemplate()
    writer.BeginPolicyGroup(policy_group)

  def testMainPolicy(self):
    main_policy = {
      'name': 'DummyMainPolicy',
      'type': 'main',
    }

    self._initWriterForPolicy(self.writer, main_policy)

    self.writer.WritePolicy(main_policy)

    output = self.GetXMLOfChildren(self._GetPoliciesElement(self.writer._doc))
    expected_output = (
        '<policy class="TestClass" displayName="$(string.DummyMainPolicy)"'
        ' explainText="$(string.DummyMainPolicy_Explain)"'
        ' key="Software\\Policies\\Test" name="DummyMainPolicy"'
        ' presentation="$(presentation.DummyMainPolicy)"'
        ' valueName="DummyMainPolicy">\n'
        '  <parentCategory ref="PolicyGroup"/>\n'
        '  <supportedOn ref="SUPPORTED_TESTOS"/>\n'
        '  <enabledValue>\n'
        '    <decimal value="1"/>\n'
        '  </enabledValue>\n'
        '  <disabledValue>\n'
        '    <decimal value="0"/>\n'
        '  </disabledValue>\n'
        '</policy>')

    self.AssertXMLEquals(output, expected_output)

  def testRecommendedPolicy(self):
    main_policy = {
      'name': 'DummyMainPolicy',
      'type': 'main',
    }

    policy_group = {
      'name': 'PolicyGroup',
      'policies': [main_policy],
    }
    self.writer.BeginTemplate()
    self.writer.BeginRecommendedPolicyGroup(policy_group)

    self.writer.WriteRecommendedPolicy(main_policy)

    output = self.GetXMLOfChildren(self._GetPoliciesElement(self.writer._doc))
    expected_output = (
        '<policy class="TestClass" displayName="$(string.DummyMainPolicy)"'
        ' explainText="$(string.DummyMainPolicy_Explain)"'
        ' key="Software\\Policies\\Test\\Recommended"'
        ' name="DummyMainPolicy_recommended"'
        ' presentation="$(presentation.DummyMainPolicy)"'
        ' valueName="DummyMainPolicy">\n'
        '  <parentCategory ref="PolicyGroup_recommended"/>\n'
        '  <supportedOn ref="SUPPORTED_TESTOS"/>\n'
        '  <enabledValue>\n'
        '    <decimal value="1"/>\n'
        '  </enabledValue>\n'
        '  <disabledValue>\n'
        '    <decimal value="0"/>\n'
        '  </disabledValue>\n'
        '</policy>')

    self.AssertXMLEquals(output, expected_output)

  def testRecommendedOnlyPolicy(self):
    main_policy = {
      'name': 'DummyMainPolicy',
      'type': 'main',
      'features': {
        'can_be_recommended': True,
        'can_be_mandatory': False,
      }
    }

    policy_group = {
      'name': 'PolicyGroup',
      'policies': [main_policy],
    }
    self.writer.BeginTemplate()
    self.writer.BeginRecommendedPolicyGroup(policy_group)

    self.writer.WritePolicy(main_policy)
    self.writer.WriteRecommendedPolicy(main_policy)

    output = self.GetXMLOfChildren(self._GetPoliciesElement(self.writer._doc))
    expected_output = (
        '<policy class="TestClass" displayName="$(string.DummyMainPolicy)"'
        ' explainText="$(string.DummyMainPolicy_Explain)"'
        ' key="Software\\Policies\\Test\\Recommended"'
        ' name="DummyMainPolicy_recommended"'
        ' presentation="$(presentation.DummyMainPolicy)"'
        ' valueName="DummyMainPolicy">\n'
        '  <parentCategory ref="PolicyGroup_recommended"/>\n'
        '  <supportedOn ref="SUPPORTED_TESTOS"/>\n'
        '  <enabledValue>\n'
        '    <decimal value="1"/>\n'
        '  </enabledValue>\n'
        '  <disabledValue>\n'
        '    <decimal value="0"/>\n'
        '  </disabledValue>\n'
        '</policy>')

    self.AssertXMLEquals(output, expected_output)

  def testStringPolicy(self):
    string_policy = {
      'name': 'SampleStringPolicy',
      'type': 'string',
    }
    self._initWriterForPolicy(self.writer, string_policy)

    self.writer.WritePolicy(string_policy)
    output = self.GetXMLOfChildren(self._GetPoliciesElement(self.writer._doc))
    expected_output = (
        '<policy class="TestClass" displayName="$(string.SampleStringPolicy)"'
        ' explainText="$(string.SampleStringPolicy_Explain)"'
        ' key="Software\\Policies\\Test" name="SampleStringPolicy"'
        ' presentation="$(presentation.SampleStringPolicy)">\n'
        '  <parentCategory ref="PolicyGroup"/>\n'
        '  <supportedOn ref="SUPPORTED_TESTOS"/>\n'
        '  <elements>\n'
        '    <text id="SampleStringPolicy" maxLength="1000000"'
            ' valueName="SampleStringPolicy"/>\n'
        '  </elements>\n'
        '</policy>')
    self.AssertXMLEquals(output, expected_output)

  def testIntPolicy(self):
    int_policy = {
      'name': 'SampleIntPolicy',
      'type': 'int',
    }
    self._initWriterForPolicy(self.writer, int_policy)

    self.writer.WritePolicy(int_policy)
    output = self.GetXMLOfChildren(self._GetPoliciesElement(self.writer._doc))
    expected_output = (
        '<policy class="TestClass" displayName="$(string.SampleIntPolicy)"'
        ' explainText="$(string.SampleIntPolicy_Explain)"'
        ' key="Software\\Policies\\Test" name="SampleIntPolicy"'
        ' presentation="$(presentation.SampleIntPolicy)">\n'
        '  <parentCategory ref="PolicyGroup"/>\n'
        '  <supportedOn ref="SUPPORTED_TESTOS"/>\n'
        '  <elements>\n'
        '    <decimal id="SampleIntPolicy" maxValue="2000000000" '
        'valueName="SampleIntPolicy"/>\n'
        '  </elements>\n'
        '</policy>')
    self.AssertXMLEquals(output, expected_output)

  def testIntEnumPolicy(self):
    enum_policy = {
      'name': 'SampleEnumPolicy',
      'type': 'int-enum',
        'items': [
          {'name': 'item_1', 'value': 0},
          {'name': 'item_2', 'value': 1},
        ]
    }

    self._initWriterForPolicy(self.writer, enum_policy)
    self.writer.WritePolicy(enum_policy)
    output = self.GetXMLOfChildren(self._GetPoliciesElement(self.writer._doc))
    expected_output = (
        '<policy class="TestClass" displayName="$(string.SampleEnumPolicy)"'
        ' explainText="$(string.SampleEnumPolicy_Explain)"'
        ' key="Software\\Policies\\Test" name="SampleEnumPolicy"'
        ' presentation="$(presentation.SampleEnumPolicy)">\n'
        '  <parentCategory ref="PolicyGroup"/>\n'
        '  <supportedOn ref="SUPPORTED_TESTOS"/>\n'
        '  <elements>\n'
        '    <enum id="SampleEnumPolicy" valueName="SampleEnumPolicy">\n'
        '      <item displayName="$(string.item_1)">\n'
        '        <value>\n'
        '          <decimal value="0"/>\n'
        '        </value>\n'
        '      </item>\n'
        '      <item displayName="$(string.item_2)">\n'
        '        <value>\n'
        '          <decimal value="1"/>\n'
        '        </value>\n'
        '      </item>\n'
        '    </enum>\n'
        '  </elements>\n'
        '</policy>')
    self.AssertXMLEquals(output, expected_output)

  def testStringEnumPolicy(self):
    enum_policy = {
      'name': 'SampleEnumPolicy',
      'type': 'string-enum',
        'items': [
          {'name': 'item_1', 'value': 'one'},
          {'name': 'item_2', 'value': 'two'},
        ]
    }

    # This test is different than the others because it also tests that space
    # usage inside <string> nodes is correct.
    dom_impl = minidom.getDOMImplementation('')
    self.writer._doc = dom_impl.createDocument(None, 'policyDefinitions', None)
    self.writer._active_policies_elem = self.writer._doc.documentElement
    self.writer._active_mandatory_policy_group_name = 'PolicyGroup'
    self.writer.WritePolicy(enum_policy)
    output = self.writer.GetTemplateText()
    expected_output = (
        '<?xml version="1.0" ?>\n'
        '<policyDefinitions>\n'
        '  <policy class="TestClass" displayName="$(string.SampleEnumPolicy)"'
          ' explainText="$(string.SampleEnumPolicy_Explain)"'
          ' key="Software\\Policies\\Test" name="SampleEnumPolicy"'
          ' presentation="$(presentation.SampleEnumPolicy)">\n'
        '    <parentCategory ref="PolicyGroup"/>\n'
        '    <supportedOn ref="SUPPORTED_TESTOS"/>\n'
        '    <elements>\n'
        '      <enum id="SampleEnumPolicy" valueName="SampleEnumPolicy">\n'
        '        <item displayName="$(string.item_1)">\n'
        '          <value>\n'
        '            <string>one</string>\n'
        '          </value>\n'
        '        </item>\n'
        '        <item displayName="$(string.item_2)">\n'
        '          <value>\n'
        '            <string>two</string>\n'
        '          </value>\n'
        '        </item>\n'
        '      </enum>\n'
        '    </elements>\n'
        '  </policy>\n'
        '</policyDefinitions>')
    self.AssertXMLEquals(output, expected_output)

  def testListPolicy(self):
    list_policy = {
      'name': 'SampleListPolicy',
      'type': 'list',
    }
    self._initWriterForPolicy(self.writer, list_policy)
    self.writer.WritePolicy(list_policy)
    output = self.GetXMLOfChildren(self._GetPoliciesElement(self.writer._doc))
    expected_output = (
        '<policy class="TestClass" displayName="$(string.SampleListPolicy)"'
        ' explainText="$(string.SampleListPolicy_Explain)"'
        ' key="Software\\Policies\\Test" name="SampleListPolicy"'
        ' presentation="$(presentation.SampleListPolicy)">\n'
        '  <parentCategory ref="PolicyGroup"/>\n'
        '  <supportedOn ref="SUPPORTED_TESTOS"/>\n'
        '  <elements>\n'
        '    <list id="SampleListPolicyDesc"'
        ' key="Software\Policies\Test\SampleListPolicy" valuePrefix=""/>\n'
        '  </elements>\n'
        '</policy>')

    self.AssertXMLEquals(output, expected_output)

  def testStringEnumListPolicy(self):
    list_policy = {
      'name': 'SampleListPolicy',
      'type': 'string-enum-list',
      'items': [
        {'name': 'item_1', 'value': 'one'},
        {'name': 'item_2', 'value': 'two'},
      ]
    }
    self._initWriterForPolicy(self.writer, list_policy)
    self.writer.WritePolicy(list_policy)
    output = self.GetXMLOfChildren(self._GetPoliciesElement(self.writer._doc))
    expected_output = (
        '<policy class="TestClass" displayName="$(string.SampleListPolicy)"'
        ' explainText="$(string.SampleListPolicy_Explain)"'
        ' key="Software\\Policies\\Test" name="SampleListPolicy"'
        ' presentation="$(presentation.SampleListPolicy)">\n'
        '  <parentCategory ref="PolicyGroup"/>\n'
        '  <supportedOn ref="SUPPORTED_TESTOS"/>\n'
        '  <elements>\n'
        '    <list id="SampleListPolicyDesc"'
        ' key="Software\Policies\Test\SampleListPolicy" valuePrefix=""/>\n'
        '  </elements>\n'
        '</policy>')

    self.AssertXMLEquals(output, expected_output)

  def testDictionaryPolicy(self):
    dict_policy = {
      'name': 'SampleDictionaryPolicy',
      'type': 'dict',
    }
    self._initWriterForPolicy(self.writer, dict_policy)

    self.writer.WritePolicy(dict_policy)
    output = self.GetXMLOfChildren(self._GetPoliciesElement(self.writer._doc))
    expected_output = (
        '<policy class="TestClass" displayName="$(string.'
            'SampleDictionaryPolicy)"'
        ' explainText="$(string.SampleDictionaryPolicy_Explain)"'
        ' key="Software\\Policies\\Test" name="SampleDictionaryPolicy"'
        ' presentation="$(presentation.SampleDictionaryPolicy)">\n'
        '  <parentCategory ref="PolicyGroup"/>\n'
        '  <supportedOn ref="SUPPORTED_TESTOS"/>\n'
        '  <elements>\n'
        '    <text id="SampleDictionaryPolicy" maxLength="1000000"'
            ' valueName="SampleDictionaryPolicy"/>\n'
        '  </elements>\n'
        '</policy>')
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
      'name': 'SampleEnumPolicy.A',
      'type': 'string-enum',
        'items': [
          {'name': 'tls1.2', 'value': 'tls1.2'}
        ]
    }
    enum_policy_b = {
      'name': 'SampleEnumPolicy.B',
      'type': 'string-enum',
        'items': [
          {'name': 'tls1.2', 'value': 'tls1.2'}
        ]
    }

    dom_impl = minidom.getDOMImplementation('')
    self.writer._doc = dom_impl.createDocument(None, 'policyDefinitions', None)
    self.writer._active_policies_elem = self.writer._doc.documentElement
    self.writer._active_mandatory_policy_group_name = 'PolicyGroup'
    self.writer.WritePolicy(enum_policy_a)
    self.writer.WritePolicy(enum_policy_b)
    output = self.writer.GetTemplateText()
    expected_output = (
        '<?xml version="1.0" ?>\n'
        '<policyDefinitions>\n'
        '  <policy class="TestClass" displayName="$(string.SampleEnumPolicy_A)"'
          ' explainText="$(string.SampleEnumPolicy_A_Explain)"'
          ' key="Software\\Policies\\Test" name="SampleEnumPolicy.A"'
          ' presentation="$(presentation.SampleEnumPolicy.A)">\n'
        '    <parentCategory ref="PolicyGroup"/>\n'
        '    <supportedOn ref="SUPPORTED_TESTOS"/>\n'
        '    <elements>\n'
        '      <enum id="SampleEnumPolicy.A" valueName="SampleEnumPolicy.A">\n'
        '        <item displayName="$(string.tls1_2)">\n'
        '          <value>\n'
        '            <string>tls1.2</string>\n'
        '          </value>\n'
        '        </item>\n'
        '      </enum>\n'
        '    </elements>\n'
        '  </policy>\n'
        '  <policy class="TestClass" displayName="$(string.SampleEnumPolicy_B)"'
          ' explainText="$(string.SampleEnumPolicy_B_Explain)"'
          ' key="Software\\Policies\\Test" name="SampleEnumPolicy.B"'
          ' presentation="$(presentation.SampleEnumPolicy.B)">\n'
        '    <parentCategory ref="PolicyGroup"/>\n'
        '    <supportedOn ref="SUPPORTED_TESTOS"/>\n'
        '    <elements>\n'
        '      <enum id="SampleEnumPolicy.B" valueName="SampleEnumPolicy.B">\n'
        '        <item displayName="$(string.tls1_2)">\n'
        '          <value>\n'
        '            <string>tls1.2</string>\n'
        '          </value>\n'
        '        </item>\n'
        '      </enum>\n'
        '    </elements>\n'
        '  </policy>\n'
        '</policyDefinitions>')
    self.AssertXMLEquals(output, expected_output)


if __name__ == '__main__':
  unittest.main()
