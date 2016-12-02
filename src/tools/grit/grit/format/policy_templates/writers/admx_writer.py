#!/usr/bin/env python
# Copyright (c) 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from xml.dom import minidom
from grit.format.policy_templates.writers import xml_formatted_writer


def GetWriter(config):
  '''Factory method for instanciating the ADMXWriter. Every Writer needs a
  GetWriter method because the TemplateFormatter uses this method to
  instantiate a Writer.
  '''
  return ADMXWriter(['win'], config)


class ADMXWriter(xml_formatted_writer.XMLFormattedWriter):
  '''Class for generating an ADMX policy template. It is used by the
  PolicyTemplateGenerator to write the admx file.
  '''

  # DOM root node of the generated ADMX document.
  _doc = None

  # The ADMX "policies" element that contains the ADMX "policy" elements that
  # are generated.
  _active_policies_elem = None

  def _AdmlString(self, name):
    '''Creates a reference to the named string in an ADML file.
    Args:
      name: Name of the referenced ADML string.
    '''
    name = name.replace('.', '_')
    return '$(string.' + name + ')'

  def _AdmlStringExplain(self, name):
    '''Creates a reference to the named explanation string in an ADML file.
    Args:
      name: Name of the referenced ADML explanation.
    '''
    name = name.replace('.', '_')
    return '$(string.' + name + '_Explain)'

  def _AdmlPresentation(self, name):
    '''Creates a reference to the named presentation element in an ADML file.
    Args:
      name: Name of the referenced ADML presentation element.
    '''
    return '$(presentation.' + name + ')'

  def _AddPolicyNamespaces(self, parent, prefix, namespace):
    '''Generates the ADMX "policyNamespace" element and adds the elements to the
    passed parent element. The namespace of the generated ADMX document is
    define via the ADMX "target" element. Used namespaces are declared with an
    ADMX "using" element. ADMX "target" and "using" elements are children of the
    ADMX "policyNamespace" element.

    Args:
      parent: The parent node to which all generated elements are added.
      prefix: A logical name that can be used in the generated ADMX document to
        refere to this namespace.
      namespace: Namespace of the generated ADMX document.
    '''
    policy_namespaces_elem = self.AddElement(parent, 'policyNamespaces')
    attributes = {
      'prefix': prefix,
      'namespace': namespace,
    }
    self.AddElement(policy_namespaces_elem, 'target', attributes)
    if 'admx_using_namespaces' in self.config:
      prefix_namespace_map = self.config['admx_using_namespaces']
      for prefix in prefix_namespace_map:
        attributes = {
          'prefix': prefix,
          'namespace': prefix_namespace_map[prefix],
        }
        self.AddElement(policy_namespaces_elem, 'using', attributes)
    attributes = {
      'prefix': 'windows',
      'namespace': 'Microsoft.Policies.Windows',
    }
    self.AddElement(policy_namespaces_elem, 'using', attributes)

  def _AddCategory(self, parent, name, display_name,
                   parent_category_name=None):
    '''Adds an ADMX category element to the passed parent node. The following
    snippet shows an example of a category element where "chromium" is the value
    of the parameter name:

    <category displayName="$(string.chromium)" name="chromium"/>

    Each parent node can have only one category with a given name. Adding the
    same category again with the same attributes is ignored, but adding it
    again with different attributes is an error.

    Args:
      parent: The parent node to which all generated elements are added.
      name: Name of the category.
      display_name: Display name of the category.
      parent_category_name: Name of the parent category. Defaults to None.
    '''
    existing = filter(lambda e: e.getAttribute('name') == name,
                      parent.getElementsByTagName('category'))
    if existing:
      assert len(existing) == 1
      assert existing[0].getAttribute('name') == name
      assert existing[0].getAttribute('displayName') == display_name
      return
    attributes = {
      'name': name,
      'displayName': display_name,
    }
    category_elem = self.AddElement(parent, 'category', attributes)
    if parent_category_name:
      attributes = {'ref': parent_category_name}
      self.AddElement(category_elem, 'parentCategory', attributes)

  def _AddCategories(self, categories):
    '''Generates the ADMX "categories" element and adds it to the categories
    main node. The "categories" element defines the category for the policies
    defined in this ADMX document. Here is an example of an ADMX "categories"
    element:

    <categories>
      <category displayName="$(string.googlechrome)" name="googlechrome">
        <parentCategory ref="Google:Cat_Google"/>
      </category>
    </categories>

    Args:
      categories_path: The categories path e.g. ['google', 'googlechrome']. For
        each level in the path a "category" element will be generated, unless
        the level contains a ':', in which case it is treated as external
        references and no element is generated. Except for the root level, each
        level refers to its parent. Since the root level category has no parent
        it does not require a parent reference.
    '''
    category_name = None
    for category in categories:
      parent_category_name = category_name
      category_name = category
      if (":" not in category_name):
        self._AddCategory(self._categories_elem, category_name,
                          self._AdmlString(category_name), parent_category_name)

  def _AddSupportedOn(self, parent, supported_os):
    '''Generates the "supportedOn" ADMX element and adds it to the passed
    parent node. The "supportedOn" element contains information about supported
    Windows OS versions. The following code snippet contains an example of a
    "supportedOn" element:

    <supportedOn>
      <definitions>
        <definition name="SUPPORTED_WINXPSP2"
                    displayName="$(string.SUPPORTED_WINXPSP2)"/>
        </definitions>
        ...
    </supportedOn>

    Args:
      parent: The parent element to which all generated elements are added.
      supported_os: List with all supported Win OSes.
    '''
    supported_on_elem = self.AddElement(parent, 'supportedOn')
    definitions_elem = self.AddElement(supported_on_elem, 'definitions')
    attributes = {
      'name': supported_os,
      'displayName': self._AdmlString(supported_os)
    }
    self.AddElement(definitions_elem, 'definition', attributes)

  def _AddStringPolicy(self, parent, name):
    '''Generates ADMX elements for a String-Policy and adds them to the
    passed parent node.
    '''
    attributes = {
      'id': name,
      'valueName': name,
      'maxLength': '1000000',
    }
    self.AddElement(parent, 'text', attributes)

  def _AddIntPolicy(self, parent, name):
    '''Generates ADMX elements for an Int-Policy and adds them to the passed
    parent node.
    '''
    attributes = {
      'id': name,
      'valueName': name,
      'maxValue': '2000000000',
    }
    self.AddElement(parent, 'decimal', attributes)

  def _AddEnumPolicy(self, parent, policy):
    '''Generates ADMX elements for an Enum-Policy and adds them to the
    passed parent element.
    '''
    name = policy['name']
    items = policy['items']
    attributes = {
      'id': name,
      'valueName': name,
    }
    enum_elem = self.AddElement(parent, 'enum', attributes)
    for item in items:
      attributes = {'displayName': self._AdmlString(item['name'])}
      item_elem = self.AddElement(enum_elem, 'item', attributes)
      value_elem = self.AddElement(item_elem, 'value')
      value_string = str(item['value'])
      if policy['type'] == 'int-enum':
        self.AddElement(value_elem, 'decimal', {'value': value_string})
      else:
        self.AddElement(value_elem, 'string', {}, value_string)

  def _AddListPolicy(self, parent, key, name):
    '''Generates ADMX XML elements for a List-Policy and adds them to the
    passed parent element.
    '''
    attributes = {
      # The ID must be in sync with ID of the corresponding element in the ADML
      # file.
      'id': name + 'Desc',
      'valuePrefix': '',
      'key': key + '\\' + name,
    }
    self.AddElement(parent, 'list', attributes)

  def _AddMainPolicy(self, parent):
    '''Generates ADMX elements for a Main-Policy amd adds them to the
    passed parent element.
    '''
    enabled_value_elem = self.AddElement(parent, 'enabledValue');
    self.AddElement(enabled_value_elem, 'decimal', {'value': '1'})
    disabled_value_elem = self.AddElement(parent, 'disabledValue');
    self.AddElement(disabled_value_elem, 'decimal', {'value': '0'})

  def _GetElements(self, policy_group_elem):
    '''Returns the ADMX "elements" child from an ADMX "policy" element. If the
    "policy" element has no "elements" child yet, a new child is created.

    Args:
      policy_group_elem: The ADMX "policy" element from which the child element
        "elements" is returned.

    Raises:
      Exception: The policy_group_elem does not contain a ADMX "policy" element.
    '''
    if policy_group_elem.tagName != 'policy':
      raise Exception('Expected a "policy" element but got a "%s" element'
                      % policy_group_elem.tagName)
    elements_list = policy_group_elem.getElementsByTagName('elements');
    if len(elements_list) == 0:
      return self.AddElement(policy_group_elem, 'elements')
    elif len(elements_list) == 1:
      return elements_list[0]
    else:
      raise Exception('There is supposed to be only one "elements" node but'
                      ' there are %s.' % str(len(elements_list)))

  def _WritePolicy(self, policy, name, key, parent):
    '''Generates AMDX elements for a Policy. There are four different policy
    types: Main-Policy, String-Policy, Enum-Policy and List-Policy.
    '''
    policies_elem = self._active_policies_elem
    policy_type = policy['type']
    policy_name = policy['name']
    if policy_type == 'external':
      # This type can only be set through cloud policy.
      return

    attributes = {
      'name': name,
      'class': self.config['win_group_policy_class'],
      'displayName': self._AdmlString(policy_name),
      'explainText': self._AdmlStringExplain(policy_name),
      'presentation': self._AdmlPresentation(policy_name),
      'key': key,
    }
    # Store the current "policy" AMDX element in self for later use by the
    # WritePolicy method.
    policy_elem = self.AddElement(policies_elem, 'policy',
                                  attributes)
    self.AddElement(policy_elem, 'parentCategory',
                    {'ref': parent})
    self.AddElement(policy_elem, 'supportedOn',
                    {'ref': self.config['win_supported_os']})
    if policy_type == 'main':
      self.AddAttribute(policy_elem, 'valueName', policy_name)
      self._AddMainPolicy(policy_elem)
    elif policy_type in ('string', 'dict'):
      # 'dict' policies are configured as JSON-encoded strings on Windows.
      parent = self._GetElements(policy_elem)
      self._AddStringPolicy(parent, policy_name)
    elif policy_type == 'int':
      parent = self._GetElements(policy_elem)
      self._AddIntPolicy(parent, policy_name)
    elif policy_type in ('int-enum', 'string-enum'):
      parent = self._GetElements(policy_elem)
      self._AddEnumPolicy(parent, policy)
    elif policy_type in ('list', 'string-enum-list'):
      parent = self._GetElements(policy_elem)
      self._AddListPolicy(parent, key, policy_name)
    elif policy_type == 'group':
      pass
    else:
      raise Exception('Unknown policy type %s.' % policy_type)

  def WritePolicy(self, policy):
    if self.CanBeMandatory(policy):
      self._WritePolicy(policy,
                        policy['name'],
                        self.config['win_reg_mandatory_key_name'],
                        self._active_mandatory_policy_group_name)

  def WriteRecommendedPolicy(self, policy):
    self._WritePolicy(policy,
                      policy['name'] + '_recommended',
                      self.config['win_reg_recommended_key_name'],
                      self._active_recommended_policy_group_name)

  def _BeginPolicyGroup(self, group, name, parent):
    '''Generates ADMX elements for a Policy-Group.
    '''
    attributes = {
      'name': name,
      'displayName': self._AdmlString(group['name'] + '_group'),
    }
    category_elem = self.AddElement(self._categories_elem,
                                    'category',
                                    attributes)
    attributes = {
      'ref': parent
    }
    self.AddElement(category_elem, 'parentCategory', attributes)

  def BeginPolicyGroup(self, group):
    self._BeginPolicyGroup(group,
                           group['name'],
                           self.config['win_mandatory_category_path'][-1])
    self._active_mandatory_policy_group_name = group['name']

  def EndPolicyGroup(self):
    self._active_mandatory_policy_group_name = \
        self.config['win_mandatory_category_path'][-1]

  def BeginRecommendedPolicyGroup(self, group):
    self._BeginPolicyGroup(group,
                           group['name'] + '_recommended',
                           self.config['win_recommended_category_path'][-1])
    self._active_recommended_policy_group_name = group['name'] + '_recommended'

  def EndRecommendedPolicyGroup(self):
    self._active_recommended_policy_group_name = \
        self.config['win_recommended_category_path'][-1]

  def BeginTemplate(self):
    '''Generates the skeleton of the ADMX template. An ADMX template contains
    an ADMX "PolicyDefinitions" element with four child nodes: "policies"
    "policyNamspaces", "resources", "supportedOn" and "categories"
    '''
    dom_impl = minidom.getDOMImplementation('')
    self._doc = dom_impl.createDocument(None, 'policyDefinitions', None)
    if self._GetChromiumVersionString() is not None:
      self.AddComment(self._doc.documentElement, self.config['build'] + \
          ' version: ' + self._GetChromiumVersionString())
    policy_definitions_elem = self._doc.documentElement

    policy_definitions_elem.attributes['revision'] = '1.0'
    policy_definitions_elem.attributes['schemaVersion'] = '1.0'

    self._AddPolicyNamespaces(policy_definitions_elem,
                              self.config['admx_prefix'],
                              self.config['admx_namespace'])
    self.AddElement(policy_definitions_elem, 'resources',
                    {'minRequiredRevision' : '1.0'})
    self._AddSupportedOn(policy_definitions_elem,
                         self.config['win_supported_os'])
    self._categories_elem = self.AddElement(policy_definitions_elem,
                                            'categories')
    self._AddCategories(self.config['win_mandatory_category_path'])
    self._AddCategories(self.config['win_recommended_category_path'])
    self._active_policies_elem = self.AddElement(policy_definitions_elem,
                                                 'policies')
    self._active_mandatory_policy_group_name = \
        self.config['win_mandatory_category_path'][-1]
    self._active_recommended_policy_group_name = \
        self.config['win_recommended_category_path'][-1]

  def GetTemplateText(self):
    return self.ToPrettyXml(self._doc)
