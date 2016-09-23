#!/usr/bin/env python
# Copyright (c) 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.


import json

from grit.format.policy_templates.writers import template_writer


def GetWriter(config):
  '''Factory method for creating RegWriter objects.
  See the constructor of TemplateWriter for description of
  arguments.
  '''
  return RegWriter(['win'], config)


class RegWriter(template_writer.TemplateWriter):
  '''Class for generating policy example files in .reg format (for Windows).
  The generated files will define all the supported policies with example
  values  set for them. This class is used by PolicyTemplateGenerator to
  write .reg  files.
  '''

  NEWLINE = '\r\n'

  def _EscapeRegString(self, string):
    return string.replace('\\', '\\\\').replace('\"', '\\\"')

  def _StartBlock(self, key, suffix, list):
    key = 'HKEY_LOCAL_MACHINE\\' + key
    if suffix:
      key = key + '\\' + suffix
    if key != self._last_key.get(id(list), None):
      list.append('')
      list.append('[%s]' % key)
      self._last_key[id(list)] = key

  def PreprocessPolicies(self, policy_list):
    return self.FlattenGroupsAndSortPolicies(policy_list,
                                             self.GetPolicySortingKey)

  def GetPolicySortingKey(self, policy):
    '''Extracts a sorting key from a policy. These keys can be used for
    list.sort() methods to sort policies.
    See TemplateWriter.SortPoliciesGroupsFirst for usage.
    '''
    is_list = policy['type'] in ('list', 'string-enum-list')
    # Lists come after regular policies.
    return (is_list, policy['name'])

  def _WritePolicy(self, policy, key, list):
    example_value = policy['example_value']

    if policy['type'] == 'external':
      # This type can only be set through cloud policy.
      return
    elif policy['type'] in ('list', 'string-enum-list'):
      self._StartBlock(key, policy['name'], list)
      i = 1
      for item in example_value:
        escaped_str = self._EscapeRegString(item)
        list.append('"%d"="%s"' % (i, escaped_str))
        i = i + 1
    else:
      self._StartBlock(key, None, list)
      if policy['type'] in ('string', 'string-enum', 'dict'):
        example_value_str = json.dumps(example_value, sort_keys=True)
        if policy['type'] == 'dict':
          example_value_str = '"%s"' % example_value_str
      elif policy['type'] == 'main':
        if example_value == True:
          example_value_str = 'dword:00000001'
        else:
          example_value_str = 'dword:00000000'
      elif policy['type'] in ('int', 'int-enum'):
        example_value_str = 'dword:%08x' % example_value
      else:
        raise Exception('unknown policy type %s:' % policy['type'])

      list.append('"%s"=%s' % (policy['name'], example_value_str))

  def WriteComment(self, comment):
    self._prefix.append('; ' + comment)

  def WritePolicy(self, policy):
    if self.CanBeMandatory(policy):
      self._WritePolicy(policy,
                        self.config['win_reg_mandatory_key_name'],
                        self._mandatory)

  def WriteRecommendedPolicy(self, policy):
    self._WritePolicy(policy,
                      self.config['win_reg_recommended_key_name'],
                      self._recommended)

  def BeginTemplate(self):
    pass

  def EndTemplate(self):
    pass

  def Init(self):
    self._mandatory = []
    self._recommended = []
    self._last_key = {}
    self._prefix = []

  def GetTemplateText(self):
    self._prefix.append('Windows Registry Editor Version 5.00')
    if self._GetChromiumVersionString() is not None:
      self.WriteComment(self.config['build'] + ' version: ' + \
          self._GetChromiumVersionString())
    all = self._prefix + self._mandatory + self._recommended
    return self.NEWLINE.join(all)
