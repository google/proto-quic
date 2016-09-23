#!/usr/bin/env python
# Copyright (c) 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

'''Unit tests for grit.format.policy_templates.writers.template_writer'''

import os
import sys
if __name__ == '__main__':
  sys.path.append(os.path.join(os.path.dirname(__file__), '../../../..'))

import unittest

from grit.format.policy_templates.writers import template_writer


POLICY_DEFS = [
  {'name': 'zp', 'type': 'string', 'caption': 'a1', 'supported_on': []},
  {
    'type': 'group',
    'caption': 'z_group1_caption',
    'name': 'group1',
    'policies': [
      {'name': 'z0', 'type': 'string', 'supported_on': []},
      {'name': 'a0', 'type': 'string', 'supported_on': []}
    ]
  },
  {
    'type': 'group',
    'caption': 'b_group2_caption',
    'name': 'group2',
    'policies': [{'name': 'q', 'type': 'string', 'supported_on': []}],
  },
  {'name': 'ap', 'type': 'string', 'caption': 'a2', 'supported_on': []}
]


GROUP_FIRST_SORTED_POLICY_DEFS = [
  {
    'type': 'group',
    'caption': 'b_group2_caption',
    'name': 'group2',
    'policies': [{'name': 'q', 'type': 'string', 'supported_on': []}],
  },
  {
    'type': 'group',
    'caption': 'z_group1_caption',
    'name': 'group1',
    'policies': [
      {'name': 'z0', 'type': 'string', 'supported_on': []},
      {'name': 'a0', 'type': 'string', 'supported_on': []}
    ]
  },
  {'name': 'ap', 'type': 'string', 'caption': 'a2', 'supported_on': []},
  {'name': 'zp', 'type': 'string', 'caption': 'a1', 'supported_on': []},
]


IGNORE_GROUPS_SORTED_POLICY_DEFS = [
  {'name': 'a0', 'type': 'string', 'supported_on': []},
  {'name': 'ap', 'type': 'string', 'caption': 'a2', 'supported_on': []},
  {'name': 'q', 'type': 'string', 'supported_on': []},
  {'name': 'z0', 'type': 'string', 'supported_on': []},
  {'name': 'zp', 'type': 'string', 'caption': 'a1', 'supported_on': []},
]


class TemplateWriterUnittests(unittest.TestCase):
  '''Unit tests for templater_writer.py.'''

  def testSortingGroupsFirst(self):
    tw = template_writer.TemplateWriter(None, None)
    sorted_list = tw.SortPoliciesGroupsFirst(POLICY_DEFS)
    self.assertEqual(sorted_list, GROUP_FIRST_SORTED_POLICY_DEFS)

  def testSortingIgnoreGroups(self):
    tw = template_writer.TemplateWriter(None, None)
    sorted_list = tw.FlattenGroupsAndSortPolicies(POLICY_DEFS)
    self.assertEqual(sorted_list, IGNORE_GROUPS_SORTED_POLICY_DEFS)


if __name__ == '__main__':
  unittest.main()
