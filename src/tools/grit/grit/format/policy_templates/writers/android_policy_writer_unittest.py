#!/usr/bin/env python
# Copyright (c) 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

'''Unit tests for grit.format.policy_templates.writers.android_policy_writer'''


import os
import sys
if __name__ == '__main__':
  sys.path.append(os.path.join(os.path.dirname(__file__), '../../../..'))

import unittest
from xml.dom import minidom

from grit.format.policy_templates.writers import writer_unittest_common
from grit.format.policy_templates.writers import android_policy_writer


class AndroidPolicyWriterUnittest(writer_unittest_common.WriterUnittestCommon):
  '''Unit tests to test assumptions in Android Policy Writer'''

  def testPolicyWithoutItems(self):
    # Test an example policy without items.
    policy = {
      'name': '_policy_name',
      'caption': '_policy_caption',
      'desc': 'This is a long policy caption. More than one sentence '
              'in a single line because it is very important.\nIgnore this.'
    }
    writer = android_policy_writer.GetWriter({})
    writer.Init()
    writer.BeginTemplate()
    writer.WritePolicy(policy)
    self.assertEquals(
        writer._resources.toxml(),
        '<resources>'
          '<string name="_policy_nameTitle">_policy_caption</string>'
          '<string name="_policy_nameDesc">This is a long policy caption. More '
              'than one sentence in a single line because it is very important.'
          '</string>'
        '</resources>')

  def testPolicyWithItems(self):
    # Test an example policy without items.
    policy = {
      'name': '_policy_name',
      'caption': '_policy_caption',
      'desc': '_policy_desc_first.\n_ignored_policy_desc',
      'items': [
        {
          'caption':'_caption1',
          'value':'_value1',
        },
        {
          'caption':'_caption2',
          'value':'_value2',
        }
      ]
    }
    writer = android_policy_writer.GetWriter({})
    writer.Init()
    writer.BeginTemplate()
    writer.WritePolicy(policy)
    self.assertEquals(
        writer._resources.toxml(),
        '<resources>'
          '<string name="_policy_nameTitle">_policy_caption</string>'
          '<string name="_policy_nameDesc">_policy_desc_first.</string>'
          '<string-array name="_policy_nameEntries">'
            '<item>_caption1</item>'
            '<item>_caption2</item>'
          '</string-array>'
          '<string-array name="_policy_nameValues">'
            '<item>_value1</item>'
            '<item>_value2</item>'
          '</string-array>'
        '</resources>')

if __name__ == '__main__':
    unittest.main()
