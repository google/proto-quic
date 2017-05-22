#!/usr/bin/env python
# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from os import path as os_path
import re
import resource_checker
from sys import path as sys_path
import test_util
import unittest

_HERE = os_path.dirname(os_path.abspath(__file__))
sys_path.append(os_path.join(_HERE, '..', '..', 'build'))

import find_depot_tools  # pylint: disable=W0611
from testing_support.super_mox import SuperMoxTestBase


class ResourceCheckerTest(SuperMoxTestBase):
  def setUp(self):
    SuperMoxTestBase.setUp(self)

    input_api = self.mox.CreateMockAnything()
    input_api.re = re
    output_api = self.mox.CreateMockAnything()
    self.checker = resource_checker.ResourceChecker(input_api, output_api)

  def ShouldFailIncludeCheck(self, line):
    """Checks that the '</include>' checker flags |line| as a style error."""
    error = self.checker.IncludeCheck(1, line)
    self.assertNotEqual('', error,
        'Should be flagged as style error: ' + line)
    highlight = test_util.GetHighlight(line, error).strip()
    self.assertTrue('include' in highlight and highlight[0] == '<')

  def ShouldPassIncludeCheck(self, line):
    """Checks that the '</include>' checker doesn't flag |line| as an error."""
    self.assertEqual('', self.checker.IncludeCheck(1, line),
        'Should not be flagged as style error: ' + line)

  def testIncludeFails(self):
    lines = [
        "</include>   ",
        "    </include>",
        "    </include>   ",
        '  <include src="blah.js" />   ',
        '<include src="blee.js"/>',
    ]
    for line in lines:
      self.ShouldFailIncludeCheck(line)

  def testIncludePasses(self):
    lines = [
        '<include src="assert.js">',
        "<include src='../../assert.js'>",
        "<i>include src='blah'</i>",
        "</i>nclude",
        "</i>include",
    ]
    for line in lines:
      self.ShouldPassIncludeCheck(line)


if __name__ == '__main__':
  unittest.main()
