#!/usr/bin/env python
# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.


"""Unit tests for instrumentation.TestRunner."""

import unittest

from pylib.base import base_test_result
from pylib.constants import host_paths
from pylib.instrumentation import instrumentation_test_instance

with host_paths.SysPath(host_paths.PYMOCK_PATH):
  import mock  # pylint: disable=import-error


class InstrumentationTestInstanceTest(unittest.TestCase):

  def setUp(self):
    options = mock.Mock()
    options.tool = ''

  def testGenerateTestResults_noStatus(self):
    results = instrumentation_test_instance.GenerateTestResults(
        None, None, [], 0, 1000)
    self.assertEqual([], results)

  def testGenerateTestResults_testPassed(self):
    statuses = [
      (1, {
        'class': 'test.package.TestClass',
        'test': 'testMethod',
      }),
      (0, {
        'class': 'test.package.TestClass',
        'test': 'testMethod',
      }),
    ]
    results = instrumentation_test_instance.GenerateTestResults(
        None, None, statuses, 0, 1000)
    self.assertEqual(1, len(results))
    self.assertEqual(base_test_result.ResultType.PASS, results[0].GetType())

  def testGenerateTestResults_testSkipped_true(self):
    statuses = [
      (1, {
        'class': 'test.package.TestClass',
        'test': 'testMethod',
      }),
      (0, {
        'test_skipped': 'true',
        'class': 'test.package.TestClass',
        'test': 'testMethod',
      }),
      (0, {
        'class': 'test.package.TestClass',
        'test': 'testMethod',
      }),
    ]
    results = instrumentation_test_instance.GenerateTestResults(
        None, None, statuses, 0, 1000)
    self.assertEqual(1, len(results))
    self.assertEqual(base_test_result.ResultType.SKIP, results[0].GetType())

  def testGenerateTestResults_testSkipped_false(self):
    statuses = [
      (1, {
        'class': 'test.package.TestClass',
        'test': 'testMethod',
      }),
      (0, {
        'test_skipped': 'false',
      }),
      (0, {
        'class': 'test.package.TestClass',
        'test': 'testMethod',
      }),
    ]
    results = instrumentation_test_instance.GenerateTestResults(
        None, None, statuses, 0, 1000)
    self.assertEqual(1, len(results))
    self.assertEqual(base_test_result.ResultType.PASS, results[0].GetType())

  def testGenerateTestResults_testFailed(self):
    statuses = [
      (1, {
        'class': 'test.package.TestClass',
        'test': 'testMethod',
      }),
      (-2, {
        'class': 'test.package.TestClass',
        'test': 'testMethod',
      }),
    ]
    results = instrumentation_test_instance.GenerateTestResults(
        None, None, statuses, 0, 1000)
    self.assertEqual(1, len(results))
    self.assertEqual(base_test_result.ResultType.FAIL, results[0].GetType())

  def testGenerateTestResults_testUnknownException(self):
    stacktrace = 'long\nstacktrace'
    statuses = [
      (1, {
        'class': 'test.package.TestClass',
        'test': 'testMethod',
      }),
      (-1, {
        'class': 'test.package.TestClass',
        'test': 'testMethod',
        'stack': stacktrace,
      }),
    ]
    results = instrumentation_test_instance.GenerateTestResults(
        None, None, statuses, 0, 1000)
    self.assertEqual(1, len(results))
    self.assertEqual(base_test_result.ResultType.FAIL, results[0].GetType())
    self.assertEqual(stacktrace, results[0].GetLog())


if __name__ == '__main__':
  unittest.main(verbosity=2)
