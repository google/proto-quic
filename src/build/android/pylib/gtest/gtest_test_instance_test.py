#!/usr/bin/env python
# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import unittest

from pylib.base import base_test_result
from pylib.gtest import gtest_test_instance


class GtestTestInstanceTests(unittest.TestCase):

  def testParseGTestListTests_simple(self):
    raw_output = [
      'TestCaseOne.',
      '  testOne',
      '  testTwo',
      'TestCaseTwo.',
      '  testThree',
      '  testFour',
    ]
    actual = gtest_test_instance.ParseGTestListTests(raw_output)
    expected = [
      'TestCaseOne.testOne',
      'TestCaseOne.testTwo',
      'TestCaseTwo.testThree',
      'TestCaseTwo.testFour',
    ]
    self.assertEqual(expected, actual)

  def testParseGTestListTests_typeParameterized_old(self):
    raw_output = [
      'TPTestCase/WithTypeParam/0.',
      '  testOne',
      '  testTwo',
    ]
    actual = gtest_test_instance.ParseGTestListTests(raw_output)
    expected = [
      'TPTestCase/WithTypeParam/0.testOne',
      'TPTestCase/WithTypeParam/0.testTwo',
    ]
    self.assertEqual(expected, actual)

  def testParseGTestListTests_typeParameterized_new(self):
    raw_output = [
      'TPTestCase/WithTypeParam/0.  # TypeParam = TypeParam0',
      '  testOne',
      '  testTwo',
    ]
    actual = gtest_test_instance.ParseGTestListTests(raw_output)
    expected = [
      'TPTestCase/WithTypeParam/0.testOne',
      'TPTestCase/WithTypeParam/0.testTwo',
    ]
    self.assertEqual(expected, actual)

  def testParseGTestListTests_valueParameterized_old(self):
    raw_output = [
      'VPTestCase.',
      '  testWithValueParam/0',
      '  testWithValueParam/1',
    ]
    actual = gtest_test_instance.ParseGTestListTests(raw_output)
    expected = [
      'VPTestCase.testWithValueParam/0',
      'VPTestCase.testWithValueParam/1',
    ]
    self.assertEqual(expected, actual)

  def testParseGTestListTests_valueParameterized_new(self):
    raw_output = [
      'VPTestCase.',
      '  testWithValueParam/0  # GetParam() = 0',
      '  testWithValueParam/1  # GetParam() = 1',
    ]
    actual = gtest_test_instance.ParseGTestListTests(raw_output)
    expected = [
      'VPTestCase.testWithValueParam/0',
      'VPTestCase.testWithValueParam/1',
    ]
    self.assertEqual(expected, actual)

  def testParseGTestOutput_pass(self):
    raw_output = [
      '[ RUN      ] FooTest.Bar',
      '[       OK ] FooTest.Bar (1 ms)',
    ]
    actual = gtest_test_instance.ParseGTestOutput(raw_output)
    self.assertEquals(1, len(actual))
    self.assertEquals('FooTest.Bar', actual[0].GetName())
    self.assertEquals(1, actual[0].GetDuration())
    self.assertEquals(base_test_result.ResultType.PASS, actual[0].GetType())

  def testParseGTestOutput_fail(self):
    raw_output = [
      '[ RUN      ] FooTest.Bar',
      '[   FAILED ] FooTest.Bar (1 ms)',
    ]
    actual = gtest_test_instance.ParseGTestOutput(raw_output)
    self.assertEquals(1, len(actual))
    self.assertEquals('FooTest.Bar', actual[0].GetName())
    self.assertEquals(1, actual[0].GetDuration())
    self.assertEquals(base_test_result.ResultType.FAIL, actual[0].GetType())

  def testParseGTestOutput_crash(self):
    raw_output = [
      '[ RUN      ] FooTest.Bar',
      '[  CRASHED ] FooTest.Bar (1 ms)',
    ]
    actual = gtest_test_instance.ParseGTestOutput(raw_output)
    self.assertEquals(1, len(actual))
    self.assertEquals('FooTest.Bar', actual[0].GetName())
    self.assertEquals(1, actual[0].GetDuration())
    self.assertEquals(base_test_result.ResultType.CRASH, actual[0].GetType())

  def testParseGTestOutput_errorCrash(self):
    raw_output = [
      '[ RUN      ] FooTest.Bar',
      '[ERROR:blah] Currently running: FooTest.Bar',
    ]
    actual = gtest_test_instance.ParseGTestOutput(raw_output)
    self.assertEquals(1, len(actual))
    self.assertEquals('FooTest.Bar', actual[0].GetName())
    self.assertEquals(0, actual[0].GetDuration())
    self.assertEquals(base_test_result.ResultType.CRASH, actual[0].GetType())

  def testParseGTestOutput_unknown(self):
    raw_output = [
      '[ RUN      ] FooTest.Bar',
    ]
    actual = gtest_test_instance.ParseGTestOutput(raw_output)
    self.assertEquals(1, len(actual))
    self.assertEquals('FooTest.Bar', actual[0].GetName())
    self.assertEquals(0, actual[0].GetDuration())
    self.assertEquals(base_test_result.ResultType.UNKNOWN, actual[0].GetType())

  def testParseGTestOutput_nonterminalUnknown(self):
    raw_output = [
      '[ RUN      ] FooTest.Bar',
      '[ RUN      ] FooTest.Baz',
      '[       OK ] FooTest.Baz (1 ms)',
    ]
    actual = gtest_test_instance.ParseGTestOutput(raw_output)
    self.assertEquals(2, len(actual))

    self.assertEquals('FooTest.Bar', actual[0].GetName())
    self.assertEquals(0, actual[0].GetDuration())
    self.assertEquals(base_test_result.ResultType.UNKNOWN, actual[0].GetType())

    self.assertEquals('FooTest.Baz', actual[1].GetName())
    self.assertEquals(1, actual[1].GetDuration())
    self.assertEquals(base_test_result.ResultType.PASS, actual[1].GetType())

  def testParseGTestOutput_deathTestCrashOk(self):
    raw_output = [
      '[ RUN      ] FooTest.Bar',
      '[ CRASHED      ]',
      '[       OK ] FooTest.Bar (1 ms)',
    ]
    actual = gtest_test_instance.ParseGTestOutput(raw_output)
    self.assertEquals(1, len(actual))

    self.assertEquals('FooTest.Bar', actual[0].GetName())
    self.assertEquals(1, actual[0].GetDuration())
    self.assertEquals(base_test_result.ResultType.PASS, actual[0].GetType())


if __name__ == '__main__':
  unittest.main(verbosity=2)

