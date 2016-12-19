#!/usr/bin/env python
# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Unit tests for instrumentation_test_instance."""

# pylint: disable=protected-access

import unittest

from pylib.base import base_test_result
from pylib.constants import host_paths
from pylib.instrumentation import instrumentation_test_instance

with host_paths.SysPath(host_paths.PYMOCK_PATH):
  import mock  # pylint: disable=import-error

_INSTRUMENTATION_TEST_INSTANCE_PATH = (
    'pylib.instrumentation.instrumentation_test_instance.%s')

class InstrumentationTestInstanceTest(unittest.TestCase):

  def setUp(self):
    options = mock.Mock()
    options.tool = ''

  @staticmethod
  def createTestInstance():
    c = _INSTRUMENTATION_TEST_INSTANCE_PATH % 'InstrumentationTestInstance'
    with mock.patch('%s._initializeApkAttributes' % c), (
         mock.patch('%s._initializeDataDependencyAttributes' % c)), (
         mock.patch('%s._initializeTestFilterAttributes' % c)), (
         mock.patch('%s._initializeFlagAttributes' % c)), (
         mock.patch('%s._initializeDriverAttributes' % c)), (
         mock.patch('%s._initializeTestControlAttributes' % c)), (
         mock.patch('%s._initializeTestCoverageAttributes' % c)):
      return instrumentation_test_instance.InstrumentationTestInstance(
          mock.MagicMock(), mock.MagicMock(), lambda s: None)

  def testGetTests_noFilter(self):
    o = self.createTestInstance()
    raw_tests = [
      {
        'annotations': {'Feature': {'value': ['Foo']}},
        'class': 'org.chromium.test.SampleTest',
        'methods': [
          {
            'annotations': {'SmallTest': None},
            'method': 'testMethod1',
          },
          {
            'annotations': {'MediumTest': None},
            'method': 'testMethod2',
          },
        ],
      },
      {
        'annotations': {'Feature': {'value': ['Bar']}},
        'class': 'org.chromium.test.SampleTest2',
        'methods': [
          {
            'annotations': {'SmallTest': None},
            'method': 'testMethod1',
          },
        ],
      }
    ]

    expected_tests = [
      {
        'annotations': {
          'Feature': {'value': ['Foo']},
          'SmallTest': None,
        },
        'class': 'org.chromium.test.SampleTest',
        'method': 'testMethod1',
      },
      {
        'annotations': {
          'Feature': {'value': ['Foo']},
          'MediumTest': None,
        },
        'class': 'org.chromium.test.SampleTest',
        'method': 'testMethod2',
      },
      {
        'annotations': {
          'Feature': {'value': ['Bar']},
          'SmallTest': None,
        },
        'class': 'org.chromium.test.SampleTest2',
        'method': 'testMethod1',
      },
    ]

    o._test_jar = 'path/to/test.jar'
    with mock.patch(_INSTRUMENTATION_TEST_INSTANCE_PATH % '_GetTestsFromPickle',
                    return_value=raw_tests):
      actual_tests = o.GetTests()

    self.assertEquals(actual_tests, expected_tests)

  def testGetTests_simpleGtestFilter(self):
    o = self.createTestInstance()
    raw_tests = [
      {
        'annotations': {'Feature': {'value': ['Foo']}},
        'class': 'org.chromium.test.SampleTest',
        'methods': [
          {
            'annotations': {'SmallTest': None},
            'method': 'testMethod1',
          },
          {
            'annotations': {'MediumTest': None},
            'method': 'testMethod2',
          },
        ],
      }
    ]

    expected_tests = [
      {
        'annotations': {
          'Feature': {'value': ['Foo']},
          'SmallTest': None,
        },
        'class': 'org.chromium.test.SampleTest',
        'method': 'testMethod1',
      },
    ]

    o._test_filter = 'org.chromium.test.SampleTest.testMethod1'
    o._test_jar = 'path/to/test.jar'
    with mock.patch(_INSTRUMENTATION_TEST_INSTANCE_PATH % '_GetTestsFromPickle',
                    return_value=raw_tests):
      actual_tests = o.GetTests()

    self.assertEquals(actual_tests, expected_tests)

  def testGetTests_wildcardGtestFilter(self):
    o = self.createTestInstance()
    raw_tests = [
      {
        'annotations': {'Feature': {'value': ['Foo']}},
        'class': 'org.chromium.test.SampleTest',
        'methods': [
          {
            'annotations': {'SmallTest': None},
            'method': 'testMethod1',
          },
          {
            'annotations': {'MediumTest': None},
            'method': 'testMethod2',
          },
        ],
      },
      {
        'annotations': {'Feature': {'value': ['Bar']}},
        'class': 'org.chromium.test.SampleTest2',
        'methods': [
          {
            'annotations': {'SmallTest': None},
            'method': 'testMethod1',
          },
        ],
      }
    ]

    expected_tests = [
      {
        'annotations': {
          'Feature': {'value': ['Bar']},
          'SmallTest': None,
        },
        'class': 'org.chromium.test.SampleTest2',
        'method': 'testMethod1',
      },
    ]

    o._test_filter = 'org.chromium.test.SampleTest2.*'
    o._test_jar = 'path/to/test.jar'
    with mock.patch(_INSTRUMENTATION_TEST_INSTANCE_PATH % '_GetTestsFromPickle',
                    return_value=raw_tests):
      actual_tests = o.GetTests()

    self.assertEquals(actual_tests, expected_tests)

  def testGetTests_negativeGtestFilter(self):
    o = self.createTestInstance()
    raw_tests = [
      {
        'annotations': {'Feature': {'value': ['Foo']}},
        'class': 'org.chromium.test.SampleTest',
        'methods': [
          {
            'annotations': {'SmallTest': None},
            'method': 'testMethod1',
          },
          {
            'annotations': {'MediumTest': None},
            'method': 'testMethod2',
          },
        ],
      },
      {
        'annotations': {'Feature': {'value': ['Bar']}},
        'class': 'org.chromium.test.SampleTest2',
        'methods': [
          {
            'annotations': {'SmallTest': None},
            'method': 'testMethod1',
          },
        ],
      }
    ]

    expected_tests = [
      {
        'annotations': {
          'Feature': {'value': ['Foo']},
          'MediumTest': None,
        },
        'class': 'org.chromium.test.SampleTest',
        'method': 'testMethod2',
      },
      {
        'annotations': {
          'Feature': {'value': ['Bar']},
          'SmallTest': None,
        },
        'class': 'org.chromium.test.SampleTest2',
        'method': 'testMethod1',
      },
    ]

    o._test_filter = '*-org.chromium.test.SampleTest.testMethod1'
    o._test_jar = 'path/to/test.jar'
    with mock.patch(_INSTRUMENTATION_TEST_INSTANCE_PATH % '_GetTestsFromPickle',
                    return_value=raw_tests):
      actual_tests = o.GetTests()

    self.assertEquals(actual_tests, expected_tests)

  def testGetTests_annotationFilter(self):
    o = self.createTestInstance()
    raw_tests = [
      {
        'annotations': {'Feature': {'value': ['Foo']}},
        'class': 'org.chromium.test.SampleTest',
        'methods': [
          {
            'annotations': {'SmallTest': None},
            'method': 'testMethod1',
          },
          {
            'annotations': {'MediumTest': None},
            'method': 'testMethod2',
          },
        ],
      },
      {
        'annotations': {'Feature': {'value': ['Bar']}},
        'class': 'org.chromium.test.SampleTest2',
        'methods': [
          {
            'annotations': {'SmallTest': None},
            'method': 'testMethod1',
          },
        ],
      }
    ]

    expected_tests = [
      {
        'annotations': {
          'Feature': {'value': ['Foo']},
          'SmallTest': None,
        },
        'class': 'org.chromium.test.SampleTest',
        'method': 'testMethod1',
      },
      {
        'annotations': {
          'Feature': {'value': ['Bar']},
          'SmallTest': None,
        },
        'class': 'org.chromium.test.SampleTest2',
        'method': 'testMethod1',
      },
    ]

    o._annotations = [('SmallTest', None)]
    o._test_jar = 'path/to/test.jar'
    with mock.patch(_INSTRUMENTATION_TEST_INSTANCE_PATH % '_GetTestsFromPickle',
                    return_value=raw_tests):
      actual_tests = o.GetTests()

    self.assertEquals(actual_tests, expected_tests)

  def testGetTests_excludedAnnotationFilter(self):
    o = self.createTestInstance()
    raw_tests = [
      {
        'annotations': {'Feature': {'value': ['Foo']}},
        'class': 'org.chromium.test.SampleTest',
        'methods': [
          {
            'annotations': {'SmallTest': None},
            'method': 'testMethod1',
          },
          {
            'annotations': {'MediumTest': None},
            'method': 'testMethod2',
          },
        ],
      },
      {
        'annotations': {'Feature': {'value': ['Bar']}},
        'class': 'org.chromium.test.SampleTest2',
        'methods': [
          {
            'annotations': {'SmallTest': None},
            'method': 'testMethod1',
          },
        ],
      }
    ]

    expected_tests = [
      {
        'annotations': {
          'Feature': {'value': ['Foo']},
          'MediumTest': None,
        },
        'class': 'org.chromium.test.SampleTest',
        'method': 'testMethod2',
      },
    ]

    o._excluded_annotations = [('SmallTest', None)]
    o._test_jar = 'path/to/test.jar'
    with mock.patch(_INSTRUMENTATION_TEST_INSTANCE_PATH % '_GetTestsFromPickle',
                    return_value=raw_tests):
      actual_tests = o.GetTests()

    self.assertEquals(actual_tests, expected_tests)

  def testGetTests_annotationSimpleValueFilter(self):
    o = self.createTestInstance()
    raw_tests = [
      {
        'annotations': {'Feature': {'value': ['Foo']}},
        'class': 'org.chromium.test.SampleTest',
        'methods': [
          {
            'annotations': {
              'SmallTest': None,
              'TestValue': '1',
            },
            'method': 'testMethod1',
          },
          {
            'annotations': {
              'MediumTest': None,
              'TestValue': '2',
            },
            'method': 'testMethod2',
          },
        ],
      },
      {
        'annotations': {'Feature': {'value': ['Bar']}},
        'class': 'org.chromium.test.SampleTest2',
        'methods': [
          {
            'annotations': {
              'SmallTest': None,
              'TestValue': '3',
            },
            'method': 'testMethod1',
          },
        ],
      }
    ]

    expected_tests = [
      {
        'annotations': {
          'Feature': {'value': ['Foo']},
          'SmallTest': None,
          'TestValue': '1',
        },
        'class': 'org.chromium.test.SampleTest',
        'method': 'testMethod1',
      },
    ]

    o._annotations = [('TestValue', '1')]
    o._test_jar = 'path/to/test.jar'
    with mock.patch(_INSTRUMENTATION_TEST_INSTANCE_PATH % '_GetTestsFromPickle',
                    return_value=raw_tests):
      actual_tests = o.GetTests()

    self.assertEquals(actual_tests, expected_tests)

  def testGetTests_annotationDictValueFilter(self):
    o = self.createTestInstance()
    raw_tests = [
      {
        'annotations': {'Feature': {'value': ['Foo']}},
        'class': 'org.chromium.test.SampleTest',
        'methods': [
          {
            'annotations': {'SmallTest': None},
            'method': 'testMethod1',
          },
          {
            'annotations': {'MediumTest': None},
            'method': 'testMethod2',
          },
        ],
      },
      {
        'annotations': {'Feature': {'value': ['Bar']}},
        'class': 'org.chromium.test.SampleTest2',
        'methods': [
          {
            'annotations': {'SmallTest': None},
            'method': 'testMethod1',
          },
        ],
      }
    ]

    expected_tests = [
      {
        'annotations': {
          'Feature': {'value': ['Bar']},
          'SmallTest': None,
        },
        'class': 'org.chromium.test.SampleTest2',
        'method': 'testMethod1',
      },
    ]

    o._annotations = [('Feature', 'Bar')]
    o._test_jar = 'path/to/test.jar'
    with mock.patch(_INSTRUMENTATION_TEST_INSTANCE_PATH % '_GetTestsFromPickle',
                    return_value=raw_tests):
      actual_tests = o.GetTests()

    self.assertEquals(actual_tests, expected_tests)

  def testGetTests_multipleAnnotationValuesRequested(self):
    o = self.createTestInstance()
    raw_tests = [
      {
        'annotations': {'Feature': {'value': ['Foo']}},
        'class': 'org.chromium.test.SampleTest',
        'methods': [
          {
            'annotations': {'SmallTest': None},
            'method': 'testMethod1',
          },
          {
            'annotations': {
              'Feature': {'value': ['Baz']},
              'MediumTest': None,
            },
            'method': 'testMethod2',
          },
        ],
      },
      {
        'annotations': {'Feature': {'value': ['Bar']}},
        'class': 'org.chromium.test.SampleTest2',
        'methods': [
          {
            'annotations': {'SmallTest': None},
            'method': 'testMethod1',
          },
        ],
      }
    ]

    expected_tests = [
      {
        'annotations': {
          'Feature': {'value': ['Baz']},
          'MediumTest': None,
        },
        'class': 'org.chromium.test.SampleTest',
        'method': 'testMethod2',
      },
      {
        'annotations': {
          'Feature': {'value': ['Bar']},
          'SmallTest': None,
        },
        'class': 'org.chromium.test.SampleTest2',
        'method': 'testMethod1',
      },
    ]

    o._annotations = [('Feature', 'Bar'), ('Feature', 'Baz')]
    o._test_jar = 'path/to/test.jar'
    with mock.patch(_INSTRUMENTATION_TEST_INSTANCE_PATH % '_GetTestsFromPickle',
                    return_value=raw_tests):
      actual_tests = o.GetTests()

    self.assertEquals(actual_tests, expected_tests)

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

  def testGenerateJUnitTestResults_testSkipped_true(self):
    statuses = [
      (1, {
        'class': 'test.package.TestClass',
        'test': 'testMethod',
      }),
      (-3, {
        'class': 'test.package.TestClass',
        'test': 'testMethod',
      }),
    ]
    results = instrumentation_test_instance.GenerateTestResults(
        None, None, statuses, 0, 1000)
    self.assertEqual(1, len(results))
    self.assertEqual(base_test_result.ResultType.SKIP, results[0].GetType())


if __name__ == '__main__':
  unittest.main(verbosity=2)
