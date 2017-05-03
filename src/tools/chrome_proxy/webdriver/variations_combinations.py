# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import re
import sys
import time
import unittest

import common


combinations = [
  # One object for each set of tests to run with the given variations.
  {
    'label': 'dummy example',
    'tests': [
      # Of the form <file_name>.<class_name>.<method_name>
      # Also accepts wildcard (*) as matching anything.
      "lite_page.LitePage.testLitePage",
      "lite_page.LitePage.testLitePageFallback",
      "quic*"
    ],
    'variations': [
      "DataReductionProxyUseQuic/Enabled",
      "DataCompressionProxyLoFi/Enabled_Preview",
      "DataCompressionProxyLitePageFallback/Enabled"
    ],
    'variations-params': [
      "DataCompressionProxyLoFi.Enabled_Preview:effective_connection_type/4G"
    ]
  }
]


def GetAllTestsFromRegexList(test_list, test_suite_iter):
  """A helper function to make a test suite from tests matching the given list.

  Args:
    test_list: a string list of all tests to run, allowing for simple regex
    test_suite_iter: An iterator of all test suites to search
  Returns:
    a test suite with all the tests specified by the test_list
  """
  id_to_test_map = {}
  for test_suite in test_suite_iter:
    for test_case in test_suite:
      for test_method in test_case:
        id_to_test_map[test_method.id()] = test_method
  my_test_suite = unittest.TestSuite()
  for test_spec in test_list:
    regex = re.compile('^' + test_spec.replace('.', '\\.').replace('*', '.*')
      + '$')
    for test_id in sorted(id_to_test_map):
      if regex.match(test_id):
        my_test_suite.addTest(id_to_test_map[test_id])
  return my_test_suite

def ParseFlagsWithExtraBrowserArgs(extra_args):
  """Generates a function to override common.ParseFlags.

  The returned function will honor everything in the original ParseFlags(), but
  adds on additional browser_args.

  Args:
    extra_args: The extra browser agruments to add.
  Returns:
    A function to override common.ParseFlags with additional browser_args.
  """
  original_flags = common.ParseFlags()
  def AddExtraBrowserArgs():
    original_flags.browser_args = ((original_flags.browser_args if
      original_flags.browser_args else '') + ' ' + extra_args)
    return original_flags
  return AddExtraBrowserArgs

def main():
  """Runs each set of tests against its set of variations.

  For each test combination, the above variation specifications will be used to
  setup the browser arguments for each test given above that will be run.
  """
  flags = common.ParseFlags()
  for variation_test in combinations:
    # Set browser arguments to use the given variations.
    extra_args = '--force-fieldtrials=' + '/'.join(variation_test['variations'])
    extra_args += ' --force-fieldtrial-params=' + ','.join(
      variation_test['variations-params'])
    common.ParseFlags = ParseFlagsWithExtraBrowserArgs(extra_args)
    # Run the given tests.
    loader = unittest.TestLoader()
    test_suite_iter = loader.discover(os.path.dirname(__file__), pattern='*.py')
    my_test_suite = GetAllTestsFromRegexList(variation_test['tests'],
      test_suite_iter)
    testRunner = unittest.runner.TextTestRunner(verbosity=2,
      failfast=flags.failfast, buffer=(not flags.disable_buffer))
    testRunner.run(my_test_suite)

if __name__ == '__main__':
  main()
