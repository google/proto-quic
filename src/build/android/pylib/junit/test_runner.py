# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import json
import os
import tempfile

from devil.utils import cmd_helper
from pylib import constants
from pylib.results import json_results

class JavaTestRunner(object):
  """Runs java tests on the host."""

  def __init__(self, args):
    self._coverage_dir = args.coverage_dir
    self._package_filter = args.package_filter
    self._runner_filter = args.runner_filter

    self._test_filter = args.test_filter
    self._test_suite = args.test_suite

  def SetUp(self):
    pass

  def RunTest(self, _test):
    """Runs junit tests from |self._test_suite|."""
    with tempfile.NamedTemporaryFile() as json_file:
      java_script = os.path.join(
          constants.GetOutDirectory(), 'bin', 'helper', self._test_suite)
      command = [java_script]

      # Add Jar arguments.
      jar_args = ['-test-jars', self._test_suite + '.jar',
              '-json-results-file', json_file.name]
      if self._test_filter:
        jar_args.extend(['-gtest-filter', self._test_filter])
      if self._package_filter:
        jar_args.extend(['-package-filter', self._package_filter])
      if self._runner_filter:
        jar_args.extend(['-runner-filter', self._runner_filter])
      command.extend(['--jar-args', '"%s"' % ' '.join(jar_args)])

      # Add JVM arguments.
      jvm_args = []
      # TODO(mikecase): Add a --robolectric-dep-dir arg to test runner.
      # Have this arg set by GN in the generated test runner scripts.
      jvm_args += [
          '-Drobolectric.dependency.dir=%s' %
          os.path.join(constants.GetOutDirectory(),
              'lib.java', 'third_party', 'robolectric')]
      if self._coverage_dir:
        if not os.path.exists(self._coverage_dir):
          os.makedirs(self._coverage_dir)
        elif not os.path.isdir(self._coverage_dir):
          raise Exception('--coverage-dir takes a directory, not file path.')
        jvm_args.append('-Demma.coverage.out.file=%s' % os.path.join(
            self._coverage_dir, '%s.ec' % self._test_suite))
      if jvm_args:
        command.extend(['--jvm-args', '"%s"' % ' '.join(jvm_args)])

      return_code = cmd_helper.RunCmd(command)
      results_list = json_results.ParseResultsFromJson(
          json.loads(json_file.read()))
      return (results_list, return_code)

  def TearDown(self):
    pass

