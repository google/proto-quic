# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import json
import os
import tempfile

from devil.utils import cmd_helper
from pylib import constants
from pylib.base import base_test_result
from pylib.base import test_run
from pylib.results import json_results


class LocalMachineJunitTestRun(test_run.TestRun):
  def __init__(self, env, test_instance):
    super(LocalMachineJunitTestRun, self).__init__(env, test_instance)

  #override
  def TestPackage(self):
    return self._test_instance.suite

  #override
  def SetUp(self):
    pass

  #override
  def RunTests(self):
    with tempfile.NamedTemporaryFile() as json_file:
      java_script = os.path.join(
          constants.GetOutDirectory(), 'bin', 'helper',
          self._test_instance.suite)
      command = [java_script]

      # Add Jar arguments.
      jar_args = ['-test-jars', self._test_instance.suite + '.jar',
                  '-json-results-file', json_file.name]
      if self._test_instance.test_filter:
        jar_args.extend(['-gtest-filter', self._test_instance.test_filter])
      if self._test_instance.package_filter:
        jar_args.extend(['-package-filter',
                         self._test_instance.package_filter])
      if self._test_instance.runner_filter:
        jar_args.extend(['-runner-filter', self._test_instance.runner_filter])
      command.extend(['--jar-args', '"%s"' % ' '.join(jar_args)])

      # Add JVM arguments.
      jvm_args = []
      # TODO(mikecase): Add a --robolectric-dep-dir arg to test runner.
      # Have this arg set by GN in the generated test runner scripts.
      jvm_args += [
          '-Drobolectric.dependency.dir=%s' %
          os.path.join(constants.GetOutDirectory(),
              'lib.java', 'third_party', 'robolectric')]
      if self._test_instance.coverage_dir:
        if not os.path.exists(self._test_instance.coverage_dir):
          os.makedirs(self._test_instance.coverage_dir)
        elif not os.path.isdir(self._test_instance.coverage_dir):
          raise Exception('--coverage-dir takes a directory, not file path.')
        jvm_args.append('-Demma.coverage.out.file=%s' % os.path.join(
            self._test_instance.coverage_dir,
            '%s.ec' % self._test_instance.suite))
      if jvm_args:
        command.extend(['--jvm-args', '"%s"' % ' '.join(jvm_args)])

      cmd_helper.RunCmd(command)
      results_list = json_results.ParseResultsFromJson(
          json.loads(json_file.read()))

      test_run_results = base_test_result.TestRunResults()
      test_run_results.AddResults(results_list)

      return [test_run_results]

  #override
  def TearDown(self):
    pass
