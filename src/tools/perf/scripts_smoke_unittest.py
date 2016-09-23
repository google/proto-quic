# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import json
import os
import subprocess
import sys
import tempfile
import unittest

from telemetry import benchmark


class ScriptsSmokeTest(unittest.TestCase):

  perf_dir = os.path.dirname(__file__)

  def RunPerfScript(self, command):
    args = [sys.executable] + command.split(' ')
    proc = subprocess.Popen(args, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, cwd=self.perf_dir)
    stdout = proc.communicate()[0]
    return_code = proc.returncode
    return return_code, stdout

  def testRunBenchmarkHelp(self):
    return_code, stdout = self.RunPerfScript('run_benchmark help')
    self.assertEquals(return_code, 0, stdout)
    self.assertIn('Available commands are', stdout)

  def testRunBenchmarkRunListsOutBenchmarks(self):
    return_code, stdout = self.RunPerfScript('run_benchmark run')
    self.assertIn('Pass --browser to list benchmarks', stdout)
    self.assertNotEquals(return_code, 0)

  def testRunBenchmarkRunNonExistingBenchmark(self):
    return_code, stdout = self.RunPerfScript('run_benchmark foo')
    self.assertIn('No benchmark named "foo"', stdout)
    self.assertNotEquals(return_code, 0)

  @benchmark.Disabled('chromeos')  # crbug.com/483212
  @benchmark.Disabled('android')   # crbug.com/641934
  def testRunBenchmarkListListsOutBenchmarks(self):
    return_code, stdout = self.RunPerfScript('run_benchmark list')
    self.assertEquals(return_code, 0, stdout)
    self.assertIn('Pass --browser to list benchmarks', stdout)
    self.assertIn('dummy_benchmark.stable_benchmark_1', stdout)

  @benchmark.Disabled('all')  # crbug.com/641934
  def testRunBenchmarkListListsOutBenchmarksOnAndroid(self):
    return_code, stdout = self.RunPerfScript(
        'run_benchmark list --device=android --browser=android-chromium')
    self.assertEquals(return_code, 0, stdout)
    self.assertIn('Pass --browser to list benchmarks', stdout)
    self.assertIn('dummy_benchmark.stable_benchmark_1', stdout)

  def testRunTrybotWithTypo(self):
    return_code, stdout = self.RunPerfScript('run_benchmark try linux octaenz')
    self.assertIn('No benchmark named "octaenz"', stdout)
    self.assertIn('octane', stdout)
    self.assertNotEqual(return_code, 0)

  def testRunRecordWprHelp(self):
    return_code, stdout = self.RunPerfScript('record_wpr')
    self.assertEquals(return_code, 0, stdout)
    self.assertIn('optional arguments:', stdout)

  def testRunRecordWprList(self):
    return_code, stdout = self.RunPerfScript('record_wpr --list-benchmarks')
    # TODO(nednguyen): Remove this once we figure out why importing
    # small_profile_extender fails on Android dbg.
    # crbug.com/561668
    if 'ImportError: cannot import name small_profile_extender' in stdout:
      self.skipTest('small_profile_extender is missing')
    self.assertEquals(return_code, 0, stdout)
    self.assertIn('kraken', stdout)

  # crbug.com/483212
  @benchmark.Disabled('chromeos')
  def testRunBenchmarkListJSONListsOutBenchmarks(self):
    tmp_file = tempfile.NamedTemporaryFile(delete=False)
    tmp_file_name = tmp_file.name
    tmp_file.close()
    try:
      return_code, _ = self.RunPerfScript(
          'run_benchmark list --json-output %s' % tmp_file_name)
      self.assertEquals(return_code, 0)
      with open(tmp_file_name, 'r') as f:
        benchmark_data = json.load(f)
        self.assertIn('dummy_benchmark.stable_benchmark_1',
                      benchmark_data['steps'])
    finally:
      os.remove(tmp_file_name)
