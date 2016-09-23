# Copyright (c) 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Top-level presubmit script for auto-bisect.

See http://dev.chromium.org/developers/how-tos/depottools/presubmit-scripts for
details on the presubmit API.
"""

import imp
import subprocess
import os

# Paths to bisect config files relative to this script.
CONFIG_FILES = [
    'bisect.cfg',
    os.path.join('..', 'run-perf-test.cfg'),
]


def CheckChangeOnUpload(input_api, output_api):
  return _CommonChecks(input_api, output_api)


def CheckChangeOnCommit(input_api, output_api):
  return _CommonChecks(input_api, output_api)


def _CommonChecks(input_api, output_api):
  """Does all presubmit checks for auto-bisect."""
  results = []
  results.extend(_CheckAllConfigFiles(input_api, output_api))
  results.extend(_RunUnitTests(input_api, output_api))
  results.extend(_RunPyLint(input_api, output_api))
  return results


def _CheckAllConfigFiles(input_api, output_api):
  """Checks all bisect config files and returns a list of presubmit results."""
  results = []
  script_path = input_api.PresubmitLocalPath()
  for config_file in CONFIG_FILES:
    file_path = os.path.join(script_path, config_file)
    results.extend(_CheckConfigFile(file_path, output_api))
  return results


def _CheckConfigFile(file_path, output_api):
  """Checks one bisect config file and returns a list of presubmit results."""
  try:
    config_file = imp.load_source('config', file_path)
  except IOError as e:
    warning = 'Failed to read config file %s: %s' % (file_path, str(e))
    return [output_api.PresubmitError(warning, items=[file_path])]

  if not hasattr(config_file, 'config'):
    warning = 'Config file has no "config" global variable: %s' % str(e)
    return [output_api.PresubmitError(warning, items=[file_path])]

  if type(config_file.config) is not dict:
    warning = 'Config file "config" global variable is not dict: %s' % str(e)
    return [output_api.PresubmitError(warning, items=[file_path])]

  for k, v in config_file.config.iteritems():
    if v != '':
      warning = 'Non-empty value in config dict: %s: %s' % (repr(k), repr(v))
      warning += ('\nThe bisection config file should only contain a config '
                  'dict with empty fields. Changes to this file should not '
                  'be submitted.')
      return [output_api.PresubmitError(warning, items=[file_path])]

  return []


def _RunUnitTests(input_api, output_api):
  """Runs unit tests for auto-bisect."""
  repo_root = input_api.change.RepositoryRoot()
  auto_bisect_dir = os.path.join(repo_root, 'tools', 'auto_bisect')
  test_runner = os.path.join(auto_bisect_dir, 'run_tests')
  return_code = subprocess.call(['python', test_runner])
  if return_code:
    message = 'Auto-bisect unit tests did not all pass.'
    return [output_api.PresubmitError(message)]
  return []


def _RunPyLint(input_api, output_api):
  """Runs unit tests for auto-bisect."""
  telemetry_path = os.path.join(
      input_api.PresubmitLocalPath(), '..', '..', 'third_party', 'telemetry')
  mock_path = os.path.join(
      input_api.PresubmitLocalPath(), '..', '..', 'third_party', 'pymock')
  disabled_warnings = [
      'relative-import',
  ]
  tests = input_api.canned_checks.GetPylint(
      input_api, output_api, disabled_warnings=disabled_warnings,
      extra_paths_list=[telemetry_path, mock_path])
  return input_api.RunTests(tests)
