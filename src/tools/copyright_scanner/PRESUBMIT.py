# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

def CheckChangeOnUpload(input_api, output_api):
  return _CommonChecks(input_api, output_api)

def CheckChangeOnCommit(input_api, output_api):
  return _CommonChecks(input_api, output_api)

def _CommonChecks(input_api, output_api):
  """Checks common to both upload and commit."""
  results = []

  would_affect_tests = [
    'PRESUBMIT.py',
    'copyright_scanner.py',
    'copyright_scanner_unittest.py'
  ]
  need_to_run_unittests = False
  for f in input_api.AffectedFiles():
    if any(t for t in would_affect_tests if f.LocalPath().endswith(t)):
      need_to_run_unittests = True
      break
  tests = [input_api.os_path.join(
    input_api.PresubmitLocalPath(), 'copyright_scanner_unittest.py')]
  results.extend(
    input_api.canned_checks.RunUnitTests(input_api, output_api, tests))
  return results
