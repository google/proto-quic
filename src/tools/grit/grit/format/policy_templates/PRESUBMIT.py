#!/usr/bin/env python
# Copyright (c) 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

UNIT_TESTS = [
  'policy_template_generator_unittest',
  'writers.adm_writer_unittest',
  'writers.adml_writer_unittest',
  'writers.admx_writer_unittest',
  'writers.android_policy_writer_unittest',
  'writers.doc_writer_unittest',
  'writers.json_writer_unittest',
  'writers.plist_strings_writer_unittest',
  'writers.plist_writer_unittest',
  'writers.reg_writer_unittest',
  'writers.template_writer_unittest'
]

def CheckChangeOnUpload(input_api, output_api):
  return input_api.canned_checks.RunPythonUnitTests(input_api,
                                                    output_api,
                                                    UNIT_TESTS)


def CheckChangeOnCommit(input_api, output_api):
  return input_api.canned_checks.RunPythonUnitTests(input_api,
                                                    output_api,
                                                    UNIT_TESTS)
