#!/usr/bin/env python
# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Wrapper for the Kasko integration tests."""


import json
import os
import sys


import common


# Bring in the Kasko test modules.
KASKO_TEST_DIR = os.path.join(os.path.dirname(__file__), os.pardir, os.pardir,
    'chrome', 'test', 'kasko')
KASKO_INTEGRATION_TEST = os.path.join(KASKO_TEST_DIR,
                                      'kasko_integration_test.py')


def main_run(args):
  if not sys.platform.startswith('win'):
    json.dump({
        'valid': False,
        'failures': ['This script should only be called on win32.'],
    }, args.output)

  with common.temporary_file() as tempfile_path:
    kasko_integration_test_res = common.run_integration_test(
        KASKO_INTEGRATION_TEST,
        ['--log-to-json', tempfile_path],
        tempfile_path, args.output)

  return kasko_integration_test_res


def main_compile_targets(args):
  json.dump(['chrome', 'chromedriver'], args.output)


if __name__ == '__main__':
  funcs = {
    'run': main_run,
    'compile_targets': main_compile_targets,
  }
  sys.exit(common.run_script(sys.argv[1:], funcs))
