#!/usr/bin/env python
# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import json
import os
import sys


import common


def main_run(args):
  with common.temporary_file() as tempfile_path:
    rc = common.run_command([
        sys.executable,
        os.path.join(common.SRC_DIR, 'third_party', 'WebKit',
                     'Tools', 'Scripts', 'lint-test-expectations'),
        '--json', tempfile_path
    ])

    with open(tempfile_path) as f:
      failures = json.load(f)

  json.dump({
      'valid': True,
      'failures': failures,
  }, args.output)

  return rc


def main_compile_targets(args):
  json.dump([], args.output)


if __name__ == '__main__':
  funcs = {
    'run': main_run,
    'compile_targets': main_compile_targets,
  }
  sys.exit(common.run_script(sys.argv[1:], funcs))
