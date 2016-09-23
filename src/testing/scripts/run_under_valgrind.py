#!/usr/bin/env python
# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import json
import os
import sys


import common


def main_run(args):
  rc = common.run_runtest(args, [
      os.path.join(common.SRC_DIR, 'tools', 'valgrind', 'chrome_tests.sh'),
      '--tool', 'memcheck',
      '--build-dir', os.path.join(common.SRC_DIR, 'out', args.build_config_fs),
    ] + args.args)

  json.dump({
      'valid': True,
      'failures': ['failed'] if rc else []
  }, args.output)

  return rc


def main_compile_targets(args):
  json.dump(['$name'], args.output)


if __name__ == '__main__':
  funcs = {
    'run': main_run,
    'compile_targets': main_compile_targets,
  }
  sys.exit(common.run_script(sys.argv[1:], funcs))
