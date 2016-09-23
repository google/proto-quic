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
    rc = common.run_runtest(args, [
        '--test-type', 'sizes',
        '--run-python-script',
        os.path.join(
            common.SRC_DIR, 'infra', 'scripts', 'legacy', 'scripts', 'slave',
            'chromium', 'sizes.py'),
        '--json', tempfile_path])
    with open(tempfile_path) as f:
      results = json.load(f)

  with open(os.path.join(common.SRC_DIR, 'tools', 'perf_expectations',
                         'perf_expectations.json')) as f:
    perf_expectations = json.load(f)

  prefix = args.args[0]

  valid = (rc == 0)
  failures = []

  for name, result in results.iteritems():
    fqtn = '%s/%s/%s' % (prefix, name, result['identifier'])
    if fqtn not in perf_expectations:
      continue

    if perf_expectations[fqtn]['type'] != 'absolute':
      print 'ERROR: perf expectation %r is not yet supported' % fqtn
      valid = False
      continue

    actual = result['value']
    expected = perf_expectations[fqtn]['regress']
    better = perf_expectations[fqtn]['better']
    check_result = ((actual <= expected) if better == 'lower'
                    else (actual >= expected))

    if not check_result:
      failures.append(fqtn)
      print 'FAILED %s: actual %s, expected %s, better %s' % (
          fqtn, actual, expected, better)

  json.dump({
      'valid': valid,
      'failures': failures,
  }, args.output)

  # sizes.py itself doesn't fail on regressions.
  if failures and rc == 0:
    rc = 1

  return rc


def main_compile_targets(args):
  json.dump(['chrome'], args.output)


if __name__ == '__main__':
  funcs = {
    'run': main_run,
    'compile_targets': main_compile_targets,
  }
  sys.exit(common.run_script(sys.argv[1:], funcs))
