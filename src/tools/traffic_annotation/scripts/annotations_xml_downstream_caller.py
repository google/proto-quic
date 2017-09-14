#!/usr/bin/env python
# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

""" Runs all scripts that use
      'tools/traffic_annotation/summary/annotations.xml' to update a file, or
      test if a file is in sync with it. Use with 'test' switch for test mode.
      Add your scripts to PROD_SCRIPTS or TEST_SCRIPTS.
"""

import os.path
import subprocess
import sys

# Add your update scripts here. Each list item will have the script name and the
# list of arguments.
PROD_SCRIPTS = [
  ["tools/metrics/histograms/update_traffic_annotation_histograms.py", []]]

# Add your test scripts here. Each list item will have the script name and the
# list of arguments.
TEST_SCRIPTS = []


def main(test_mode):
  src_path = os.path.abspath(
      os.path.join(os.path.dirname(__file__), "..", "..", ".."))

  for script in TEST_SCRIPTS if test_mode else PROD_SCRIPTS:
    args = [os.path.join(src_path, script[0])]
    args += script[1]
    if sys.platform == "win32":
      args.insert(0, "python")

    result = subprocess.call(args)
    if result:
      if test_mode:
        logging.error("Running '%s' script failed with error code: %i." % (
                      script, result))
      return result
  return 0


if __name__ == "__main__":
  test_mode = (len(sys.argv) > 1 and "test" in sys.argv[1])
  sys.exit(main(test_mode))
