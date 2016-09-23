#!/usr/bin/env python
# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""A tool to deobfuscate Java stack traces.

Utility wrapper around ReTrace to deobfuscate stack traces that have been
mangled by ProGuard. Takes stack traces from stdin (eg. adb logcat |
java_deobfuscate.py proguard.mapping) and files.
"""

# Can just run:
# java -jar third_party/proguard/lib/retrace.jar -regex \
# "(?:.*?\bat\s+%c\.%m\s*\(%s(?::%l)?\)\s*)|(?:(?:.*?[:\"]\s+)?%c(?::.*)?)" \
# ~/mapping
# in terminal to achieve same effect as this tool.

import argparse
import os
import subprocess
import sys

_THIRD_PARTY_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                                os.pardir, os.pardir, os.pardir,
                                                'third_party'))
sys.path.append(os.path.join(_THIRD_PARTY_DIR, 'catapult', 'devil'))
from devil.utils import cmd_helper


# This regex is taken from
# http://proguard.sourceforge.net/manual/retrace/usage.html.
_LINE_PARSE_REGEX = (
    r'(?:.*?\bat\s+%c\.%m\s*\(%s(?::%l)?\)\s*)|(?:(?:.*?[:"]\s+)?%c(?::.*)?)')


def main():
  parser = argparse.ArgumentParser(description=(__doc__))
  parser.add_argument(
      'mapping_file',
      help='ProGuard mapping file from build which the stacktrace is from.')
  parser.add_argument(
      '--stacktrace',
      help='Stacktrace file to be deobfuscated.')
  args = parser.parse_args()

  retrace_path = os.path.join(_THIRD_PARTY_DIR, 'proguard',
                              'lib', 'retrace.jar')

  base_args = ['java', '-jar', retrace_path, '-regex', _LINE_PARSE_REGEX,
               args.mapping_file]
  if args.stacktrace:
    subprocess.call(base_args + [args.stacktrace])
  else:
    for line in cmd_helper.IterCmdOutputLines(base_args):
      print line


if __name__ == '__main__':
  main()
