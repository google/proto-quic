#!/usr/bin/env python
# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""A tool to deobfuscate Java stack traces.

Utility wrapper around ReTrace to deobfuscate stack traces that have been
mangled by ProGuard. Takes stack traces from stdin (eg. adb logcat |
java_deobfuscate.py proguard.mapping) and files.
"""

import argparse
import os

_SRC_DIR = os.path.normpath(
    os.path.join(os.path.dirname(__file__), os.pardir, os.pardir, os.pardir))

# This regex is based on the one from:
# http://proguard.sourceforge.net/manual/retrace/usage.html.
# But with the "at" part changed to "(?::|\bat)", to account for lines like:
#     06-22 13:58:02.895  4674  4674 E THREAD_STATE:     bLA.a(PG:173)
# Normal stack trace lines look like:
# java.lang.RuntimeException: Intentional Java Crash
#     at org.chromium.chrome.browser.tab.Tab.handleJavaCrash(Tab.java:682)
#     at org.chromium.chrome.browser.tab.Tab.loadUrl(Tab.java:644)
_LINE_PARSE_REGEX = (
    r'(?:.*?(?::|\bat)\s+%c\.%m\s*\(%s(?::%l)?\)\s*)|'
    r'(?:(?:.*?[:"]\s+)?%c(?::.*)?)')


def main():
  parser = argparse.ArgumentParser(description=(__doc__))
  parser.add_argument(
      'mapping_file',
      help='ProGuard mapping file from build which the stacktrace is from.')
  parser.add_argument(
      '--stacktrace',
      help='Stacktrace file to be deobfuscated.')
  args = parser.parse_args()

  retrace_path = os.path.join(
      _SRC_DIR, 'third_party', 'proguard', 'lib', 'retrace.jar')

  cmd = ['java', '-jar', retrace_path, '-regex', _LINE_PARSE_REGEX,
         args.mapping_file]
  if args.stacktrace:
    cmd.append(args.stacktrace)
  os.execvp('java', cmd)


if __name__ == '__main__':
  main()
