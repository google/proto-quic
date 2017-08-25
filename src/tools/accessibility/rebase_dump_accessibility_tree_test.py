#!/usr/bin/env python
# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Rebase DumpAccessibilityTree Tests.

This script is intended to be run when you make a change that could affect the
expected results of tests in:

    content/test/data/accessibility

It assumes that you've already uploaded a change and the try jobs have finished.
It collects all of the results from try jobs on all platforms and updates the
expectation files locally. From there you can run 'git diff' to make sure all
of the changes look reasonable, then upload the change for code review.

Optional argument: patchset number, otherwise will default to latest patchset
"""

import json
import os
import re
import sys
import tempfile
import time
import urllib
import urlparse

# Load BeautifulSoup. It's checked into two places in the Chromium tree.
sys.path.append('third_party/WebKit/Tools/Scripts/webkitpy/thirdparty/')
from BeautifulSoup import BeautifulSoup

# The location of the DumpAccessibilityTree html test files and expectations.
TEST_DATA_PATH = os.path.join(os.getcwd(), 'content/test/data/accessibility')

# A global that keeps track of files we've already updated, so we don't
# bother to update the same file twice.
completed_files = set()

def Fix(line):
  if line[:3] == '@@@':
    try:
      line = re.search('[^@]@([^@]*)@@@', line).group(1)
    except:
      pass
  return line

def ParseLog(logdata):
  '''Parse the log file for failing tests and overwrite the expected
     result file locally with the actual results from the log.'''
  lines = logdata.splitlines()
  test_file = None
  expected_file = None
  start = None
  for i in range(len(lines)):
    line = Fix(lines[i])
    if line.find('Testing:') >= 0:
      test_file = re.search(
          'content.test.*accessibility.([^@]*)', line).group(1)
      expected_file = None
      start = None
    if line.find('Expected output:') >= 0:
      expected_file = re.search(
          'content.test.*accessibility.([^@]*)', line).group(1)
    if line == 'Actual':
      start = i + 2
    if start and test_file and expected_file and line.find('End-of-file') >= 0:
      dst_fullpath = os.path.join(TEST_DATA_PATH, expected_file)
      if dst_fullpath in completed_files:
        continue

      actual = [Fix(line) for line in lines[start : i] if line]
      fp = open(dst_fullpath, 'w')
      fp.write('\n'.join(actual))
      fp.close()
      print "* %s" % os.path.relpath(dst_fullpath)
      completed_files.add(dst_fullpath)
      start = None
      test_file = None
      expected_file = None

def Run():
  '''Main. Get the issue number and parse the code review page.'''
  if len(sys.argv) == 2:
    patchSetArg = '--patchset=%s' % sys.argv[1]
  else:
    patchSetArg = '';

  (_, tmppath) = tempfile.mkstemp()
  print 'Temp file: %s' % tmppath
  os.system('git cl try-results --json %s %s' % (tmppath, patchSetArg))

  try_result = open(tmppath).read()
  if len(try_result) < 1000:
    print 'Did not seem to get try bot data.'
    print try_result
    return

  data = json.loads(try_result)
  os.unlink(tmppath)

  #print(json.dumps(data, indent=4))

  for builder in data:
    #print builder['result']
    if builder['result'] == 'FAILURE':
      url = builder['url']
      tokens = url.split('/')
      bucket = tokens[4]
      platform = tokens[6]
      build = tokens[8]
      logdog_prefix = 'chromium/bb/%s/%s/%s' % (bucket, platform, build)
      logdog_steps = '%s/+/recipes/steps' % logdog_prefix
      print logdog_prefix
      steps = os.popen('cit logdog ls "%s"' % logdog_steps).readlines()
      a11y_step = None
      for step in steps:
        if (step.find('content_browsertests') >= 0 and
            step.find('with_patch') >= 0 and
            step.find('trigger') == -1 and
            step.find('Upload') == -1):
          a11y_step = step.rstrip()
      if not a11y_step:
        print 'No content_browsertests (with patch) step found'
        continue
      print a11y_step
      logdog_cat = ('cit logdog cat -raw "%s/%s/0/stdout"' %
        (logdog_steps, a11y_step))
      output = os.popen(logdog_cat).read()
      ParseLog(output)

if __name__ == '__main__':
  sys.exit(Run())
