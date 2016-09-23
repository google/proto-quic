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
"""

import os
import re
import sys
import time
import urllib

# Load BeautifulSoup. It's checked into two places in the Chromium tree.
sys.path.append(
    'third_party/trace-viewer/third_party/tvcm/third_party/beautifulsoup')
from BeautifulSoup import BeautifulSoup

# The location of the DumpAccessibilityTree html test files and expectations.
TEST_DATA_PATH = os.path.join(os.getcwd(), 'content/test/data/accessibility')

# A global that keeps track of files we've already updated, so we don't
# bother to update the same file twice.
completed_files = set()

def GitClIssue():
  '''Retrieve the current issue number as a string.'''
  result = os.popen('git cl issue').read()
  # Returns string like: 'Issue number: 12345 (https://...)'
  return result.split()[2]

def ParseFailure(name, url):
  '''Parse given the name of a failing trybot and the url of its build log.'''

  # Figure out the platform.
  if name.find('android') >= 0:
    platform_suffix = '-expected-android.txt'
  elif name.find('mac') >= 0:
    platform_suffix = '-expected-mac.txt'
  elif name.find('win') >= 0:
    platform_suffix = '-expected-win.txt'
  else:
    return

  # Read the content_browsertests log file.
  data = None
  lines = None
  urls = []
  for url_suffix in [
      '/steps/content_browsertests%20(with%20patch)/logs/stdio/text',
      '/steps/content_browsertests/logs/stdio/text']:
    urls.append(url + url_suffix)
  for url in urls:
    response = urllib.urlopen(url)
    if response.getcode() == 200:
      data = response.read()
      lines = data.splitlines()
      break

  if not data:
    return

  # Parse the log file for failing tests and overwrite the expected
  # result file locally with the actual results from the log.
  test_name = None
  start = None
  filename = None
  for i in range(len(lines)):
    line = lines[i]
    if line[:12] == '[ RUN      ]':
      test_name = line[13:]
    if test_name and line[:8] == 'Testing:':
      filename = re.search('content.test.*accessibility.(.*)', line).group(1)
    if test_name and line == 'Actual':
      start = i + 2
    if start and test_name and filename and line[:12] == '[  FAILED  ]':
      # Get the path to the html file.
      dst_fullpath = os.path.join(TEST_DATA_PATH, filename)
      # Strip off .html and replace it with the platform expected suffix.
      dst_fullpath = dst_fullpath[:-5] + platform_suffix
      if dst_fullpath in completed_files:
        continue

      actual = [line for line in lines[start : i - 1] if line]
      fp = open(dst_fullpath, 'w')
      fp.write('\n'.join(actual))
      fp.close()
      print dst_fullpath
      completed_files.add(dst_fullpath)
      start = None
      test_name = None
      filename = None

def ParseTrybots(data):
  '''Parse the code review page to find links to try bots.'''
  soup = BeautifulSoup(data)
  failures = soup.findAll(
      'a',
      { "class" : "build-result build-status-color-failure" })
  print 'Found %d trybots that failed' % len(failures)
  for f in failures:
    name = f.text.replace('&nbsp;', '')
    url = f['href']
    ParseFailure(name, url)

def Run():
  '''Main. Get the issue number and parse the code review page.'''
  if len(sys.argv) == 2:
    issue = sys.argv[1]
  else:
    issue = GitClIssue()

  url = 'https://codereview.chromium.org/%s' % issue
  print 'Fetching issue from %s' % url
  response = urllib.urlopen(url)
  if response.getcode() != 200:
    print 'Error code %d accessing url: %s' % (response.getcode(), url)
  data = response.read()
  ParseTrybots(data)

if __name__ == '__main__':
  sys.exit(Run())
