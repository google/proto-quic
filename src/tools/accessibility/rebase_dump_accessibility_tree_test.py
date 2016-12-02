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

import json
import os
import re
import sys
import time
import urllib

# Load BeautifulSoup. It's checked into two places in the Chromium tree.
sys.path.append('third_party/WebKit/Tools/Scripts/webkitpy/thirdparty/')
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
  print
  print "Checking trybot: %s" % name
  url = url.replace('/builders/', '/json/builders/')
  response = urllib.urlopen(url)
  if response.getcode() == 200:
    jsondata = response.read()

  if not jsondata:
    print "Failed to fetch from: " + url
    return

  try:
    data = json.loads(jsondata)
  except:
    print "Failed to parse JSON from: " + url
    return

  for step in data["steps"]:
    name = step["name"]
    if name[:len("content_browsertests")] == "content_browsertests":
      if name.find("without") >= 0:
        continue
      if name.find("retry") >= 0:
        continue
      print "Found content_browsertests logs"
      for log in step["logs"]:
        (log_name, log_url) = log
        if log_name == "stdio":
          continue
        log_url += '/text'
        log_response = urllib.urlopen(log_url)
        if log_response.getcode() == 200:
          logdata = log_response.read()
          ParseLog(logdata)
        else:
          print "Failed to fetch test log data from: " + url

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
    return
  data = response.read()
  ParseTrybots(data)

  print
  if len(completed_files) == 0:
    print "No output from DumpAccessibilityTree test results found."
    return
  else:
    print "Summary: modified the following files:"
    all_files = list(completed_files)
    all_files.sort()
    for f in all_files:
      print "* %s" % os.path.relpath(f)

if __name__ == '__main__':
  sys.exit(Run())
