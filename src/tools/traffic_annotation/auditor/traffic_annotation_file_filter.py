#!/usr/bin/env python
# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os.path
import re
import subprocess
import sys


def _GetFilesFromGit():
  """Gets the list of files in the git repository."""
  args = []
  if sys.platform == 'win32':
    args.append('git.bat')
  else:
    args.append('git')
  args.append('ls-files')
  command = subprocess.Popen(args, stdout=subprocess.PIPE)
  output, _ = command.communicate()
  return [os.path.realpath(p) for p in output.splitlines()]


class TrafficAnnotationFileFilter():
  KEYWORDS = [
    'network_traffic_annotation',
    'network_traffic_annotation_test_helper',
    'NetworkTrafficAnnotationTag',
    'PartialNetworkTrafficAnnotationTag',
    'DefineNetworkTrafficAnnotation',
    'DefinePartialNetworkTrafficAnnotation',
    'CompleteNetworkTrafficAnnotation',
    'BranchedCompleteNetworkTrafficAnnotation',
    'NO_TRAFFIC_ANNOTATION_YET',
    'NO_PARTIAL_TRAFFIC_ANNOTATION_YET',
    'MISSING_TRAFFIC_ANNOTATION',
    'TRAFFIC_ANNOTATION_FOR_TESTS',
    'PARTIAL_TRAFFIC_ANNOTATION_FOR_TESTS',
    'SSLClientSocket',  # SSLClientSocket::
    'TCPClientSocket',  # TCPClientSocket::
    'UDPClientSocket',  # UDPClientSocket::
    'URLFetcher::Create',  # This one is used with class as it's too generic.
    'CreateDatagramClientSocket',  # ClientSocketFactory::
    'CreateSSLClientSocket',  # ClientSocketFactory::
    'CreateTransportClientSocket',  # ClientSocketFactory::
    'CreateRequest',  # URLRequestContext::
  ]

  def __init__(self,
               skip_tests=True):
    """Creates a new TrafficAnnotationFileFilter.

    Args:
      skip_tests: bool Flag stating if test files should be returned or not.
    """
    assert(all(re.match('^[A-Za-z:_]+$', keyword) for keyword in self.KEYWORDS))
    self.content_matcher = re.compile('.*(' + '|'.join(self.KEYWORDS) + ').*')
    self.file_name_matcher = re.compile(
        '^(?!.*?test)^.*(\.cc|\.mm)$' if skip_tests else
        '^.*(\.cc|\.mm)$')
    self.git_files = filter(lambda x: self.FileIsRelevantContent(x),
                            _GetFilesFromGit())

  def FileIsRelevantContent(self, filename):
    if self.file_name_matcher.match(filename):
      with open(filename, 'r') as in_file:
        for line in in_file:
          if self.content_matcher.match(line):
            return True
    return False


  def GetFilteredFilesList(self, dir_name='/'):
    """Returns the list of relevant files in given directory.
    Args:
      dir_name: str The directory to search for relevant files, e.g.
         'chrome/browser'. All child directories would also be searched.

    Returns:
      list of str List of relevant files
    """
    matcher = re.compile(os.path.abspath(dir_name) + '/.*')
    return filter(matcher.match, self.git_files)
