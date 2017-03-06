# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import sys
import unittest
import StringIO

import mock  # pylint: disable=import-error

from core import path_util
import fetch_benchmark_deps


def NormPaths(paths):
  return sorted([os.path.normcase(p) for p in paths.splitlines()])


class FetchBenchmarkDepsUnittest(unittest.TestCase):
  """The test guards fetch_benchmark_deps.

  It assumes the following telemetry APIs always success:
  telemetry.wpr.archive_info.WprArchiveInfo.DownloadArchivesIfNeeded
  py_utils.cloud_storage.GetFilesInDirectoryIfChanged
  """

  def setUp(self):
    """Override sys.argv as if it is called from command line."""
    self._argv = sys.argv
    sys.argv = ['./fetch_benchmark_deps', '']

  def _RunFetchBenchmarkDepsTest(self, benchmark_name,
                                 expected_fetched_file_paths=None):
    """Simulates './fetch_benchmark_deps [benchmark_name]'

    It checks if the paths returned are expected and have corresponding sha1
    checksums. The expected result can be omitted if the dependencies of
    specified benchmarks are subject to changes.

    Args:
      benchmark_name: benchmark name
      expected_fetched_file_paths: the expected result.
    """
    sys.argv[1] = benchmark_name
    output = StringIO.StringIO()
    with mock.patch('telemetry.wpr.archive_info.WprArchiveInfo'
                    '.DownloadArchivesIfNeeded') as mock_download:
      with mock.patch('py_utils.cloud_storage'
                      '.GetFilesInDirectoryIfChanged') as mock_get:
        mock_download.return_value = True
        mock_get.GetFilesInDirectoryIfChanged.return_value = True
        fetch_benchmark_deps.main(output)
    for f in output.getvalue().splitlines():
      fullpath = os.path.join(path_util.GetChromiumSrcDir(), f)
      sha1path = fullpath + '.sha1'
      self.assertTrue(os.path.isfile(sha1path))
    if expected_fetched_file_paths:
      self.assertEquals(expected_fetched_file_paths,
                        NormPaths(output.getvalue()))

  def testFetchWPRs(self):
    self._RunFetchBenchmarkDepsTest('smoothness.top_25_smooth')

  def testFetchServingDirs(self):
    self._RunFetchBenchmarkDepsTest('media.tough_video_cases')

  def testFetchOctane(self):
    octane_wpr_path = os.path.join(
        os.path.dirname(__file__), 'page_sets', 'data', 'octane_002.wpr')
    expected = os.path.relpath(octane_wpr_path,
                               path_util.GetChromiumSrcDir())
    self._RunFetchBenchmarkDepsTest('octane', NormPaths(expected))
