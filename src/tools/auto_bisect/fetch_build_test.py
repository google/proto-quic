# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Unit tests for the fetch_builds module."""

import errno
import unittest

# The third-party mock module is expected to be available in PYTHONPATH.
import mock

import fetch_build


# The tests below test private functions (W0212).
# Some methods don't reference self because they use the mock module (R0201).
# pylint: disable=R0201,W0212
class FetchBuildTest(unittest.TestCase):

  def setUp(self):
    # Mocks of the os and bisect_utils modules are used in the methods below.
    cloud_storage_patcher = mock.patch('fetch_build.cloud_storage')
    self.mock_cloud_storage = cloud_storage_patcher.start()
    self.addCleanup(cloud_storage_patcher.stop)

  @mock.patch('fetch_build.os.path.exists')
  def test_FetchFromCloudStorage_FileFound(self, mock_os_path_exists):
    self.mock_cloud_storage.Exists.return_value = True
    mock_os_path_exists.return_value = True
    local_path = fetch_build.FetchFromCloudStorage(
        'my_bucket', 'remote/foo.zip', 'local')
    self.assertEqual('local/foo.zip', local_path)
    self.mock_cloud_storage.Get.assert_called_with(
        'my_bucket', 'remote/foo.zip', 'local/foo.zip')

  def test_FetchFromCloudStorage_FileNotFound(self):
    self.mock_cloud_storage.Exists.return_value = False
    local_path = fetch_build.FetchFromCloudStorage(
        'my_bucket', 'remote/foo.zip', 'local')
    self.assertIsNone(local_path)
    self.assertFalse(self.mock_cloud_storage.Get.called)


class BuildArchiveTest(unittest.TestCase):

  def test_CreatePerfBuildArchive(self):
    archive = fetch_build.BuildArchive.Create(fetch_build.PERF_BUILDER)
    self.assertEqual('chrome-perf', archive.BucketName())
    self.assertTrue(isinstance(archive, fetch_build.PerfBuildArchive))

  def test_CreateFullBuildArchive(self):
    archive = fetch_build.BuildArchive.Create(fetch_build.FULL_BUILDER)
    archive._platform = 'linux'
    self.assertEqual('chromium-linux-archive', archive.BucketName())
    self.assertTrue(isinstance(archive, fetch_build.FullBuildArchive))

  def test_BuildArchive_NonExistentType(self):
    self.assertRaises(
        NotImplementedError, fetch_build.BuildArchive.Create, 'other')

  def test_FullBuildArchive_Linux(self):
    archive = fetch_build.FullBuildArchive()
    archive._platform = 'linux'
    self.assertEqual('chromium-linux-archive', archive.BucketName())
    self.assertEqual(
        'chromium.linux/Linux Builder/full-build-linux_1234567890abcdef.zip',
        archive.FilePath('1234567890abcdef'))

  def test_FullBuildArchive_Android(self):
    archive = fetch_build.FullBuildArchive()
    archive._platform = 'android'
    self.assertEqual('chromium-android', archive.BucketName())
    self.assertEqual(
        'android_main_rel/full-build-linux_1234567890abcdef.zip',
        archive.FilePath('1234567890abcdef'))

  def test_FullBuildArchive_Linux_BuilderName(self):
    archive = fetch_build.FullBuildArchive()
    archive._platform = 'linux'
    self.assertEqual('linux_full_bisect_builder', archive.GetBuilderName())

  def test_FullBuildArchive_Windows_BuildTime(self):
    archive = fetch_build.FullBuildArchive()
    archive._platform = 'win'
    self.assertEqual(14400, archive.GetBuilderBuildTime())

  def test_PerfBuildArchive_Linux(self):
    archive = fetch_build.PerfBuildArchive()
    archive._platform = 'linux'
    self.assertEqual('chrome-perf', archive.BucketName())
    self.assertEqual(
        'Linux Builder/full-build-linux_1234567890abcdef.zip',
        archive.FilePath('1234567890abcdef'))

  def test_PerfBuildArchive_Android(self):
    archive = fetch_build.PerfBuildArchive()
    archive._platform = 'android'
    self.assertEqual('chrome-perf', archive.BucketName())
    self.assertEqual(
        'android_perf_rel/full-build-linux_123456.zip',
        archive.FilePath('123456'))

  def test_PerfBuildArchive_AndroidArm64(self):
    archive = fetch_build.PerfBuildArchive()
    archive._platform = 'android_arm64'
    self.assertEqual('chrome-perf', archive.BucketName())
    self.assertEqual(
        'android_perf_rel_arm64/full-build-linux_123456.zip',
        archive.FilePath('123456'))

  def test_PerfBuildArchive_64BitWindows(self):
    archive = fetch_build.PerfBuildArchive(target_arch='x64')
    archive._platform = 'win64'
    self.assertEqual('chrome-perf', archive.BucketName())
    self.assertEqual(
        'Win x64 Builder/full-build-win32_123456.zip',
        archive.FilePath('123456'))

  def test_PerfBuildArchive_WithDepsPatchSha(self):
    archive = fetch_build.PerfBuildArchive()
    archive._platform = 'linux'
    self.assertEqual(
        'Linux Builder/full-build-linux_123456'
        '_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.zip',
        archive.FilePath(123456, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'))

  def test_PerfBuildArchive_64BitWindows_BuilderName(self):
    archive = fetch_build.PerfBuildArchive()
    archive._platform = 'win64'
    self.assertEqual('winx64_bisect_builder', archive.GetBuilderName())

  def test_PerfBuildArchive_64BitWindows_BuildTime(self):
    archive = fetch_build.PerfBuildArchive()
    archive._platform = 'win64'
    self.assertEqual(14400, archive.GetBuilderBuildTime())

  def test_PerfBuildArchive_Windows_BuilderName(self):
    archive = fetch_build.PerfBuildArchive()
    archive._platform = 'win'
    self.assertEqual('win_perf_bisect_builder', archive.GetBuilderName())

  def test_PerfBuildArchive_Windows_BuildTime(self):
    archive = fetch_build.PerfBuildArchive()
    archive._platform = 'win'
    self.assertEqual(14400, archive.GetBuilderBuildTime())

  def test_PerfBuildArchive_Linux_BuilderName(self):
    archive = fetch_build.PerfBuildArchive()
    archive._platform = 'linux'
    self.assertEqual('linux_perf_bisect_builder', archive.GetBuilderName())

  def test_PerfBuildArchive_Linux_BuildTime(self):
    archive = fetch_build.PerfBuildArchive()
    archive._platform = 'linux'
    self.assertEqual(14400, archive.GetBuilderBuildTime())

  def test_PerfBuildArchive_Android_BuilderName(self):
    archive = fetch_build.PerfBuildArchive()
    archive._platform = 'android'
    self.assertEqual('android_perf_bisect_builder', archive.GetBuilderName())

  def test_PerfBuildArchive_Android_BuildTime(self):
    archive = fetch_build.PerfBuildArchive()
    archive._platform = 'android'
    self.assertEqual(14400, archive.GetBuilderBuildTime())

  def test_PerfBuildArchive_Mac_BuilderName(self):
    archive = fetch_build.PerfBuildArchive()
    archive._platform = 'mac'
    self.assertEqual('mac_perf_bisect_builder', archive.GetBuilderName())

  def test_PerfBuildArchive_mac_BuildTime(self):
    archive = fetch_build.PerfBuildArchive()
    archive._platform = 'mac'
    self.assertEqual(14400, archive.GetBuilderBuildTime())

  def test_GetBuildBotUrl_Perf(self):
    self.assertEqual(
        fetch_build.PERF_TRY_SERVER_URL,
        fetch_build.GetBuildBotUrl(fetch_build.PERF_BUILDER))

  def test_GetBuildBotUrl_full(self):
    self.assertEqual(
        fetch_build.LINUX_TRY_SERVER_URL,
        fetch_build.GetBuildBotUrl(fetch_build.FULL_BUILDER))


class UnzipTest(unittest.TestCase):

  def setUp(self):
    # Mocks of the os and bisect_utils modules are used in the methods below.
    os_patcher = mock.patch('fetch_build.os')
    self.mock_os = os_patcher.start()
    self.addCleanup(os_patcher.stop)

    bisect_utils_patcher = mock.patch('fetch_build.bisect_utils')
    self.mock_bisect_utils = bisect_utils_patcher.start()
    self.addCleanup(bisect_utils_patcher.stop)

  @mock.patch('fetch_build._MakeDirectory')
  @mock.patch('fetch_build._UnzipUsingCommand')
  def test_Unzip_Linux(self, mock_UnzipUsingCommand, mock_MakeDirectory):
    self.mock_bisect_utils.IsLinuxHost.return_value = True
    self.mock_bisect_utils.IsMacHost.return_value = False
    self.mock_bisect_utils.IsWindowsHost.return_value = False
    fetch_build.Unzip('x.zip', 'out_dir', verbose=False)
    mock_MakeDirectory.assert_called_with('out_dir')
    mock_UnzipUsingCommand.assert_called_with(
        ['unzip', '-o'], 'x.zip', 'out_dir')

  @mock.patch('fetch_build._MakeDirectory')
  @mock.patch('fetch_build._UnzipUsingZipFile')
  def test_Unzip_Mac_LargeFile(
      self, mock_UnzipUsingZipFile, mock_MakeDirectory):
    # The zipfile module is used to unzip on mac when the file is > 4GB.
    self.mock_bisect_utils.IsLinuxHost.return_value = False
    self.mock_bisect_utils.IsMacHost.return_value = True
    self.mock_bisect_utils.IsWindowsHost.return_value = False
    self.mock_os.path.getsize.return_value = 2 ** 33  # 8GB
    fetch_build.Unzip('x.zip', 'out_dir', verbose=False)
    mock_MakeDirectory.assert_called_with('out_dir')
    mock_UnzipUsingZipFile.assert_called_with('x.zip', 'out_dir', False)

  def test_UnzipUsingCommand(self):
    # The _UnzipUsingCommand function should move to the output
    # directory and run the command with the file's absolute path.
    self.mock_os.path.abspath.return_value = '/foo/some/path/x.zip'
    self.mock_os.getcwd.return_value = 'curr_dir'
    self.mock_bisect_utils.RunProcess.return_value = 0
    fetch_build._UnzipUsingCommand(['unzip'], 'x.zip', 'out_dir')
    self.mock_os.chdir.assert_has_calls(
        [mock.call('out_dir'), mock.call('curr_dir')])
    self.mock_bisect_utils.RunProcess.assert_called_with(
        ['unzip', '/foo/some/path/x.zip'])

  def test_MakeDirectory(self):
    # _MakeDirectory uses os.makedirs.
    fetch_build._MakeDirectory('some/path')
    self.mock_os.makedirs.assert_called_with('some/path')

  def test_MakeDirectory_RaisesError(self):
    self.mock_os.makedirs.side_effect = OSError()
    self.assertRaises(OSError, fetch_build._MakeDirectory, 'some/path')

  def test_MakeDirectory_NoErrorIfDirectoryAlreadyExists(self):
    already_exists = OSError()
    already_exists.errno = errno.EEXIST
    self.mock_os.makedirs.side_effect = already_exists
    fetch_build._MakeDirectory('some/path')

  @mock.patch('fetch_build.shutil')
  def test_RemoveDirectoryTree(self, mock_shutil):
    # _RemoveDirectoryTree uses shutil.rmtree.
    fetch_build._RemoveDirectoryTree('some/path')
    mock_shutil.rmtree.assert_called_with('some/path')


if __name__ == '__main__':
  unittest.main()

