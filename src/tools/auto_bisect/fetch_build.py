# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""This module contains functions for fetching and extracting archived builds.

The builds may be stored in different places by different types of builders;
for example, builders on tryserver.chromium.perf stores builds in one place,
while builders on chromium.linux store builds in another.

This module can be either imported or run as a stand-alone script to download
and extract a build.

Usage: fetch_build.py <type> <revision> <output_dir> [options]
"""

import argparse
import errno
import logging
import os
import shutil
import sys
import zipfile

_PY_UTILS_PATH = os.path.abspath(os.path.join(
    os.path.dirname(__file__), '..', '..', 'third_party', 'catapult',
    'common', 'py_utils'))
if _PY_UTILS_PATH not in sys.path:
  sys.path.insert(1, _PY_UTILS_PATH)
from py_utils import cloud_storage

import bisect_utils

# Possible builder types.
PERF_BUILDER = 'perf'
FULL_BUILDER = 'full'
ANDROID_CHROME_PERF_BUILDER = 'android-chrome-perf'

# Maximum time in seconds to wait after posting build request to the try server.
MAX_MAC_BUILD_TIME = 14400
MAX_WIN_BUILD_TIME = 14400
MAX_LINUX_BUILD_TIME = 14400

# Try server status page URLs, used to get build status.
PERF_TRY_SERVER_URL = 'http://build.chromium.org/p/tryserver.chromium.perf'
LINUX_TRY_SERVER_URL = 'http://build.chromium.org/p/tryserver.chromium.linux'


def GetBucketAndRemotePath(revision, builder_type=PERF_BUILDER,
                           target_arch='ia32', target_platform='chromium',
                           deps_patch_sha=None, extra_src=None):
  """Returns the location where a build archive is expected to be.

  Args:
    revision: Revision string, e.g. a git commit hash or SVN revision.
    builder_type: Type of build archive.
    target_arch: Architecture, e.g. "ia32".
    target_platform: Platform name, e.g. "chromium" or "android".
    deps_patch_sha: SHA1 hash which identifies a particular combination of
        custom revisions for dependency repositories.
    extra_src: Path to a script which can be used to modify the bisect script's
        behavior.

  Returns:
    A pair of strings (bucket, path), where the archive is expected to be.
  """
  logging.info('Getting GS URL for archive of builder "%s", "%s", "%s".',
               builder_type, target_arch, target_platform)
  build_archive = BuildArchive.Create(
      builder_type, target_arch=target_arch, target_platform=target_platform,
      extra_src=extra_src)
  bucket = build_archive.BucketName()
  remote_path = build_archive.FilePath(revision, deps_patch_sha=deps_patch_sha)
  return bucket, remote_path


def GetBuilderNameAndBuildTime(builder_type=PERF_BUILDER, target_arch='ia32',
                               target_platform='chromium', extra_src=None):
  """Gets builder bot name and build time in seconds based on platform."""
  logging.info('Getting builder name for builder "%s", "%s", "%s".',
               builder_type, target_arch, target_platform)
  build_archive = BuildArchive.Create(
      builder_type, target_arch=target_arch, target_platform=target_platform,
      extra_src=extra_src)
  return build_archive.GetBuilderName(), build_archive.GetBuilderBuildTime()


def GetBuildBotUrl(builder_type=PERF_BUILDER, target_arch='ia32',
                   target_platform='chromium', extra_src=None):
  """Gets buildbot URL for a given builder type."""
  logging.info('Getting buildbot URL for "%s", "%s", "%s".',
               builder_type, target_arch, target_platform)
  build_archive = BuildArchive.Create(
      builder_type, target_arch=target_arch, target_platform=target_platform,
      extra_src=extra_src)
  return build_archive.GetBuildBotUrl()


class BuildArchive(object):
  """Represents a place where builds of some type are stored.

  There are two pieces of information required to locate a file in Google
  Cloud Storage, bucket name and file path. Subclasses of this class contain
  specific logic about which bucket names and paths should be used to fetch
  a build.
  """

  @staticmethod
  def Create(builder_type, target_arch='ia32', target_platform='chromium',
             extra_src=None):
    if builder_type == PERF_BUILDER:
      return PerfBuildArchive(target_arch, target_platform)
    if builder_type == FULL_BUILDER:
      return FullBuildArchive(target_arch, target_platform)
    if builder_type == ANDROID_CHROME_PERF_BUILDER:
      try:
        # Load and initialize a module in extra source file and
        # return its module object to access android-chrome specific data.
        loaded_extra_src = bisect_utils.LoadExtraSrc(extra_src)
        return AndroidChromeBuildArchive(
            target_arch, target_platform, loaded_extra_src)
      except (IOError, TypeError, ImportError):
        raise RuntimeError('Invalid or missing --extra_src. [%s]' % extra_src)
    raise NotImplementedError('Builder type "%s" not supported.' % builder_type)

  def __init__(self, target_arch='ia32', target_platform='chromium',
               extra_src=None):
    self._extra_src = extra_src
    if bisect_utils.IsLinuxHost() and target_platform == 'android':
      if target_arch == 'arm64':
        self._platform = 'android_arm64'
      else:
        self._platform = 'android'
    elif bisect_utils.IsLinuxHost() and target_platform == 'android-chrome':
      self._platform = 'android-chrome'
    elif bisect_utils.IsLinuxHost():
      self._platform = 'linux'
    elif bisect_utils.IsMacHost():
      self._platform = 'mac'
    elif bisect_utils.Is64BitWindows() and target_arch == 'x64':
      self._platform = 'win64'
    elif bisect_utils.IsWindowsHost():
      self._platform = 'win'
    else:
      raise NotImplementedError('Unknown platform "%s".' % sys.platform)

  def BucketName(self):
    raise NotImplementedError()

  def FilePath(self, revision, deps_patch_sha=None):
    """Returns the remote file path to download a build from.

    Args:
      revision: A Chromium revision; this could be a git commit hash or
          commit position or SVN revision number.
      deps_patch_sha: The SHA1 hash of a patch to the DEPS file, which
          uniquely identifies a change to use a particular revision of
          a dependency.

    Returns:
      A file path, which not does not include a bucket name.
    """
    raise NotImplementedError()

  def _ZipFileName(self, revision, deps_patch_sha=None):
    """Gets the file name of a zip archive for a particular revision.

    This returns a file name of the form full-build-<platform>_<revision>.zip,
    which is a format used by multiple types of builders that store archives.

    Args:
      revision: A git commit hash or other revision string.
      deps_patch_sha: SHA1 hash of a DEPS file patch.

    Returns:
      The archive file name.
    """
    base_name = 'full-build-%s' % self._PlatformName()
    if deps_patch_sha:
      revision = '%s_%s' % (revision, deps_patch_sha)
    return '%s_%s.zip' % (base_name, revision)

  def _PlatformName(self):
    """Return a string to be used in paths for the platform."""
    if self._platform in ('win', 'win64'):
      # Build archive for win64 is still stored with "win32" in the name.
      return 'win32'
    if self._platform in ('linux', 'android', 'android_arm64'):
      # Android builds are also stored with "linux" in the name.
      return 'linux'
    if self._platform == 'mac':
      return 'mac'
    raise NotImplementedError('Unknown platform "%s".' % sys.platform)

  def GetBuilderName(self):
    raise NotImplementedError()

  def GetBuilderBuildTime(self):
    """Returns the time to wait for a build after requesting one."""
    if self._platform in ('win', 'win64'):
      return MAX_WIN_BUILD_TIME
    if self._platform in ('linux', 'android',
                          'android_arm64', 'android-chrome'):
      return MAX_LINUX_BUILD_TIME
    if self._platform == 'mac':
      return MAX_MAC_BUILD_TIME
    raise NotImplementedError('Unsupported Platform "%s".' % sys.platform)

  def GetBuildBotUrl(self):
    raise NotImplementedError()


class PerfBuildArchive(BuildArchive):

  def BucketName(self):
    return 'chrome-perf'

  def FilePath(self, revision, deps_patch_sha=None):
    return '%s/%s' % (self._ArchiveDirectory(),
                      self._ZipFileName(revision, deps_patch_sha))

  def _ArchiveDirectory(self):
    """Returns the directory name to download builds from."""
    platform_to_directory = {
        'android': 'android_perf_rel',
        'android_arm64': 'android_perf_rel_arm64',
        'linux': 'Linux Builder',
        'mac': 'Mac Builder',
        'win64': 'Win x64 Builder',
        'win': 'Win Builder',
    }
    assert self._platform in platform_to_directory
    return platform_to_directory.get(self._platform)

  def GetBuilderName(self):
    """Gets builder bot name based on platform."""
    if self._platform == 'win64':
      return 'winx64_bisect_builder'
    elif self._platform == 'win':
      return 'win_perf_bisect_builder'
    elif self._platform == 'linux':
      return 'linux_perf_bisect_builder'
    elif self._platform == 'android':
      return 'android_perf_bisect_builder'
    elif self._platform == 'android_arm64':
      return 'android_arm64_perf_bisect_builder'
    elif self._platform == 'mac':
      return 'mac_perf_bisect_builder'
    raise NotImplementedError('Unsupported platform "%s".' % sys.platform)

  def GetBuildBotUrl(self):
    """Returns buildbot URL for fetching build info."""
    return PERF_TRY_SERVER_URL


class FullBuildArchive(BuildArchive):

  def BucketName(self):
    platform_to_bucket = {
        'android': 'chromium-android',
        'linux': 'chromium-linux-archive',
        'mac': 'chromium-mac-archive',
        'win64': 'chromium-win-archive',
        'win': 'chromium-win-archive',
    }
    assert self._platform in platform_to_bucket
    return platform_to_bucket.get(self._platform)

  def FilePath(self, revision, deps_patch_sha=None):
    return '%s/%s' % (self._ArchiveDirectory(),
                      self._ZipFileName(revision, deps_patch_sha))

  def _ArchiveDirectory(self):
    """Returns the remote directory to download builds from."""
    platform_to_directory = {
        'android': 'android_main_rel',
        'linux': 'chromium.linux/Linux Builder',
        'mac': 'chromium.mac/Mac Builder',
        'win64': 'chromium.win/Win x64 Builder',
        'win': 'chromium.win/Win Builder',
    }
    assert self._platform in platform_to_directory
    return platform_to_directory.get(self._platform)

  def GetBuilderName(self):
    """Gets builder bot name based on platform."""
    if self._platform == 'linux':
      return 'linux_full_bisect_builder'
    raise NotImplementedError('Unsupported platform "%s".' % sys.platform)

  def GetBuildBotUrl(self):
    """Returns buildbot URL for fetching build info."""
    return LINUX_TRY_SERVER_URL


class AndroidChromeBuildArchive(BuildArchive):
  """Represents a place where builds of android-chrome type are stored.

  If AndroidChromeBuildArchive is used, it is assumed that the --extra_src
  is a valid Python module which contains the module-level functions
  GetBucketName and GetArchiveDirectory.
  """

  def BucketName(self):
    return self._extra_src.GetBucketName()

  def _ZipFileName(self, revision, deps_patch_sha=None):
    """Gets the file name of a zip archive on android-chrome.

    This returns a file name of the form build_product_<revision>.zip,
    which is a format used by android-chrome.

    Args:
      revision: A git commit hash or other revision string.
      deps_patch_sha: SHA1 hash of a DEPS file patch.

    Returns:
      The archive file name.
    """
    if deps_patch_sha:
      revision = '%s_%s' % (revision, deps_patch_sha)
    return 'build_product_%s.zip' % revision

  def FilePath(self, revision, deps_patch_sha=None):
    return '%s/%s' % (self._ArchiveDirectory(),
                      self._ZipFileName(revision, deps_patch_sha))

  def _ArchiveDirectory(self):
    """Returns the directory name to download builds from."""
    return self._extra_src.GetArchiveDirectory()

  def GetBuilderName(self):
    """Returns the builder name extra source."""
    return self._extra_src.GetBuilderName()

  def GetBuildBotUrl(self):
    """Returns buildbot URL for fetching build info."""
    return self._extra_src.GetBuildBotUrl()


def BuildIsAvailable(bucket_name, remote_path):
  """Checks whether a build is currently archived at some place."""
  logging.info('Checking existence: gs://%s/%s' % (bucket_name, remote_path))
  try:
    exists = cloud_storage.Exists(bucket_name, remote_path)
    logging.info('Exists? %s' % exists)
    return exists
  except cloud_storage.CloudStorageError:
    return False


def FetchFromCloudStorage(bucket_name, source_path, destination_dir):
  """Fetches file(s) from the Google Cloud Storage.

  As a side-effect, this prints messages to stdout about what's happening.

  Args:
    bucket_name: Google Storage bucket name.
    source_path: Source file path.
    destination_dir: Destination file path.

  Returns:
    Local file path of downloaded file if it was downloaded. If the file does
    not exist in the given bucket, or if there was an error while downloading,
    None is returned.
  """
  target_file = os.path.join(destination_dir, os.path.basename(source_path))
  gs_url = 'gs://%s/%s' % (bucket_name, source_path)
  try:
    if cloud_storage.Exists(bucket_name, source_path):
      logging.info('Fetching file from %s...', gs_url)
      cloud_storage.Get(bucket_name, source_path, target_file)
      if os.path.exists(target_file):
        return target_file
    else:
      logging.info('File %s not found in cloud storage.', gs_url)
      return None
  except Exception as e:
    logging.warn('Exception while fetching from cloud storage: %s', e)
    if os.path.exists(target_file):
      os.remove(target_file)
  return None


def Unzip(file_path, output_dir, verbose=True):
  """Extracts a zip archive's contents into the given output directory.

  This was based on ExtractZip from build/scripts/common/chromium_utils.py.

  Args:
    file_path: Path of the zip file to extract.
    output_dir: Path to the destination directory.
    verbose: Whether to print out what is being extracted.

  Raises:
    IOError: The unzip command had a non-zero exit code.
    RuntimeError: Failed to create the output directory.
  """
  _MakeDirectory(output_dir)

  # On Linux and Mac, we use the unzip command because it handles links and
  # file permissions bits, so achieving this behavior is easier than with
  # ZipInfo options.
  #
  # The Mac Version of unzip unfortunately does not support Zip64, whereas
  # the python module does, so we have to fall back to the python zip module
  # on Mac if the file size is greater than 4GB.
  mac_zip_size_limit = 2 ** 32  # 4GB
  if (bisect_utils.IsLinuxHost() or
      (bisect_utils.IsMacHost()
       and os.path.getsize(file_path) < mac_zip_size_limit)):
    unzip_command = ['unzip', '-o']
    _UnzipUsingCommand(unzip_command, file_path, output_dir)
    return

  # On Windows, try to use 7z if it is installed, otherwise fall back to the
  # Python zipfile module. If 7z is not installed, then this may fail if the
  # zip file is larger than 512MB.
  sevenzip_path = r'C:\Program Files\7-Zip\7z.exe'
  if bisect_utils.IsWindowsHost() and os.path.exists(sevenzip_path):
    unzip_command = [sevenzip_path, 'x', '-y']
    _UnzipUsingCommand(unzip_command, file_path, output_dir)
    return

  _UnzipUsingZipFile(file_path, output_dir, verbose)


def _UnzipUsingCommand(unzip_command, file_path, output_dir):
  """Extracts a zip file using an external command.

  Args:
    unzip_command: An unzipping command, as a string list, without the filename.
    file_path: Path to the zip file.
    output_dir: The directory which the contents should be extracted to.

  Raises:
    IOError: The command had a non-zero exit code.
  """
  absolute_filepath = os.path.abspath(file_path)
  command = unzip_command + [absolute_filepath]
  return_code = _RunCommandInDirectory(output_dir, command)
  if return_code:
    _RemoveDirectoryTree(output_dir)
    raise IOError('Unzip failed: %s => %s' % (str(command), return_code))


def _RunCommandInDirectory(directory, command):
  """Changes to a directory, runs a command, then changes back."""
  saved_dir = os.getcwd()
  os.chdir(directory)
  return_code = bisect_utils.RunProcess(command)
  os.chdir(saved_dir)
  return return_code


def _UnzipUsingZipFile(file_path, output_dir, verbose=True):
  """Extracts a zip file using the Python zipfile module."""
  assert bisect_utils.IsWindowsHost() or bisect_utils.IsMacHost()
  zf = zipfile.ZipFile(file_path)
  for name in zf.namelist():
    if verbose:
      print 'Extracting %s' % name
    zf.extract(name, output_dir)
    if bisect_utils.IsMacHost():
      # Restore file permission bits.
      mode = zf.getinfo(name).external_attr >> 16
      os.chmod(os.path.join(output_dir, name), mode)


def _MakeDirectory(path):
  try:
    os.makedirs(path)
  except OSError as e:
    if e.errno != errno.EEXIST:
      raise


def _RemoveDirectoryTree(path):
  try:
    if os.path.exists(path):
      shutil.rmtree(path)
  except OSError, e:
    if e.errno != errno.ENOENT:
      raise


def Main(argv):
  """Downloads and extracts a build based on the command line arguments."""
  parser = argparse.ArgumentParser()
  parser.add_argument('builder_type')
  parser.add_argument('revision')
  parser.add_argument('output_dir')
  parser.add_argument('--target-arch', default='ia32')
  parser.add_argument('--target-platform', default='chromium')
  parser.add_argument('--deps-patch-sha')
  args = parser.parse_args(argv[1:])

  bucket_name, remote_path = GetBucketAndRemotePath(
      args.revision, args.builder_type, target_arch=args.target_arch,
      target_platform=args.target_platform,
      deps_patch_sha=args.deps_patch_sha)
  print 'Bucket name: %s, remote path: %s' % (bucket_name, remote_path)

  if not BuildIsAvailable(bucket_name, remote_path):
    print 'Build is not available.'
    return 1

  FetchFromCloudStorage(bucket_name, remote_path, args.output_dir)
  print 'Build has been downloaded to and extracted in %s.' % args.output_dir
  return 0


if __name__ == '__main__':
  sys.exit(Main(sys.argv))
