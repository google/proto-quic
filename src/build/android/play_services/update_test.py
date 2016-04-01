#!/usr/bin/env python
# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

'''Unittests for update.py.

They set up a temporary directory that is used to mock a bucket, the directory
containing the configuration files and the android sdk directory.

Tests run the script with various inputs and check the status of the filesystem
'''

import shutil
import tempfile
import unittest
import os
import sys
import zipfile
import contextlib

sys.path.append(os.path.join(os.path.dirname(__file__), os.pardir))
from play_services import update


class TestFunctions(unittest.TestCase):
  DEFAULT_CONFIG_VERSION = 42
  DEFAULT_LICENSE = 'Default License'
  DEFAULT_ZIP_SHA1 = 'zip0and0filling0to0forty0chars0000000000'

  def __init__(self, *args, **kwargs):
    super(TestFunctions, self).__init__(*args, **kwargs)
    self.paths = None  # Initialized in SetUpWorkdir
    self.workdir = None  # Initialized in setUp

  #override
  def setUp(self):
    self.workdir = tempfile.mkdtemp()

  #override
  def tearDown(self):
    shutil.rmtree(self.workdir)
    self.workdir = None

  def testUpload(self):
    version = 1337
    self.SetUpWorkdir(
        xml_version=version,
        gms_lib=True,
        source_prop=True)

    status = update.main([
        'upload',
        '--dry-run',
        '--skip-git',
        '--bucket', self.paths.bucket,
        '--config', self.paths.config_file,
        '--sdk-root', self.paths.sdk_root
    ])
    self.assertEqual(status, 0, 'the command should have succeeded.')

    # bucket should contain license, name = license.sha1
    self.assertTrue(os.path.isfile(self.paths.config_license_sha1))
    license_sha1 = _GetFileContent(self.paths.config_license_sha1)
    bucket_license = os.path.join(self.paths.bucket, str(version),
                                  license_sha1)
    self.assertTrue(os.path.isfile(bucket_license))
    self.assertEqual(_GetFileContent(bucket_license), self.DEFAULT_LICENSE)

    # bucket should contain zip, name = zip.sha1
    self.assertTrue(os.path.isfile(self.paths.config_zip_sha1))
    bucket_zip = os.path.join(self.paths.bucket, str(version),
                              _GetFileContent(self.paths.config_zip_sha1))
    self.assertTrue(os.path.isfile(bucket_zip))

    # unzip, should contain expected files
    with zipfile.ZipFile(bucket_zip, "r") as bucket_zip_file:
      self.assertEqual(bucket_zip_file.namelist(),
                       ['dummy_file', 'res/values/version.xml'])

  def testUploadAlreadyLatestVersion(self):
    self.SetUpWorkdir(
        xml_version=self.DEFAULT_CONFIG_VERSION,
        gms_lib=True,
        source_prop=True)

    status = update.main([
        'upload',
        '--dry-run',
        '--skip-git',
        '--bucket', self.paths.bucket,
        '--config', self.paths.config_file,
        '--sdk-root', self.paths.sdk_root,
    ])
    self.assertEqual(status, 0, 'the command should have succeeded.')

    # bucket should be empty
    self.assertFalse(os.listdir(self.paths.bucket))
    self.assertFalse(os.path.isfile(self.paths.config_license_sha1))
    self.assertFalse(os.path.isfile(self.paths.config_zip_sha1))

  def testDownload(self):
    self.SetUpWorkdir(populate_bucket=True)

    with _MockedInput('y'):
      status = update.main([
          'download',
          '--dry-run',
          '--bucket', self.paths.bucket,
          '--config', self.paths.config_file,
          '--sdk-root', self.paths.sdk_root,
      ])

    self.assertEqual(status, 0, 'the command should have succeeded.')

    # sdk_root should contain zip contents, zip sha1, license
    self.assertTrue(os.path.isfile(os.path.join(self.paths.gms_lib,
                                                'dummy_file')))
    self.assertTrue(os.path.isfile(self.paths.gms_root_sha1))
    self.assertTrue(os.path.isfile(self.paths.gms_root_license))
    self.assertEquals(_GetFileContent(self.paths.gms_root_license),
                      self.DEFAULT_LICENSE)

  def testDownloadBot(self):
    self.SetUpWorkdir(populate_bucket=True, bot_env=True)

    # No need to type 'y' on bots
    status = update.main([
        'download',
        '--dry-run',
        '--bucket', self.paths.bucket,
        '--config', self.paths.config_file,
        '--sdk-root', self.paths.sdk_root,
    ])

    self.assertEqual(status, 0, 'the command should have succeeded.')

    # sdk_root should contain zip contents, zip sha1, license
    self.assertTrue(os.path.isfile(os.path.join(self.paths.gms_lib,
                                                'dummy_file')))
    self.assertTrue(os.path.isfile(self.paths.gms_root_sha1))
    self.assertTrue(os.path.isfile(self.paths.gms_root_license))
    self.assertEquals(_GetFileContent(self.paths.gms_root_license),
                      self.DEFAULT_LICENSE)

  def testDownloadAlreadyUpToDate(self):
    self.SetUpWorkdir(
        populate_bucket=True,
        existing_zip_sha1=self.DEFAULT_ZIP_SHA1)

    status = update.main([
        'download',
        '--dry-run',
        '--bucket', self.paths.bucket,
        '--config', self.paths.config_file,
        '--sdk-root', self.paths.sdk_root,
    ])

    self.assertEqual(status, 0, 'the command should have succeeded.')

    # there should not be new files downloaded to sdk_root
    self.assertFalse(os.path.isfile(os.path.join(self.paths.gms_lib,
                                                 'dummy_file')))
    self.assertFalse(os.path.isfile(self.paths.gms_root_license))

  def testDownloadAcceptedLicense(self):
    self.SetUpWorkdir(
        populate_bucket=True,
        existing_license=self.DEFAULT_LICENSE)

    # License already accepted, no need to type
    status = update.main([
        'download',
        '--dry-run',
        '--bucket', self.paths.bucket,
        '--config', self.paths.config_file,
        '--sdk-root', self.paths.sdk_root,
    ])

    self.assertEqual(status, 0, 'the command should have succeeded.')

    # sdk_root should contain zip contents, zip sha1, license
    self.assertTrue(os.path.isfile(os.path.join(self.paths.gms_lib,
                                                'dummy_file')))
    self.assertTrue(os.path.isfile(self.paths.gms_root_sha1))
    self.assertTrue(os.path.isfile(self.paths.gms_root_license))
    self.assertEquals(_GetFileContent(self.paths.gms_root_license),
                      self.DEFAULT_LICENSE)

  def testDownloadNewLicense(self):
    self.SetUpWorkdir(
        populate_bucket=True,
        existing_license='Old license')

    with _MockedInput('y'):
      status = update.main([
          'download',
          '--dry-run',
          '--bucket', self.paths.bucket,
          '--config', self.paths.config_file,
          '--sdk-root', self.paths.sdk_root,
      ])

    self.assertEqual(status, 0, 'the command should have succeeded.')

    # sdk_root should contain zip contents, zip sha1, NEW license
    self.assertTrue(os.path.isfile(os.path.join(self.paths.gms_lib,
                                                'dummy_file')))
    self.assertTrue(os.path.isfile(self.paths.gms_root_sha1))
    self.assertTrue(os.path.isfile(self.paths.gms_root_license))
    self.assertEquals(_GetFileContent(self.paths.gms_root_license),
                      self.DEFAULT_LICENSE)

  def testDownloadRefusedLicense(self):
    self.SetUpWorkdir(
        populate_bucket=True,
        existing_license='Old license')

    with _MockedInput('n'):
      status = update.main([
          'download',
          '--dry-run',
          '--bucket', self.paths.bucket,
          '--config', self.paths.config_file,
          '--sdk-root', self.paths.sdk_root,
      ])

    self.assertEqual(status, 0, 'the command should have succeeded.')

    # there should not be new files downloaded to sdk_root
    self.assertFalse(os.path.isfile(os.path.join(self.paths.gms_lib,
                                                 'dummy_file')))
    self.assertEquals(_GetFileContent(self.paths.gms_root_license),
                      'Old license')

  def testDownloadNoAndroidSDK(self):
    self.SetUpWorkdir(
        populate_bucket=True,
        existing_license='Old license')

    non_existing_sdk_root = os.path.join(self.workdir, 'non_existing_sdk_root')
    # Should not run, no typing needed
    status = update.main([
        'download',
        '--dry-run',
        '--bucket', self.paths.bucket,
        '--config', self.paths.config_file,
        '--sdk-root', non_existing_sdk_root,
    ])

    self.assertEqual(status, 0, 'the command should have succeeded.')
    self.assertFalse(os.path.isdir(non_existing_sdk_root))

  def SetUpWorkdir(self,
                   bot_env=False,
                   config_version=DEFAULT_CONFIG_VERSION,
                   existing_license=None,
                   existing_zip_sha1=None,
                   gms_lib=False,
                   populate_bucket=False,
                   source_prop=None,
                   xml_version=None):
    '''Prepares workdir by putting it in the specified state

    Args:
      - general
        bot_env: sets or unsets CHROME_HEADLESS

      - bucket
        populate_bucket: boolean. Populate the bucket with a zip and license
                         file. The sha1s will be copied to the config directory

      - config
        config_version: number. Version of the current SDK. Defaults to
                        `self.DEFAULT_CONFIG_VERSION`

      - sdk_root
        existing_license: string. Create a LICENSE file setting the specified
                          text as content of the currently accepted license.
        existing_zip_sha1: string. Create a sha1 file setting the specified
                           hash as hash of the SDK supposed to be installed
        gms_lib: boolean. Create a dummy file in the location of the play
                 services SDK.
        source_prop: boolean. Create a source.properties file that contains
                     the license to upload.
        xml_version: number. Create a version.xml file with the specified
                     version that is used when uploading
    '''
    self.paths = Paths(self.workdir)

    # Create the main directories
    _MakeDirs(self.paths.sdk_root)
    _MakeDirs(self.paths.config_dir)
    _MakeDirs(self.paths.bucket)

    # is not configured via argument.
    update.SHA1_DIRECTORY = self.paths.config_dir

    os.environ['CHROME_HEADLESS'] = '1' if bot_env else ''

    if config_version:
      _MakeDirs(os.path.dirname(self.paths.config_file))
      with open(self.paths.config_file, 'w') as stream:
        stream.write(('{"version_number":%d,'
                      '"version_xml_path": "res/values/version.xml"}'
                      '\n') % config_version)

    if existing_license:
      _MakeDirs(self.paths.gms_root)
      with open(self.paths.gms_root_license, 'w') as stream:
        stream.write(existing_license)

    if existing_zip_sha1:
      _MakeDirs(self.paths.gms_root)
      with open(self.paths.gms_root_sha1, 'w') as stream:
        stream.write(existing_zip_sha1)

    if gms_lib:
      _MakeDirs(self.paths.gms_lib)
      with open(os.path.join(self.paths.gms_lib, 'dummy_file'), 'w') as stream:
        stream.write('foo\n')

    if source_prop:
      _MakeDirs(os.path.dirname(self.paths.source_prop))
      with open(self.paths.source_prop, 'w') as stream:
        stream.write('Foo=Bar\n'
                     'Pkg.License=%s\n'
                     'Baz=Fizz\n' % self.DEFAULT_LICENSE)

    if populate_bucket:
      _MakeDirs(self.paths.config_dir)
      bucket_dir = os.path.join(self.paths.bucket, str(config_version))
      _MakeDirs(bucket_dir)

      # TODO(dgn) should we use real sha1s? comparison with the real sha1 is
      # done but does not do anything other than displaying a message.
      config_license_sha1 = 'license0and0filling0to0forty0chars000000'
      with open(self.paths.config_license_sha1, 'w') as stream:
        stream.write(config_license_sha1)

      with open(os.path.join(bucket_dir, config_license_sha1), 'w') as stream:
        stream.write(self.DEFAULT_LICENSE)

      config_zip_sha1 = self.DEFAULT_ZIP_SHA1
      with open(self.paths.config_zip_sha1, 'w') as stream:
        stream.write(config_zip_sha1)

      pre_zip_lib = os.path.join(self.workdir, 'pre_zip_lib')
      post_zip_lib = os.path.join(bucket_dir, config_zip_sha1)
      _MakeDirs(pre_zip_lib)
      with open(os.path.join(pre_zip_lib, 'dummy_file'), 'w') as stream:
        stream.write('foo\n')
      shutil.make_archive(post_zip_lib, 'zip', pre_zip_lib)
      # make_archive appends .zip
      shutil.move(post_zip_lib + '.zip', post_zip_lib)

    if xml_version:
      _MakeDirs(os.path.dirname(self.paths.xml_version))
      with open(self.paths.xml_version, 'w') as stream:
        stream.write(
            '<?xml version="1.0" encoding="utf-8"?>\n'
            '<resources>\n'
            '    <integer name="google_play_services_version">%d</integer>\n'
            '</resources>\n' % xml_version)


class Paths(object):
  '''Declaration of the paths commonly manipulated in the tests.'''

  def __init__(self, workdir):
    self.bucket = os.path.join(workdir, 'bucket')

    self.config_dir = os.path.join(workdir, 'config')
    self.config_file = os.path.join(self.config_dir, 'config.json')
    self.config_license_sha1 = os.path.join(self.config_dir, 'LICENSE.sha1')
    self.config_zip_sha1 = os.path.join(
        self.config_dir,
        'google_play_services_library.zip.sha1')

    self.sdk_root = os.path.join(workdir, 'sdk_root')
    self.gms_root = os.path.join(self.sdk_root, 'extras', 'google',
                                 'google_play_services')
    self.gms_root_sha1 = os.path.join(self.gms_root,
                                      'google_play_services_library.zip.sha1')
    self.gms_root_license = os.path.join(self.gms_root, 'LICENSE')
    self.source_prop = os.path.join(self.gms_root, 'source.properties')
    self.gms_lib = os.path.join(self.gms_root, 'libproject',
                                'google-play-services_lib')
    self.xml_version = os.path.join(self.gms_lib, 'res', 'values',
                                    'version.xml')


def _GetFileContent(file_path):
  with open(file_path, 'r') as stream:
    return stream.read()


def _MakeDirs(path):
  '''Avoids having to do the error handling everywhere.'''
  if not os.path.exists(path):
    os.makedirs(path)


@contextlib.contextmanager
def _MockedInput(typed_string):
  '''Makes raw_input return |typed_string| while inside the context.'''
  try:
    original_raw_input = __builtins__.raw_input
    __builtins__.raw_input = lambda _: typed_string
    yield
  finally:
    __builtins__.raw_input = original_raw_input


if __name__ == '__main__':
  unittest.main()
