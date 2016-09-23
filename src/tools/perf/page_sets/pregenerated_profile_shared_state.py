# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import logging
import os
import shutil
import sys
import tempfile
import zipfile

from py_utils import cloud_storage

from telemetry.page import shared_page_state


class PregeneratedProfileSharedState(shared_page_state.SharedPageState):
  def __init__(self, test, finder_options, story_set):
    super(PregeneratedProfileSharedState, self).__init__(
        test, finder_options, story_set)
    self._unzipped_profile = None
    self._migrated_profile = None
    self._pregenerated_profile_archive_dir = None

  def WillRunStory(self, page):
    if self._ShouldDownloadPregeneratedProfileArchive():
      self._DownloadPregeneratedProfileArchive()

      if self._ShouldMigrateProfile():
        self._MigratePregeneratedProfile()
    super(PregeneratedProfileSharedState, self).WillRunStory(page)

  def TearDownState(self):
    if self._unzipped_profile:
      shutil.rmtree(self._unzipped_profile)
      self._unzipped_profile = None
    if self._migrated_profile:
      shutil.rmtree(self._migrated_profile)
      self._migrated_profile = None
    super(PregeneratedProfileSharedState, self).TearDownState()

  def _ShouldDownloadPregeneratedProfileArchive(self):
    """Whether to download a pre-generated profile archive."""
    if not self._pregenerated_profile_archive_dir:
      return False

    if self._finder_options.browser_options.profile_dir:
      logging.warning("Profile directory specified on command line: %s, this"
                      "overrides the benchmark's default profile directory.",
                      self._finder_options.browser_options.profile_dir)
      return False

    if self._possible_browser.IsRemote():
      return False

    return True

  def _DownloadPregeneratedProfileArchive(self):
    """Download and extract the profile directory archive if one exists.

    On success, updates self._finder_options.browser_options.profile_dir with
    the directory of the extracted profile.
    """
    try:
      cloud_storage.GetIfChanged(self._pregenerated_profile_archive_dir,
                                 cloud_storage.PUBLIC_BUCKET)
    except (cloud_storage.CredentialsError,
            cloud_storage.PermissionError) as e:
      if os.path.exists(self._pregenerated_profile_archive_dir):
        # If the profile directory archive exists, assume the user has their
        # own local copy simply warn.
        logging.warning('Could not download Profile archive: %s',
                        self._pregenerated_profile_archive_dir)
      else:
        # If the archive profile directory doesn't exist, this is fatal.
        logging.error('Can not run without required profile archive: %s. '
                      'If you believe you have credentials, follow the '
                      'instructions below.',
                      self._pregenerated_profile_archive_dir)
        logging.error(str(e))
        sys.exit(-1)

    # Check to make sure the zip file exists.
    if not os.path.isfile(self._pregenerated_profile_archive_dir):
      raise Exception("Profile directory archive not downloaded: ",
                      self._pregenerated_profile_archive_dir)

    # The location to extract the profile into.
    self._unzipped_profile = tempfile.mkdtemp()
    profile_archive_path_basename = os.path.basename(
        self._pregenerated_profile_archive_dir)
    extracted_profile_dir_path = os.path.join(
        self._unzipped_profile,
        os.path.splitext(profile_archive_path_basename)[0])

    # Unzip profile directory.
    with zipfile.ZipFile(self._pregenerated_profile_archive_dir) as f:
      try:
        f.extractall(self._unzipped_profile)
      except Exception as e:
        # Cleanup any leftovers from unzipping.
        shutil.rmtree(self._unzipped_profile)
        logging.error("Error extracting profile directory zip file: %s", e)
        sys.exit(-1)

    if not os.path.exists(extracted_profile_dir_path):
      raise Exception("Failed to extract profile: ",
                      extracted_profile_dir_path)

    # Run with freshly extracted profile directory.
    logging.info("Using profile archive directory: %s",
                 extracted_profile_dir_path)
    self._finder_options.browser_options.profile_dir = (
        extracted_profile_dir_path)

  def _ShouldMigrateProfile(self):
    return not self._migrated_profile

  def _MigrateProfile(self, finder_options, found_browser,
                      initial_profile, final_profile):
    """Migrates a profile to be compatible with a newer version of Chrome.

    Launching Chrome with the old profile will perform the migration.
    """
    # Save the current input and output profiles.
    saved_input_profile = finder_options.browser_options.profile_dir
    saved_output_profile = finder_options.browser_options.output_profile_path

    # Set the input and output profiles.
    finder_options.browser_options.profile_dir = initial_profile
    finder_options.browser_options.output_profile_path = final_profile

    # Launch the browser, then close it.
    browser = found_browser.Create(finder_options)
    browser.Close()

    # Load the saved input and output profiles.
    finder_options.browser_options.profile_dir = saved_input_profile
    finder_options.browser_options.output_profile_path = saved_output_profile

  def _MigratePregeneratedProfile(self):
    """Migrates the pre-generated profile by launching Chrome with it.

    On success, updates self._migrated_profile and
    self._finder_options.browser_options.profile_dir with the directory of the
    migrated profile.
    """
    self._migrated_profile = tempfile.mkdtemp()
    logging.info("Starting migration of pre-generated profile to %s",
                 self._migrated_profile)
    pregenerated_profile = self._finder_options.browser_options.profile_dir

    possible_browser = self._FindBrowser(self._finder_options)
    self._MigrateProfile(self._finder_options, possible_browser,
                         pregenerated_profile, self._migrated_profile)
    self._finder_options.browser_options.profile_dir = self._migrated_profile
    logging.info("Finished migration of pre-generated profile to %s",
                 self._migrated_profile)
