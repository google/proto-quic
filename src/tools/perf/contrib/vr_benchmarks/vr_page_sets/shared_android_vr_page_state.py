# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
from core import path_util
path_util.AddAndroidPylibToPath()
from pylib.utils import shared_preference_utils
from telemetry.core import android_platform
from telemetry.core import platform
from telemetry.page import shared_page_state
from telemetry.internal.platform import android_device


class SharedAndroidVrPageState(shared_page_state.SharedPageState):
  """SharedPageState for VR Telemetry tests.

  Performs the same functionality as SharedPageState, but with two main
  differences:
  1. It is currently restricted to Android
  2. It performs VR-specific setup such as installing and configuring
     additional APKs that are necessary for testing
  """
  def __init__(self, test, finder_options, story_set):
    # TODO(bsheedy): See about making this a cross-platform SharedVrPageState -
    # Seems like we should be able to use SharedPageState's default platform
    # property instead of specifying AndroidPlatform, and then just perform
    # different setup based off the platform type
    device = android_device.GetDevice(finder_options)
    assert device, 'Android device is required for this story'
    self._platform = platform.GetPlatformForDevice(device, finder_options)
    assert self._platform, 'Unable to create Android platform'
    assert isinstance(self._platform, android_platform.AndroidPlatform)

    super(SharedAndroidVrPageState, self).__init__(test, finder_options,
                                                   story_set)
    self._PerformAndroidVrSetup()

  def _PerformAndroidVrSetup(self):
    self._InstallVrCore()
    self._ConfigureVrCore()

  def _InstallVrCore(self):
    # TODO(bsheedy): Add support for temporarily replacing it if it's still
    # installed as a system app on the test device
    self._platform.InstallApplication(
        os.path.join(path_util.GetChromiumSrcDir(), 'third_party',
                     'gvr-android-sdk', 'test-apks', 'vr_services',
                     'vr_services_current.apk'))

  def _ConfigureVrCore(self):
    settings = shared_preference_utils.ExtractSettingsFromJson(
        os.path.join(path_util.GetChromiumSrcDir(),
                     self._finder_options.shared_prefs_file))
    for setting in settings:
      shared_pref = self._platform.GetSharedPrefs(setting['package'],
                                                  setting['filename'])
      shared_preference_utils.ApplySharedPreferenceSetting(
          shared_pref, setting)

  @property
  def platform(self):
    return self._platform
