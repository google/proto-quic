# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
from core import path_util
path_util.AddAndroidPylibToPath()
from pylib.utils import shared_preference_utils
from telemetry.core import android_platform
from telemetry.core import platform
from telemetry.core import util
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
    self._InstallNfcApk()

  def _InstallVrCore(self):
    """Installs the VrCore APK."""
    # TODO(bsheedy): Add support for temporarily replacing it if it's still
    # installed as a system app on the test device
    self._platform.InstallApplication(
        os.path.join(path_util.GetChromiumSrcDir(), 'third_party',
                     'gvr-android-sdk', 'test-apks', 'vr_services',
                     'vr_services_current.apk'))

  def _ConfigureVrCore(self):
    """Configures VrCore using the settings file passed to the benchmark."""
    settings = shared_preference_utils.ExtractSettingsFromJson(
        os.path.join(path_util.GetChromiumSrcDir(),
                     self._finder_options.shared_prefs_file))
    for setting in settings:
      shared_pref = self._platform.GetSharedPrefs(setting['package'],
                                                  setting['filename'])
      shared_preference_utils.ApplySharedPreferenceSetting(
          shared_pref, setting)

  def _InstallNfcApk(self):
    """Installs the APK that allows VR tests to simulate a headset NFC scan."""
    chromium_root = path_util.GetChromiumSrcDir()
    # Find the most recently build APK
    candidate_apks = []
    for build_path in util.GetBuildDirectories(chromium_root):
      apk_path = os.path.join(build_path, 'apks', 'VrNfcSimulator.apk')
      if os.path.exists(apk_path):
        last_changed = os.path.getmtime(apk_path)
        candidate_apks.append((last_changed, apk_path))

    if not candidate_apks:
      raise RuntimeError(
          'Could not find VrNfcSimulator.apk in a build output directory')
    newest_apk_path = sorted(candidate_apks)[-1][1]
    self._platform.InstallApplication(
        os.path.join(chromium_root, newest_apk_path))

  @property
  def platform(self):
    return self._platform
