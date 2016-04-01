# Copyright (c) 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Class representing instrumentation test apk and jar."""

import os

from devil.android import apk_helper
from pylib.instrumentation import test_jar
from pylib.local.device import local_device_test_run


class TestPackage(test_jar.TestJar):
  def __init__(self, apk_path, jar_path, test_support_apk_path,
               additional_apks=None, apk_under_test=None,
               test_apk_incremental_install_script=None,
               apk_under_test_incremental_install_script=None):
    test_jar.TestJar.__init__(self, jar_path)

    if not os.path.exists(apk_path):
      raise Exception('%s not found, please build it' % apk_path)
    self._additional_apks = additional_apks or []
    self._apk_name = os.path.splitext(os.path.basename(apk_path))[0]
    if apk_under_test:
      self._apk_under_test = apk_helper.ApkHelper(apk_under_test)
    else:
      self._apk_under_test = None
    self._test_apk = apk_helper.ApkHelper(apk_path)
    self._test_support_apk_path = test_support_apk_path
    self._test_apk_incremental_install_script = (
        test_apk_incremental_install_script)
    self._apk_under_test_incremental_install_script = (
        apk_under_test_incremental_install_script)

  def GetApkPath(self):
    """Returns the absolute path to the APK."""
    return self._test_apk.path

  def GetApkUnderTest(self):
    """Returns an ApkHelper instance for the apk under test.

    Note that --apk-under-test is not required, so this can be None.
    """
    return self._apk_under_test

  def GetApkName(self):
    """Returns the name of the apk without the suffix."""
    return self._apk_name

  def GetPackageName(self):
    """Returns the package name of this APK."""
    return self._test_apk.GetPackageName()

  def GetTestApk(self):
    """Returns an ApkHelper instance for the test apk."""
    return self._test_apk

  # Override.
  def Install(self, device):
    if self._test_apk_incremental_install_script:
      local_device_test_run.IncrementalInstall(device, self._test_apk,
          self._test_apk_incremental_install_script)
    else:
      device.Install(self._test_apk)

    if self._apk_under_test_incremental_install_script:
      local_device_test_run.IncrementalInstall(device,
          self._apk_under_test, self._apk_under_test_incremental_install_script)
    elif self._apk_under_test:
      device.Install(self._apk_under_test)

    if (self._test_support_apk_path and
        os.path.exists(self._test_support_apk_path)):
      device.Install(self._test_support_apk_path)
    for apk in (a for a in self._additional_apks if os.path.exists(a)):
      device.Install(apk)
