# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

""" A simple device interface for build steps.

"""

import logging
import os
import re
import sys

from util import build_utils

from devil.android import device_errors
from devil.android import device_utils
from devil.android.sdk import adb_wrapper


def GetAttachedDevices():
  return [a.GetDeviceSerial()
          for a in adb_wrapper.AdbWrapper.Devices()]


class BuildDevice(object):
  def __init__(self, configuration):
    self.id = configuration['id']
    self.description = configuration['description']
    self.install_metadata = configuration['install_metadata']
    assert all(isinstance(entry, dict) for entry in self.install_metadata), (
        'Invalid BuildDevice configuration')
    self.device = device_utils.DeviceUtils(self.id)

  def RunShellCommand(self, *args, **kwargs):
    return self.device.RunShellCommand(*args, **kwargs)

  def PushChangedFiles(self, *args, **kwargs):
    return self.device.PushChangedFiles(*args, **kwargs)

  def GetSerialNumber(self):
    return self.id

  def Install(self, *args, **kwargs):
    return self.device.Install(*args, **kwargs)

  def InstallSplitApk(self, *args, **kwargs):
    return self.device.InstallSplitApk(*args, **kwargs)

  def GetInstallMetadata(self, apk_package, refresh=False):
    """Gets the metadata on the device for a given apk.

    Args:
      apk_package: A string with the package name for which to get metadata.
      refresh: A boolean indicating whether to re-read package metadata from
        the device, or use the values from the current configuration.
    """
    if refresh:
      self.install_metadata = self.device.StatDirectory(
          '/data/app/', as_root=True)
    # Matches names like: org.chromium.chrome.apk, org.chromium.chrome-1.apk
    apk_pattern = re.compile('%s(-[0-9]*)?(.apk)?$' % re.escape(apk_package))
    return next(
        (entry for entry in self.install_metadata
         if apk_pattern.match(entry['filename'])),
        None)


def GetConfigurationForDevice(device_id):
  device = device_utils.DeviceUtils(device_id)
  configuration = None
  has_root = False
  is_online = device.IsOnline()
  if is_online:
    has_root = device.HasRoot()
    configuration = {
        'id': device_id,
        'description': device.build_description,
        'install_metadata': device.StatDirectory('/data/app/', as_root=True),
      }
  return configuration, is_online, has_root


def WriteConfigurations(configurations, path):
  # Currently we only support installing to the first device.
  build_utils.WriteJson(configurations[:1], path, only_if_changed=True)


def ReadConfigurations(path):
  return build_utils.ReadJson(path)


def GetBuildDevice(configurations):
  assert len(configurations) == 1
  return BuildDevice(configurations[0])


def GetBuildDeviceFromPath(path):
  configurations = ReadConfigurations(path)
  if len(configurations) > 0:
    return GetBuildDevice(ReadConfigurations(path))
  return None
