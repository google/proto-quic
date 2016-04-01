# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import datetime
import logging
import os
import shutil
import tempfile
import threading

from devil.android import device_blacklist
from devil.android import device_errors
from devil.android import device_utils
from devil.android import logcat_monitor
from devil.utils import file_utils
from devil.utils import parallelizer
from pylib import constants
from pylib.base import environment


def _DeviceCachePath(device):
  file_name = 'device_cache_%s.json' % device.adb.GetDeviceSerial()
  return os.path.join(constants.GetOutDirectory(), file_name)


class LocalDeviceEnvironment(environment.Environment):

  def __init__(self, args, _error_func):
    super(LocalDeviceEnvironment, self).__init__()
    self._blacklist = (device_blacklist.Blacklist(args.blacklist_file)
                       if args.blacklist_file
                       else None)
    self._device_serial = args.test_device
    self._devices_lock = threading.Lock()
    self._devices = []
    self._max_tries = 1 + args.num_retries
    self._tool_name = args.tool
    self._enable_device_cache = args.enable_device_cache
    self._concurrent_adb = args.enable_concurrent_adb
    self._logcat_output_dir = args.logcat_output_dir
    self._logcat_output_file = args.logcat_output_file
    self._logcat_monitors = []

  #override
  def SetUp(self):
    available_devices = device_utils.DeviceUtils.HealthyDevices(
        self._blacklist, enable_device_files_cache=self._enable_device_cache)
    if not available_devices:
      raise device_errors.NoDevicesError
    if self._device_serial:
      self._devices = [d for d in available_devices
                       if d.adb.GetDeviceSerial() == self._device_serial]
      if not self._devices:
        raise device_errors.DeviceUnreachableError(
            'Could not find device %r' % self._device_serial)
    else:
      self._devices = available_devices

    if self._enable_device_cache:
      for d in self._devices:
        cache_path = _DeviceCachePath(d)
        if os.path.exists(cache_path):
          logging.info('Using device cache: %s', cache_path)
          with open(cache_path) as f:
            d.LoadCacheData(f.read())
          # Delete cached file so that any exceptions cause it to be cleared.
          os.unlink(cache_path)
    if self._logcat_output_file:
      self._logcat_output_dir = tempfile.mkdtemp()
    if self._logcat_output_dir:
      for d in self._devices:
        logcat_file = os.path.join(
            self._logcat_output_dir,
            '%s_%s' % (d.adb.GetDeviceSerial(),
                       datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%S')))
        monitor = logcat_monitor.LogcatMonitor(
            d.adb, clear=True, output_file=logcat_file)
        self._logcat_monitors.append(monitor)
        monitor.Start()

  @property
  def devices(self):
    if not self._devices:
      raise device_errors.NoDevicesError()
    return self._devices

  @property
  def concurrent_adb(self):
    return self._concurrent_adb

  @property
  def parallel_devices(self):
    return parallelizer.SyncParallelizer(self.devices)

  @property
  def max_tries(self):
    return self._max_tries

  @property
  def tool(self):
    return self._tool_name

  #override
  def TearDown(self):
    # Write the cache even when not using it so that it will be ready the first
    # time that it is enabled. Writing it every time is also necessary so that
    # an invalid cache can be flushed just by disabling it for one run.
    for d in self._devices:
      cache_path = _DeviceCachePath(d)
      with open(cache_path, 'w') as f:
        f.write(d.DumpCacheData())
        logging.info('Wrote device cache: %s', cache_path)
    for m in self._logcat_monitors:
      m.Stop()
      m.Close()
    if self._logcat_output_file:
      file_utils.MergeFiles(
          self._logcat_output_file,
          [m.output_file for m in self._logcat_monitors])
      shutil.rmtree(self._logcat_output_dir)

  def BlacklistDevice(self, device, reason='local_device_failure'):
    device_serial = device.adb.GetDeviceSerial()
    if self._blacklist:
      self._blacklist.Extend([device_serial], reason=reason)
    with self._devices_lock:
      self._devices = [d for d in self._devices if str(d) != device_serial]

