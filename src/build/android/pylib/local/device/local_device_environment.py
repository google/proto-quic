# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import contextlib
import datetime
import functools
import logging
import os
import shutil
import tempfile
import threading

from devil import base_error
from devil.android import device_blacklist
from devil.android import device_errors
from devil.android import device_list
from devil.android import device_utils
from devil.android import logcat_monitor
from devil.utils import file_utils
from devil.utils import parallelizer
from pylib import constants
from pylib.base import environment
from py_trace_event import trace_event
from tracing_build import trace2html


def _DeviceCachePath(device):
  file_name = 'device_cache_%s.json' % device.adb.GetDeviceSerial()
  return os.path.join(constants.GetOutDirectory(), file_name)


def handle_shard_failures(f):
  """A decorator that handles device failures for per-device functions.

  Args:
    f: the function being decorated. The function must take at least one
      argument, and that argument must be the device.
  """
  return handle_shard_failures_with(None)(f)


# TODO(jbudorick): Refactor this to work as a decorator or context manager.
def handle_shard_failures_with(on_failure):
  """A decorator that handles device failures for per-device functions.

  This calls on_failure in the event of a failure.

  Args:
    f: the function being decorated. The function must take at least one
      argument, and that argument must be the device.
    on_failure: A binary function to call on failure.
  """
  def decorator(f):
    @functools.wraps(f)
    def wrapper(dev, *args, **kwargs):
      try:
        return f(dev, *args, **kwargs)
      except device_errors.CommandTimeoutError:
        logging.exception('Shard timed out: %s(%s)', f.__name__, str(dev))
      except device_errors.DeviceUnreachableError:
        logging.exception('Shard died: %s(%s)', f.__name__, str(dev))
      except base_error.BaseError:
        logging.exception('Shard failed: %s(%s)', f.__name__, str(dev))
      except SystemExit:
        logging.exception('Shard killed: %s(%s)', f.__name__, str(dev))
        raise
      if on_failure:
        on_failure(dev, f.__name__)
      return None

    return wrapper

  return decorator


class LocalDeviceEnvironment(environment.Environment):

  def __init__(self, args, _error_func):
    super(LocalDeviceEnvironment, self).__init__()
    self._blacklist = (device_blacklist.Blacklist(args.blacklist_file)
                       if args.blacklist_file
                       else None)
    self._device_serial = args.test_device
    self._devices_lock = threading.Lock()
    self._devices = None
    self._concurrent_adb = args.enable_concurrent_adb
    self._enable_device_cache = args.enable_device_cache
    self._logcat_monitors = []
    self._logcat_output_dir = args.logcat_output_dir
    self._logcat_output_file = args.logcat_output_file
    self._max_tries = 1 + args.num_retries
    self._skip_clear_data = args.skip_clear_data
    self._target_devices_file = args.target_devices_file
    self._tool_name = args.tool
    self._trace_output = args.trace_output

  #override
  def SetUp(self):
    pass

  def _InitDevices(self):
    device_arg = 'default'
    if self._target_devices_file:
      device_arg = device_list.GetPersistentDeviceList(
          self._target_devices_file)
      if not device_arg:
        logging.warning('No target devices specified. Falling back to '
                        'running on all available devices.')
        device_arg = 'default'
      else:
        logging.info(
            'Read device list %s from target devices file.', str(device_arg))
    elif self._device_serial:
      device_arg = self._device_serial

    self._devices = device_utils.DeviceUtils.HealthyDevices(
        self._blacklist, enable_device_files_cache=self._enable_device_cache,
        default_retries=self._max_tries - 1, device_arg=device_arg)
    if not self._devices:
      raise device_errors.NoDevicesError

    if self._logcat_output_file:
      self._logcat_output_dir = tempfile.mkdtemp()

    @handle_shard_failures_with(on_failure=self.BlacklistDevice)
    def prepare_device(d):
      d.WaitUntilFullyBooted(timeout=10)

      if self._enable_device_cache:
        cache_path = _DeviceCachePath(d)
        if os.path.exists(cache_path):
          logging.info('Using device cache: %s', cache_path)
          with open(cache_path) as f:
            d.LoadCacheData(f.read())
          # Delete cached file so that any exceptions cause it to be cleared.
          os.unlink(cache_path)

      if self._logcat_output_dir:
        logcat_file = os.path.join(
            self._logcat_output_dir,
            '%s_%s' % (d.adb.GetDeviceSerial(),
                       datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%S')))
        monitor = logcat_monitor.LogcatMonitor(
            d.adb, clear=True, output_file=logcat_file)
        self._logcat_monitors.append(monitor)
        monitor.Start()

    self.parallel_devices.pMap(prepare_device)

  @staticmethod
  def _JsonToTrace(json_path, html_path, delete_json=True):
    # First argument is call site.
    cmd = [__file__, json_path, '--title', 'Android Test Runner Trace',
           '--output', html_path]
    trace2html.Main(cmd)
    if delete_json:
      os.remove(json_path)

  @property
  def blacklist(self):
    return self._blacklist

  @property
  def concurrent_adb(self):
    return self._concurrent_adb

  @property
  def devices(self):
    # Initialize lazily so that host-only tests do not fail when no devices are
    # attached.
    if self._devices is None:
      self._InitDevices()
    if not self._devices:
      raise device_errors.NoDevicesError()
    return self._devices

  @property
  def max_tries(self):
    return self._max_tries

  @property
  def parallel_devices(self):
    return parallelizer.SyncParallelizer(self.devices)

  @property
  def skip_clear_data(self):
    return self._skip_clear_data

  @property
  def tool(self):
    return self._tool_name

  @property
  def trace_output(self):
    return self._trace_output

  #override
  def TearDown(self):
    if self._devices is None:
      return
    @handle_shard_failures_with(on_failure=self.BlacklistDevice)
    def tear_down_device(d):
      # Write the cache even when not using it so that it will be ready the
      # first time that it is enabled. Writing it every time is also necessary
      # so that an invalid cache can be flushed just by disabling it for one
      # run.
      cache_path = _DeviceCachePath(d)
      if os.path.exists(os.path.dirname(cache_path)):
        with open(cache_path, 'w') as f:
          f.write(d.DumpCacheData())
          logging.info('Wrote device cache: %s', cache_path)
      else:
        logging.warning(
            'Unable to write device cache as %s directory does not exist',
            os.path.dirname(cache_path))

    self.parallel_devices.pMap(tear_down_device)

    for m in self._logcat_monitors:
      try:
        m.Stop()
        m.Close()
        _, temp_path = tempfile.mkstemp()
        with open(m.output_file, 'r') as infile:
          with open(temp_path, 'w') as outfile:
            for line in infile:
              outfile.write('Device(%s) %s' % (m.adb.GetDeviceSerial(), line))
        shutil.move(temp_path, m.output_file)
      except base_error.BaseError:
        logging.exception('Failed to stop logcat monitor for %s',
                          m.adb.GetDeviceSerial())
      except IOError:
        logging.exception('Failed to locate logcat for device %s',
                          m.adb.GetDeviceSerial())

    if self._logcat_output_file:
      file_utils.MergeFiles(
          self._logcat_output_file,
          [m.output_file for m in self._logcat_monitors
           if os.path.exists(m.output_file)])
      shutil.rmtree(self._logcat_output_dir)

  def BlacklistDevice(self, device, reason='local_device_failure'):
    device_serial = device.adb.GetDeviceSerial()
    if self._blacklist:
      self._blacklist.Extend([device_serial], reason=reason)
    with self._devices_lock:
      self._devices = [d for d in self._devices if str(d) != device_serial]

  def DisableTracing(self):
    if not trace_event.trace_is_enabled():
      logging.warning('Tracing is not running.')
    else:
      trace_event.trace_disable()
    self._JsonToTrace(self._trace_output + '.json',
                      self._trace_output)

  def EnableTracing(self):
    if trace_event.trace_is_enabled():
      logging.warning('Tracing is already running.')
    else:
      trace_event.trace_enable(self._trace_output + '.json')

  @contextlib.contextmanager
  def Tracing(self):
    try:
      self.EnableTracing()
      yield
    finally:
      self.DisableTracing()
