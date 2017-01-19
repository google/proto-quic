# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import logging
import sys

from devil.android import logcat_monitor
from devil.utils import reraiser_thread
from pylib import constants

sys.path.insert(0, os.path.abspath(os.path.join(
    constants.DIR_SOURCE_ROOT, 'tools', 'swarming_client')))
from libs.logdog import bootstrap # pylint: disable=import-error

class LogdogLogcatMonitor(logcat_monitor.LogcatMonitor):
  """Logcat monitor that writes logcat to a logdog stream.
  The logdog stream client will return a url, where contains the logcat.
  """
  def __init__(self, adb, stream_name, clear=True, filter_specs=None):
    super(LogdogLogcatMonitor, self).__init__(adb, clear, filter_specs)
    self._logcat_url = ''
    self._logdog_stream = None
    self._stream_client = None
    self._stream_name = stream_name
    try:
      self._stream_client = bootstrap.ButlerBootstrap.probe().stream_client()
      self._logdog_stream = self._stream_client.open_text(self._stream_name)
    except bootstrap.NotBootstrappedError as e:
      if logging.getLogger().isEnabledFor(logging.DEBUG):
        logging.exception('Unable to enable logdog_logcat: %s.', e)
    except (KeyError, ValueError) as e:
      logging.exception('Error when creating stream_client/stream: %s.', e)
    except Exception as e: # pylint: disable=broad-except
      logging.exception('Unknown Error: %s.', e)

  def GetLogcatURL(self):
    """Return logcat url.

    The default logcat url is '', if failed to create stream_client.
    """
    return self._logcat_url

  def Stop(self):
    """Stops the logcat monitor.

    Close the logdog stream as well.
    """
    try:
      super(LogdogLogcatMonitor, self)._StopRecording()
      if self._logdog_stream:
        try:
          self._logcat_url = self._stream_client.get_viewer_url(
              self._stream_name)
        except (KeyError, ValueError) as e:
          logging.exception('Error cannot get viewer url: %s', e)
        self._logdog_stream.close()
    except Exception as e: # pylint: disable=broad-except
      logging.exception('Unknown Error: %s.', e)

  def Start(self):
    """Starts the logdog logcat monitor.

    Clears the logcat if |clear| was set in |__init__|.
    """
    if self._clear:
      self._adb.Logcat(clear=True)
    self._StartRecording()

  def _StartRecording(self):
    """Starts recording logcat to file.

    Write logcat to stream at the same time.
    """
    def record_to_stream():
      if self._logdog_stream:
        for data in self._adb.Logcat(filter_specs=self._filter_specs,
                                     logcat_format='threadtime'):
          if self._stop_recording_event.isSet():
            return
          self._logdog_stream.write(data + '\n')

    self._stop_recording_event.clear()
    if not self._record_thread:
      self._record_thread = reraiser_thread.ReraiserThread(record_to_stream)
      self._record_thread.start()

  def Close(self):
    """Override parent's close method."""
    pass

  def __del__(self):
    """Override parent's delete method."""
    pass
