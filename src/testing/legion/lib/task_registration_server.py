# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""The registration server used to register tasks.

The registration server is started by the test controller and allows the tasks
to register themselves when they start. Authentication of the tasks controllers
is based on an OTP passed to the run_task binary on startup.
"""

import logging
import threading

from legion.lib import common_lib
from legion.lib.rpc import SimpleJSONRPCServer


class TaskRegistrationServer(object):
  """Discovery server run on the host."""

  def __init__(self):
    self._expected_tasks = {}
    self._rpc_server = None
    self._thread = None
    self._port = common_lib.GetUnusedPort()

  @property
  def port(self):
    return self._port

  def _RegisterTaskRPC(self, otp, ip, port):
    """The RPC used by a task to register with the registration server."""
    assert otp in self._expected_tasks
    cb = self._expected_tasks.pop(otp)
    cb(ip, port)

  def RegisterTaskCallback(self, otp, callback):
    """Registers a callback associated with an OTP."""
    assert callable(callback)
    self._expected_tasks[otp] = callback

  def Start(self):
    """Starts the registration server."""
    logging.info('Starting task registration server')
    self._rpc_server = SimpleJSONRPCServer.SimpleJSONRPCServer(
        ('', self._port), allow_none=True, logRequests=False)
    self._rpc_server.register_function(
        self._RegisterTaskRPC, 'RegisterTask')
    self._thread = threading.Thread(target=self._rpc_server.serve_forever)
    self._thread.start()

  def Shutdown(self):
    """Shuts the discovery server down."""
    if self._thread and self._thread.is_alive():
      logging.info('Shutting down task registration server')
      self._rpc_server.shutdown()
