# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import sys

from core import path_util

from telemetry.core import local_server
from telemetry.core import util


# This invokes pywebsocket's standalone.py under third_party/pywebsocket
class PywebsocketServerBackend(local_server.LocalServerBackend):

  def __init__(self):
    super(PywebsocketServerBackend, self).__init__()
    self.port = 8001
    self.base_dir = os.path.relpath(
        os.path.join(path_util.GetChromiumSrcDir(),
                     'third_party', 'pywebsocket', 'src'),
        start=util.GetTelemetryDir())

  def StartAndGetNamedPorts(self, args):
    return [local_server.NamedPort('http', self.port)]

  def ServeForever(self):
    os.chdir(self.base_dir)
    cmd = [
        sys.executable, '-m', 'mod_pywebsocket.standalone',
        '--port', str(self.port),
        '--log-level', 'debug',
        '-d', 'example'
    ]
    os.execv(sys.executable, cmd)


class PywebsocketServer(local_server.LocalServer):

  def __init__(self):
    super(PywebsocketServer, self).__init__(PywebsocketServerBackend)

  def GetBackendStartupArgs(self):
    return {}
