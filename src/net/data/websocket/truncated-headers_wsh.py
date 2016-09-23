# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from mod_pywebsocket import handshake


def web_socket_do_extra_handshake(request):
  msg = ('HTTP/1.1 101 Switching Protocols\r\n'
         'Upgrade: websocket\r\n'
         'Connection: Upgrade\r\n'
         'Sec-WebSocket-Accept: 3rfd')
  request.connection.write(msg)
  # Prevent pywebsocket from sending its own handshake message.
  raise handshake.AbortedByUserException('Close the connection')


def web_socket_transfer_data(request):
  pass
