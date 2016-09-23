# Copyright 2014 The LUCI Authors. All rights reserved.
# Use of this source code is governed under the Apache License, Version 2.0
# that can be found in the LICENSE file.

import BaseHTTPServer
import json
import logging
import threading
import urllib2


class MockHandler(BaseHTTPServer.BaseHTTPRequestHandler):
  def _json(self, data):
    """Sends a JSON response."""
    self.send_response(200)
    self.send_header('Content-type', 'application/json')
    self.end_headers()
    json.dump(data, self.wfile)

  def _octet_stream(self, data):
    """Sends a binary response."""
    self.send_response(200)
    self.send_header('Content-type', 'application/octet-stream')
    self.end_headers()
    self.wfile.write(data)

  def _read_body(self):
    """Reads the request body."""
    return self.rfile.read(int(self.headers['Content-Length']))

  def _drop_body(self):
    """Reads the request body."""
    size = int(self.headers['Content-Length'])
    while size:
      chunk = min(4096, size)
      self.rfile.read(chunk)
      size -= chunk

  def log_message(self, fmt, *args):
    logging.info(
        '%s - - [%s] %s', self.address_string(), self.log_date_time_string(),
        fmt % args)


class MockServer(object):
  _HANDLER_CLS = None

  def __init__(self):
    self._closed = False
    self._server = BaseHTTPServer.HTTPServer(
        ('127.0.0.1', 0), self._HANDLER_CLS)
    self._server.url = self.url = 'http://localhost:%d' % (
      self._server.server_port)
    self._thread = threading.Thread(target=self._run, name='httpd')
    self._thread.daemon = True
    self._thread.start()
    logging.info('%s', self.url)

  def close(self):
    self.close_start()
    self.close_end()

  def close_start(self):
    assert not self._closed
    self._closed = True
    urllib2.urlopen(self.url + '/on/quit')

  def close_end(self):
    assert self._closed
    self._thread.join()

  def _run(self):
    while not self._closed:
      self._server.handle_request()
