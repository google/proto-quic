# Copyright 2014 The LUCI Authors. All rights reserved.
# Use of this source code is governed under the Apache License, Version 2.0
# that can be found in the LICENSE file.

import logging

import httpserver_mock


class CipdServerHandler(httpserver_mock.MockHandler):
  """An extremely minimal implementation of the cipd server API v1.0."""

  ### Mocked HTTP Methods

  def do_GET(self):
    logging.info('GET %s', self.path)
    if self.path in ('/on/load', '/on/quit'):
      self._octet_stream('')
    elif self.path == '/auth/api/v1/server/oauth_config':
      self._json({
        'client_id': 'c',
        'client_not_so_secret': 's',
        'primary_url': self.server.url})
    elif self.path.startswith('/_ah/api/repo/v1/instance/resolve?'):
      self._json({
        'status': 'SUCCESS',
        'instance_id': 'a' * 40,
      })
    elif self.path.startswith('/_ah/api/repo/v1/client?'):
      self._json({
        'status': 'SUCCESS',
        'client_binary': {
          'fetch_url': self.server.url + '/fake_google_storage/cipd_client',
        },
      })
    elif self.path == '/fake_google_storage/cipd_client':
      # The content is not actually used because run_isolated_test.py
      # mocks popen.
      self._octet_stream('#!/usr/sh\n')
    else:
      raise NotImplementedError(self.path)


class MockCipdServer(httpserver_mock.MockServer):
  _HANDLER_CLS = CipdServerHandler
