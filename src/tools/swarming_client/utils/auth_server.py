#!/usr/bin/env python
# Copyright 2016 The LUCI Authors. All rights reserved.
# Use of this source code is governed under the Apache License, Version 2.0
# that can be found in the LICENSE file.

import base64
import BaseHTTPServer
import collections
import json
import logging
import os
import re
import SocketServer
import threading
import time


# OAuth access token with its expiration time.
AccessToken = collections.namedtuple('AccessToken', [
  'access_token',  # urlsafe str with the token
  'expiry',        # expiration time as unix timestamp in seconds
])


class TokenError(Exception):
  """Raised by TokenProvider if the token can't be created.

  See TokenProvider docs for more info.
  """

  def __init__(self, code, msg, fatal=False):
    super(TokenError, self).__init__(msg)
    self.code = code
    self.fatal = fatal


class RPCError(Exception):
  """Raised by LocalAuthServer RPC handlers to reply with HTTP error status."""

  def __init__(self, code, msg):
    super(RPCError, self).__init__(msg)
    self.code = code


class TokenProvider(object):
  """Interface for an object that can create OAuth tokens on demand.

  Defined as a concrete class only for documentation purposes.
  """

  def generate_token(self, scopes):
    """Generates a new access token with given scopes.

    Will be called from multiple threads (possibly concurrently) whenever
    LocalAuthServer needs to refresh a token with particular scopes.

    Can rise RPCError exceptions. They will be immediately converted to
    corresponding RPC error replies (e.g. HTTP 500). This is appropriate for
    low-level or transient errors.

    Can also raise TokenError. It will be converted to GetOAuthToken reply with
    non-zero error_code. It will also optionally be cached, so that the provider
    would never be called again for the same set of scopes. This is appropriate
    for high-level or fatal errors.

    Returns AccessToken on success.
    """
    raise NotImplementedError()


class LocalAuthServer(object):
  """LocalAuthServer handles /rpc/LuciLocalAuthService.* requests.

  It exposes an HTTP JSON RPC API that is used by task processes to grab an
  access token for the service account associated with the task.

  It implements RPC handling details and in-memory cache for the tokens, but
  defers to the supplied TokenProvider for the actual token generation.
  """

  def __init__(self):
    self._lock = threading.Lock() # guards everything below
    self._accept_thread = None
    self._cache = {} # dict (tuple of scopes => AccessToken | TokenError).
    self._token_provider = None
    self._rpc_secret = None
    self._server = None

  def start(self, token_provider, port=0):
    """Starts the local auth RPC server on some 127.0.0.1 port.

    Args:
      token_provider: instance of TokenProvider to use for making tokens.
      port: local TCP port to bind to, or 0 to bind to any available port.

    Returns:
      A dict to put into 'local_auth' section of LUCI_CONTEXT.
    """
    server = _HTTPServer(self, ('127.0.0.1', port))

    # This secret will be placed in a file on disk accessible only to current
    # user processes. RPC requests are expected to send this secret verbatim.
    # That way we authenticate RPCs as coming from current user's processes.
    rpc_secret = base64.b64encode(os.urandom(48))

    with self._lock:
      assert not self._server, 'Already running'
      logging.info('Local auth server: http://127.0.0.1:%d', server.server_port)
      self._token_provider = token_provider
      self._rpc_secret = rpc_secret
      self._server = server
      self._accept_thread = threading.Thread(target=self._server.serve_forever)
      self._accept_thread.start()
      return {
        'rpc_port': self._server.server_port,
        'secret': self._rpc_secret,
      }

  def stop(self):
    """Stops the server and resets the state."""
    with self._lock:
      if not self._server:
        return
      server, self._server = self._server, None
      thread, self._accept_thread = self._accept_thread, None
      self._token_provider = None
      self._rpc_secret = None
      self._cache.clear()
    logging.debug('Stopping the local auth server...')
    server.shutdown()
    thread.join()
    server.server_close()
    logging.info('The local auth server is stopped')

  def handle_rpc(self, method, request):
    """Called by _RequestHandler to handle one RPC call.

    Called from internal server thread. May be called even if the server is
    already stopped (due to BaseHTTPServer.HTTPServer implementation that
    stupidly leaks handler threads).

    Args:
      method: name of the invoked RPC method, e.g. "GetOAuthToken".
      request: JSON dict with the request body.

    Returns:
      JSON dict with the response body.

    Raises:
      RPCError to return non-200 HTTP code and an error message as plain text.
    """
    if method == 'GetOAuthToken':
      return self.handle_get_oauth_token(request)
    raise RPCError(404, 'Unknown RPC method "%s".' % method)

  ### RPC method handlers. Called from internal threads.

  def handle_get_oauth_token(self, request):
    """Returns an OAuth token representing the task service account.

    The returned token is usable for at least 1 min.

    Request body:
    {
      "scopes": [<str scope1>, <str scope2>, ...],
      "secret": <str from LUCI_CONTEXT.local_auth.secret>
    }

    Response body:
    {
      "error_code": <int, 0 or missing on success>,
      "error_message": <str, optional>,
      "access_token": <str with actual token (on success)>,
      "expiry": <int with unix timestamp in seconds (on success)>
    }
    """
    # Validate scopes. It is conceptually a set, so remove duplicates.
    scopes = request.get('scopes')
    if not scopes:
      raise RPCError(400, 'Field "scopes" is required.')
    if (not isinstance(scopes, list) or
        not all(isinstance(s, basestring) for s in scopes)):
      raise RPCError(400, 'Field "scopes" must be a list of strings.')
    scopes = tuple(sorted(set(map(str, scopes))))

    # Validate the secret format.
    secret = request.get('secret')
    if not secret:
      raise RPCError(400, 'Field "secret" is required.')
    if not isinstance(secret, basestring):
      raise RPCError(400, 'Field "secret" must be a string.')
    secret = str(secret)

    # Grab the correct secret and the provider from the lock-guarded state.
    with self._lock:
      if not self._server:
        raise RPCError(503, 'Stopped already.')
      rpc_secret = self._rpc_secret
      token_provider = self._token_provider

    # Use constant time check to prevent malicious processes from discovering
    # the secret byte-by-byte measuring response time.
    if not constant_time_equals(secret, rpc_secret):
      raise RPCError(403, 'Invalid "secret".')

    # Grab the token (or a fatal error) from the memory cache, checks token
    # expiration time.
    tok_or_err = None
    need_refresh = False
    with self._lock:
      if not self._server:
        raise RPCError(503, 'Stopped already.')
      tok_or_err = self._cache.get(scopes)
      need_refresh = (
          not tok_or_err or
          isinstance(tok_or_err, AccessToken) and should_refresh(tok_or_err))

    # Do the refresh outside of the RPC server lock to unblock other clients
    # that are hitting the cache. The token provider should implement its own
    # synchronization.
    if need_refresh:
      try:
        tok_or_err = token_provider.generate_token(scopes)
        assert isinstance(tok_or_err, AccessToken), tok_or_err
      except TokenError as exc:
        tok_or_err = exc
      # Cache the token or fatal errors (to avoid useless retry later).
      if isinstance(tok_or_err, AccessToken) or tok_or_err.fatal:
        with self._lock:
          if not self._server:
            raise RPCError(503, 'Stopped already.')
          self._cache[scopes] = tok_or_err

    # Done.
    if isinstance(tok_or_err, AccessToken):
      return {
        'access_token': tok_or_err.access_token,
        'expiry': int(tok_or_err.expiry),
      }
    if isinstance(tok_or_err, TokenError):
      return {
        'error_code': tok_or_err.code,
        'error_message': str(tok_or_err.message or 'unknown'),
      }
    raise AssertionError('impossible')


def constant_time_equals(a, b):
  """Compares two strings in constant time regardless of theirs content."""
  if len(a) != len(b):
    return False
  result = 0
  for x, y in zip(a, b):
    result |= ord(x) ^ ord(y)
  return result == 0


def should_refresh(tok):
  """Returns True if the token must be refreshed because it expires soon."""
  return time.time() > tok.expiry - 60


class _HTTPServer(SocketServer.ThreadingMixIn, BaseHTTPServer.HTTPServer):
  """Used internally by LocalAuthServer."""

  # How often to poll 'select' in local HTTP server.
  #
  # Defines minimal amount of time 'stop' would block. Overridden in tests to
  # speed them up.
  poll_interval = 0.5

  # From SocketServer.ThreadingMixIn.
  daemon_threads = True
  # From BaseHTTPServer.HTTPServer.
  request_queue_size = 50

  def __init__(self, local_auth_server, addr):
    BaseHTTPServer.HTTPServer.__init__(self, addr, _RequestHandler)
    self.local_auth_server = local_auth_server

  def serve_forever(self, poll_interval=None):
    """Overrides default poll interval."""
    BaseHTTPServer.HTTPServer.serve_forever(
        self, poll_interval or self.poll_interval)

  def handle_error(self, request, client_address):
    """Overrides default handle_error that dumbs stuff to stdout."""
    logging.exception('local auth server: Exception happened')


class _RequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):
  """Used internally by LocalAuthServer.

  Parses the request, serializes and write the response.
  """

  # Buffer the reply, no need to send each line separately.
  wbufsize = -1

  def log_message(self, fmt, *args):
    """Overrides default log_message to not abuse stderr."""
    logging.debug('local auth server: ' + fmt, *args)

  def send_error(self, code, message=None):
    """Overrides default send_error to send 'text/plain' response."""
    assert isinstance(message, str), 'unicode is not allowed'
    logging.warning('local auth server: HTTP %d - %s', code, message)
    message = (message or '') + '\n'
    self.send_response(code)
    self.send_header('Connection', 'close')
    self.send_header('Content-Length', str(len(message)))
    self.send_header('Content-Type', 'text/plain')
    self.end_headers()
    self.wfile.write(message)

  def do_POST(self):
    """Implements POST handler."""
    # Parse URL to extract method name.
    m = re.match(r'^/rpc/LuciLocalAuthService\.([a-zA-Z0-9_]+)$', self.path)
    if not m:
      self.send_error(404, 'Expecting /rpc/LuciLocalAuthService.*')
      return
    method = m.group(1)

    # The request body MUST be JSON. Ignore charset, we don't care.
    ct = self.headers.get('content-type')
    if not ct or ct.split(';')[0] != 'application/json':
      self.send_error(
          400, 'Expecting "application/json" Content-Type, got %r' % ct)
      return

    # Read the body. Chunked transfer encoding or compression is no supported.
    try:
      content_len = int(self.headers['content-length'])
    except ValueError:
      self.send_error(400, 'Missing on invalid Content-Length header')
      return
    try:
      req = json.loads(self.rfile.read(content_len))
    except ValueError as exc:
      self.send_error(400, 'Not a JSON: %s' % exc)
      return
    if not isinstance(req, dict):
      self.send_error(400, 'Not a JSON dictionary')
      return

    # Let the LocalAuthServer handle the request. Prepare the response body.
    try:
      resp = self.server.local_auth_server.handle_rpc(method, req)
      response_body = json.dumps(resp) + '\n'
    except RPCError as exc:
      self.send_error(exc.code, exc.message)
      return
    except Exception as exc:
      self.send_error(500, 'Internal error: %s' % exc)
      return

    # Send the response.
    self.send_response(200)
    self.send_header('Connection', 'close')
    self.send_header('Content-Length', str(len(response_body)))
    self.send_header('Content-Type', 'application/json')
    self.end_headers()
    self.wfile.write(response_body)


def main():
  """Launches a local HTTP auth service and waits for Ctrl+C.

  Useful during development and manual testing.
  """
  logging.basicConfig(level=logging.DEBUG)

  class DumbProvider(object):
    def generate_token(self, scopes):
      logging.info('generate_token(%s) called', scopes)
      return AccessToken('fake_tok', time.time() + 80)

  server = LocalAuthServer()
  ctx = server.start(token_provider=DumbProvider(), port=11111)
  print 'LUCI_CONTEXT:\n' + json.dumps(
      {'local_auth': ctx}, indent=2, sort_keys=True)
  try:
    while True:
      time.sleep(1)
  except KeyboardInterrupt:
    pass
  finally:
    server.stop()


if __name__ == '__main__':
  main()
