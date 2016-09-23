# Copyright 2016 The LUCI Authors. All rights reserved.
# Use of this source code is governed under the Apache License, Version 2.0
# that can be found in the LICENSE file.

import collections
import contextlib
import json
import os
import socket
import sys
import threading
import types

from libs.logdog import streamname, varint


_StreamParamsBase = collections.namedtuple('_StreamParamsBase',
    ('name', 'type', 'content_type', 'tags', 'tee', 'binary_file_extension'))


# Magic number at the beginning of a Butler stream
#
# See "ProtocolFrameHeaderMagic" in:
# <luci-go>/logdog/client/butlerlib/streamproto
BUTLER_MAGIC = 'BTLR1\x1e'


class StreamParams(_StreamParamsBase):
  """Defines the set of parameters to apply to a new stream."""

  # A text content stream.
  TEXT = 'text'
  # A binary content stream.
  BINARY = 'binary'
  # A datagram content stream.
  DATAGRAM = 'datagram'

  # Tee parameter to tee this stream through the Butler's STDOUT.
  TEE_STDOUT = 'stdout'
  # Tee parameter to tee this stream through the Butler's STDERR.
  TEE_STDERR = 'stderr'

  @classmethod
  def make(cls, **kwargs):
    """Returns (StreamParams): A new StreamParams instance with supplied values.

    Any parameter that isn't supplied will be set to None.

    Args:
      kwargs (dict): Named parameters to apply.
    """
    return cls(**{f: kwargs.get(f) for f in cls._fields})

  def validate(self):
    """Raises (ValueError): if the parameters are not valid."""
    streamname.validate_stream_name(self.name)

    if self.type not in (self.TEXT, self.BINARY, self.DATAGRAM):
      raise ValueError('Invalid type (%s)' % (self.type,))

    if self.tags is not None:
      if not isinstance(self.tags, collections.Mapping):
        raise ValueError('Invalid tags type (%s)' % (self.tags,))
      for k, v in self.tags.iteritems():
        streamname.validate_tag(k, v)

    if self.tee not in (None, self.TEE_STDOUT, self.TEE_STDERR):
      raise ValueError('Invalid tee type (%s)' % (self.tee,))

    if not isinstance(self.binary_file_extension,
        (types.NoneType, types.StringTypes)):
      raise ValueError('Invalid binary file extension type (%s)' % (
          self.binary_file_extension,))

  def to_json(self):
    """Returns (str): The JSON representation of the StreamParams.

    Converts stream parameters to JSON for Butler consumption.

    Raises:
      ValueError: if these parameters are not valid.
    """
    self.validate()

    obj = {
        'name': self.name,
        'type': self.type,
    }

    def maybe_add(key, value):
      if value is not None:
        obj[key] = value
    maybe_add('contentType', self.content_type)
    maybe_add('tags', self.tags)
    maybe_add('tee', self.tee)
    maybe_add('binaryFileExtension', self.binary_file_extension)

    # Note that "dumps' will dump UTF-8 by default, which is what Butler wants.
    return json.dumps(obj, sort_keys=True, ensure_ascii=True, indent=None)


class StreamProtocolRegistry(object):
  """Registry of streamserver URI protocols and their client classes.
  """

  def __init__(self):
    self._registry = {}

  def register_protocol(self, protocol, client_cls):
    assert issubclass(client_cls, StreamClient)
    if self._registry.get(protocol) is not None:
      raise KeyError('Duplicate protocol registered.')
    self._registry[protocol] = client_cls

  def create(self, uri):
    uri = uri.split(':', 1)
    if len(uri) != 2:
      raise ValueError('Invalid stream server URI [%s]' % (uri,))
    protocol, value = uri

    client_cls = self._registry.get(protocol)
    if not client_cls:
      raise ValueError('Unknown stream client protocol (%s)' % (protocol,))
    return client_cls._create(value)

# Default (global) registry.
_default_registry = StreamProtocolRegistry()


def create(uri):
  """Returns (StreamClient): A stream client for the specified URI.

  This uses the default StreamProtocolRegistry to instantiate a StreamClient
  for the specified URI.

  Args:
    uri: The streamserver URI.

  Raises:
    ValueError if the supplied URI references an invalid or improperly
        configured streamserver.
  """
  return _default_registry.create(uri)


class StreamClient(object):
  """Abstract base class for a streamserver client.
  """

  class _DatagramStream(object):
    """Wraps a stream object to write length-prefixed datagrams."""

    def __init__(self, fd):
      self._fd = fd

    def send(self, data):
      varint.write_uvarint(self._fd, len(data))
      self._fd.write(data)

    def close(self):
      return self._fd.close()

  def __init__(self):
    self._name_lock = threading.Lock()
    self._names = set()

  def _register_new_stream(self, name):
    """Registers a new stream name.

    The Butler will internally reject any duplicate stream names. However, there
    isn't really feedback when this happens except a closed stream client. This
    is a client-side check to provide a more user-friendly experience in the
    event that a user attempts to register a duplicate stream name.

    Note that this is imperfect, as something else could register stream names
    with the same Butler instance and this library has no means of tracking.
    This is a best-effort experience, not a reliable check.

    Args:
      name (str): The name of the stream.

    Raises:
      ValueError if the stream name has already been registered.
    """
    with self._name_lock:
      if name in self._names:
        raise ValueError("Duplicate stream name [%s]" % (name,))
      self._names.add(name)

  @classmethod
  def _create(cls, value):
    """Returns (StreamClient): A new stream client connection.

    Validates the streamserver parameters and creates a new StreamClient
    instance that connects to them.

    Implementing classes must override this.
    """
    raise NotImplementedError()

  def _connect_raw(self):
    """Returns (file): A new file-like stream.

    Creates a new raw connection to the streamserver. This connection MUST not
    have any data written to it past initialization (if needed) when it has been
    returned.

    The file-like object must implement `write` and `close`.

    Implementing classes must override this.
    """
    raise NotImplementedError()

  def new_connection(self, params):
    """Returns (file): A new configured stream.

    The returned object implements (minimally) `write` and `close`.

    Creates a new LogDog stream with the specified parameters.

    Args:
      params (StreamParams): The parameters to use with the new connection.

    Raises:
      ValueError if the stream name has already been used, or if the parameters
      are not valid.
    """
    self._register_new_stream(params.name)
    params_json = params.to_json()

    fd = self._connect_raw()
    fd.write(BUTLER_MAGIC)
    varint.write_uvarint(fd, len(params_json))
    fd.write(params_json)
    return fd

  @contextlib.contextmanager
  def text(self, name, **kwargs):
    """Context manager to create, use, and teardown a TEXT stream.

    This context manager creates a new butler TEXT stream with the specified
    parameters, yields it, and closes it on teardown.

    Args:
      name (str): the LogDog name of the stream.
      kwargs (dict): Log stream parameters. These may be any keyword arguments
          accepted by `open_text`.

    Returns (file): A file-like object to a Butler UTF-8 text stream supporting
        `write`.
    """
    fd = None
    try:
      fd = self.open_text(name, **kwargs)
      yield fd
    finally:
      if fd is not None:
        fd.close()

  def open_text(self, name, content_type=None, tags=None, tee=None,
                binary_file_extension=None):
    """Returns (file): A file-like object for a single text stream.

    This creates a new butler TEXT stream with the specified parameters.

    Args:
      name (str): the LogDog name of the stream.
      content_type (str): The optional content type of the stream. If None, a
          default content type will be chosen by the Butler.
      tags (dict): An optional key/value dictionary pair of LogDog stream tags.
      tee (str): Describes how stream data should be tee'd through the Butler.
          One of StreamParams' TEE arguments.
      binary_file_extension (str): A custom binary file extension. If not
          provided, a default extension may be chosen or the binary stream may
          not be emitted.

    Returns (file): A file-like object to a Butler text stream. This object can
        have UTF-8 text content written to it with its `write` method, and must
        be closed when finished using its `close` method.
    """
    params = StreamParams.make(
        name=name,
        type=StreamParams.TEXT,
        content_type=content_type,
        tags=tags,
        tee=tee,
        binary_file_extension=binary_file_extension)
    return self.new_connection(params)

  @contextlib.contextmanager
  def binary(self, name, **kwargs):
    """Context manager to create, use, and teardown a BINARY stream.

    This context manager creates a new butler BINARY stream with the specified
    parameters, yields it, and closes it on teardown.

    Args:
      name (str): the LogDog name of the stream.
      kwargs (dict): Log stream parameters. These may be any keyword arguments
          accepted by `open_binary`.

    Returns (file): A file-like object to a Butler binary stream supporting
        `write`.
    """
    fd = None
    try:
      fd = self.open_binary(name, **kwargs)
      yield fd
    finally:
      if fd is not None:
        fd.close()

  def open_binary(self, name, content_type=None, tags=None, tee=None,
                binary_file_extension=None):
    """Returns (file): A file-like object for a single binary stream.

    This creates a new butler BINARY stream with the specified parameters.

    Args:
      name (str): the LogDog name of the stream.
      content_type (str): The optional content type of the stream. If None, a
          default content type will be chosen by the Butler.
      tags (dict): An optional key/value dictionary pair of LogDog stream tags.
      tee (str): Describes how stream data should be tee'd through the Butler.
          One of StreamParams' TEE arguments.
      binary_file_extension (str): A custom binary file extension. If not
          provided, a default extension may be chosen or the binary stream may
          not be emitted.

    Returns (file): A file-like object to a Butler binary stream. This object
        can have UTF-8 content written to it with its `write` method, and must
        be closed when finished using its `close` method.
    """
    params = StreamParams.make(
        name=name,
        type=StreamParams.BINARY,
        content_type=content_type,
        tags=tags,
        tee=tee,
        binary_file_extension=binary_file_extension)
    return self.new_connection(params)

  @contextlib.contextmanager
  def datagram(self, name, **kwargs):
    """Context manager to create, use, and teardown a DATAGRAM stream.

    This context manager creates a new butler DATAAGRAM stream with the
    specified parameters, yields it, and closes it on teardown.

    Args:
      name (str): the LogDog name of the stream.
      kwargs (dict): Log stream parameters. These may be any keyword arguments
          accepted by `open_datagram`.

    Returns (_DatagramStream): A datagram stream object. Datagrams can be
        written to it using its `send` method.
    """
    fd = None
    try:
      fd = self.open_datagram(name, **kwargs)
      yield fd
    finally:
      if fd is not None:
        fd.close()

  def open_datagram(self, name, content_type=None, tags=None, tee=None,
                    binary_file_extension=None):
    """Creates a new butler DATAGRAM stream with the specified parameters.

    Args:
      name (str): the LogDog name of the stream.
      content_type (str): The optional content type of the stream. If None, a
          default content type will be chosen by the Butler.
      tags (dict): An optional key/value dictionary pair of LogDog stream tags.
      tee (str): Describes how stream data should be tee'd through the Butler.
          One of StreamParams' TEE arguments.
      binary_file_extension (str): A custom binary file extension. If not
          provided, a default extension may be chosen or the binary stream may
          not be emitted.

    Returns (_DatagramStream): A datagram stream object. Datagrams can be
        written to it using its `send` method. This object must be closed when
        finished by using its `close` method.
    """
    params = StreamParams.make(
        name=name,
        type=StreamParams.DATAGRAM,
        content_type=content_type,
        tags=tags,
        tee=tee,
        binary_file_extension=binary_file_extension)
    return self._DatagramStream(self.new_connection(params))


class _NamedPipeStreamClient(StreamClient):
  """A StreamClient implementation that connects to a Windows named pipe.
  """

  def __init__(self, name):
    r"""Initializes a new Windows named pipe stream client.

    Args:
      name (str): The name of the Windows named pipe to use (e.g., "\\.\name")
    """
    super(_NamedPipeStreamClient, self).__init__()
    self._name = name

  @classmethod
  def _create(cls, value):
    return cls(value)

  def _connect_raw(self):
    return open(self._name, 'wb')

_default_registry.register_protocol('net.pipe', _NamedPipeStreamClient)


class _UnixDomainSocketStreamClient(StreamClient):
  """A StreamClient implementation that uses a UNIX domain socket.
  """

  class SocketFile(object):
    """A write-only file-like object that writes to a UNIX socket."""

    def __init__(self, fd):
      self._fd = fd

    def write(self, data):
      self._fd.send(data)

    def close(self):
      self._fd.close()


  def __init__(self, path):
    """Initializes a new UNIX domain socket stream client.

    Args:
      path (str): The path to the named UNIX domain socket.
    """
    super(_UnixDomainSocketStreamClient, self).__init__()
    self._path = path

  @classmethod
  def _create(cls, value):
    if not os.path.exists(value):
      raise ValueError('UNIX domain socket [%s] does not exist.' % (value,))
    return cls(value)

  def _connect_raw(self):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(self._path)
    return self.SocketFile(sock)

_default_registry.register_protocol('unix', _UnixDomainSocketStreamClient)
