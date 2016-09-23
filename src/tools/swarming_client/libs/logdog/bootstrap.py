# Copyright 2016 The LUCI Authors. All rights reserved.
# Use of this source code is governed under the Apache License, Version 2.0
# that can be found in the LICENSE file.

import collections
import os

from libs.logdog import stream, streamname


class NotBootstrappedError(RuntimeError):
  """Raised when the current environment is missing Butler bootstrap variables.
  """


_ButlerBootstrapBase = collections.namedtuple('_ButlerBootstrapBase',
    ('project', 'prefix', 'streamserver_uri'))


class ButlerBootstrap(_ButlerBootstrapBase):
  """Loads LogDog Butler bootstrap parameters from the environment.

  LogDog Butler adds variables describing the LogDog stream parameters to the
  environment when it bootstraps an application. This class probes the
  environment and identifies those parameters.
  """

  _ENV_PROJECT = 'LOGDOG_STREAM_PROJECT'
  _ENV_PREFIX = 'LOGDOG_STREAM_PREFIX'
  _ENV_STREAM_SERVER_PATH = 'LOGDOG_STREAM_SERVER_PATH'

  @classmethod
  def probe(cls, env=None):
    """Returns (ButlerBootstrap): The probed bootstrap environment.

    Args:
      env (dict): The environment to probe. If None, `os.getenv` will be used.

    Raises:
      NotBootstrappedError if the current environment is not boostrapped.
    """
    if env is None:
      env = os.environ
    project = env.get(cls._ENV_PROJECT)
    prefix = env.get(cls._ENV_PREFIX)

    if not project:
      raise NotBootstrappedError('Missing project [%s]' % (cls._ENV_PROJECT,))

    if not prefix:
      raise NotBootstrappedError('Missing prefix [%s]' % (cls._ENV_PREFIX,))
    try:
      streamname.validate_stream_name(prefix)
    except ValueError as e:
      raise NotBootstrappedError('Prefix (%s) is invalid: %s' % (prefix, e))

    return cls(project=project, prefix=prefix,
               streamserver_uri=env.get(cls._ENV_STREAM_SERVER_PATH))

  def stream_client(self):
    """Returns: (StreamClient) stream client for the bootstrap streamserver URI.

    If the Butler accepts external stream connections, it will export a
    streamserver URI in the environment. This will create a StreamClient
    instance to operate on the streamserver if one is defined.

    Raises:
      ValueError: If no streamserver URI is present in the environment.
    """
    if not self.streamserver_uri:
      raise ValueError('No streamserver in bootstrap environment.')
    return stream.create(self.streamserver_uri)
