# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Helper functions to upload data to logdog."""

import logging
import os
import sys

from pylib import constants
from pylib.utils import decorators

sys.path.insert(0, os.path.abspath(os.path.join(
    constants.DIR_SOURCE_ROOT, 'tools', 'swarming_client')))
from libs.logdog import bootstrap # pylint: disable=import-error


@decorators.NoRaiseException(default_return_value='')
def text(name, data):
  """Uploads text to logdog.

  Args:
    name: Name of the logdog stream.
    data: String with data you want to upload.

  Returns:
    Link to view uploaded text in logdog viewer.
  """
  logging.info('Writing text to logdog stream, %s', name)
  with get_logdog_client().text(name) as stream:
    stream.write(data)
    return stream.get_viewer_url()


@decorators.NoRaiseException(default_return_value=None)
def open_text(name):
  """Returns a file like object which you can write to.

  Args:
    name: Name of the logdog stream.

  Returns:
    A file like object. close() file when done.
  """
  logging.info('Opening text logdog stream, %s', name)
  return get_logdog_client().open_text(name)


@decorators.NoRaiseException(default_return_value='')
def binary(name, binary_path):
  """Uploads binary to logdog.

  Args:
    name: Name of the logdog stream.
    binary_path: Path to binary you want to upload.

  Returns:
    Link to view uploaded binary in logdog viewer.
  """
  logging.info('Writing binary to logdog stream, %s', name)
  with get_logdog_client().binary(name) as stream:
    with open(binary_path, 'r') as f:
      stream.write(f.read())
      return stream.get_viewer_url()


@decorators.NoRaiseException(default_return_value='')
def get_viewer_url(name):
  """Get Logdog viewer URL.

  Args:
    name: Name of the logdog stream.

  Returns:
    Link to view uploaded binary in logdog viewer.
  """
  return get_logdog_client().get_viewer_url(name)


@decorators.Memoize
def get_logdog_client():
  logging.debug('Getting logdog client.')
  return bootstrap.ButlerBootstrap.probe().stream_client()
