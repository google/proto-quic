# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Helper functions to upload data to Google Storage.

Text data should be streamed to logdog using |logdog_helper| module.
Due to logdog not having image or HTML viewer, those instead should be uploaded
to Google Storage directly using this module.
"""

import logging
import os
import sys
import time

from devil.utils import cmd_helper
from pylib.constants import host_paths
from pylib.utils import decorators

sys.path.append(os.path.join(host_paths.DIR_SOURCE_ROOT, 'build'))
import find_depot_tools  # pylint: disable=import-error

_URL_TEMPLATE = 'https://storage.googleapis.com/%s/'


@decorators.NoRaiseException(default_return_value='')
def upload(name, filepath, bucket):
  """Uploads data to Google Storage.

  Args:
    name: Name of the file on Google Storage.
    filepath: Path to file you want to upload.
    bucket: Bucket to upload file to.
  """
  gs_path = os.path.join('gs://%s/' % bucket, name)
  logging.info('Uploading %s to %s', filepath, gs_path)
  cmd_helper.RunCmd(
      [os.path.join(find_depot_tools.DEPOT_TOOLS_PATH, 'gsutil.py'), 'cp',
       filepath, gs_path])

  return os.path.join(_URL_TEMPLATE % bucket, name)


def unique_name(basename, timestamp=True, device=None):
  """Helper function for creating a unique name for a logdog stream.

  Args:
    basename: Base of the unique name.
    timestamp: Whether or not to add a timestamp to name.
    device: Device to add device serial of to name.
  """
  return '%s%s%s' % (
      basename,
      '_%s' % time.strftime('%Y%m%dT%H%M%S', time.localtime())
      if timestamp else '',
      '_%s' % device.serial if device else '')
