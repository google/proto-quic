#!/usr/bin/env python
# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""Tool to help developers rebase branches across the Blink rename."""

import argparse
import json
import os
import subprocess
import shutil
import sys
import tempfile


class _DepotToolsNotFoundException(Exception):
  pass


def _whereis(name):
  """Find and return the first entry in $PATH containing a file named |name|.

  Returns the path if found; otherwise returns nothing.
  """
  for path in os.environ['PATH'].split(os.pathsep):
    if os.path.exists(os.path.join(path, name)):
      return path


def _find_depot_tools():
  """Attempts to configure and return a wrapper for invoking depot tools.

  Returns:
    A helper object for invoking depot tools.

  Raises:
    _DepotToolsNotFoundException: An error occurred trying to find depot tools.
  """

  class DepotToolsWrapper(object):

    def __init__(self, path):
      self.__download_from_google_storage = os.path.join(
          path, 'download_from_google_storage.py')
      self.__gsutil = os.path.join(path, 'gsutil.py')

    def call_download_from_google_storage(self, *args):
      """Runs download_from_google_storage with the given args."""
      subprocess.check_call(['python', self.__download_from_google_storage] +
                            list(args))

    def call_gsutil(self, *args):
      """Runs gsutil with the given args."""
      subprocess.check_call(['python', self.__gsutil] + list(args))

  # Attempt to find download_from_google_storage.py from depot_tools
  path = _whereis('download_from_google_storage.py')
  if not path:
    raise _DepotToolsNotFoundException(
        'download_from_google_storage.py not found. Make sure depot_tools is '
        'in $PATH.')

  # Make sure gsutil.py is in the same location
  path2 = _whereis('download_from_google_storage.py')
  if not path2:
    raise _DepotToolsNotFoundException(
        'gsutil.py not found. Make sure depot_tools is in $PATH.')

  if path != path2:
    raise _DepotToolsNotFoundException(
        'download_from_google_storage.py found in %s but gsutil.py found in %s.'
        % (path, path2))

  return DepotToolsWrapper(path)


class Bootstrapper(object):
  """Helper class for bootstrapping startup of the rebase helper.

  Performs update checks and stages any required binaries."""

  def __init__(self, depot_tools, components_manifest_name):
    """Bootstrapper constructor.

    Args:
      depot_tools: a wrapper for invoking depot_tools.
      components_manifest_name: The name of the components manifest.
    """
    self.__depot_tools = depot_tools
    self.__components_manifest_name = components_manifest_name
    self.__tmpdir = None

  def __enter__(self):
    self.__tmpdir = tempfile.mkdtemp()
    return self

  def __exit__(self, exc_type, exc_value, traceback):
    shutil.rmtree(self.__tmpdir, ignore_errors=True)

  def update(self):
    """Performs an update check for various components."""
    components = self._get_latest_components()
    for name, sha1_hash in components.iteritems():
      args = [
          '--no_auth', '--no_resume', '-b', 'chromium-blink-rename',
          '--extract', sha1_hash
      ]
      if '-' in name:
        name, platform = name.split('-', 1)
        args.append('-p')
        args.append(platform)
      args.append('-o')
      args.append(os.path.join('staging', '%s.tar.gz' % name))
      self.__depot_tools.call_download_from_google_storage(*args)

  def _get_latest_components(self):
    """Fetches info about the latest components from google storage.

    The return value should be a dict of component names to SHA1 hashes."""
    components_path = os.path.join(self.__tmpdir, 'COMPONENTS')
    self.__depot_tools.call_gsutil(
        'cp', 'gs://chromium-blink-rename/%s' % self.__components_manifest_name,
        components_path)
    with open(components_path) as f:
      return json.loads(f.read())


def main():
  # Intentionally suppress help. These are internal testing flags.
  parser = argparse.ArgumentParser(add_help=False)
  parser.add_argument('--components-manifest-name', default='COMPONENTS')
  parser.add_argument('--pylib-path')
  args, remaining_argv = parser.parse_known_args()

  script_dir = os.path.dirname(os.path.realpath(__file__))
  os.chdir(script_dir)

  try:
    depot_tools = _find_depot_tools()
  except _DepotToolsNotFoundException as e:
    print e.message
    return 1

  print 'Checking for updates...'
  with Bootstrapper(depot_tools, args.components_manifest_name) as bootstrapper:
    bootstrapper.update()

  # Import stage 2 and launch it.
  tool_pylib = args.pylib_path
  if not tool_pylib:
    tool_pylib = os.path.abspath(os.path.join(script_dir, 'staging/pylib'))
  sys.path.insert(0, tool_pylib)
  from blink_rename_merge_helper import driver
  # Note: for compatibility with older versions of run.py, set sys.argv to the
  # unconsumed args.
  sys.argv = sys.argv[:1] + remaining_argv
  driver.run()


if __name__ == '__main__':
  sys.exit(main())
