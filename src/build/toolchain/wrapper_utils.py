# Copyright (c) 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Helper functions for gcc_toolchain.gni wrappers."""

import os
import re
import subprocess
import shlex
import sys

_BAT_PREFIX = 'cmd /c call '
_WHITELIST_RE = re.compile('whitelisted_resource_(?P<resource_id>[0-9]+)')


def CommandToRun(command):
  """Generates commands compatible with Windows.

  When running on a Windows host and using a toolchain whose tools are
  actually wrapper scripts (i.e. .bat files on Windows) rather than binary
  executables, the |command| to run has to be prefixed with this magic.
  The GN toolchain definitions take care of that for when GN/Ninja is
  running the tool directly.  When that command is passed in to this
  script, it appears as a unitary string but needs to be split up so that
  just 'cmd' is the actual command given to Python's subprocess module.

  Args:
    command: List containing the UNIX style |command|.

  Returns:
    A list containing the Windows version of the |command|.
  """
  if command[0].startswith(_BAT_PREFIX):
    command = command[0].split(None, 3) + command[1:]
  return command


def ResolveRspLinks(inputs):
  """Return a list of files contained in a response file.

  Args:
    inputs: A command containing rsp files.

  Returns:
    A set containing the rsp file content."""
  rspfiles = [a[1:] for a in inputs if a.startswith('@')]
  resolved = set()
  for rspfile in rspfiles:
    with open(rspfile, 'r') as f:
      resolved.update(shlex.split(f.read()))

  return resolved


def CombineResourceWhitelists(whitelist_candidates, outfile):
  """Combines all whitelists for a resource file into a single whitelist.

  Args:
    whitelist_candidates: List of paths to rsp files containing all targets.
    outfile: Path to save the combined whitelist.
  """
  whitelists = ('%s.whitelist' % candidate for candidate in whitelist_candidates
                if os.path.exists('%s.whitelist' % candidate))

  resources = set()
  for whitelist in whitelists:
    with open(whitelist, 'r') as f:
      resources.update(f.readlines())

  with open(outfile, 'w') as f:
    f.writelines(resources)


def ExtractResourceIdsFromPragmaWarnings(text):
  """Returns set of resource IDs that are inside unknown pragma warnings.

  Args:
    text: The text that will be scanned for unknown pragma warnings.

  Returns:
    A set containing integers representing resource IDs.
  """
  used_resources = set()
  lines = text.splitlines()
  for ln in lines:
    match = _WHITELIST_RE.search(ln)
    if match:
      resource_id = int(match.group('resource_id'))
      used_resources.add(resource_id)

  return used_resources


def CaptureCommandStderr(command, env=None):
  """Returns the stderr of a command.

  Args:
    command: A list containing the command and arguments.
    env: Environment variables for the new process.
  """
  child = subprocess.Popen(command, stderr=subprocess.PIPE, env=env)
  _, stderr = child.communicate()
  return child.returncode, stderr
