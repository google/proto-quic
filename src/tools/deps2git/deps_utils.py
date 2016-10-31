#!/usr/bin/python
# Copyright (c) 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Utilities for formatting and writing DEPS files."""

import errno
import os
import shutil
import subprocess
import sys
import time


class VarImpl(object):
  """Implement the Var function used within the DEPS file."""

  def __init__(self, local_scope):
    self._local_scope = local_scope

  def Lookup(self, var_name):
    """Implements the Var syntax."""
    if var_name in self._local_scope.get('vars', {}):
      return self._local_scope['vars'][var_name]
    raise Exception('Var is not defined: %s' % var_name)


def GetDepsContent(deps_path):
  """Read a DEPS file and return all the sections."""
  deps_file = open(deps_path, 'rU')
  content = deps_file.read()
  local_scope = {}
  var = VarImpl(local_scope)
  global_scope = {
      'Var': var.Lookup,
      'deps': {},
      'deps_os': {},
      'include_rules': [],
      'skip_child_includes': [],
      'hooks': [],
  }
  exec(content, global_scope, local_scope)
  local_scope.setdefault('deps', {})
  local_scope.setdefault('deps_os', {})
  local_scope.setdefault('include_rules', [])
  local_scope.setdefault('skip_child_includes', [])
  local_scope.setdefault('hooks', [])

  return (local_scope['deps'], local_scope['deps_os'],
          local_scope['include_rules'], local_scope['skip_child_includes'],
          local_scope['hooks'])


def PrettyDeps(deps, indent=0):
  """Stringify a deps dictionary in a pretty way."""
  pretty = ' ' * indent
  pretty += '{\n'

  indent += 4

  for item in sorted(deps):
    if type(deps[item]) == dict:
      value = PrettyDeps(deps[item], indent)
    else:
      value = ' ' * (indent + 4)
      if deps[item] is None:
        value += str(deps[item])
      else:
        value += '\'%s\'' % str(deps[item])
    pretty += ' ' * indent
    pretty += '\'%s\':\n' % item
    pretty += '%s,\n' % value

  indent -= 4
  pretty += ' ' * indent
  pretty += '}'
  return pretty


def PrettyObj(obj):
  """Stringify an object in a pretty way."""
  pretty = str(obj).replace('{', '{\n    ')
  pretty = pretty.replace('}', '\n}')
  pretty = pretty.replace('[', '[\n    ')
  pretty = pretty.replace(']', '\n]')
  pretty = pretty.replace('\':', '\':\n        ')
  pretty = pretty.replace(', ', ',\n    ')
  return pretty


def Varify(deps):
  """Replace all instances of our git server with a git_url var."""
  deps = deps.replace(
      '\'https://chromium.googlesource.com/chromium/blink.git',
      'Var(\'webkit_url\') + \'')
  deps = deps.replace(
      '\'https://chromium.googlesource.com', 'Var(\'git_url\') + \'')
  deps = deps.replace(
      '\'https://git.chromium.org', 'Var(\'git_url\') + \'')
  deps = deps.replace('VAR_WEBKIT_REV\'', '\' + Var(\'webkit_rev\')')
  deps = deps.replace('VAR_ANGLE_REVISION\'',
                      '\' + \'@\' + Var(\'angle_revision\')')
  return deps


def WriteDeps(deps_file_name, deps_vars, deps, deps_os, include_rules,
              skip_child_includes, hooks):
  """Given all the sections in a DEPS file, write it to disk."""
  new_deps = ('# DO NOT EDIT EXCEPT FOR LOCAL TESTING.\n'
              '# THIS IS A GENERATED FILE.\n',
              '# ALL MANUAL CHANGES WILL BE OVERWRITTEN.\n',
              '# SEE http://code.google.com/p/chromium/wiki/UsingGit\n',
              '# FOR HOW TO ROLL DEPS\n'
              'vars = %s\n\n' % PrettyObj(deps_vars),
              'deps = %s\n\n' % Varify(PrettyDeps(deps)),
              'deps_os = %s\n\n' % Varify(PrettyDeps(deps_os)),
              'include_rules = %s\n\n' % PrettyObj(include_rules),
              'skip_child_includes = %s\n\n' % PrettyObj(skip_child_includes),
              'hooks = %s\n' % PrettyObj(hooks))
  new_deps = ''.join(new_deps)
  if deps_file_name:
    deps_file = open(deps_file_name, 'wb')
  else:
    deps_file = sys.stdout

  try:
    deps_file.write(new_deps)
  finally:
    if deps_file_name:
      deps_file.close()

def RemoveDirectory(*path):
  """Recursively removes a directory, even if it's marked read-only.

  Remove the directory located at *path, if it exists.

  shutil.rmtree() doesn't work on Windows if any of the files or directories
  are read-only, which svn repositories and some .svn files are.  We need to
  be able to force the files to be writable (i.e., deletable) as we traverse
  the tree.

  Even with all this, Windows still sometimes fails to delete a file, citing
  a permission error (maybe something to do with antivirus scans or disk
  indexing).  The best suggestion any of the user forums had was to wait a
  bit and try again, so we do that too.  It's hand-waving, but sometimes it
  works. :/

  Copied from chrome/trunk/tools/build/scripts/common/chromium_utils.py
  """
  file_path = os.path.join(*path)
  if not os.path.exists(file_path):
    return

  if sys.platform == 'win32':
    # Give up and use cmd.exe's rd command.
    file_path = os.path.normcase(file_path)
    for _ in xrange(3):
      if not subprocess.call(['cmd.exe', '/c', 'rd', '/q', '/s', file_path]):
        break
      time.sleep(3)
    return

  def RemoveWithRetry_non_win(rmfunc, path):
    if os.path.islink(path):
      return os.remove(path)
    else:
      return rmfunc(path)

  remove_with_retry = RemoveWithRetry_non_win

  def RmTreeOnError(function, path, excinfo):
    """This works around a problem whereby python 2.x on Windows has no ability
    to check for symbolic links.  os.path.islink always returns False.  But
    shutil.rmtree will fail if invoked on a symbolic link whose target was
    deleted before the link.  E.g., reproduce like this:
    > mkdir test
    > mkdir test\1
    > mklink /D test\current test\1
    > python -c "import chromium_utils; deps_utils.RemoveDirectory('test')"
    To avoid this issue, we pass this error-handling function to rmtree.  If
    we see the exact sort of failure, we ignore it.  All other failures we re-
    raise.
    """

    exception_type = excinfo[0]
    exception_value = excinfo[1]
    # If shutil.rmtree encounters a symbolic link on Windows, os.listdir will
    # fail with a WindowsError exception with an ENOENT errno (i.e., file not
    # found).  We'll ignore that error.  Note that WindowsError is not defined
    # for non-Windows platforms, so we use OSError (of which it is a subclass)
    # to avoid lint complaints about an undefined global on non-Windows
    # platforms.
    if (function is os.listdir) and issubclass(exception_type, OSError):
      if exception_value.errno == errno.ENOENT:
        # File does not exist, and we're trying to delete, so we can ignore the
        # failure.
        print 'WARNING:  Failed to list %s during rmtree.  Ignoring.\n' % path
      else:
        raise
    else:
      raise

  for root, dirs, files in os.walk(file_path, topdown=False):
    # For POSIX:  making the directory writable guarantees removability.
    # Windows will ignore the non-read-only bits in the chmod value.
    os.chmod(root, 0770)
    for name in files:
      remove_with_retry(os.remove, os.path.join(root, name))
    for name in dirs:
      remove_with_retry(lambda p: shutil.rmtree(p, onerror=RmTreeOnError),
                        os.path.join(root, name))

  remove_with_retry(os.rmdir, file_path)
