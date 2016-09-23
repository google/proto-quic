#!/usr/bin/env python
# Copyright (c) 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Runs tests with Xvfb and Openbox on Linux and normally on other platforms."""

import os
import platform
import signal
import subprocess
import sys
import threading

import test_env


def _kill(proc, send_signal):
  """Kills |proc| and ignores exceptions thrown for non-existent processes."""
  try:
    os.kill(proc.pid, send_signal)
  except OSError:
    pass


def kill(proc, timeout_in_seconds=10):
  """Tries to kill |proc| gracefully with a timeout for each signal."""
  if not proc or not proc.pid:
    return

  _kill(proc, signal.SIGTERM)
  thread = threading.Thread(target=proc.wait)
  thread.start()

  thread.join(timeout_in_seconds)
  if thread.is_alive():
    print >> sys.stderr, 'Xvfb running after SIGTERM, trying SIGKILL.'
    _kill(proc, signal.SIGKILL)

  thread.join(timeout_in_seconds)
  if thread.is_alive():
    print >> sys.stderr, 'Xvfb running after SIGTERM and SIGKILL; good luck!'


def wait_for_xvfb(xdisplaycheck, env):
  """Waits for xvfb to be fully initialized by using xdisplaycheck."""
  try:
    subprocess.check_output([xdisplaycheck], stderr=subprocess.STDOUT, env=env)
  except OSError:
    print >> sys.stderr, 'Failed to load %s with cwd=%s' % (
        xdisplaycheck, os.getcwd())
    return False
  except subprocess.CalledProcessError as e:
    print >> sys.stderr, ('Xvfb failed to load (code %d) according to %s' %
                          (e.returncode, xdisplaycheck))
    return False

  return True


def should_start_xvfb(env):
  """Xvfb is only used on Linux and shouldn't be invoked recursively."""
  return sys.platform == 'linux2' and env.get('_CHROMIUM_INSIDE_XVFB') != '1'


def start_xvfb(env, build_dir, xvfb_path='Xvfb', display=':9'):
  """Start a virtual X server that can run tests without an existing X session.

  Returns the Xvfb and Openbox process Popen objects, or None on failure.
  The |env| dictionary is modified to set the DISPLAY and prevent re-entry.

  Args:
    env:       The os.environ dictionary [copy] to check for re-entry.
    build_dir: The path of the build directory, used for xdisplaycheck.
    xvfb_path: The path to Xvfb.
    display:   The X display number to use.
  """
  assert should_start_xvfb(env)
  assert env.get('_CHROMIUM_INSIDE_XVFB') != '1'
  env['_CHROMIUM_INSIDE_XVFB'] = '1'
  env['DISPLAY'] = display
  xvfb_proc = None
  openbox_proc = None
  xcompmgr_proc = None

  try:
    xvfb_cmd = [xvfb_path, display, '-screen', '0', '1280x800x24', '-ac',
                '-nolisten', 'tcp', '-dpi', '96']
    xvfb_proc = subprocess.Popen(xvfb_cmd, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT)

    if not wait_for_xvfb(os.path.join(build_dir, 'xdisplaycheck'), env):
      rc = xvfb_proc.poll()
      if rc is None:
        print 'Xvfb still running after xdisplaycheck failure, stopping.'
        kill(xvfb_proc)
      else:
        print 'Xvfb exited (code %d) after xdisplaycheck failure.' % rc
      print 'Xvfb output:'
      for l in xvfb_proc.communicate()[0].splitlines():
        print '> %s' % l
      return (None, None, None)

    # Some ChromeOS tests need a window manager.
    openbox_proc = subprocess.Popen('openbox', stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, env=env)

    # Some tests need a compositing manager to make use of transparent visuals.
    xcompmgr_proc = subprocess.Popen('xcompmgr', stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, env=env)
  except OSError as e:
    print >> sys.stderr, 'Failed to start Xvfb or Openbox or xcompmgr: %s' % \
      str(e)
    kill(xvfb_proc)
    kill(openbox_proc)
    kill(xcompmgr_proc)
    return (None, None, None)

  return (xvfb_proc, openbox_proc, xcompmgr_proc)


def run_executable(cmd, build_dir, env):
  """Runs an executable within Xvfb on Linux or normally on other platforms.

  Returns the exit code of the specified commandline, or 1 on failure.
  """
  xvfb = None
  openbox = None
  xcompmgr = None
  if should_start_xvfb(env):
    (xvfb, openbox, xcompmgr) = start_xvfb(env, build_dir)
    if not xvfb or not xvfb.pid or not openbox or not openbox.pid or \
       not xcompmgr or not xcompmgr.pid:
      return 1
  try:
    return test_env.run_executable(cmd, env)
  finally:
    kill(xvfb)
    kill(openbox)
    kill(xcompmgr)


def main():
  if len(sys.argv) < 3:
    print >> sys.stderr, (
        'Usage: xvfb.py [path to build_dir] [command args...]')
    return 2
  return run_executable(sys.argv[2:], sys.argv[1], os.environ.copy())


if __name__ == "__main__":
  sys.exit(main())
