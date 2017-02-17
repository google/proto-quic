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


def run_executable(cmd, env):
  """Runs an executable within Xvfb on Linux or normally on other platforms.

  Returns the exit code of the specified commandline, or 1 on failure.
  """
  if sys.platform == 'linux2':
    if env.get('_CHROMIUM_INSIDE_XVFB') == '1':
      openbox_proc = None
      xcompmgr_proc = None
      try:
        # Some ChromeOS tests need a window manager.
        openbox_proc = subprocess.Popen('openbox', stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT, env=env)

        # Some tests need a compositing wm to make use of transparent visuals.
        xcompmgr_proc = subprocess.Popen('xcompmgr', stdout=subprocess.PIPE,
                                         stderr=subprocess.STDOUT, env=env)

        return test_env.run_executable(cmd, env)
      except OSError as e:
        print >> sys.stderr, 'Failed to start Xvfb or Openbox: %s' % str(e)
        return 1
      finally:
        kill(openbox_proc)
        kill(xcompmgr_proc)
    else:
      env['_CHROMIUM_INSIDE_XVFB'] = '1'
      xvfb_script = __file__
      if xvfb_script.endswith('.pyc'):
        xvfb_script = xvfb_script[:-1]
      return subprocess.call(['xvfb-run', '-a', "--server-args=-screen 0 "
                              "1280x800x24 -ac -nolisten tcp -dpi 96",
                              xvfb_script] + cmd, env=env)
  else:
    return test_env.run_executable(cmd, env)


def main():
  if len(sys.argv) < 2:
    print >> sys.stderr, (
        'Usage: xvfb.py [command args...]')
    return 2
  return run_executable(sys.argv[1:], os.environ.copy())


if __name__ == "__main__":
  sys.exit(main())
