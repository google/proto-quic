# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Utility methods."""

import atexit
import multiprocessing
import os
import threading


SRC_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))))


def MakeProcessPool(*args):
  """Wrapper for multiprocessing.Pool, with fix to terminate on exit."""
  ret = multiprocessing.Pool(*args)
  def close_pool():
    ret.terminate()

  def on_exit():
    thread = threading.Thread(target=close_pool)
    thread.daemon = True
    thread.start()

  # Without calling terminate() on a separate thread, the call can block
  # forever.
  atexit.register(on_exit)
  return ret


def ForkAndCall(func, *args, **kwargs):
  """Uses multiprocessing to run the given function in a fork'ed process.

  Returns:
    A Result object (call .get() to get the return value)
  """
  pool_of_one = MakeProcessPool(1)
  result = pool_of_one.apply_async(func, args=args, kwds=kwargs)
  pool_of_one.close()
  return result
