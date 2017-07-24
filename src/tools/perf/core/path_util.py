# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import sys

import inspect
import traceback


def GetChromiumSrcDir():
  return os.path.abspath(os.path.join(
      os.path.dirname(__file__), '..', '..', '..'))


def GetTelemetryDir():
  return os.path.join(
      GetChromiumSrcDir(), 'third_party', 'catapult', 'telemetry')


def GetPerfDir():
  return os.path.join(GetChromiumSrcDir(), 'tools', 'perf')


def GetPerfStorySetsDir():
  return os.path.join(GetPerfDir(), 'page_sets')


def GetPerfBenchmarksDir():
  return os.path.join(GetPerfDir(), 'benchmarks')


def GetPerfContribDir():
  return os.path.join(GetPerfDir(), 'contrib')


def AddTelemetryToPath():
  telemetry_path = GetTelemetryDir()
  if telemetry_path not in sys.path:
    sys.path.insert(1, telemetry_path)


def AddPyUtilsToPath():
  py_utils_dir = os.path.join(
      GetChromiumSrcDir(), 'third_party', 'catapult', 'common', 'py_utils')
  if py_utils_dir not in sys.path:
    sys.path.insert(1, py_utils_dir)


# Modify shutil.rmtree to print the last call stacks that invoke shutil.rmtree
# TODO(nedn): remove these after crbug.com/742422 is addressed.
import shutil
import logging

_actual_rmtree = shutil.rmtree

def rmtree_with_log(*args, **kwargs):
  frame = inspect.stack()[1][0]
  caller_file = os.path.abspath(inspect.stack()[1][1])
  # Only show extra logging if this rmtree call is invoked by Chromium code.
  if caller_file.startswith(GetChromiumSrcDir()):
    logging.info('rmtree is invoked with arguments: %s %s', args, kwargs)
    # Also log the last 3 stacks.
    stack_trace = ''.join(traceback.format_stack(frame)[-3:])
    logging.info('Call site info: %s', stack_trace)
  return _actual_rmtree(*args, **kwargs)

shutil.rmtree = rmtree_with_log
