# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import sys

sys.path.insert(1, os.path.join(os.path.abspath(__file__), '..', '..'))

from chrome_telemetry_build import chromium_config


def GetChromiumSrcDir():
  return chromium_config.GetChromiumSrcDir()



def GetTelemetryDir():
  return chromium_config.GetTelemetryDir()


def GetPerfDir():
  return os.path.join(GetChromiumSrcDir(), 'tools', 'perf')


def GetPerfStorySetsDir():
  return os.path.join(GetPerfDir(), 'page_sets')


def GetPerfBenchmarksDir():
  return os.path.join(GetPerfDir(), 'benchmarks')


def AddTelemetryToPath():
  telemetry_path = GetTelemetryDir()
  if telemetry_path not in sys.path:
    sys.path.insert(1, telemetry_path)


def AddPyUtilsToPath():
  py_utils_dir = os.path.join(
      GetChromiumSrcDir(), 'third_party', 'catapult', 'common', 'py_utils')
  if py_utils_dir not in sys.path:
    sys.path.insert(1, py_utils_dir)
