# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import sys

# Add //tools/perf/ to system path
tools_perf_dir = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                              '..', '..'))
if tools_perf_dir not in sys.path:
  sys.path.append(tools_perf_dir)

from chrome_telemetry_build import chromium_config
from core import path_util

TELEMETRY_DIR = path_util.GetTelemetryDir()
PYLIB_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                         '..', '..', '..', '..',
                                         'build', 'android'))

_top_level_dir = os.path.dirname(os.path.realpath(__file__))

def Config(benchmark_subdirs):
  return chromium_config.ChromiumConfig(
      top_level_dir=_top_level_dir,
      benchmark_dirs=[os.path.join(_top_level_dir, subdir)
                      for subdir in benchmark_subdirs])
