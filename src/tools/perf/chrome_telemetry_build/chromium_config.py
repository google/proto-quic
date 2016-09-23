# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import logging
import os
import sys


def GetChromiumSrcDir():
  return os.path.abspath(
      os.path.join(os.path.abspath(__file__), '..', '..', '..', '..'))


def GetTelemetryDir():
  return os.path.join(GetChromiumSrcDir(), 'third_party', 'catapult',
                      'telemetry')


CLIENT_CONFIG_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), 'binary_dependencies.json')

sys.path.insert(1, os.path.join(GetTelemetryDir()))

from telemetry import project_config


class ChromiumConfig(project_config.ProjectConfig):

  def __init__(self, top_level_dir=None, benchmark_dirs=None,
               client_configs=None,
               default_chrome_root=GetChromiumSrcDir()):
    if client_configs is None:
      client_configs = [CLIENT_CONFIG_PATH]

    perf_dir = os.path.join(GetChromiumSrcDir(), 'tools', 'perf')
    if not benchmark_dirs:
      benchmark_dirs = [os.path.join(perf_dir, 'benchmarks')]
      logging.info('No benchmark directories specified. Defaulting to %s',
                   benchmark_dirs)
    if not top_level_dir:
      top_level_dir = perf_dir
      logging.info('No top level directory specified. Defaulting to %s',
                   top_level_dir)

    super(ChromiumConfig, self).__init__(
        top_level_dir=top_level_dir, benchmark_dirs=benchmark_dirs,
        client_configs=client_configs, default_chrome_root=default_chrome_root)
