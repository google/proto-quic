# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import imp
import inspect
import os
import sys

from core import perf_benchmark


def GetClassFilePath(clazz):
  """ Return the absolute file path to |clazz|. """
  assert inspect.isclass(clazz)
  path = os.path.abspath(inspect.getfile(clazz))
  if path.endswith('.pyc'):
    return path[:-1]
  return path


def GetBenchmarkNamesForFile(top_level_dir, benchmark_file_dir):
  """  Return the list of all benchmark names of benchmarks defined in
    |benchmark_file_dir|.
  """
  original_sys_path = sys.path[:]
  top_level_dir = os.path.abspath(top_level_dir)
  original_sys_path = sys.path[:]
  if top_level_dir not in sys.path:
    sys.path.append(top_level_dir)
  try:
    module = imp.load_source('_tmp_module_name_', benchmark_file_dir)
    benchmark_names = []
    for _, obj in inspect.getmembers(module):
      if (inspect.isclass(obj) and issubclass(obj, perf_benchmark.PerfBenchmark)
          and GetClassFilePath(obj) == benchmark_file_dir):
        benchmark_names.append(obj.Name())
    return sorted(benchmark_names)
  finally:
    sys.path = original_sys_path
