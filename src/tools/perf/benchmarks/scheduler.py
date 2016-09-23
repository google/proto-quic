# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
from telemetry import benchmark

from core import perf_benchmark
from measurements import smoothness

import page_sets


@benchmark.Disabled('reference')  # crbug.com/549428
class SchedulerToughSchedulingCases(perf_benchmark.PerfBenchmark):
  """Measures rendering statistics while interacting with pages that have
  challenging scheduling properties.

  https://docs.google.com/a/chromium.org/document/d/
      17yhE5Po9By0sCdM1yZT3LiUECaUr_94rQt9j-4tOQIM/view"""
  test = smoothness.Smoothness
  page_set = page_sets.ToughSchedulingCasesPageSet

  @classmethod
  def Name(cls):
    return 'scheduler.tough_scheduling_cases'
