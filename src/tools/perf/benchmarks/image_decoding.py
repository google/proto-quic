# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from core import perf_benchmark
from telemetry import benchmark

from measurements import image_decoding
import page_sets


@benchmark.Owner(emails=['cblume@chromium.org', 'reveman@chromium.org'])
class ImageDecodingToughImageCases(perf_benchmark.PerfBenchmark):
  test = image_decoding.ImageDecoding
  # TODO: Rename this page set to tough_image_cases.py
  page_set = page_sets.ImageDecodingMeasurementPageSet

  @classmethod
  def Name(cls):
    return 'image_decoding.image_decoding_measurement'

  @classmethod
  def ShouldDisable(cls, possible_browser):
    # crbug.com/667501
    return possible_browser.platform.GetDeviceTypeName() == 'Nexus 7'

  def GetExpectations(self):
    return page_sets.ImageDecodingMeasurementStoryExpectations()
