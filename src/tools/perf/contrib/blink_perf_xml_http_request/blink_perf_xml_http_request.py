# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
from benchmarks import blink_perf
from telemetry import story


# pylint: disable=protected-access
class BlinkPerfXMLHttpRequest(blink_perf._BlinkPerfBenchmark):
  tag = 'xml_http_request'
  subdir = 'XMLHttpRequest'

  def GetExpectations(self):
    class StoryExpectations(story.expectations.StoryExpectations):
      def SetExpectations(self):
        pass # Nothing disabled.
    return StoryExpectations()
