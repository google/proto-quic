# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# These tests access private methods in the speedindex module.
# pylint: disable=protected-access

import unittest

from telemetry.util import color_histogram
from telemetry.util import rgba_color

from metrics import speedindex


class FakeImageUtil(object):

  # pylint: disable=unused-argument
  def GetColorHistogram(self, image, ignore_color=None, tolerance=None):
    return image.ColorHistogram()


class FakeVideo(object):

  def __init__(self, frames):
    self._frames = frames

  def GetVideoFrameIter(self):
    for frame in self._frames:
      yield frame


class FakeBitmap(object):

  def __init__(self, r, g, b):
    self._histogram = color_histogram.ColorHistogram(r, g, b, rgba_color.WHITE)

  # pylint: disable=unused-argument
  def ColorHistogram(self, ignore_color=None, tolerance=None):
    return self._histogram


class FakeTab(object):

  def __init__(self, video_capture_result=None):
    self._javascript_result = None
    self._video_capture_result = FakeVideo(video_capture_result)

  @property
  def video_capture_supported(self):
    return self._video_capture_result is not None

  def SetEvaluateJavaScriptResult(self, result):
    self._javascript_result = result

  def EvaluateJavaScript(self, _):
    return self._javascript_result

  def StartVideoCapture(self, min_bitrate_mbps=1):
    assert self.video_capture_supported
    assert min_bitrate_mbps > 0

  def StopVideoCapture(self):
    assert self.video_capture_supported
    return self._video_capture_result

  def Highlight(self, _):
    pass


class SpeedIndexImplTest(unittest.TestCase):

  def testVideoCompleteness(self):
    frames = [
        (0.0, FakeBitmap([0, 0, 0, 10], [0, 0, 0, 10], [0, 0, 0, 10])),
        (0.1, FakeBitmap([10, 0, 0, 0], [10, 0, 0, 0], [10, 0, 0, 0])),
        (0.2, FakeBitmap([0, 0, 2, 8], [0, 0, 4, 6], [0, 0, 1, 9])),
        (0.3, FakeBitmap([0, 3, 2, 5], [2, 1, 0, 7], [0, 3, 0, 7])),
        (0.4, FakeBitmap([0, 0, 1, 0], [0, 0, 1, 0], [0, 0, 1, 0])),
        (0.5, FakeBitmap([0, 4, 6, 0], [0, 4, 6, 0], [0, 4, 6, 0])),
    ]
    max_distance = 42.

    tab = FakeTab(frames)
    impl = speedindex.VideoSpeedIndexImpl(FakeImageUtil())
    impl.Start(tab)
    impl.Stop(tab)
    time_completeness = impl.GetTimeCompletenessList(tab)
    self.assertEqual(len(time_completeness), 6)
    self.assertEqual(time_completeness[0], (0.0, 0))
    self.assertTimeCompleteness(
        time_completeness[1], 0.1, 1 - (16 + 16 + 16) / max_distance)
    self.assertTimeCompleteness(
        time_completeness[2], 0.2, 1 - (12 + 10 + 13) / max_distance)
    self.assertTimeCompleteness(
        time_completeness[3], 0.3, 1 - (6 + 10 + 8) / max_distance)
    self.assertTimeCompleteness(
        time_completeness[4], 0.4, 1 - (4 + 4 + 4) / max_distance)
    self.assertEqual(time_completeness[5], (0.5, 1))

  def testBlankPage(self):
    frames = [
        (0.0, FakeBitmap([0, 0, 0, 1], [0, 0, 0, 1], [0, 0, 0, 1])),
        (0.1, FakeBitmap([0, 0, 0, 1], [0, 0, 0, 1], [0, 0, 0, 1])),
        (0.2, FakeBitmap([1, 0, 0, 0], [0, 0, 0, 1], [0, 0, 0, 1])),
        (0.3, FakeBitmap([0, 0, 0, 1], [0, 0, 0, 1], [0, 0, 0, 1])),
    ]
    tab = FakeTab(frames)
    impl = speedindex.VideoSpeedIndexImpl(FakeImageUtil())
    impl.Start(tab)
    impl.Stop(tab)
    time_completeness = impl.GetTimeCompletenessList(tab)
    self.assertEqual(len(time_completeness), 4)
    self.assertEqual(time_completeness[0], (0.0, 1.0))
    self.assertEqual(time_completeness[1], (0.1, 1.0))
    self.assertEqual(time_completeness[2], (0.2, 0.0))
    self.assertEqual(time_completeness[3], (0.3, 1.0))

  def assertTimeCompleteness(self, time_completeness, time, completeness):
    self.assertEqual(time_completeness[0], time)
    self.assertAlmostEqual(time_completeness[1], completeness)


if __name__ == "__main__":
  unittest.main()
