# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry.util import image_util
from telemetry.util import rgba_color
from telemetry.value import scalar

from metrics import Metric


class SpeedIndexMetric(Metric):
  """The speed index metric is one way of measuring page load speed.

  It is meant to approximate user perception of page load speed, and it
  is based on the amount of time that it takes to paint to the visual
  portion of the screen. It includes paint events that occur after the
  onload event, and it doesn't include time loading things off-screen.

  This speed index metric is based on WebPageTest.org (WPT).
  For more info see: http://goo.gl/e7AH5l
  """

  def __init__(self):
    super(SpeedIndexMetric, self).__init__()
    self._impl = None

  @classmethod
  def CustomizeBrowserOptions(cls, options):
    options.AppendExtraBrowserArgs('--disable-infobars')

  def Start(self, _, tab):
    """Start recording events.

    This method should be called in the WillNavigateToPage method of
    a PageTest, so that all the events can be captured. If it's called
    in DidNavigateToPage, that will be too late.
    """
    if not tab.video_capture_supported:
      return
    self._impl = VideoSpeedIndexImpl()
    self._impl.Start(tab)

  def Stop(self, _, tab):
    """Stop recording."""
    if not tab.video_capture_supported:
      return
    assert self._impl, 'Must call Start() before Stop()'
    assert self.IsFinished(tab), 'Must wait for IsFinished() before Stop()'
    self._impl.Stop(tab)

  # Optional argument chart_name is not in base class Metric.
  # pylint: disable=arguments-differ
  def AddResults(self, tab, results, chart_name=None):
    """Calculate the speed index and add it to the results."""
    try:
      if tab.video_capture_supported:
        index = self._impl.CalculateSpeedIndex(tab)
        none_value_reason = None
      else:
        index = None
        none_value_reason = 'Video capture is not supported.'
    finally:
      self._impl = None  # Release the tab so that it can be disconnected.

    results.AddValue(scalar.ScalarValue(
        results.current_page, '%s_speed_index' % chart_name, 'ms', index,
        description='Speed Index. This focuses on time when visible parts of '
                    'page are displayed and shows the time when the '
                    'first look is "almost" composed. If the contents of the '
                    'testing page are composed by only static resources, load '
                    'time can measure more accurately and speed index will be '
                    'smaller than the load time. On the other hand, If the '
                    'contents are composed by many XHR requests with small '
                    'main resource and javascript, speed index will be able to '
                    'get the features of performance more accurately than load '
                    'time because the load time will measure the time when '
                    'static resources are loaded. If you want to get more '
                    'detail, please refer to http://goo.gl/Rw3d5d. Currently '
                    'there are two implementations: for Android and for '
                    'Desktop. The Android version uses video capture; the '
                    'Desktop one uses paint events and has extra overhead to '
                    'catch paint events.', none_value_reason=none_value_reason))

  def IsFinished(self, tab):
    """Decide whether the recording should be stopped.

    A page may repeatedly request resources in an infinite loop; a timeout
    should be placed in any measurement that uses this metric, e.g.:
      def IsDone():
        return self._speedindex.IsFinished(tab)
      util.WaitFor(IsDone, 60)

    Returns:
      True if 2 seconds have passed since last resource received, false
      otherwise.
    """
    return tab.HasReachedQuiescence()


class SpeedIndexImpl(object):

  def Start(self, tab):
    raise NotImplementedError()

  def Stop(self, tab):
    raise NotImplementedError()

  def GetTimeCompletenessList(self, tab):
    """Returns a list of time to visual completeness tuples.

    In the WPT PHP implementation, this is also called 'visual progress'.
    """
    raise NotImplementedError()

  def CalculateSpeedIndex(self, tab):
    """Calculate the speed index.

    The speed index number conceptually represents the number of milliseconds
    that the page was "visually incomplete". If the page were 0% complete for
    1000 ms, then the score would be 1000; if it were 0% complete for 100 ms
    then 90% complete (ie 10% incomplete) for 900 ms, then the score would be
    1.0*100 + 0.1*900 = 190.

    Returns:
      A single number, milliseconds of visual incompleteness.
    """
    time_completeness_list = self.GetTimeCompletenessList(tab)
    prev_completeness = 0.0
    speed_index = 0.0
    prev_time = time_completeness_list[0][0]
    for time, completeness in time_completeness_list:
      # Add the incremental value for the interval just before this event.
      elapsed_time = time - prev_time
      incompleteness = (1.0 - prev_completeness)
      speed_index += elapsed_time * incompleteness

      # Update variables for next iteration.
      prev_completeness = completeness
      prev_time = time
    return int(speed_index)


class VideoSpeedIndexImpl(SpeedIndexImpl):

  def __init__(self, image_util_module=image_util):
    # Allow image_util to be passed in so we can fake it out for testing.
    super(VideoSpeedIndexImpl, self).__init__()
    self._time_completeness_list = None
    self._image_util_module = image_util_module

  def Start(self, tab):
    assert tab.video_capture_supported
    # Blank out the current page so it doesn't count towards the new page's
    # completeness.
    tab.Highlight(rgba_color.WHITE)
    # TODO(tonyg): Bitrate is arbitrary here. Experiment with screen capture
    # overhead vs. speed index accuracy and set the bitrate appropriately.
    tab.StartVideoCapture(min_bitrate_mbps=4)

  def Stop(self, tab):
    # Ignore white because Chrome may blank out the page during load and we want
    # that to count as 0% complete. Relying on this fact, we also blank out the
    # previous page to white. The tolerance of 8 experimentally does well with
    # video capture at 4mbps. We should keep this as low as possible with
    # supported video compression settings.
    video_capture = tab.StopVideoCapture()
    histograms = [
        (time, self._image_util_module.GetColorHistogram(
            image, ignore_color=rgba_color.WHITE, tolerance=8))
        for time, image in video_capture.GetVideoFrameIter()
    ]

    start_histogram = histograms[0][1]
    final_histogram = histograms[-1][1]
    total_distance = start_histogram.Distance(final_histogram)

    def FrameProgress(histogram):
      if total_distance == 0:
        if histogram.Distance(final_histogram) == 0:
          return 1.0
        else:
          return 0.0
      return 1 - histogram.Distance(final_histogram) / total_distance

    self._time_completeness_list = [(time, FrameProgress(hist))
                                    for time, hist in histograms]

  def GetTimeCompletenessList(self, tab):
    assert self._time_completeness_list, 'Must call Stop() first.'
    return self._time_completeness_list
