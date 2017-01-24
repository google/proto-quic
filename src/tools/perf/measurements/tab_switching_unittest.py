# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import contextlib
from telemetry.internal.results import page_test_results
from telemetry.testing import page_test_test_case

from measurements import tab_switching

import mock


class BrowserForTest(object):
  def __init__(self):
    self.tabs = []
    self.platform = mock.MagicMock()
    self.platform.CanMonitorPower = mock.Mock(return_value=False)

  def AddTab(self, tab):
    tab.browser = self
    self.tabs.append(tab)


class StorySetForTest(object):
  def __init__(self):
    self.stories = []

  def AddStory(self, story):
    story.story_set = self
    self.stories.append(story)


class TabSwitchingUnittest(page_test_test_case.PageTestTestCase):
  @staticmethod
  def MakeStoryForTest():
    story = mock.MagicMock()
    story.story_set = None
    return story

  @staticmethod
  def MakeTabForTest():
    tab = mock.MagicMock()
    tab.browser = None
    tab.HasReachedQuiescence = mock.Mock(return_value=True)
    return tab

  def testIsDone(self):
    """Tests ValidateAndMeasurePage, specifically _IsDone check."""
    measure = tab_switching.TabSwitching()

    # For sanity check: #tabs == #stories
    story_set = StorySetForTest()
    story_set.AddStory(self.MakeStoryForTest())
    story_set.AddStory(self.MakeStoryForTest())

    # Set up a browser with two tabs open
    browser = BrowserForTest()
    tab_0 = self.MakeTabForTest()
    browser.AddTab(tab_0)
    tab_1 = self.MakeTabForTest()
    browser.AddTab(tab_1)

    # Mock histogram result to test _IsDone really works.
    expected_histogram = [
        # To get first_histogram for last tab (tab_1).
        '{"count": 0, "buckets": []}',
        # First _IsDone check for tab_0. Retry.
        '{"count": 0, "buckets": []}',
        # Second _IsDone check for tab_0. Retry.
        '{"count": 0, "buckets": []}',
        # Third _IsDone check for tab_0. Pass.
        '{"count": 1, "buckets": [{"low": 1, "high": 2, "count": 1}]}',
        # To get prev_histogram. End of tab_0 loop.
        '{"count": 1, "buckets": [{"low": 1, "high": 2, "count": 1}]}',
        # First _IsDone check for tab_1. Retry.
        '{"count": 1, "buckets": [{"low": 1, "high": 2, "count": 1}]}',
        # Second _IsDone check for tab_1. Pass.
        '{"count": 2, "buckets": [{"low": 1, "high": 2, "count": 1},'
        '{"low": 2, "high": 3, "count": 1}]}',
        # To get prev_histogram. End of tab_1 loop.
        '{"count": 2, "buckets": [{"low": 1, "high": 2, "count": 1},'
        '{"low": 2, "high": 3, "count": 1}]}',
        ]
    mock_get_histogram = mock.MagicMock(side_effect=expected_histogram)

    with contextlib.nested(
        mock.patch('telemetry.value.histogram_util.GetHistogram',
                   mock_get_histogram),
        mock.patch('metrics.keychain_metric.KeychainMetric')):
      measure.ValidateAndMeasurePage(story_set.stories[0], browser.tabs[-1],
                                     page_test_results.PageTestResults())
      self.assertEqual(len(expected_histogram),
                       len(mock_get_histogram.mock_calls))
      expected_calls = [mock.call(mock.ANY, mock.ANY, t) for t in
                        [tab_1] + [tab_0] * 4 + [tab_1] * 3]
      self.assertEqual(expected_calls, mock_get_histogram.mock_calls)
