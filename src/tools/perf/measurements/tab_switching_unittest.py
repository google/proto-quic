# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import contextlib
from measurements import tab_switching
import mock
from page_sets.system_health import multi_tab_stories
from telemetry import benchmark
from telemetry import story as story_module
from telemetry.internal.results import page_test_results
from telemetry.testing import page_test_test_case
from telemetry.testing import options_for_unittests
from telemetry.value import histogram


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

INTEGRATION_TEST_TAB_COUNT = 3

class EmptyMultiTabStory(multi_tab_stories.MultiTabStory):
  NAME = 'multitab:test:empty'
  URL_LIST = ['about:blank'] * INTEGRATION_TEST_TAB_COUNT
  URL = URL_LIST[0]

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
        # DidNavigateToPage() calls GetHistogram() once
        '{"count": 0, "buckets": []}',
        # ValidateAndMeasurePage() calls GetHistogram() once
        '{"count": 2, "buckets": [{"low": 1, "high": 2, "count": 1},'
        '{"low": 2, "high": 3, "count": 1}]}',
        ]
    mock_get_histogram = mock.MagicMock(side_effect=expected_histogram)

    with contextlib.nested(
        mock.patch('telemetry.value.histogram_util.GetHistogram',
                   mock_get_histogram),
        mock.patch('metrics.keychain_metric.KeychainMetric')):
      measure.DidNavigateToPage(story_set.stories[0], browser.tabs[-1])
      measure.ValidateAndMeasurePage(story_set.stories[0], browser.tabs[-1],
                                     page_test_results.PageTestResults())
      self.assertEqual(len(expected_histogram),
                       len(mock_get_histogram.mock_calls))
      # The last tab is passed to DidNavigateToPage() and
      # ValidateAndMeasurePage()
      expected_calls = [mock.call(mock.ANY, mock.ANY, t) for t in
                        [browser.tabs[-1]] * 2]
      self.assertEqual(expected_calls, mock_get_histogram.mock_calls)

  @benchmark.Enabled('has tabs')
  @benchmark.Disabled('mac')
  @benchmark.Disabled('android')
  def testTabSwitching(self):
    """IT of TabSwitching measurement and multi-tab story"""
    ps = story_module.StorySet()
    ps.AddStory(EmptyMultiTabStory(ps, False))
    measurement = tab_switching.TabSwitching()
    options = options_for_unittests.GetCopy()
    results = self.RunMeasurement(measurement, ps, options=options)
    self.assertEquals(len(results.failures), 0)

    self.assertEquals(len(results.all_summary_values), 1)
    summary = results.all_summary_values[0]
    self.assertIsInstance(summary, histogram.HistogramValue)
    self.assertEquals(summary.name, 'MPArch_RWH_TabSwitchPaintDuration')
    histogram_count = sum([b.count for b in summary.buckets])
    self.assertEquals(histogram_count, INTEGRATION_TEST_TAB_COUNT)
    histogram_mean = summary.GetRepresentativeNumber()
    self.assertGreater(histogram_mean, 0)
