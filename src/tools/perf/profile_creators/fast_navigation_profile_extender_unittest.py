# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import unittest

from profile_creators.fast_navigation_profile_extender import (
    FastNavigationProfileExtender)
from telemetry.testing import options_for_unittests

import mock  # pylint: disable=import-error


class FakeTab(object):
  pass


class FakeTabList(object):

  def __init__(self):
    self._tabs = []

  def New(self):
    tab = FakeTab()
    self._tabs.append(tab)
    return tab

  def __len__(self):
    return len(self._tabs)


class FakeBrowser(object):

  def __init__(self):
    self.tabs = FakeTabList()


# Testing private method.
# pylint: disable=protected-access
class FastNavigationProfileExtenderTest(unittest.TestCase):

  def testPerformNavigations(self):
    maximum_batch_size = 15
    options = options_for_unittests.GetCopy()
    extender = FastNavigationProfileExtender(options, maximum_batch_size)

    navigation_urls = []
    for i in range(extender._NUM_TABS):
      navigation_urls.append('http://test%s.com' % i)
    batch_size = 5
    navigation_urls_batch = navigation_urls[3:3 + batch_size]

    extender.GetUrlIterator = mock.MagicMock(
        return_value=iter(navigation_urls_batch))
    extender.ShouldExitAfterBatchNavigation = mock.MagicMock(return_value=True)
    extender._WaitForQueuedTabsToLoad = mock.MagicMock()

    extender._browser = FakeBrowser()
    extender._BatchNavigateTabs = mock.MagicMock()

    # Set up a callback to record the tabs and urls in each navigation.
    callback_tabs_batch = []
    callback_urls_batch = []

    def SideEffect(*args, **_):
      batch = args[0]
      for tab, url in batch:
        callback_tabs_batch.append(tab)
        callback_urls_batch.append(url)
    extender._BatchNavigateTabs.side_effect = SideEffect

    # Perform the navigations.
    extender._PerformNavigations()

    # Each url in the batch should have been navigated to exactly once.
    self.assertEqual(set(callback_urls_batch), set(navigation_urls_batch))

    # The other urls should not have been navigated to.
    navigation_urls_remaining = (set(navigation_urls) -
                                 set(navigation_urls_batch))
    self.assertFalse(navigation_urls_remaining & set(callback_urls_batch))

    # The first couple of tabs should have been navigated once. The remaining
    # tabs should not have been navigated.
    for i in range(len(extender._browser.tabs)):
      tab = extender._browser.tabs._tabs[i]

      if i < batch_size:
        expected_tab_navigation_count = 1
      else:
        expected_tab_navigation_count = 0

      count = callback_tabs_batch.count(tab)
      self.assertEqual(count, expected_tab_navigation_count)
