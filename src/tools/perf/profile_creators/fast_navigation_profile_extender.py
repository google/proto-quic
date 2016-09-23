# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import time

from profile_creators import profile_extender
from telemetry.core import exceptions
from telemetry.core import util


class FastNavigationProfileExtender(profile_extender.ProfileExtender):
  """Extends a Chrome profile.

  This class creates or extends an existing profile by performing a set of tab
  navigations in large batches. This is accomplished by opening a large number
  of tabs, simultaneously navigating all the tabs, and then waiting for all the
  tabs to load. This provides two benefits:
    - Takes advantage of the high number of logical cores on modern CPUs.
    - The total time spent waiting for navigations to time out scales linearly
      with the number of batches, but does not scale with the size of the
      batch.
  """

  def __init__(self, finder_options, maximum_batch_size):
    """Initializer.

    Args:
      maximum_batch_size: A positive integer indicating the number of tabs to
      simultaneously perform navigations.
    """
    super(FastNavigationProfileExtender, self).__init__(finder_options)

    # The instance keeps a list of Tabs that can be navigated successfully.
    # This means that the Tab is not crashed, and is processing JavaScript in a
    # timely fashion.
    self._navigation_tabs = []

    # The number of tabs to use.
    self._NUM_TABS = maximum_batch_size

    # The amount of additional time to wait for a batch of pages to finish
    # loading for each page in the batch.
    self._BATCH_TIMEOUT_PER_PAGE_IN_SECONDS = 20

    # The amount of time to wait for a page to quiesce. Some pages will never
    # quiesce.
    self._TIME_TO_WAIT_FOR_PAGE_TO_QUIESCE_IN_SECONDS = 10

  def Run(self):
    """Superclass override."""
    try:
      self.SetUpBrowser()
      self._PerformNavigations()
    finally:
      self.TearDownBrowser()

    # When there hasn't been an exception, verify that the profile was
    # correctly extended.
    # TODO(erikchen): I've intentionally omitted my implementation of
    # VerifyProfileWasExtended() in small_profile_extender, since the profile
    # is not being correctly extended. http://crbug.com/484833
    # http://crbug.com/484880
    self.VerifyProfileWasExtended()

  def VerifyProfileWasExtended(self):
    """Verifies that the profile was correctly extended.

    Can be overridden by subclasses.
    """
    pass

  def GetUrlIterator(self):
    """Gets URLs for the browser to navigate to.

    Intended for subclass override.

    Returns:
      An iterator whose elements are urls to be navigated to.
    """
    raise NotImplementedError()

  def ShouldExitAfterBatchNavigation(self):
    """Returns a boolean indicating whether profile extension is finished.

    Intended for subclass override.
    """
    raise NotImplementedError()

  def CleanUpAfterBatchNavigation(self):
    """A hook for subclasses to perform cleanup after each batch of
    navigations.

    Can be overridden by subclasses.
    """
    pass

  def _RefreshNavigationTabs(self):
    """Updates the member self._navigation_tabs to contain self._NUM_TABS
    elements, each of which is not crashed. The crashed tabs are intentionally
    leaked, since Telemetry doesn't have a good way of killing crashed tabs.

    It is also possible for a tab to be stalled in an infinite JavaScript loop.
    These tabs will be in self.browser.tabs, but not in self._navigation_tabs.
    There is no way to kill these tabs, so they are also leaked. This method is
    careful to only use tabs in self._navigation_tabs, or newly created tabs.
    """
    live_tabs = [tab for tab in self._navigation_tabs if tab.IsAlive()]
    self._navigation_tabs = live_tabs

    while len(self._navigation_tabs) < self._NUM_TABS:
      self._navigation_tabs.append(self._browser.tabs.New())

  def _RemoveNavigationTab(self, tab):
    """Removes a tab which is no longer in a useable state from
    self._navigation_tabs. The tab is not removed from self.browser.tabs,
    since there is no guarantee that the tab can be safely removed."""
    self._navigation_tabs.remove(tab)

  def _RetrieveTabUrl(self, tab, timeout):
    """Retrives the URL of the tab."""
    # TODO(erikchen): Use tab.url instead, which talks to the browser process
    # instead of the renderer process. http://crbug.com/486119
    return tab.EvaluateJavaScript('document.URL', timeout)

  def _WaitForUrlToChange(self, tab, initial_url, end_time):
    """Waits for the tab to navigate away from its initial url.

    If time.time() is larger than end_time, the function does nothing.
    Otherwise, the function tries to return no later than end_time.
    """
    while True:
      seconds_to_wait = end_time - time.time()
      if seconds_to_wait <= 0:
        break

      current_url = self._RetrieveTabUrl(tab, seconds_to_wait)
      if current_url != initial_url and current_url != '':
        break

      # Retrieving the current url is a non-trivial operation. Add a small
      # sleep here to prevent this method from contending with the actual
      # navigation.
      time.sleep(0.01)

  def _WaitForTabToBeReady(self, tab, end_time):
    """Waits for the tab to be ready.

    If time.time() is larger than end_time, the function does nothing.
    Otherwise, the function tries to return no later than end_time.
    """
    seconds_to_wait = end_time - time.time()
    if seconds_to_wait <= 0:
      return
    tab.WaitForDocumentReadyStateToBeComplete(seconds_to_wait)

    # Wait up to 10 seconds for the page to quiesce. If the page hasn't
    # quiesced in 10 seconds, it will probably never quiesce.
    seconds_to_wait = end_time - time.time()
    seconds_to_wait = max(0, seconds_to_wait)
    try:
      util.WaitFor(tab.HasReachedQuiescence, seconds_to_wait)
    except exceptions.TimeoutException:
      pass

  def _BatchNavigateTabs(self, batch):
    """Performs a batch of tab navigations with minimal delay.

    Args:
      batch: A list of tuples (tab, url).

    Returns:
      A list of tuples (tab, initial_url). |initial_url| is the url of the
      |tab| prior to a navigation command being sent to it.
    """
    # Attempting to pass in a timeout of 0 seconds results in a synchronous
    # socket error from the websocket library. Pass in a very small timeout
    # instead so that the websocket library raises a Timeout exception. This
    # prevents the logic from accidentally catching different socket
    # exceptions.
    timeout_in_seconds = 0.01

    queued_tabs = []
    for tab, url in batch:
      initial_url = self._RetrieveTabUrl(tab, 20)
      try:
        tab.Navigate(url, None, timeout_in_seconds)
      except exceptions.TimeoutException:
        # We expect to receive a timeout exception, since we're not waiting for
        # the navigation to complete.
        pass
      queued_tabs.append((tab, initial_url))
    return queued_tabs

  def _WaitForQueuedTabsToLoad(self, queued_tabs):
    """Waits for all the batch navigated tabs to finish loading.

    Args:
      queued_tabs: A list of tuples (tab, initial_url). Each tab is guaranteed
      to have already been sent a navigation command.
    """
    total_batch_timeout = (len(queued_tabs) *
                           self._BATCH_TIMEOUT_PER_PAGE_IN_SECONDS)
    end_time = time.time() + total_batch_timeout
    for tab, initial_url in queued_tabs:
      # Since we didn't wait any time for the tab url navigation to commit, it's
      # possible that the tab hasn't started navigating yet.
      self._WaitForUrlToChange(tab, initial_url, end_time)
      self._WaitForTabToBeReady(tab, end_time)

  def _GetUrlsToNavigate(self, url_iterator):
    """Returns an array of urls to navigate to, given a url_iterator."""
    urls = []
    for _ in xrange(self._NUM_TABS):
      try:
        urls.append(url_iterator.next())
      except StopIteration:
        break
    return urls

  def _PerformNavigations(self):
    """Repeatedly fetches a batch of urls, and navigates to those urls. This
    will run until an empty batch is returned, or
    ShouldExitAfterBatchNavigation() returns True.
    """
    url_iterator = self.GetUrlIterator()
    while True:
      self._RefreshNavigationTabs()
      urls = self._GetUrlsToNavigate(url_iterator)

      if len(urls) == 0:
        break

      batch = []
      for i in range(len(urls)):
        url = urls[i]
        tab = self._navigation_tabs[i]
        batch.append((tab, url))

      queued_tabs = self._BatchNavigateTabs(batch)
      self._WaitForQueuedTabsToLoad(queued_tabs)

      self.CleanUpAfterBatchNavigation()

      if self.ShouldExitAfterBatchNavigation():
        break
