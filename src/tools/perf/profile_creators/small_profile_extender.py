# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import page_sets

from profile_creators import fast_navigation_profile_extender


class SmallProfileExtender(
    fast_navigation_profile_extender.FastNavigationProfileExtender):
  """Creates a small profile by performing 25 navigations."""

  def __init__(self, finder_options):
    # Use exactly 5 tabs to generate the profile. This is because consumers of
    # this profile will perform a session restore, and expect 5 restored tabs.
    maximum_batch_size = 5
    super(SmallProfileExtender, self).__init__(
        finder_options, maximum_batch_size)

    # Get the list of urls from the typical 25 page set.
    self._page_set = page_sets.Typical25PageSet()
    urls = []
    for story in self._page_set.stories:
      urls.append(story.url)
    self._navigation_urls = urls

  def GetUrlIterator(self):
    """Superclass override."""
    return iter(self._navigation_urls)

  def ShouldExitAfterBatchNavigation(self):
    """Superclass override."""
    return False

  def WebPageReplayArchivePath(self):
    """Superclass override."""
    return self._page_set.WprFilePathForStory(
        self._page_set.stories[0])

  def FetchWebPageReplayArchives(self):
    """Superclass override."""
    self._page_set.wpr_archive_info.DownloadArchivesIfNeeded()
