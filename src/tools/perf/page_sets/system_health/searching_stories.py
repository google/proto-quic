# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from page_sets.system_health import system_health_story


class SearchGoogleStory(system_health_story.SystemHealthStory):
  NAME = 'search:portal:google'
  URL = 'https://www.google.co.uk/'

  _SEARCH_BOX_SELECTOR = 'input[aria-label="Search"]'
  _RESULT_SELECTOR = '.r > a[href*="wikipedia"]'

  def _DidLoadDocument(self, action_runner):
    # Click on the search box.
    action_runner.Wait(1)
    action_runner.WaitForElement(selector=self._SEARCH_BOX_SELECTOR)
    action_runner.TapElement(selector=self._SEARCH_BOX_SELECTOR)

    # Submit search query.
    action_runner.Wait(1)
    action_runner.EnterText('what is science')
    action_runner.Wait(0.5)
    action_runner.PressKey('Return')

    # Scroll to the Wikipedia result.
    action_runner.WaitForElement(selector=self._RESULT_SELECTOR)
    action_runner.Wait(1)
    action_runner.ScrollPageToElement(selector=self._RESULT_SELECTOR)

    # Click on the Wikipedia result.
    action_runner.Wait(1)
    action_runner.TapElement(selector=self._RESULT_SELECTOR)
    action_runner.tab.WaitForDocumentReadyStateToBeComplete()
