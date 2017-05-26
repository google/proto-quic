# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from page_sets.system_health import platforms
from page_sets.system_health import story_tags
from page_sets.system_health import system_health_story

from telemetry import decorators

from devil.android.sdk import keyevent # pylint: disable=import-error


class BlankAboutBlankStory(system_health_story.SystemHealthStory):
  """Story that loads the about:blank page."""
  NAME = 'load:chrome:blank'
  URL = 'about:blank'

  def _DidLoadDocument(self, action_runner):
    # Request a RAF and wait for it to be processed to ensure that the metric
    # Startup.FirstWebContents.NonEmptyPaint2 is recorded.
    action_runner.ExecuteJavaScript(
        """
        window.__hasRunRAF = false;
        requestAnimationFrame(function() {
          window.__hasRunRAF = true;
        });
        """
    )
    action_runner.WaitForJavaScriptCondition("window.__hasRunRAF")


@decorators.Disabled('android-webview')  # Webview does not have omnibox
class SearchOmniboxStory(system_health_story.SystemHealthStory):
  """Story that peforms search by using omnibox search provider

  Loads a website and enters a search query on omnibox and navigates to default
  search provider (google).
  """
  NAME = 'browse:chrome:omnibox'
  URL = 'https://www.google.co.in'
  SUPPORTED_PLATFORMS = platforms.MOBILE_ONLY
  TAGS = [story_tags.EMERGING_MARKET]

  def _DidLoadDocument(self, action_runner):
    app_ui = action_runner.tab.browser.GetAppUi()
    platform = action_runner.tab.browser.platform
    app_ui.WaitForUiNode(resource_id='url_bar')
    url_bar = app_ui.GetUiNode(resource_id='url_bar')
    url_bar.Tap()
    action_runner.Wait(1) # user wait before typing
    platform.android_action_runner.InputText('drake')
    action_runner.Wait(0.5) # user wait after typing
    platform.android_action_runner.InputKeyEvent(keyevent.KEYCODE_ENTER)

    action_runner.WaitForNavigate()
    action_runner.ScrollPage(use_touch=True, distance=500)


@decorators.Disabled('android-webview')  # Webview does not have new tab page.
class MobileNewTabPageStory(system_health_story.SystemHealthStory):
  """Story that loads new tab page and performs searches.

  Given a list of typical search queries, this story does for each of them:
   - enter the search query on the new tab page search box
   - read results
   - navigates back to new tab page
  """
  NAME = 'browse:chrome:newtab'
  URL = 'chrome://newtab'
  _SEARCH_TEXTS = ['does google know everything',
                   'most famous paintings',
                   'current weather',
                   'best movies 2016',
                   'how to tie a tie']

  SUPPORTED_PLATFORMS = platforms.MOBILE_ONLY
  TAGS = [story_tags.EMERGING_MARKET]

  def _DidLoadDocument(self, action_runner):
    app_ui = action_runner.tab.browser.GetAppUi()
    platform = action_runner.tab.browser.platform
    for keyword in self._SEARCH_TEXTS:
      app_ui.WaitForUiNode(resource_id='search_box').Tap()
      platform.android_action_runner.InputText(keyword)
      platform.android_action_runner.InputKeyEvent(keyevent.KEYCODE_ENTER)
      action_runner.WaitForNavigate()
      action_runner.Wait(1.5) # Read results
      action_runner.ScrollPage(use_touch=True)
      action_runner.NavigateBack()
      action_runner.WaitForNavigate()

    app_ui.WaitForUiNode(resource_id='menu_button').Tap()
    app_ui.WaitForUiNode(resource_id='menu_item_text')
