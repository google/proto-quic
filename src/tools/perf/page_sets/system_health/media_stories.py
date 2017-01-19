# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from page_sets.system_health import platforms
from page_sets.system_health import system_health_story

from page_sets.login_helpers import google_login
from page_sets.login_helpers import pandora_login

from telemetry import benchmark
from telemetry import decorators


class _MediaStory(system_health_story.SystemHealthStory):
  """Abstract base class for media System Health user stories."""

  ABSTRACT_STORY = True
  SUPPORTED_PLATFORMS = platforms.DESKTOP_ONLY
  PLAY_DURATION = 20
  PLAY_SELECTOR = NotImplemented
  STOP_SELECTOR = NotImplemented
  TIME_SELECTOR = NotImplemented

  def RunPageInteractions(self, action_runner):
    self._NavigateToMedia(action_runner)
    # Play Media.
    if self.PLAY_SELECTOR:
      self._WaitForAndClickElementBySelector(action_runner, self.PLAY_SELECTOR)
    self._WaitForPlayTime(action_runner)
    # Stop media.
    self._WaitForAndClickElementBySelector(action_runner, self.STOP_SELECTOR)

  def _NavigateToMedia(self, action_runner):
    raise NotImplementedError

  def _WaitForAndClickElementBySelector(self, action_runner, selector):
    action_runner.WaitForElement(selector=selector)
    action_runner.ClickElement(selector=selector)

  def _WaitForPlayTime(self, action_runner):
    action_runner.Wait(self.PLAY_DURATION)
    while self._GetTimeInSeconds(action_runner) < self.PLAY_DURATION:
      action_runner.Wait(
          self.PLAY_DURATION - self._GetTimeInSeconds(action_runner))

  def _GetTimeInSeconds(self, action_runner):
    minutes, seconds = action_runner.EvaluateJavaScript(
        'document.querySelector({{ selector }}).textContent',
        selector=self.TIME_SELECTOR).split(':')
    return int(minutes * 60 + seconds)


################################################################################
# Audio stories.
################################################################################


@benchmark.Disabled('all')  # crbug.com/649392
class GooglePlayMusicDesktopStory(_MediaStory):
  NAME = 'play:media:google_play_music'
  URL = 'https://music.google.com'

  PLAY_SELECTOR = '.x-scope.paper-fab-0'
  STOP_SELECTOR = '.style-scope.sj-play-button'
  TIME_SELECTOR = '#time-container-current'
  SEARCH_SELECTOR = '.title.fade-out.tooltip'
  NAVIGATE_SELECTOR = '.description.tooltip.fade-out'

  def _Login(self, action_runner):
    google_login.LoginGoogleAccount(action_runner, 'googletest',
                                    self.credentials_path)

  def _NavigateToMedia(self, action_runner):
    # Clicks on Today's top hits.
    action_runner.Wait(1)  # Add 1 second wait to make the browsing realistic.
    self._WaitForAndClickElementBySelector(action_runner, self.SEARCH_SELECTOR)
    # Clicks on playlist.
    action_runner.Wait(1)  # Add 1 second wait to make the browsing realistic.
    self._WaitForAndClickElementBySelector(action_runner,
                                           self.NAVIGATE_SELECTOR)


@benchmark.Disabled('win')  # crbug.com/649392
class SoundCloudDesktopStory(_MediaStory):
  NAME = 'play:media:soundcloud'
  URL = 'https://soundcloud.com'

  PLAY_SELECTOR = '.sc-button-play.playButton.sc-button.sc-button-xlarge'
  STOP_SELECTOR = '.playControl.playControls__icon.sc-ir.playing'
  TIME_SELECTOR = '.playbackTimeline__timePassed>span[aria-hidden=true]'
  SEARCH_SELECTOR = '.headerSearch'
  SEARCH_QUERY = 'SSmooth Jazz'  # First S for some reason gets ommited.

  def _NavigateToMedia(self, action_runner):
    self._WaitForAndClickElementBySelector(action_runner, self.SEARCH_SELECTOR)
    action_runner.Wait(1)  # Add 1 second wait to make the browsing realistic.
    action_runner.EnterText(self.SEARCH_QUERY)
    action_runner.PressKey('Return')


@decorators.Disabled('all')  # crbug.com/649392
class PandoraDesktopStory(_MediaStory):
  NAME = 'play:media:pandora'
  URL = 'https://pandora.com'

  PLAY_SELECTOR = None
  STOP_SELECTOR = '.pauseButton'
  TIME_SELECTOR = '.elapsedTime'
  SEARCH_SELECTOR = '.searchInput'

  def _Login(self, action_runner):
    pandora_login.LoginAccount(action_runner, 'pandora', self.credentials_path)

  def _NavigateToMedia(self, action_runner):
    pass  # Audio autoplays on Pandora, no need to search.
