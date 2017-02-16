# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from page_sets.system_health import platforms
from page_sets.system_health import story_tags

from telemetry import decorators
from telemetry.page import page
from telemetry.page import shared_page_state


# Extra wait time after the page has loaded required by the loading metric. We
# use it in all benchmarks to avoid divergence between benchmarks.
# TODO(petrcermak): Switch the memory benchmarks to use it as well.
_WAIT_TIME_AFTER_LOAD = 10


class _SystemHealthSharedState(shared_page_state.SharedPageState):
  """Shared state which enables disabling stories on individual platforms.

  This class adds support for enabling/disabling individual stories on
  individual platforms using the same approaches as for benchmarks:

    1. Disabled/Enabled decorator:

       @decorators.Disabled('win')
       class Story(system_health_story.SystemHealthStory):
         ...

    2. ShouldDisable method:

       class Story(system_health_story.SystemHealthStory):
         ...

         @classmethod
         def ShouldDisable(cls, possible_browser):
           return possible_browser.platform.GetOSName() == 'win'
  """

  def CanRunStory(self, story):
    return story.CanRun(self.possible_browser)


class _MetaSystemHealthStory(type):
  """Metaclass for SystemHealthStory."""

  @property
  def ABSTRACT_STORY(cls):
    """Class field marking whether the class is abstract.

    If true, the story will NOT be instantiated and added to a System Health
    story set. This field is NOT inherited by subclasses (that's why it's
    defined on the metaclass).
    """
    return cls.__dict__.get('ABSTRACT_STORY', False)


class SystemHealthStory(page.Page):
  """Abstract base class for System Health user stories."""
  __metaclass__ = _MetaSystemHealthStory

  # The full name of a single page story has the form CASE:GROUP:PAGE (e.g.
  # 'load:search:google').
  NAME = NotImplemented
  URL = NotImplemented
  ABSTRACT_STORY = True
  SUPPORTED_PLATFORMS = platforms.ALL_PLATFORMS
  TAGS = None
  PLATFORM_SPECIFIC = False

  def __init__(self, story_set, take_memory_measurement):
    case, group, _ = self.NAME.split(':')
    tags = []
    if self.TAGS:
      for t in self.TAGS:
        assert t in story_tags.ALL_TAGS
        tags.append(t.name)
    super(SystemHealthStory, self).__init__(
        shared_page_state_class=_SystemHealthSharedState, page_set=story_set,
        name=self.NAME, url=self.URL, tags=tags,
        credentials_path='../data/credentials.json',
        grouping_keys={'case': case, 'group': group},
        platform_specific=self.PLATFORM_SPECIFIC)
    self._take_memory_measurement = take_memory_measurement

  @classmethod
  def CanRun(cls, possible_browser):
    if (decorators.ShouldSkip(cls, possible_browser)[0] or
        cls.ShouldDisable(possible_browser)):
      return False
    return True

  @classmethod
  def ShouldDisable(cls, possible_browser):
    """Override this method to disable a story under specific conditions.

    This method is modelled after telemetry.benchmark.Benchmark.ShouldDisable().
    """
    del possible_browser
    return False

  def _Measure(self, action_runner):
    if self._take_memory_measurement:
      action_runner.MeasureMemory(deterministic_mode=True)
    else:
      action_runner.Wait(_WAIT_TIME_AFTER_LOAD)

  def _Login(self, action_runner):
    pass

  def _DidLoadDocument(self, action_runner):
    pass

  def RunNavigateSteps(self, action_runner):
    self._Login(action_runner)
    super(SystemHealthStory, self).RunNavigateSteps(action_runner)

  def RunPageInteractions(self, action_runner):
    action_runner.tab.WaitForDocumentReadyStateToBeComplete()
    self._DidLoadDocument(action_runner)
    self._Measure(action_runner)
