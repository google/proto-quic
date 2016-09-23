# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os

import page_sets

from telemetry import decorators
from telemetry import page
from telemetry.testing import story_set_smoke_test


class StorySetUnitTest(story_set_smoke_test.StorySetSmokeTest):

  def setUp(self):
    self.story_sets_dir = os.path.dirname(os.path.realpath(__file__))
    self.top_level_dir = os.path.dirname(self.story_sets_dir)

  # TODO(tbarzic): crbug.com/386416.
  @decorators.Disabled('chromeos')
  def testSmoke(self):
    self.RunSmokeTest(self.story_sets_dir, self.top_level_dir)

  # TODO(nednguyen): Remove this test once crbug.com/508538 is fixed.
  # TODO(tbarzic): crbug.com/386416.
  @decorators.Disabled('chromeos')
  def testNoPageDefinedSyntheticDelay(self):
    for story_set_class in self.GetAllStorySetClasses(self.story_sets_dir,
                                                      self.top_level_dir):
      if story_set_class is page_sets.ToughSchedulingCasesPageSet:
        continue
      story_set = story_set_class()
      for story in story_set:
        if isinstance(story, page.Page):
          self.assertFalse(
            story.synthetic_delays,
            'Page %s in page set %s has non empty synthetic delay. '
            'Synthetic delay is no longer supported. See crbug.com/508538.' %
            (story.display_name, story_set.Name()))
