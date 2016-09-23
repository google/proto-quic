# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
from telemetry.page import page as page_module
from telemetry import story


class ToughLayerCasesPage(page_module.Page):

  def __init__(self, url, page_set):
    super(ToughLayerCasesPage, self).__init__(url=url, page_set=page_set)


class ToughLayerCasesPageSet(story.StorySet):

  """ A collection of tests to measure layer performance. """

  def __init__(self):
    super(ToughLayerCasesPageSet, self).__init__()

    self.AddStory(ToughLayerCasesPage(
      'file://layer_stress_tests/opacity.html', self))
