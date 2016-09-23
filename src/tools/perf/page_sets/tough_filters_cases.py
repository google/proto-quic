# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
from telemetry.page import page as page_module
from telemetry import story


class ToughFiltersCasesPage(page_module.Page):

  def RunPageInteractions(self, action_runner):
    with action_runner.CreateInteraction('Filter'):
      action_runner.Wait(10)


class PirateMarkPage(page_module.Page):

  def RunPageInteractions(self, action_runner):
    with action_runner.CreateInteraction('Filter'):
      action_runner.EvaluateJavaScript(
          'document.getElementById("benchmarkButtonText").click()')
      action_runner.Wait(10)

class ToughFiltersCasesPageSet(story.StorySet):

  """
  Description: Self-driven filters animation examples
  """

  def __init__(self):
    super(ToughFiltersCasesPageSet, self).__init__(
      archive_data_file='data/tough_filters_cases.json',
      cloud_storage_bucket=story.PARTNER_BUCKET)

    urls_list = [
      'http://rawgit.com/WebKit/webkit/master/PerformanceTests/Animometer/developer.html?test-interval=20&display=minimal&controller=fixed&frame-rate=50&kalman-process-error=1&kalman-measurement-error=4&time-measurement=performance&suite-name=Animometer&test-name=Focus&complexity=100', # pylint: disable=line-too-long
      'http://letmespellitoutforyou.com/samples/svg/filter_terrain.svg',
      'http://static.bobdo.net/Analog_Clock.svg',
    ]

    for url in urls_list:
      self.AddStory(ToughFiltersCasesPage(url, self))

    self.AddStory(PirateMarkPage(
        'http://web.archive.org/web/20150502135732/http://ie.microsoft.com/testdrive/Performance/Pirates/Default.html', self)) # pylint: disable=line-too-long
