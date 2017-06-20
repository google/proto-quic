# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
from telemetry.page import page as page_module
from telemetry import story


class MseCasesPage(page_module.Page):

  def __init__(self, url, page_set, name):
    super(MseCasesPage, self).__init__(url=url, page_set=page_set, name=name)

  def RunNavigateSteps(self, action_runner):
    super(MseCasesPage, self).RunNavigateSteps(action_runner)
    action_runner.WaitForJavaScriptCondition('window.__testDone == true')


class MseCasesPageSet(story.StorySet):

  """ Media source extensions perf benchmark """

  def __init__(self):
    super(MseCasesPageSet, self).__init__(
        cloud_storage_bucket=story.PUBLIC_BUCKET)

    urls_list = [
      'file://mse_cases/startup_test.html?testType=AV',
      'file://mse_cases/startup_test.html?testType=AV&useAppendStream=true',
      # pylint: disable=line-too-long
      'file://mse_cases/startup_test.html?testType=AV&doNotWaitForBodyOnLoad=true',
      # pylint: disable=line-too-long
      'file://mse_cases/startup_test.html?testType=AV&useAppendStream=true&doNotWaitForBodyOnLoad=true',
      'file://mse_cases/startup_test.html?testType=V',
      'file://mse_cases/startup_test.html?testType=V&useAppendStream=true',
      # pylint: disable=line-too-long
      'file://mse_cases/startup_test.html?testType=V&doNotWaitForBodyOnLoad=true',
      # pylint: disable=line-too-long
      'file://mse_cases/startup_test.html?testType=V&useAppendStream=true&doNotWaitForBodyOnLoad=true',
      'file://mse_cases/startup_test.html?testType=A',
      'file://mse_cases/startup_test.html?testType=A&useAppendStream=true',
      # pylint: disable=line-too-long
      'file://mse_cases/startup_test.html?testType=A&doNotWaitForBodyOnLoad=true',
      # pylint: disable=line-too-long
      'file://mse_cases/startup_test.html?testType=A&useAppendStream=true&doNotWaitForBodyOnLoad=true',
    ]

    for url in urls_list:
      self.AddStory(MseCasesPage(url, self, url.split('/')[-1]))

class MseCasesStoryExpectations(
    story.expectations.StoryExpectations):

  def SetExpectations(self):
    pass
