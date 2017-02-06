# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
from telemetry.page import page as page_module
from telemetry import story


class ToughEnergyCasesPage(page_module.Page):

  def __init__(self, url, page_set):
    super(ToughEnergyCasesPage, self).__init__(
        url=url, page_set=page_set, credentials_path = 'data/credentials.json')

class CodePenPage(ToughEnergyCasesPage):

  def __init__(self, url, page_set):
    super(CodePenPage, self).__init__(url, page_set)
    self.credentials = 'codepen'


class GooglePage(ToughEnergyCasesPage):

  def __init__(self, url, page_set):
    super(GooglePage, self).__init__(
        url=url,
        page_set=page_set)
    self.credentials = 'google2'

  def RunNavigateSteps(self, action_runner):
    super(GooglePage, self).RunNavigateSteps(action_runner)
    action_runner.WaitForJavaScriptCondition2(
        'window.gmonkey !== undefined &&'
        'document.getElementById("gb") !== null')


class ToughEnergyCasesPageSet(story.StorySet):
  """Pages for measuring Chrome power draw."""

  def __init__(self):
    super(ToughEnergyCasesPageSet, self).__init__(
        archive_data_file='data/tough_energy_cases.json',
        cloud_storage_bucket=story.PARTNER_BUCKET)

    # TODO: this part of the test is disabled because it fails when
    # run with replay data and not with live data.  See crbug.com/465692
    # for complete details.
    # Why: productivity, top google properties
    #self.AddStory(GooglePage('https://mail.google.com/mail/', self))

    # Disabled: pegs CPU too much to get meaningful results.
    # Why: Image constantly changed in the background, above the fold
    # self.AddStory(CodePenPage(
    #     'http://codepen.io/testificate364/debug/eIutG', self))

    # Disabled: pegs CPU too much to get meaningful results.
    # Why: Image constantly changed in the background, below the fold
    # self.AddStory(CodePenPage(
    #     'http://codepen.io/testificate364/debug/zcDdv', self))

    # Why: CSS Animation, above the fold
    self.AddStory(CodePenPage(
         'http://codepen.io/testificate364/debug/nrbDc', self))

    # Why: CSS Animation, below the fold
    self.AddStory(CodePenPage(
        'http://codepen.io/testificate364/debug/fhKCg', self))

    # Why: requestAnimationFrame, above the fold
    self.AddStory(CodePenPage(
        'http://codepen.io/testificate364/debug/paJhg',self))

    # Why: requestAnimationFrame, below the fold
    self.AddStory(CodePenPage(
        'http://codepen.io/testificate364/debug/yaosK', self))

    # Why: setTimeout animation, above the fold
    self.AddStory(CodePenPage(
        'http://codepen.io/testificate364/debug/DLbxg', self))

    # Why: setTimeout animation, below the fold
    self.AddStory(CodePenPage(
        'http://codepen.io/testificate364/debug/kFvpd', self))

    # Why: setInterval animation, above the fold
    self.AddStory(CodePenPage(
        'http://codepen.io/testificate364/debug/lEhyw', self))

    # Why: setInterval animation, below the fold
    self.AddStory(CodePenPage(
        'http://codepen.io/testificate364/debug/zhgBD', self))

    # Why: Animated GIF, above the fold
    self.AddStory(CodePenPage(
        'http://codepen.io/testificate364/debug/jetyn', self))

    # Why: Animated GIF, below the fold
    self.AddStory(CodePenPage(
        'http://codepen.io/testificate364/debug/Kvdxs', self))

    # Why: HTML5 video, above the fold
    self.AddStory(CodePenPage(
        'http://codepen.io/testificate364/debug/lJAiH', self))

    # Why: HTML5 video, below the fold
    self.AddStory(CodePenPage(
        'http://codepen.io/testificate364/debug/EFceH', self))

    # Disabled: pegs CPU too much to get meaningful results.
    # Why: PostMessage between frames, above the fold
    # self.AddStory(CodePenPage(
    #    'http://codepen.io/testificate364/debug/pgBHu', self))

    # Disabled: pegs CPU too much to get meaningful results.
    # Why: Asynchronous XHR continually running
    # self.AddStory(CodePenPage(
    # 'http://codepen.io/testificate364/debug/iwAfJ', self))

    # Disabled: pegs CPU too much to get meaningful results.
    # Why: Web Worker continually running
    # self.AddStory(CodePenPage(
    #     'http://codepen.io/testificate364/debug/ckItK', self))

    # Why: flash video
    self.AddStory(CodePenPage(
        'http://codepen.io/testificate364/debug/slBue', self))

    # Why: Blank page in the foreground
    self.AddStory(CodePenPage(
        'http://codepen.io/testificate364/debug/HdIgr', self))
