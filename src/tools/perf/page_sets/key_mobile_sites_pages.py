# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
from telemetry.page import page as page_module
from telemetry.page import shared_page_state


class KeyMobileSitesPage(page_module.Page):

  def __init__(self, url, page_set, name='', tags=None):
    super(KeyMobileSitesPage, self).__init__(
        url=url, page_set=page_set, name=name,
        shared_page_state_class=shared_page_state.SharedMobilePageState,
        credentials_path='data/credentials.json', tags=tags)
    self.archive_data_file = 'data/key_mobile_sites.json'


class CapitolVolkswagenPage(KeyMobileSitesPage):

  """ Why: Typical mobile business site """

  def __init__(self, page_set):
    super(CapitolVolkswagenPage, self).__init__(
      url=('http://iphone.capitolvolkswagen.com/index.htm'
           '#new-inventory_p_2Fsb-new_p_2Ehtm_p_3Freset_p_3DInventoryListing'),
      page_set=page_set)

  def RunNavigateSteps(self, action_runner):
    super(CapitolVolkswagenPage, self).RunNavigateSteps(action_runner)
    action_runner.WaitForElement(text='Next 35')
    action_runner.WaitForJavaScriptCondition(
        'document.body.scrollHeight > 2560')



class TheVergeArticlePage(KeyMobileSitesPage):

  """ Why: Top tech blog """

  def __init__(self, page_set):
    super(TheVergeArticlePage, self).__init__(
      # pylint: disable=line-too-long
      url='http://www.theverge.com/2012/10/28/3568746/amazon-7-inch-fire-hd-ipad-mini-ad-ballsy',
      page_set=page_set)

  def RunNavigateSteps(self, action_runner):
    super(TheVergeArticlePage, self).RunNavigateSteps(action_runner)
    action_runner.WaitForJavaScriptCondition(
        'window.Chorus !== undefined &&'
        'window.Chorus.Comments !== undefined &&'
        'window.Chorus.Comments.Json !== undefined &&'
        '(window.Chorus.Comments.loaded ||'
        ' window.Chorus.Comments.Json.load_comments())')


class CnnArticlePage(KeyMobileSitesPage):

  """ Why: Top news site """

  def __init__(self, page_set):
    super(CnnArticlePage, self).__init__(
      # pylint: disable=line-too-long
      url='http://www.cnn.com/2012/10/03/politics/michelle-obama-debate/index.html',
      page_set=page_set)

  def RunNavigateSteps(self, action_runner):
    super(CnnArticlePage, self).RunNavigateSteps(action_runner)
    action_runner.Wait(8)



class FacebookPage(KeyMobileSitesPage):

  """ Why: #1 (Alexa global) """

  def __init__(self, page_set):
    super(FacebookPage, self).__init__(
      url='https://facebook.com/barackobama',
      page_set=page_set)

  def RunNavigateSteps(self, action_runner):
    super(FacebookPage, self).RunNavigateSteps(action_runner)
    action_runner.WaitForJavaScriptCondition(
        'document.getElementById("u_0_c") !== null &&'
        'document.body.scrollHeight > window.innerHeight')


class YoutubeMobilePage(KeyMobileSitesPage):

  """ Why: #3 (Alexa global) """

  def __init__(self, page_set):
    super(YoutubeMobilePage, self).__init__(
      url='http://m.youtube.com/watch?v=9hBpF_Zj4OA',
      page_set=page_set)

  def RunNavigateSteps(self, action_runner):
    super(YoutubeMobilePage, self).RunNavigateSteps(action_runner)
    action_runner.WaitForJavaScriptCondition(
        'document.getElementById("paginatortarget") !== null')


class LinkedInPage(KeyMobileSitesPage):

  """ Why: #12 (Alexa global),Public profile """

  def __init__(self, page_set):
    super(LinkedInPage, self).__init__(
      url='https://www.linkedin.com/in/linustorvalds',
      page_set=page_set,
      name='LinkedIn')

  def RunNavigateSteps(self, action_runner):
    super(LinkedInPage, self).RunNavigateSteps(action_runner)
    action_runner.WaitForJavaScriptCondition(
        'document.getElementById("profile-view-scroller") !== null')



class YahooAnswersPage(KeyMobileSitesPage):

  """ Why: #1 Alexa reference """

  def __init__(self, page_set):
    super(YahooAnswersPage, self).__init__(
      # pylint: disable=line-too-long
      url='http://answers.yahoo.com/question/index?qid=20110117024343AAopj8f',
      page_set=page_set)

  def RunNavigateSteps(self, action_runner):
    super(YahooAnswersPage, self).RunNavigateSteps(action_runner)
    action_runner.WaitForElement(text='Other Answers (1 - 20 of 149)')
    action_runner.ClickElement(text='Other Answers (1 - 20 of 149)')


class GmailPage(KeyMobileSitesPage):

  """ Why: productivity, top google properties """

  def __init__(self, page_set):
    super(GmailPage, self).__init__(
      url='https://mail.google.com/mail/',
      page_set=page_set)

    self.credentials = 'google'

  def RunNavigateSteps(self, action_runner):
    super(GmailPage, self).RunNavigateSteps(action_runner)
    action_runner.WaitForJavaScriptCondition(
        'document.getElementById("og_user_warning") !== null')
    action_runner.WaitForJavaScriptCondition(
        'document.getElementById("og_user_warning") === null')


class GroupClonedPage(KeyMobileSitesPage):

  """ Why: crbug.com/172906 """

  def __init__(self, page_set):
    super(GroupClonedPage, self).__init__(
      url='http://groupcloned.com',
      page_set=page_set)


  def RunNavigateSteps(self, action_runner):
    super(GroupClonedPage, self).RunNavigateSteps(action_runner)
    action_runner.Wait(5)
    action_runner.WaitForJavaScriptCondition('''
        document.getElementById("element-19") !== null &&
        document.getElementById("element-19").contentDocument
          .getElementById("element-22") !== null &&
        document.getElementById("element-19").contentDocument
          .getElementsByClassName(
              "container list-item gc-list-item stretched").length !== 0''')


class GroupClonedListImagesPage(KeyMobileSitesPage):

  """ Why: crbug.com/172906 """

  def __init__(self, page_set):
    super(GroupClonedListImagesPage, self).__init__(
      url='http://groupcloned.com/test/list-images-variable/index.html',
      page_set=page_set)

  def RunNavigateSteps(self, action_runner):
    super(GroupClonedListImagesPage, self).RunNavigateSteps(action_runner)
    action_runner.WaitForJavaScriptCondition(
        'document.getElementById("element-5") !== null')


class GoogleNewsMobilePage(KeyMobileSitesPage):

  """ Why: Google News: accelerated scrolling version """

  def __init__(self, page_set):
    super(GoogleNewsMobilePage, self).__init__(
      url='http://mobile-news.sandbox.google.com/news/pt1',
      page_set=page_set)

  def RunNavigateSteps(self, action_runner):
    super(GoogleNewsMobilePage, self).RunNavigateSteps(action_runner)
    action_runner.WaitForJavaScriptCondition(
        'typeof NEWS_telemetryReady !== "undefined" && '
        'NEWS_telemetryReady == true')


class GoogleNewsMobile2Page(KeyMobileSitesPage):

  """
  Why: Google News: this iOS version is slower than accelerated scrolling
  """

  def __init__(self, page_set):
    super(GoogleNewsMobile2Page, self).__init__(
      url='http://mobile-news.sandbox.google.com/news/pt0',
      page_set=page_set)

  def RunNavigateSteps(self, action_runner):
    super(GoogleNewsMobile2Page, self).RunNavigateSteps(action_runner)
    action_runner.WaitForJavaScriptCondition(
        'document.getElementById(":h") != null')
    action_runner.Wait(1)


class AmazonNicolasCagePage(KeyMobileSitesPage):

  """
  Why: #1 world commerce website by visits; #3 commerce in the US by time spent
  """

  def __init__(self, page_set):
    super(AmazonNicolasCagePage, self).__init__(
      url='http://www.amazon.com/gp/aw/s/ref=is_box_?k=nicolas+cage',
      page_set=page_set)
