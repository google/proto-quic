# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
from telemetry.page import page as page_module
from telemetry.page import shared_page_state
from telemetry import story


def _GetCurrentLocation(action_runner):
  return action_runner.EvaluateJavaScript('document.location.href')


def _WaitForLocationChange(action_runner, old_href):
  action_runner.WaitForJavaScriptCondition(
      'document.location.href != {{ old_href }}', old_href=old_href)


class Top7StressPage(page_module.Page):

  def __init__(self, url, page_set, name=''):
    super(Top7StressPage, self).__init__(
        url=url, page_set=page_set, name=name,
        shared_page_state_class=shared_page_state.SharedDesktopPageState,
        credentials_path = 'data/credentials.json')
    self.archive_data_file = 'data/top_7_stress.json'

  def RunPageInteractions(self, action_runner):
    raise NotImplementedError()


class GoogleWebSearchPage(Top7StressPage):

  """ Why: top google property; a google tab is often open """

  def __init__(self, page_set):
    super(GoogleWebSearchPage, self).__init__(
      url='https://www.google.com/#hl=en&q=barack+obama',
      page_set=page_set)

  def RunNavigateSteps(self, action_runner):
    super(GoogleWebSearchPage, self).RunNavigateSteps(action_runner)
    action_runner.WaitForElement(text='Next')

  def RunPageInteractions(self, action_runner):
    with action_runner.CreateGestureInteraction('ScrollAction'):
      action_runner.ScrollPage()
    old_href = _GetCurrentLocation(action_runner)
    action_runner.ClickElement(text='Next')
    _WaitForLocationChange(action_runner, old_href)
    action_runner.WaitForElement(text='Next')
    with action_runner.CreateGestureInteraction('ScrollAction'):
      action_runner.ScrollPage()
    old_href = _GetCurrentLocation(action_runner)
    action_runner.ClickElement(text='Next')
    _WaitForLocationChange(action_runner, old_href)
    action_runner.WaitForElement(text='Next')
    with action_runner.CreateGestureInteraction('ScrollAction'):
      action_runner.ScrollPage()
    old_href = _GetCurrentLocation(action_runner)
    action_runner.ClickElement(text='Next')
    _WaitForLocationChange(action_runner, old_href)
    action_runner.WaitForElement(text='Previous')
    with action_runner.CreateGestureInteraction('ScrollAction'):
      action_runner.ScrollPage()
    old_href = _GetCurrentLocation(action_runner)
    action_runner.ClickElement(text='Previous')
    _WaitForLocationChange(action_runner, old_href)
    action_runner.WaitForElement(text='Previous')
    with action_runner.CreateGestureInteraction('ScrollAction'):
      action_runner.ScrollPage()
    old_href = _GetCurrentLocation(action_runner)
    action_runner.ClickElement(text='Previous')
    _WaitForLocationChange(action_runner, old_href)
    action_runner.WaitForElement(text='Previous')
    with action_runner.CreateGestureInteraction('ScrollAction'):
      action_runner.ScrollPage()
    old_href = _GetCurrentLocation(action_runner)
    action_runner.ClickElement(text='Previous')
    _WaitForLocationChange(action_runner, old_href)
    action_runner.WaitForElement(text='Images')
    with action_runner.CreateGestureInteraction('ScrollAction'):
      action_runner.ScrollPage()
    old_href = _GetCurrentLocation(action_runner)
    action_runner.ClickElement(text='Images')
    _WaitForLocationChange(action_runner, old_href)
    action_runner.WaitForElement(text='Images')


class GmailPage(Top7StressPage):

  """ Why: productivity, top google properties """

  def __init__(self, page_set):
    super(GmailPage, self).__init__(
      url='https://mail.google.com/mail/',
      page_set=page_set)

    self.credentials = 'google'

  def RunNavigateSteps(self, action_runner):
    super(GmailPage, self).RunNavigateSteps(action_runner)
    action_runner.WaitForJavaScriptCondition(
        'window.gmonkey !== undefined &&'
        'document.getElementById("gb") !== null')

  def RunPageInteractions(self, action_runner):
    old_href = _GetCurrentLocation(action_runner)
    action_runner.ClickElement(
        'a[href="https://mail.google.com/mail/u/0/?shva=1#starred"]')
    _WaitForLocationChange(action_runner, old_href)
    old_href = _GetCurrentLocation(action_runner)
    action_runner.ClickElement(
        'a[href="https://mail.google.com/mail/u/0/?shva=1#inbox"]')
    _WaitForLocationChange(action_runner, old_href)


class GoogleCalendarPage(Top7StressPage):

  """ Why: productivity, top google properties """

  def __init__(self, page_set):
    super(GoogleCalendarPage, self).__init__(
      url='https://www.google.com/calendar/',
      page_set=page_set)

    self.credentials = 'google'

  def RunNavigateSteps(self, action_runner):
    super(GoogleCalendarPage, self).RunNavigateSteps(action_runner)
    action_runner.Wait(2)
    action_runner.WaitForElement('div[class~="navForward"]')
    action_runner.ExecuteJavaScript('''
        (function() {
          var elem = document.createElement('meta');
          elem.name='viewport';
          elem.content='initial-scale=1';
          document.body.appendChild(elem);
        })();''')
    action_runner.Wait(1)

  def RunPageInteractions(self, action_runner):
    action_runner.ClickElement('div[class~="navForward"]')
    action_runner.Wait(2)
    action_runner.WaitForElement('div[class~="navForward"]')
    action_runner.ClickElement('div[class~="navForward"]')
    action_runner.Wait(2)
    action_runner.WaitForElement('div[class~="navForward"]')
    action_runner.ClickElement('div[class~="navForward"]')
    action_runner.Wait(2)
    action_runner.WaitForElement('div[class~="navForward"]')
    action_runner.ClickElement('div[class~="navForward"]')
    action_runner.Wait(2)
    action_runner.WaitForElement('div[class~="navBack"]')
    action_runner.ClickElement('div[class~="navBack"]')
    action_runner.Wait(2)
    action_runner.WaitForElement('div[class~="navBack"]')
    action_runner.ClickElement('div[class~="navBack"]')
    action_runner.Wait(2)
    action_runner.WaitForElement('div[class~="navBack"]')
    action_runner.ClickElement('div[class~="navBack"]')
    action_runner.Wait(2)
    action_runner.WaitForElement('div[class~="navBack"]')
    action_runner.ClickElement('div[class~="navBack"]')
    action_runner.Wait(2)
    action_runner.WaitForElement('div[class~="navBack"]')


class GooglePlusPage(Top7StressPage):

  """ Why: social; top google property; Public profile; infinite scrolls """

  def __init__(self, page_set):
    super(GooglePlusPage, self).__init__(
      url='https://plus.google.com/110031535020051778989/posts',
      page_set=page_set)

    self.credentials = 'google'

  def RunNavigateSteps(self, action_runner):
    super(GooglePlusPage, self).RunNavigateSteps(action_runner)
    action_runner.WaitForElement(text='Home')

  def RunPageInteractions(self, action_runner):
    action_runner.ClickElement(text='Home')
    action_runner.Wait(2)
    action_runner.WaitForElement(text='Profile')
    action_runner.ClickElement(text='Profile')
    action_runner.Wait(2)
    action_runner.WaitForElement(text='Explore')
    action_runner.ClickElement(text='Explore')
    action_runner.Wait(2)
    action_runner.WaitForElement(text='Events')
    action_runner.ClickElement(text='Events')
    action_runner.Wait(2)
    action_runner.WaitForElement(text='Communities')
    action_runner.ClickElement(text='Communities')
    action_runner.Wait(2)
    action_runner.WaitForElement(text='Home')


class BlogspotPage(Top7StressPage):

  """ Why: #11 (Alexa global), google property; some blogger layouts have
  infinite scroll but more interesting """

  def __init__(self, page_set):
    super(BlogspotPage, self).__init__(
      url='http://googlewebmastercentral.blogspot.com/',
      page_set=page_set,
      name='Blogger')

  def RunNavigateSteps(self, action_runner):
    super(BlogspotPage, self).RunNavigateSteps(action_runner)
    action_runner.WaitForElement(text='accessibility')

  def RunPageInteractions(self, action_runner):
    action_runner.ClickElement(text='accessibility')
    action_runner.WaitForNavigate()
    with action_runner.CreateGestureInteraction('ScrollAction'):
      action_runner.ScrollPage()
    # Insert 300ms wait to simulate user finger movement,
    # and ensure scheduling of idle tasks.
    action_runner.Wait(0.3)
    action_runner.ClickElement(text='advanced')
    action_runner.WaitForNavigate()
    with action_runner.CreateGestureInteraction('ScrollAction'):
      action_runner.ScrollPage()
    action_runner.Wait(0.3)
    action_runner.ClickElement(text='beginner')
    action_runner.WaitForNavigate()
    with action_runner.CreateGestureInteraction('ScrollAction'):
      action_runner.ScrollPage()
    action_runner.Wait(0.3)
    action_runner.ClickElement(text='Home')
    action_runner.WaitForNavigate()


class WordpressPage(Top7StressPage):

  """ Why: #18 (Alexa global), Picked an interesting post """

  def __init__(self, page_set):
    super(WordpressPage, self).__init__(
      # pylint: disable=line-too-long
      url='http://en.blog.wordpress.com/2012/09/04/freshly-pressed-editors-picks-for-august-2012/',
      page_set=page_set,
      name='Wordpress')

  def RunNavigateSteps(self, action_runner):
    super(WordpressPage, self).RunNavigateSteps(action_runner)
    action_runner.WaitForElement(
        # pylint: disable=line-too-long
        'a[href="http://en.blog.wordpress.com/2012/08/30/new-themes-able-and-sight/"]')

  def RunPageInteractions(self, action_runner):
    with action_runner.CreateGestureInteraction('ScrollAction'):
      action_runner.ScrollPage()
    # Insert 300ms wait to simulate user finger movement,
    # and ensure scheduling of idle tasks.
    action_runner.Wait(0.3)
    action_runner.ClickElement(
        # pylint: disable=line-too-long
        'a[href="http://en.blog.wordpress.com/2012/08/30/new-themes-able-and-sight/"]')
    action_runner.WaitForNavigate()
    with action_runner.CreateGestureInteraction('ScrollAction'):
      action_runner.ScrollPage()
    action_runner.Wait(0.3)
    action_runner.ClickElement(text='Features')
    action_runner.WaitForNavigate()
    with action_runner.CreateGestureInteraction('ScrollAction'):
      action_runner.ScrollPage()
    action_runner.Wait(0.3)
    action_runner.ClickElement(text='News')
    action_runner.WaitForNavigate()
    with action_runner.CreateGestureInteraction('ScrollAction'):
      action_runner.ScrollPage()


class FacebookPage(Top7StressPage):

  """ Why: top social,Public profile """

  def __init__(self, page_set):
    super(FacebookPage, self).__init__(
      url='https://www.facebook.com/barackobama',
      page_set=page_set,
      name='Facebook')
    self.credentials = 'facebook2'

  def RunNavigateSteps(self, action_runner):
    super(FacebookPage, self).RunNavigateSteps(action_runner)
    action_runner.WaitForElement(text='About')

  def RunPageInteractions(self, action_runner):
    # Scroll and wait for the next page to be loaded.
    with action_runner.CreateGestureInteraction('ScrollAction'):
      action_runner.ScrollPage()
    action_runner.WaitForJavaScriptCondition(
        'document.documentElement.scrollHeight - window.innerHeight - '
        'window.pageYOffset > 0')

    # Scroll and wait again.
    with action_runner.CreateGestureInteraction('ScrollAction'):
      action_runner.ScrollPage()
    action_runner.WaitForJavaScriptCondition(
        'document.documentElement.scrollHeight - window.innerHeight - '
        'window.pageYOffset > 0')

class Top7StressPageSet(story.StorySet):

  """ Pages hand-picked for stress testing. """

  def __init__(self):
    super(Top7StressPageSet, self).__init__(
      archive_data_file='data/top_7_stress.json',
      cloud_storage_bucket=story.PARTNER_BUCKET)

    self.AddStory(GoogleWebSearchPage(self))
    self.AddStory(GmailPage(self))
    self.AddStory(GoogleCalendarPage(self))
    self.AddStory(GooglePlusPage(self))
    self.AddStory(BlogspotPage(self))
    self.AddStory(WordpressPage(self))
    self.AddStory(FacebookPage(self))
