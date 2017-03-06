# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
from telemetry import story
from telemetry.page import page as page_module
from telemetry.page import shared_page_state


class SimplePage(page_module.Page):

  def __init__(self, url, page_set):
    super(SimplePage, self).__init__(
        url=url,
        page_set=page_set,
        shared_page_state_class=shared_page_state.SharedPageState,
        credentials_path='data/credentials.json')
    self.archive_data_file = 'data/text_selection_sites.json'

  def RunNavigateSteps(self, action_runner):
    super(SimplePage, self).RunNavigateSteps(action_runner)
    action_runner.WaitForJavaScriptCondition(
        'document.readyState == "complete"')


class SimpleTextSelectionPage(SimplePage):

  def __init__(self, url, page_set):
    super(SimpleTextSelectionPage, self).__init__(url=url, page_set=page_set)

  def RunPageInteractions(self, action_runner):
    # Create a fixed position div in the top left corner of the page, and
    # another one in the bottom right corner of the page.
    # Select the text within the first div.
    action_runner.ExecuteJavaScript('''
        (function() {
          var text_div = document.createElement('div');
          var text_div_2 = document.createElement('div');

          text_div.style.fontSize = text_div_2.style.fontSize = "10vh";
          text_div.style.lineHeight = text_div_2.style.lineHeight = "normal";
          text_div.style.color = text_div_2.style.color = "red";
          text_div.style.zIndex = text_div_2.style.zIndex = "1000";
          text_div.style.position = text_div_2.style.position = "fixed";
          text_div.style.left = "10%";
          text_div.style.top = "10%";
          text_div_2.style.right="0";
          text_div_2.style.bottom="2%";

          text_div.id="text-for-perf-test";
          text_div_2.id="text-for-perf-test-2";
          text_div.innerText="Hello";
          text_div_2.innerText="World";

          document.body.insertBefore(text_div, document.body.firstChild);
          document.body.appendChild(text_div_2);

          var selection = window.getSelection();
          var textNode = text_div.childNodes[0];
          selection.setBaseAndExtent(textNode, 0, textNode, 5);

          window.requestAnimationFrame(function() {
            text_div.style.color="green";
          });
        })();''')

    # Wait two frames so that the selection information is sent to chromium
    # and it is able to process input events interacting with selection.
    action_runner.WaitForJavaScriptCondition(
        'document.getElementById("text-for-perf-test").style.color == "green"')
    action_runner.ExecuteJavaScript('''
          window.requestAnimationFrame(function() {
            document.getElementById("text-for-perf-test").style.color="red";
          });
        ''')
    action_runner.WaitForJavaScriptCondition(
        'document.getElementById("text-for-perf-test").style.color == "red"')

    # Confirm that the selection is set correctly.
    text = action_runner.EvaluateJavaScript('window.getSelection().toString()')
    assert text == "Hello"

    # Tap on the selected text to make the handles show up.
    with action_runner.CreateGestureInteraction('TapAction'):
      action_runner.TapElement('#text-for-perf-test')

    text_div_bottom = float(action_runner.EvaluateJavaScript('''
        document.getElementById("text-for-perf-test").getClientRects()[0].bottom
        '''))
    text_div_2_bottom = float(action_runner.EvaluateJavaScript('''
        document.getElementById(
            "text-for-perf-test-2").getClientRects()[0].bottom
        '''))
    body_rect_str = action_runner.EvaluateJavaScript('''
        var r = window.__GestureCommon_GetBoundingVisibleRect(document.body);
        r.left + " " + r.top + " " + r.height + " " + r.width;
        ''')
    body_rect_left, body_rect_top, body_rect_height, body_rect_width = map(
        float, body_rect_str.split())

    # Start the drag gesture 5 pixels below the bottom left corner of the
    # first div in order to drag the left selection handle.
    p1_left_ratio = .1
    p1_top_ratio = float((text_div_bottom + 5 - body_rect_top) /
                         body_rect_height)

    # End the drag gesture below the bottom right corner of the second div,
    # so that the selection end is in the second div and we can easily
    # determine the position of the corresponding handle.
    p2_top_ratio = float((text_div_2_bottom - body_rect_top) /
                         body_rect_height)

    with action_runner.CreateGestureInteraction('DragAction-1'):
      action_runner.DragPage(left_start_ratio=p1_left_ratio,
          top_start_ratio=p1_top_ratio, left_end_ratio=.99,
          top_end_ratio=p2_top_ratio, speed_in_pixels_per_second=300,
          use_touch=1)

    # Confirm that the selection has changed.
    text = action_runner.EvaluateJavaScript('window.getSelection().toString()')
    assert text != "Hello"

    # Determine the coordinates of the end of the selection
    sel_end_str = action_runner.EvaluateJavaScript('''
          var rects = window.getSelection().getRangeAt(0).getClientRects();
          var last_rect = rects[rects.length - 1];
          last_rect.right + " " + last_rect.bottom;
        ''')
    sel_end_x, sel_end_y = map(float, sel_end_str.split())

    # Start the second drag gesture 5 pixels below the end of the selection
    # in order to drag the selection handle.
    p2_left_ratio = float((sel_end_x - body_rect_left) / body_rect_width)
    p2_top_ratio = float((sel_end_y + 5 - body_rect_top) / body_rect_height)

    with action_runner.CreateGestureInteraction('DragAction-2'):
      action_runner.DragPage(left_start_ratio=p2_left_ratio,
          top_start_ratio=p2_top_ratio, left_end_ratio=p1_left_ratio,
          top_end_ratio=p1_top_ratio, speed_in_pixels_per_second=300,
          use_touch=1)

    # Confirm that the selection is back to the text in the first div.
    text = action_runner.EvaluateJavaScript('window.getSelection().toString()')
    assert text == "Hello"


class TextSelectionSitesPageSet(story.StorySet):
  def __init__(self):
    super(TextSelectionSitesPageSet, self).__init__(
      archive_data_file='data/top_10_mobile.json',
      cloud_storage_bucket=story.PARTNER_BUCKET)

    # A subset of top_10_mobile page set
    page_urls = [
        'https://www.google.co.uk/#hl=en&q=science',
        'https://m.facebook.com/rihanna',
        'http://search.yahoo.com/search;_ylt=?p=google',
        'http://www.baidu.com/s?word=google',
        'https://mobile.twitter.com/justinbieber?skip_interstitial=true',
        'http://yandex.ru/touchsearch?text=science'
    ]

    for url in page_urls:
      self.AddStory(SimpleTextSelectionPage(url, self))
