# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from collections import defaultdict
from itertools import starmap
from telemetry.core import util
from telemetry.page import legacy_page_test
from telemetry.value import scalar

from measurements import timeline_controller
import py_utils


class BlinkStyle(legacy_page_test.LegacyPageTest):

  def __init__(self):
    super(BlinkStyle, self).__init__()
    self._controller = None

  def WillNavigateToPage(self, page, tab):
    self._controller = timeline_controller.TimelineController()
    self._controller.trace_categories = 'blink_style,blink.console'
    self._controller.SetUp(page, tab)
    self._controller.Start(tab)

  def DidRunPage(self, platform):
    if self._controller:
      self._controller.CleanUp(platform)

  def ValidateAndMeasurePage(self, page, tab, results):
    with tab.action_runner.CreateInteraction('wait-for-quiescence'):
      tab.ExecuteJavaScript('console.time("");')
      try:
        util.WaitFor(tab.HasReachedQuiescence, 15)
      except py_utils.TimeoutException:
        # Some sites never reach quiesence. As this benchmark normalizes/
        # categories results, it shouldn't be necessary to reach the same
        # state on every run.
        pass

    tab.ExecuteJavaScript('''
        for (var i = 0; i < 11; i++) {
          var cold = i % 2 == 0;
          var name = "update_style";
          if (cold) name += "_cold";
          console.time(name);
          // Occasionally documents will break the APIs we need
          try {
            // On cold runs, force a new StyleResolver
            if (cold) {
              var style = document.createElement("style");
              document.head.appendChild(style);
              style.remove();
            }
            // Invalidate style for the whole document
            document.documentElement.lang += "z";
            // Force a style update (but not layout)
            getComputedStyle(document.documentElement).color;
          } catch (e) {}
          console.timeEnd(name);
        }''')

    self._controller.Stop(tab, results)
    renderer = self._controller.model.GetRendererThreadFromTabId(tab.id)
    markers = [event for event in renderer.async_slices
               if event.name.startswith('update_style')
               and event.category == 'blink.console']
    # Drop the first run.
    markers = markers[1:]
    assert len(markers) == 10

    def duration(event):
      if event.has_thread_timestamps:
        return event.thread_duration
      else:
        return event.duration

    for marker in markers:
      for event in renderer.all_slices:
        if (event.name == 'Document::updateStyle'
            and event.start >= marker.start
            and event.end <= marker.end):
          access_count = event.args.get('resolverAccessCount')
          if access_count is None:
            # absent in earlier versions
            continue
          min_access_count = 50

          if access_count >= min_access_count:
            result = 1000 * (duration(event) / access_count)
            results.AddValue(scalar.ScalarValue(
                page, marker.name, 'ms/1000 elements', result))

    class ParserEvent(object):

      def __init__(self, summary_event, tokenize_event, parse_event):
        min_sheet_length = 1000
        ua_sheet_mode = 5
        enormous_token_threshold = 100
        large_token_threshold = 5

        self.mode = summary_event.args.get('mode')
        self.length = summary_event.args.get('length')
        self.tokens = summary_event.args.get('tokenCount')
        self.tokenize_duration = duration(tokenize_event)
        self.parse_duration = duration(parse_event)
        self.chars_per_token = 0
        if self.tokens:
          self.chars_per_token = self.length / float(self.tokens)
        if self.mode == ua_sheet_mode or self.length < min_sheet_length:
          self.category = 'ignored'
        elif self.chars_per_token > enormous_token_threshold:
          self.category = 'enormous_tokens'
        elif self.chars_per_token > large_token_threshold:
          self.category = 'large_tokens'
        else:
          self.category = 'regular'

    parser_events = [event for event in renderer.all_slices
                     if event.name == 'CSSParserImpl::parseStyleSheet'
                     or event.name == 'CSSParserImpl::parseStyleSheet.tokenize'
                     or event.name == 'CSSParserImpl::parseStyleSheet.parse']

    merged_events = starmap(ParserEvent, zip(*[iter(parser_events)] * 3))

    events_by_category = defaultdict(list)
    for event in merged_events:
      if event.category != 'ignored':
        events_by_category[event.category].append(event)

    for category, events in events_by_category.items():
      parse_duration = sum(event.parse_duration for event in events)
      tokenize_duration = sum(event.tokenize_duration for event in events)
      tokens = sum(event.tokens for event in events)
      length = sum(event.length for event in events)

      results.AddValue(
          scalar.ScalarValue(page, ('parse_css_%s' % category),
                             'tokens/s', 1000 / (parse_duration / tokens)))

      results.AddValue(
          scalar.ScalarValue(page, ('tokenize_css_%s' % category),
                             'char/s',  1000 / (tokenize_duration / length)))
