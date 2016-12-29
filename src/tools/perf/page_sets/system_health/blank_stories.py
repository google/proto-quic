# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from page_sets.system_health import system_health_story


class BlankAboutBlankStory(system_health_story.SystemHealthStory):
  """Story that loads the about:blank page."""

  NAME = 'blank:about:blank'
  URL = 'about:blank'

  def _DidLoadDocument(self, action_runner):
    # Request a RAF and wait for it to be processed to ensure that the metric
    # Startup.FirstWebContents.NonEmptyPaint2 is recorded.
    action_runner.ExecuteJavaScript(
        """
        window.__hasRunRAF = false;
        requestAnimationFrame(function() {
          window.__hasRunRAF = true;
        });
        """
    )
    action_runner.WaitForJavaScriptCondition("window.__hasRunRAF")
