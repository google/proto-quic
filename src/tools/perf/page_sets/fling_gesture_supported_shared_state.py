# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import logging

from telemetry.page import shared_page_state


class FlingGestureSupportedSharedState(
    shared_page_state.Shared10InchTabletPageState):

  def CanRunOnBrowser(self, browser_info, _):
    if not browser_info.HasFlingGestureSupport():
      logging.warning('Browser does not support fling gestures, skipping test')
      return False
    return True
