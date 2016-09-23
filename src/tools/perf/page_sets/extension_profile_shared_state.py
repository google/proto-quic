# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import shutil

from profile_creators import extension_profile_extender
from profile_creators import profile_generator
from telemetry.page import shared_page_state


class ExtensionProfileSharedState(shared_page_state.SharedPageState):
  """Shared state tied with extension profile.

  Generates extension profile on initialization.
  """

  def __init__(self, test, finder_options, story_set):
    super(ExtensionProfileSharedState, self).__init__(
        test, finder_options, story_set)
    generator = profile_generator.ProfileGenerator(
        extension_profile_extender.ExtensionProfileExtender,
        'extension_profile')
    self._out_dir, self._owns_out_dir = generator.Run(finder_options)
    if self._out_dir:
      finder_options.browser_options.profile_dir = self._out_dir
    else:
      finder_options.browser_options.dont_override_profile = True

  def TearDownState(self):
    """Clean up generated profile directory."""
    super(ExtensionProfileSharedState, self).TearDownState()
    if self._owns_out_dir:
      shutil.rmtree(self._out_dir)
