# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from profile_creators import cookie_profile_extender
from profile_creators import profile_extender


class LargeProfileExtender(profile_extender.ProfileExtender):
  """This class creates a large profile by performing a large number of url
  navigations."""

  def Run(self):
    extender = cookie_profile_extender.CookieProfileExtender(
        self.finder_options)
    extender.Run()
