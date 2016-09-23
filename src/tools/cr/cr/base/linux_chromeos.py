# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Linux Chrome OS platform."""

import os

import cr

class LinuxChromeOSPlatform(cr.Platform):
  """Platform for Linux Chrome OS target"""

  ACTIVE = cr.Config.From(
      CR_BINARY=os.path.join('{CR_BUILD_DIR}', '{CR_BUILD_TARGET}'),
      CHROME_DEVEL_SANDBOX='/usr/local/sbin/chrome-devel-sandbox',
      GYP_DEF_chromeos=1,
      GN_ARG_target_os='"chromeos"',
  )

  @property
  def enabled(self):
    return cr.Platform.System() == 'Linux'

  @property
  def priority(self):
    return 2

  @property
  def paths(self):
    return ['{GOMA_DIR}']
