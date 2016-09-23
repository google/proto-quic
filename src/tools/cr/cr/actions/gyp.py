# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""A module to add gyp support to cr."""

import cr
import os

GYP_DEFINE_PREFIX = 'GYP_DEF_'

class GypPrepareOut(cr.PrepareOut):
  """A prepare action that runs gyp whenever you select an output directory."""

  ACTIVE = cr.Config.From(
      GYP_GENERATORS='ninja',
      GYP_GENERATOR_FLAGS='output_dir={CR_OUT_BASE} config={CR_BUILDTYPE}',
      GYP_DEF_target_arch='{CR_ENVSETUP_ARCH}',
  )

  def UpdateContext(self):
    # Collapse GYP_DEFINES from all GYP_DEF prefixes
    gyp_defines = cr.context.Find('GYP_DEFINES') or ''
    for key, value in cr.context.exported.items():
      if key.startswith(GYP_DEFINE_PREFIX):
        gyp_defines += ' %s=%s' % (key[len(GYP_DEFINE_PREFIX):], value)
    cr.context['GYP_DEFINES'] = gyp_defines.strip()
    if cr.context.verbose >= 1:
      print cr.context.Substitute('GYP_DEFINES = {GYP_DEFINES}')

  def Prepare(self):
    if cr.context.verbose >= 1:
      print cr.context.Substitute('Invoking gyp with {GYP_GENERATOR_FLAGS}')

    cr.Host.Execute(
        '{CR_SRC}/build/gyp_chromium',
        '--depth={CR_SRC}',
        '--check'
    )
