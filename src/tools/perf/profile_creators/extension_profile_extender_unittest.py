# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import shutil
import tempfile

from profile_creators import extension_profile_extender
from telemetry import decorators
from telemetry.testing import options_for_unittests
from telemetry.testing import page_test_test_case


class ExtensionProfileExtenderUnitTest(page_test_test_case.PageTestTestCase):
  """Smoke test for creating an extension profile.

     Creates an extension profile and verifies that it has non-empty contents.
  """
  # Should be enabled on mac, disabled because flaky: https://crbug.com/586362.
  @decorators.Disabled('all')  # Extension generation only works on Mac for now.
  def testExtensionProfileCreation(self):
    tmp_dir = tempfile.mkdtemp()
    files_in_crx_dir = 0
    try:
      options = options_for_unittests.GetCopy()
      # TODO(eakuefner): Remove this after crrev.com/1874473006 rolls in.
      try:
        getattr(options, 'output_profile_path')
        options.output_profile_path = tmp_dir
      except AttributeError:
        options.browser_options.output_profile_path = tmp_dir
      extender = extension_profile_extender.ExtensionProfileExtender(options)
      extender.Run()

      crx_dir = os.path.join(tmp_dir, 'external_extensions_crx')
      files_in_crx_dir = len(os.listdir(crx_dir))
    finally:
      shutil.rmtree(tmp_dir)
    self.assertGreater(files_in_crx_dir, 0)
