# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import logging
import os
import py_utils
import time

from telemetry.page import legacy_page_test
from telemetry.util import image_util

class Screenshot(legacy_page_test.LegacyPageTest):
  """Takes a PNG screenshot of the page."""

  def __init__(self, png_outdir, wait_time=0):
    super(Screenshot, self).__init__()
    self._png_outdir = png_outdir
    self._wait_time = wait_time

  def ValidateAndMeasurePage(self, page, tab, results):
    if not tab.screenshot_supported:
      raise legacy_page_test.MeasurementFailure(
        'Screenshotting not supported on this platform')

    try:
      tab.WaitForDocumentReadyStateToBeComplete()
    except py_utils.TimeoutException:
      logging.warning("WaitForDocumentReadyStateToBeComplete() timeout, " +
                      "page: %s", page.display_name)
      return

    time.sleep(self._wait_time)

    if not os.path.exists(self._png_outdir):
      logging.info("Creating directory %s", self._png_outdir)
      try:
        os.makedirs(self._png_outdir)
      except OSError:
        logging.warning("Directory %s could not be created", self._png_outdir)
        raise

    outpath = os.path.abspath(
        os.path.join(self._png_outdir, page.file_safe_name)) + '.png'
    # Replace win32 path separator char '\' with '\\'.
    outpath = outpath.replace('\\', '\\\\')

    screenshot = tab.Screenshot()

    # TODO(lchoi): Add logging to image_util.py and/or augment error handling of
    # image_util.WritePngFile
    logging.info("Writing PNG file to %s. This may take awhile.", outpath)
    start = time.time()
    image_util.WritePngFile(screenshot, outpath)
    logging.info("PNG file written successfully. (Took %f seconds)",
                 time.time()-start)
