# Copyright 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import glob
import os

from telemetry.page import legacy_page_test
from telemetry.value import scalar


_JS = 'chrome.gpuBenchmarking.printToSkPicture("{0}");'


class SkpicturePrinter(legacy_page_test.LegacyPageTest):

  def __init__(self, skp_outdir):
    super(SkpicturePrinter, self).__init__()
    self._skp_outdir = skp_outdir

  def CustomizeBrowserOptions(self, options):
    options.AppendExtraBrowserArgs(['--enable-gpu-benchmarking',
                                    '--no-sandbox',
                                    '--enable-deferred-image-decoding'])

  def ValidateAndMeasurePage(self, page, tab, results):
    if tab.browser.platform.GetOSName() in ['android', 'chromeos']:
      raise legacy_page_test.MeasurementFailure(
          'SkPicture printing not supported on this platform')

    # Replace win32 path separator char '\' with '\\'.
    outpath = os.path.abspath(
        os.path.join(self._skp_outdir, page.file_safe_name))
    js = _JS.format(outpath.replace('\\', '\\\\'))
    tab.EvaluateJavaScript(js)
    pictures = glob.glob(os.path.join(outpath, '*.skp'))
    results.AddValue(scalar.ScalarValue(
        results.current_page, 'saved_picture_count', 'count', len(pictures)))
