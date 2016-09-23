# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import os

from telemetry.page import legacy_page_test


_JS = 'chrome.gpuBenchmarking.printPagesToSkPictures("{0}");'


class MultipageSkpicturePrinter(legacy_page_test.LegacyPageTest):

  def __init__(self, mskp_outdir):
    super(MultipageSkpicturePrinter, self).__init__()
    self._mskp_outdir = mskp_outdir

  def CustomizeBrowserOptions(self, options):
    options.AppendExtraBrowserArgs(['--enable-gpu-benchmarking',
                                    '--no-sandbox',
                                    '--enable-deferred-image-decoding'])

  def ValidateAndMeasurePage(self, page, tab, results):
    if tab.browser.platform.GetOSName() in ['android', 'chromeos']:
      raise legacy_page_test.MeasurementFailure(
          'Multipage SkPicture printing not supported on this platform')

    # Replace win32 path separator char '\' with '\\'.
    outpath = os.path.abspath(
        os.path.join(self._mskp_outdir, page.file_safe_name + '.mskp'))
    js = _JS.format(outpath.replace('\\', '\\\\'))
    tab.EvaluateJavaScript(js)
