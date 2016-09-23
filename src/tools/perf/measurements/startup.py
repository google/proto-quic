# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from telemetry.page import legacy_page_test

from metrics import keychain_metric
from metrics import startup_metric


class Startup(legacy_page_test.LegacyPageTest):
  """Performs a measurement of Chromium's startup performance.

  Uses cold start if cold==True, otherwise uses warm start. A cold start means
  none of the Chromium files are in the disk cache. A warm start assumes the OS
  has already cached much of Chromium's content. For warm tests, you should
  repeat the page set to ensure it's cached.
  """

  def __init__(self, cold=False):
    super(Startup, self).__init__(needs_browser_restart_after_each_page=True)
    self._cold = cold

  def CustomizeBrowserOptions(self, options):
    if self._cold:
      options.clear_sytem_cache_for_browser_and_profile_on_start = True
    options.AppendExtraBrowserArgs([
        '--enable-stats-collection-bindings'
    ])
    keychain_metric.KeychainMetric.CustomizeBrowserOptions(options)

  def ValidateAndMeasurePage(self, page, tab, results):
    del page  # unused
    keychain_metric.KeychainMetric().AddResults(tab, results)
    startup_metric.StartupMetric().AddResults(tab, results)


class StartWithUrl(Startup):
  """Performs a measurement of Chromium's performance starting with a URL.

  Uses cold start if cold==True, otherwise uses warm start. A cold start means
  none of the Chromium files are in the disk cache. A warm start assumes the OS
  has already cached much of Chromium's content. For warm tests, you should
  repeat the page set to ensure it's cached.

  The startup URL is taken from the page's startup_url. This
  allows the testing of multiple different URLs in a single benchmark.
  """

  def __init__(self, cold=False):
    super(StartWithUrl, self).__init__(cold=cold)
