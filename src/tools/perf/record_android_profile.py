#!/usr/bin/env python
# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import sys
import tempfile

from core import path_util
path_util.AddTelemetryToPath()

from telemetry.internal.browser import browser_finder
from telemetry.internal.browser import browser_options


def _RunPrebuilt(options):
  browser_to_create = browser_finder.FindBrowser(options)
  with browser_to_create.Create(options) as browser:
    output_file = os.path.join(tempfile.mkdtemp(), options.profiler)
    raw_input('Press enter to start profiling...')
    print '>> Starting profiler', options.profiler
    browser.profiling_controller.Start(options.profiler, output_file)
    try:
      raw_input('Press enter or CTRL+C to stop')
    except KeyboardInterrupt:
      pass
    finally:
      print '<< Stopping ...',
      sys.stdout.flush()
      browser.profiling_controller.Stop()
    print 'Stopped profiler ', options.profiler


if __name__ == '__main__':
  browser_finder_options = browser_options.BrowserFinderOptions()
  parser = browser_finder_options.CreateParser('')
  profiler_options, _ = parser.parse_args()
  sys.exit(_RunPrebuilt(profiler_options))
