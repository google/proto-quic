# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import sys

from telemetry import benchmark
from telemetry.internal.browser import browser_finder

sys.path.append(os.path.join(os.path.dirname(__file__), '..',
                             '..', 'variations'))
import fieldtrial_util  # pylint: disable=import-error


class PerfBenchmark(benchmark.Benchmark):
  """ Super class for all benchmarks in src/tools/perf/benchmarks directory.
  All the perf benchmarks must subclass from this one to to make sure that
  the field trial configs are activated for the browser during benchmark runs.
  For more info, see: https://goo.gl/4uvaVM
  """

  def SetExtraBrowserOptions(self, options):
    """ To be overridden by perf benchmarks. """
    pass

  def CustomizeBrowserOptions(self, options):
    # Subclass of PerfBenchmark should override  SetExtraBrowserOptions to add
    # more browser options rather than overriding CustomizeBrowserOptions.
    super(PerfBenchmark, self).CustomizeBrowserOptions(options)

    # Enable taking screen shot on failed pages for all perf benchmarks.
    options.take_screenshot_for_failed_page = True

    # The current field trial config is used for an older build in the case of
    # reference. This is a problem because we are then subjecting older builds
    # to newer configurations that may crash.  To work around this problem,
    # don't add the field trials to reference builds.
    if options.browser_type != 'reference':
      variations = self._GetVariationsBrowserArgs(options.finder_options)
      options.AppendExtraBrowserArgs(variations)
    self.SetExtraBrowserOptions(options)

  @staticmethod
  def _FixupTargetOS(target_os):
    if target_os == 'darwin':
      return 'mac'
    if target_os.startswith('win'):
      return 'win'
    if target_os.startswith('linux'):
      return 'linux'
    return target_os

  def _GetVariationsBrowserArgs(self, finder_options):
    variations_dir = os.path.join(os.path.dirname(__file__), '..',
                                  '..', '..', 'testing', 'variations')
    possible_browser = browser_finder.FindBrowser(finder_options)
    if not possible_browser:
      return []

    return fieldtrial_util.GenerateArgs(
        os.path.join(variations_dir,
                     'fieldtrial_testing_config_%s.json' % self._FixupTargetOS(
                         possible_browser.target_os)))

  @staticmethod
  def IsSvelte(possible_browser):
    """Returns whether a possible_browser is on a svelte Android build."""
    if possible_browser.target_os == 'android':
      return possible_browser.platform.IsSvelte()
    return False
