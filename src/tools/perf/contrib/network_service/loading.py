# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from benchmarks import loading

from telemetry import benchmark


@benchmark.Owner(emails=['yzshen@chromium.org'])
class LoadingDesktopNetworkService(loading.LoadingDesktop):
  """Measures loading performance of desktop sites, with the network service
  enabled.
  """
  @classmethod
  def Name(cls):
    return 'loading.desktop.network_service'

  def SetExtraBrowserOptions(self, options):
    enable_features_arg = '--enable-features=NetworkService'

    # If an "--enable-features" argument has been specified, append to the value
    # list of that argument.
    for arg in options.extra_browser_args:
      if arg.startswith('--enable-features='):
        options.extra_browser_args.remove(arg)
        enable_features_arg = arg + ',NetworkService'
        break

    options.AppendExtraBrowserArgs([ enable_features_arg, '--incognito' ])
