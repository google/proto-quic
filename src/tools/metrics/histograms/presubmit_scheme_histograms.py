# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Check to see if the ShouldAllowOpenURLFailureScheme enum in histograms.xml
needs to be updated. This can be called from a chromium PRESUBMIT.py to ensure
updates to the enum in chrome_content_browser_client_extensions_part.cc also
include the generated changes to histograms.xml.
"""

import update_histogram_enum

def PrecheckShouldAllowOpenURLEnums(input_api, output_api):
  source_file = 'chrome/browser/extensions/' \
                'chrome_content_browser_client_extensions_part.cc'

  affected_files = (f.LocalPath() for f in input_api.AffectedFiles())
  if source_file not in affected_files:
    return []

  if update_histogram_enum.HistogramNeedsUpdate(
      histogram_enum_name='ShouldAllowOpenURLFailureScheme',
      source_enum_path=source_file,
      start_marker='^enum ShouldAllowOpenURLFailureScheme {',
      end_marker='^SCHEME_LAST'):
    return [output_api.PresubmitPromptWarning(
        'ShouldAllowOpenURLFailureScheme has been updated but histogram.xml '
        'does not appear to be updated.\nPlease run:\n'
        '  python tools/metrics/histograms/'
        'update_should_allow_open_url_histograms.py\n')]
  return []
