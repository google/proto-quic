# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Check to see if the various BadMessage enums in histograms.xml need to be
updated. This can be called from a chromium PRESUBMIT.py to ensure updates to
bad_message.h also include the generated changes to histograms.xml
"""

import update_histogram_enum

def PrecheckBadMessage(input_api, output_api, histogram_name):
  source_path = ''

  # This function is called once per bad_message.h-containing directory. Check
  # for the |bad_message.h| file, and if present, remember its path.
  for f in input_api.AffectedFiles():
    if f.LocalPath().endswith('bad_message.h'):
      source_path = f.LocalPath()
      break

  # If the |bad_message.h| wasn't found in this change, then there is nothing to
  # do and histogram.xml does not need to be updated.
  if source_path == '':
    return []

  START_MARKER='^enum (class )?BadMessageReason {'
  END_MARKER='^BAD_MESSAGE_MAX'
  if update_histogram_enum.HistogramNeedsUpdate(
      histogram_enum_name=histogram_name,
      source_enum_path=source_path,
      start_marker=START_MARKER,
      end_marker=END_MARKER):
    return [output_api.PresubmitPromptWarning(
        'bad_messages.h has been updated but histogram.xml does not '
        'appear to be updated.\nPlease run:\n'
        '  python tools/metrics/histograms/update_bad_message_reasons.py\n')]
  return []
