# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""
See http://dev.chromium.org/developers/how-tos/depottools/presubmit-scripts
for more details on the presubmit API built into depot_tools.
"""


def CheckChange(input_api, output_api):
  """Checks that histograms.xml is pretty-printed and well-formatted."""
  for f in input_api.AffectedTextFiles():
    p = f.AbsoluteLocalPath()
    if input_api.basename(p) != 'histograms.xml':
      continue
    cwd = input_api.os_path.dirname(p)
    if cwd != input_api.PresubmitLocalPath():
      continue

    exit_code = input_api.subprocess.call(
        ['python', 'validate_format.py'], cwd=cwd)
    if exit_code != 0:
      return [output_api.PresubmitError(
          'histograms.xml is not well formatted; run %s/validate_format.py '
          'and fix the reported errors' % cwd)]
  return []


def CheckChangeOnUpload(input_api, output_api):
  return CheckChange(input_api, output_api)


def CheckChangeOnCommit(input_api, output_api):
  return CheckChange(input_api, output_api)
