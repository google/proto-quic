# Copyright 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Presubmit script for changes affecting tools/perf/.

See http://dev.chromium.org/developers/how-tos/depottools/presubmit-scripts
for more details about the presubmit API built into depot_tools.
"""

import os
import re
import sys


def _CommonChecks(input_api, output_api):
  """Performs common checks, which includes running pylint."""
  results = []

  results.extend(_CheckWprShaFiles(input_api, output_api))
  results.extend(_CheckJson(input_api, output_api))
  results.extend(input_api.RunTests(input_api.canned_checks.GetPylint(
      input_api, output_api, extra_paths_list=_GetPathsToPrepend(input_api),
      pylintrc='pylintrc')))
  return results


def _GetPathsToPrepend(input_api):
  perf_dir = input_api.PresubmitLocalPath()
  chromium_src_dir = input_api.os_path.join(perf_dir, '..', '..')
  telemetry_dir = input_api.os_path.join(
      chromium_src_dir, 'third_party', 'catapult', 'telemetry')
  experimental_dir = input_api.os_path.join(
      chromium_src_dir, 'third_party', 'catapult', 'experimental')
  return [
      telemetry_dir,
      input_api.os_path.join(telemetry_dir, 'third_party', 'mock'),
      experimental_dir,
  ]


def _CheckWprShaFiles(input_api, output_api):
  """Check whether the wpr sha files have matching URLs."""
  old_sys_path = sys.path
  try:
    perf_dir = input_api.PresubmitLocalPath()
    py_utils_path = os.path.abspath(os.path.join(
        perf_dir, '..', '..', 'third_party', 'catapult', 'common', 'py_utils'))
    sys.path.insert(1, py_utils_path)
    from py_utils import cloud_storage  # pylint: disable=import-error
  finally:
    sys.path = old_sys_path

  results = []
  for affected_file in input_api.AffectedFiles(include_deletes=False):
    filename = affected_file.AbsoluteLocalPath()
    if not filename.endswith('wpr.sha1'):
      continue
    expected_hash = cloud_storage.ReadHash(filename)
    is_wpr_file_uploaded = any(
        cloud_storage.Exists(bucket, expected_hash)
        for bucket in cloud_storage.BUCKET_ALIASES.itervalues())
    if not is_wpr_file_uploaded:
      wpr_filename = filename[:-5]
      results.append(output_api.PresubmitError(
          'The file matching %s is not in Cloud Storage yet.\n'
          'You can upload your new WPR archive file with the command:\n'
          'depot_tools/upload_to_google_storage.py --bucket '
          '<Your pageset\'s bucket> %s.\nFor more info: see '
          'http://www.chromium.org/developers/telemetry/'
          'record_a_page_set#TOC-Upload-the-recording-to-Cloud-Storage' %
          (filename, wpr_filename)))
  return results


def _CheckJson(input_api, output_api):
  """Checks whether JSON files in this change can be parsed."""
  for affected_file in input_api.AffectedFiles(include_deletes=False):
    filename = affected_file.AbsoluteLocalPath()
    if os.path.splitext(filename)[1] != '.json':
      continue
    try:
      input_api.json.load(open(filename))
    except ValueError:
      return [output_api.PresubmitError('Error parsing JSON in %s!' % filename)]
  return []


def CheckChangeOnUpload(input_api, output_api):
  report = []
  report.extend(_CommonChecks(input_api, output_api))
  return report


def CheckChangeOnCommit(input_api, output_api):
  report = []
  report.extend(_CommonChecks(input_api, output_api))
  return report


def _AreBenchmarksModified(change):
  """Checks whether CL contains any modification to Telemetry benchmarks."""
  for affected_file in change.AffectedFiles():
    file_path = affected_file.LocalPath()
    # Changes to unittest files should not count.
    if file_path.endswith('test.py'):
        continue
    if (os.path.join('tools', 'perf', 'benchmarks') in file_path or
        os.path.join('tools', 'perf', 'measurements') in file_path):
      return True
  return False


def PostUploadHook(cl, change, output_api):
  """git cl upload will call this hook after the issue is created/modified.

  This hook adds extra try bots list to the CL description in order to run
  Telemetry benchmarks on Perf trybots in addition to CQ trybots if the CL
  contains any changes to Telemetry benchmarks.
  """
  benchmarks_modified = _AreBenchmarksModified(change)
  rietveld_obj = cl.RpcServer()
  issue = cl.issue
  original_description = rietveld_obj.get_description(issue)
  if not benchmarks_modified or re.search(
      r'^CQ_INCLUDE_TRYBOTS=.*', original_description, re.M | re.I):
    return []

  results = []
  bots = [
    'linux_perf_cq',
    'mac_retina_perf_cq',
    'winx64_10_perf_cq'
  ]
  bots = ['master.tryserver.chromium.perf:%s' % s for s in bots]
  bots_string = ';'.join(bots)
  description = original_description
  description += '\nCQ_INCLUDE_TRYBOTS=%s' % bots_string
  results.append(output_api.PresubmitNotifyResult(
      'Automatically added Perf trybots to run Telemetry benchmarks on CQ.'))

  if description != original_description:
    rietveld_obj.update_description(issue, description)

  return results
