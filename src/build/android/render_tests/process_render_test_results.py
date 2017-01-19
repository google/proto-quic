#!/usr/bin/env python
#
# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import argparse
import collections
import logging
import os
import posixpath
import re
import shutil
import sys
import tempfile
import zipfile

sys.path.append(os.path.join(os.path.dirname(__file__), os.pardir))
import devil_chromium
from devil.android import device_utils
from devil.utils import cmd_helper
from pylib.constants import host_paths

sys.path.append(os.path.join(host_paths.DIR_SOURCE_ROOT, 'build'))
import find_depot_tools  # pylint: disable=import-error

sys.path.append(os.path.join(host_paths.DIR_SOURCE_ROOT, 'third_party'))
import jinja2  # pylint: disable=import-error

try:
  from PIL import Image  # pylint: disable=import-error
  from PIL import ImageChops  # pylint: disable=import-error
  can_compute_diffs = True
except ImportError:
  can_compute_diffs = False
  logging.exception('Error importing PIL library. Image diffs will not be '
                    'displayed properly unless PIL module is installed.')

_RE_IMAGE_NAME = re.compile(
    r'(?P<test_class>\w+)\.'
    r'(?P<description>\w+)\.'
    r'(?P<device_model>\w+)\.'
    r'(?P<orientation>port|land)\.png')

_RENDER_TEST_BASE_URL = 'https://storage.googleapis.com/chromium-render-tests/'
_RENDER_TEST_BUCKET = 'gs://chromium-render-tests/'

_JINJA_TEMPLATE_DIR = os.path.dirname(os.path.abspath(__file__))
_JINJA_TEMPLATE_FILENAME = 'render_webpage.html.jinja2'


def _UploadFiles(upload_dir, files):
  """Upload files to the render tests GS bucket."""
  if files:
    google_storage_upload_dir = os.path.join(_RENDER_TEST_BUCKET, upload_dir)
    cmd = [os.path.join(find_depot_tools.DEPOT_TOOLS_PATH, 'gsutil.py'),
           '-m', 'cp']
    cmd.extend(files)
    cmd.append(google_storage_upload_dir)
    cmd_helper.RunCmd(cmd)


def _GoogleStorageUrl(upload_dir, filename):
  return os.path.join(
      _RENDER_TEST_BASE_URL, upload_dir, os.path.basename(filename))


def _ComputeImageDiff(failure_image, golden_image):
  """Compute mask showing which pixels are different between two images."""
  return (ImageChops.difference(failure_image, golden_image)
      .convert('L')
      .point(lambda i: 255 if i else 0))


def ProcessRenderTestResults(devices, render_results_dir,
                             upload_dir, html_file):
  """Grabs render results from device and generates webpage displaying results.

  Args:
    devices: List of DeviceUtils objects to grab results from.
    render_results_path: Path where render test results are storage.
        Will look for failures render test results on the device in
        /sdcard/chromium_tests_root/<render_results_path>/failures/
        and will look for golden images at Chromium src/<render_results_path>/.
    upload_dir: Directory to upload the render test results to.
    html_file: File to write the test results to.
  """
  results_dict = collections.defaultdict(lambda: collections.defaultdict(list))

  diff_upload_dir = os.path.join(upload_dir, 'diffs')
  failure_upload_dir = os.path.join(upload_dir, 'failures')
  golden_upload_dir = os.path.join(upload_dir, 'goldens')

  diff_images = []
  failure_images = []
  golden_images = []

  temp_dir = None
  try:
    temp_dir = tempfile.mkdtemp()

    for device in devices:
      failures_device_dir = posixpath.join(
          device.GetExternalStoragePath(),
          'chromium_tests_root', render_results_dir, 'failures')
      device.PullFile(failures_device_dir, temp_dir)

    for failure_filename in os.listdir(os.path.join(temp_dir, 'failures')):
      m = _RE_IMAGE_NAME.match(failure_filename)
      if not m:
        logging.warning(
            'Unexpected file in render test failures, %s', failure_filename)
        continue
      failure_file = os.path.join(temp_dir, 'failures', failure_filename)

      # Check to make sure we have golden image for this failure.
      golden_file = os.path.join(
          host_paths.DIR_SOURCE_ROOT, render_results_dir, failure_filename)
      if not os.path.exists(golden_file):
        logging.error('Cannot find golden image for %s', failure_filename)
        continue

      # Compute image diff between failure and golden.
      if can_compute_diffs:
        diff_image = _ComputeImageDiff(
            Image.open(failure_file), Image.open(golden_file))
        diff_filename = '_diff'.join(
            os.path.splitext(os.path.basename(failure_file)))
        diff_file = os.path.join(temp_dir, diff_filename)
        diff_image.save(diff_file)
        diff_images.append(diff_file)

      failure_images.append(failure_file)
      golden_images.append(golden_file)

      test_class = m.group('test_class')
      device_model = m.group('device_model')

      results_entry = {
          'description': m.group('description'),
          'orientation': m.group('orientation'),
          'failure_image': _GoogleStorageUrl(failure_upload_dir, failure_file),
          'golden_image': _GoogleStorageUrl(golden_upload_dir, golden_file),
      }
      if can_compute_diffs:
        results_entry.update(
            {'diff_image': _GoogleStorageUrl(diff_upload_dir, diff_file)})
      results_dict[test_class][device_model].append(results_entry)

    if can_compute_diffs:
      _UploadFiles(diff_upload_dir, diff_images)
    _UploadFiles(failure_upload_dir, failure_images)
    _UploadFiles(golden_upload_dir, golden_images)

    if failure_images:
      failures_zipfile = os.path.join(temp_dir, 'failures.zip')
      with zipfile.ZipFile(failures_zipfile, mode='w') as zf:
        for failure_file in failure_images:
          zf.write(failure_file, os.path.join(
              render_results_dir, os.path.basename(failure_file)))
        failure_zip_url = _GoogleStorageUrl(upload_dir, failures_zipfile)
      _UploadFiles(upload_dir, [failures_zipfile])
    else:
      failure_zip_url = None

    jinja2_env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(_JINJA_TEMPLATE_DIR),
        trim_blocks=True)
    template = jinja2_env.get_template(_JINJA_TEMPLATE_FILENAME)
    #  pylint: disable=no-member
    processed_template_output = template.render(
        full_results=dict(results_dict),
        failure_zip_url=failure_zip_url, show_diffs=can_compute_diffs)
    #  pylint: enable=no-member
    with open(html_file, 'wb') as f:
      f.write(processed_template_output)
  finally:
    if temp_dir:
      shutil.rmtree(temp_dir)


def main():
  parser = argparse.ArgumentParser()

  parser.add_argument('--render-results-dir',
                      required=True,
                      help='Path on device to look for render test images')
  parser.add_argument('--output-html-file',
                      required=True,
                      help='File to output the results webpage.')
  parser.add_argument('-d', '--device', dest='devices', action='append',
                      default=[],
                      help='Device to look for render test results on. '
                           'Default is to look on all connected devices.')
  parser.add_argument('--adb-path', type=os.path.abspath,
                      help='Absolute path to the adb binary to use.')
  parser.add_argument('--buildername', type=str, required=True,
                      help='Bot buildername. Used to generate path to upload '
                           'render test results')
  parser.add_argument('--build-number', type=str, required=True,
                      help='Bot build number. Used to generate path to upload '
                           'render test results')

  args = parser.parse_args()
  devil_chromium.Initialize(adb_path=args.adb_path)
  devices = device_utils.DeviceUtils.HealthyDevices(device_arg=args.devices)

  upload_dir = os.path.join(args.buildername, args.build_number)
  ProcessRenderTestResults(
      devices, args.render_results_dir, upload_dir, args.output_html_file)


if __name__ == '__main__':
  sys.exit(main())
