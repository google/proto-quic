#!/usr/bin/env python
# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import argparse
import collections
import json
import logging
import os
import sys
import zipfile

_BASE_CHART = {
    'format_version': '0.1',
    'benchmark_name': 'apk_size',
    'benchmark_description': 'APK size information.',
    'trace_rerun_options': [],
    'charts': {}
}


# TODO(rnephew): Add support for split apks.
class ApkSizeInfo(object):

  def __init__(self, path):
    """ApkSizeInfo constructor.

    Args:
      path: Path to apk.
    """
    if not os.path.isfile(path):
      raise IOError('Not a valid file path for apk.')
    if not os.access(path, os.R_OK):
      raise IOError('File is not readable.')
    if not zipfile.is_zipfile(path):
      raise TypeError('Not a valid apk')
    logging.info('APK: %s', path)
    self._apk_size = os.path.getsize(path)
    self._zipfile = zipfile.ZipFile(path, 'r')
    self._processed_files = None
    self._compressed_size = 0
    self._total_files = 0
    self._uncompressed_size = 0
    self._ProcessFiles()

  def _ProcessFiles(self):
    """Uses zipinfo to process apk file information."""
    INITIAL_FILE_EXTENSION_INFO = {
        'number': 0,
        'compressed_bytes': 0,
        'uncompressed_bytes': 0
    }
    self._processed_files = collections.defaultdict(
        lambda: dict(INITIAL_FILE_EXTENSION_INFO))

    for f in self._zipfile.infolist():
      _, file_ext = os.path.splitext(f.filename)
      file_ext = file_ext[1:] # Drop . from extension.

      self._compressed_size += f.compress_size
      self._total_files += 1
      self._uncompressed_size += f.file_size
      self._processed_files[file_ext]['number'] += 1
      self._processed_files[file_ext]['compressed_bytes'] += f.compress_size
      self._processed_files[file_ext]['uncompressed_bytes'] += f.file_size
    return self._processed_files

  def Compare(self, other_apk):
    """Compares size information of two apks.

    Args:
      other_apk: ApkSizeInfo instance to compare size against.

    Returns:
      Dictionary of comparision results.
    """
    if not isinstance(other_apk, type(self)):
      raise TypeError('Must pass it an ApkSizeInfo object')

    other_lib_compressed = other_apk.processed_files['so']['compressed_bytes']
    other_lib_uncompressed = (
        other_apk.processed_files['so']['uncompressed_bytes'])
    this_lib_compressed = self._processed_files['so']['compressed_bytes']
    this_lib_uncompressed = self._processed_files['so']['uncompressed_bytes']

    # TODO(rnephew) This will be made obsolete with modern and legacy apks being
    # separate, a new method to compare will be required eventually.
    return collections.OrderedDict([
        ('APK_size_reduction',
            other_apk.compressed_size - self.compressed_size),
        ('ARM32_Legacy_install_or_upgrade_reduction',
            (other_lib_compressed - this_lib_compressed) +
            (other_lib_uncompressed - this_lib_uncompressed)),
        ('ARM32_Legacy_system_image_reduction',
            other_lib_compressed - this_lib_compressed),
        ('ARM32_Modern_ARM64_install_or_upgrade_reduction',
            other_lib_uncompressed - this_lib_uncompressed),
        ('ARM32_Modern_ARM64_system_image_reduction',
            other_lib_uncompressed - this_lib_uncompressed),
    ])

  @property
  def apk_size(self):
    return self._apk_size

  @property
  def compressed_size(self):
    return self._compressed_size

  @property
  def total_files(self):
    return self._total_files

  @property
  def uncompressed_size(self):
    return self._uncompressed_size

  @property
  def processed_files(self):
    return self._processed_files

def add_value(chart_data, graph_title, trace_title, value, units,
              improvement_direction='down', important=True):
  chart_data['charts'].setdefault(graph_title, {})
  chart_data['charts'][graph_title][trace_title] = {
      'type': 'scalar',
      'value': value,
      'units': units,
      'imporvement_direction': improvement_direction,
      'important': important
  }

def chartjson_size_info(apk, output_dir):
  """Sends size information to perf dashboard.

  Args:
    apk: ApkSizeInfo object
  """
  data = _BASE_CHART.copy()
  files = apk.processed_files
  add_value(data, 'files', 'total', apk.total_files, 'count')
  add_value(data, 'size', 'total_size_compressed', apk.compressed_size, 'bytes')
  add_value(data, 'size', 'total_size_uncompressed', apk.uncompressed_size,
            'bytes')
  add_value(data, 'size', 'apk_overhead', apk.apk_size - apk.compressed_size,
           'bytes')
  for ext in files:
    add_value(data, 'files', ext, files[ext]['number'], 'count')
    add_value(data, 'size_compressed', ext, files[ext]['compressed_bytes'],
              'bytes')
    add_value(data, 'size_uncompressed', ext, files[ext]['uncompressed_bytes'],
              'bytes')

  logging.info('Outputing data to json file %s', output_dir)
  with open(os.path.join(output_dir, 'results-chart.json'), 'w') as json_file:
    json.dump(data, json_file)

def print_human_readable_size_info(apk):
  """Prints size information in human readable format.

  Args:
    apk: ApkSizeInfo object
  """
  files = apk.processed_files
  logging.critical('Stats for files as they exist within the apk:')
  for ext in files:
    logging.critical('  %-8s %s bytes in %s files', ext,
                     files[ext]['compressed_bytes'], files[ext]['number'])
  logging.critical('--------------------------------------')
  logging.critical(
      'All Files: %s bytes in %s files', apk.compressed_size, apk.total_files)
  logging.critical('APK Size: %s', apk.apk_size)
  logging.critical('APK overhead: %s', apk.apk_size - apk.compressed_size)
  logging.critical('--------------------------------------')
  logging.critical('Stats for files when extracted from the apk:')
  for ext in files:
    logging.critical('  %-8s %s bytes in %s files', ext,
                     files[ext]['uncompressed_bytes'], files[ext]['number'])
  logging.critical('--------------------------------------')
  logging.critical(
      'All Files: %s bytes in %s files', apk.uncompressed_size, apk.total_files)

def chartjson_compare(compare_dict, output_dir):
  """Sends size comparison between two apks to perf dashboard.

  Args:
    compare_dict: Dictionary returned from APkSizeInfo.Compare()
  """
  data = _BASE_CHART.copy()
  for key, value in compare_dict.iteritems():
    add_value(data, 'compare', key, value, 'bytes')

  logging.info('Outputing data to json file %s', output_dir)
  with open(os.path.join(output_dir, 'results-chart.json'), 'w') as json_file:
    json.dump(data, json_file)

def print_human_readable_compare(compare_dict):
  """Prints size comparison between two apks in human readable format.

  Args:
    compare_dict: Dictionary returned from ApkSizeInfo.Compare()
  """
  for key, value in compare_dict.iteritems():
    logging.critical('  %-50s %s bytes', key, value)

def main():
  parser = argparse.ArgumentParser()
  parser.add_argument('file_path')
  parser.add_argument('-c', '--compare', help='APK to compare against.')
  parser.add_argument('-o', '--output-dir',
                      help='Sets it to return data in bot readable format')
  parser.add_argument('-d', '--device', help='Dummy option for perf runner.')
  args = parser.parse_args()

  apk = ApkSizeInfo(args.file_path)
  if args.compare:
    compare_dict = apk.Compare(ApkSizeInfo(args.compare))
    print_human_readable_compare(compare_dict)
    if args.output_dir:
      chartjson_compare(compare_dict, args.output_dir)
  else:
    print_human_readable_size_info(apk)
    if args.output_dir:
       chartjson_size_info(apk, args.output_dir)

if __name__ == '__main__':
  sys.exit(main())
