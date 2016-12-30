#!/usr/bin/env python
#
# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Processes an Android AAR file."""

import argparse
import os
import posixpath
import re
import shutil
import sys
from xml.etree import ElementTree
import zipfile

from util import build_utils

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__),
                                             os.pardir, os.pardir)))
import gn_helpers


def _IsManifestEmpty(manifest_str):
  """Returns whether the given manifest has merge-worthy elements.

  E.g.: <activity>, <service>, etc.
  """
  doc = ElementTree.fromstring(manifest_str)
  for node in doc:
    if node.tag == 'application':
      if len(node):
        return False
    elif node.tag != 'uses-sdk':
      return False

  return True


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument('--input-file',
                      help='Path to the AAR file.',
                      required=True,
                      metavar='FILE')
  parser.add_argument('--extract',
                      help='Extract the files to output directory.',
                      action='store_true')
  parser.add_argument('--list',
                      help='List all the resource and jar files.',
                      action='store_true')
  parser.add_argument('--output-dir',
                      help='Output directory for the extracted files. Must '
                      'be set if --extract is set.',
                      metavar='DIR')

  args = parser.parse_args()
  if not args.extract and not args.list:
    parser.error('Either --extract or --list has to be specified.')

  aar_file = args.input_file
  output_dir = args.output_dir

  if args.extract:
    # Clear previously extracted versions of the AAR.
    shutil.rmtree(output_dir, True)
    build_utils.ExtractAll(aar_file, path=output_dir)

  if args.list:
    data = {}
    data['aidl'] = []
    data['assets'] = []
    data['resources'] = []
    data['subjars'] = []
    data['subjar_tuples'] = []
    data['has_classes_jar'] = False
    data['has_proguard_flags'] = False
    data['has_native_libraries'] = False
    data['has_r_text_file'] = False
    with zipfile.ZipFile(aar_file) as z:
      data['is_manifest_empty'] = (
          _IsManifestEmpty(z.read('AndroidManifest.xml')))

      for name in z.namelist():
        if name.endswith('/'):
          continue
        if name.startswith('aidl/'):
          data['aidl'].append(name)
        elif name.startswith('res/'):
          data['resources'].append(name)
        elif name.startswith('libs/') and name.endswith('.jar'):
          label = posixpath.basename(name)[:-4]
          label = re.sub(r'[^a-zA-Z0-9._]', '_', label)
          data['subjars'].append(name)
          data['subjar_tuples'].append([label, name])
        elif name.startswith('assets/'):
          data['assets'].append(name)
        elif name.startswith('jni/'):
          data['has_native_libraries'] = True
        elif name == 'classes.jar':
          data['has_classes_jar'] = True
        elif name == 'proguard.txt':
          data['has_proguard_flags'] = True
        elif name == 'R.txt':
          # Some AARs, e.g. gvr_controller_java, have empty R.txt. Such AARs
          # have no resources as well. We treat empty R.txt as having no R.txt.
          data['has_r_text_file'] = (z.read('R.txt').strip() != '')

    print gn_helpers.ToGNString(data)


if __name__ == '__main__':
  sys.exit(main())
