#!/usr/bin/env python
# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.


import argparse
import json
import os
import sys

from util import build_utils


_GCC_PREPROCESS_PATH = os.path.join(
    os.path.dirname(__file__), 'gcc_preprocess.py')


def ParseArgs():
  parser = argparse.ArgumentParser()
  parser.add_argument('--configuration-name', required=True,
                      help='The build CONFIGURATION_NAME.')
  parser.add_argument('--enable-multidex', action='store_true', default=False,
                      help='If passed, multidex may be enabled.')
  parser.add_argument('--enabled-configurations', default=[],
                      help='The configuration(s) for which multidex should be '
                           'enabled. If not specified and --enable-multidex is '
                           'passed, multidex will be enabled for all '
                           'configurations.')
  parser.add_argument('--multidex-configuration-path', required=True,
                      help='The path to which the multidex configuration JSON '
                           'should be saved.')
  parser.add_argument('--multidex-config-java-file', required=True)
  parser.add_argument('--multidex-config-java-stamp', required=True)
  parser.add_argument('--multidex-config-java-template', required=True)

  args = parser.parse_args()

  if args.enabled_configurations:
    args.enabled_configurations = build_utils.ParseGnList(
        args.enabled_configurations)

  return args


def _WriteConfigJson(multidex_enabled, multidex_configuration_path):
  config = {
    'enabled': multidex_enabled,
  }

  with open(multidex_configuration_path, 'w') as f:
    f.write(json.dumps(config))


def _GenerateMultidexConfigJava(multidex_enabled, args):
  gcc_preprocess_cmd = [
    sys.executable, _GCC_PREPROCESS_PATH,
    '--include-path=',
    '--template', args.multidex_config_java_template,
    '--stamp', args.multidex_config_java_stamp,
    '--output', args.multidex_config_java_file,
  ]
  if multidex_enabled:
    gcc_preprocess_cmd += [
      '--defines', 'ENABLE_MULTIDEX',
    ]

  build_utils.CheckOutput(gcc_preprocess_cmd)


def main():
  args = ParseArgs()

  multidex_enabled = (
      args.enable_multidex
      and (not args.enabled_configurations
           or args.configuration_name in args.enabled_configurations))

  _WriteConfigJson(multidex_enabled, args.multidex_configuration_path)
  _GenerateMultidexConfigJava(multidex_enabled, args)

  return 0


if __name__ == '__main__':
  sys.exit(main())

