#!/usr/bin/env python
#
# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Generates the obfuscated jar and test jar for an apk.

If proguard is not enabled or 'Release' is not in the configuration name,
obfuscation will be a no-op.
"""

import json
import optparse
import os
import sys
import tempfile

from util import build_utils
from util import proguard_util


_PROGUARD_KEEP_CLASS = '''-keep class %s {
  *;
}
'''


def ParseArgs(argv):
  parser = optparse.OptionParser()
  parser.add_option('--android-sdk', help='path to the Android SDK folder')
  parser.add_option('--android-sdk-tools',
                    help='path to the Android SDK build tools folder')
  parser.add_option('--android-sdk-jar',
                    help='path to Android SDK\'s android.jar')
  parser.add_option('--proguard-jar-path',
                    help='Path to proguard.jar in the sdk')
  parser.add_option('--input-jars-paths',
                    help='Path to jars to include in obfuscated jar')

  parser.add_option('--proguard-configs',
                    help='Paths to proguard config files')

  parser.add_option('--configuration-name',
                    help='Gyp configuration name (i.e. Debug, Release)')

  parser.add_option('--debug-build-proguard-enabled', action='store_true',
                    help='--proguard-enabled takes effect on release '
                         'build, this flag enable the proguard on debug '
                         'build.')
  parser.add_option('--proguard-enabled', action='store_true',
                    help='Set if proguard is enabled for this target.')

  parser.add_option('--obfuscated-jar-path',
                    help='Output path for obfuscated jar.')

  parser.add_option('--testapp', action='store_true',
                    help='Set this if building an instrumentation test apk')
  parser.add_option('--tested-apk-obfuscated-jar-path',
                    help='Path to obfusctated jar of the tested apk')
  parser.add_option('--test-jar-path',
                    help='Output path for jar containing all the test apk\'s '
                    'code.')

  parser.add_option('--stamp', help='File to touch on success')

  parser.add_option('--main-dex-list-path',
                    help='The list of classes to retain in the main dex. '
                         'These will not be obfuscated.')
  parser.add_option('--multidex-configuration-path',
                    help='A JSON file containing multidex build configuration.')
  parser.add_option('--verbose', '-v', action='store_true',
                    help='Print all proguard output')

  (options, args) = parser.parse_args(argv)

  if args:
    parser.error('No positional arguments should be given. ' + str(args))

  # Check that required options have been provided.
  required_options = (
      'android_sdk',
      'android_sdk_tools',
      'android_sdk_jar',
      'proguard_jar_path',
      'input_jars_paths',
      'configuration_name',
      'obfuscated_jar_path',
      )

  if options.testapp:
    required_options += (
        'test_jar_path',
        )

  build_utils.CheckOptions(options, parser, required=required_options)
  return options, args


def DoProguard(options):
  proguard = proguard_util.ProguardCmdBuilder(options.proguard_jar_path)
  proguard.outjar(options.obfuscated_jar_path)

  input_jars = build_utils.ParseGnList(options.input_jars_paths)

  exclude_paths = []
  configs = build_utils.ParseGnList(options.proguard_configs)
  if options.tested_apk_obfuscated_jar_path:
    # configs should only contain the process_resources.py generated config.
    assert len(configs) == 1, (
        'test apks should not have custom proguard configs: ' + str(configs))
    proguard.tested_apk_info(options.tested_apk_obfuscated_jar_path + '.info')

  proguard.libraryjars([options.android_sdk_jar])
  proguard_injars = [p for p in input_jars if p not in exclude_paths]
  proguard.injars(proguard_injars)

  multidex_config = _PossibleMultidexConfig(options)
  if multidex_config:
    configs.append(multidex_config)

  proguard.configs(configs)
  proguard.verbose(options.verbose)
  proguard.CheckOutput()


def _PossibleMultidexConfig(options):
  if not options.multidex_configuration_path:
    return None

  with open(options.multidex_configuration_path) as multidex_config_file:
    multidex_config = json.loads(multidex_config_file.read())

  if not (multidex_config.get('enabled') and options.main_dex_list_path):
    return None

  main_dex_list_config = ''
  with open(options.main_dex_list_path) as main_dex_list:
    for clazz in (l.strip() for l in main_dex_list):
      if clazz.endswith('.class'):
        clazz = clazz[:-len('.class')]
      clazz = clazz.replace('/', '.')
      main_dex_list_config += (_PROGUARD_KEEP_CLASS % clazz)
  with tempfile.NamedTemporaryFile(
      delete=False,
      dir=os.path.dirname(options.main_dex_list_path),
      prefix='main_dex_list_proguard',
      suffix='.flags') as main_dex_config_file:
    main_dex_config_file.write(main_dex_list_config)
  return main_dex_config_file.name


def main(argv):
  options, _ = ParseArgs(argv)

  input_jars = build_utils.ParseGnList(options.input_jars_paths)

  if options.testapp:
    dependency_class_filters = [
        '*R.class', '*R$*.class', '*Manifest.class', '*BuildConfig.class']
    build_utils.MergeZips(
        options.test_jar_path, input_jars, dependency_class_filters)

  if ((options.configuration_name == 'Release' and options.proguard_enabled) or
     (options.configuration_name == 'Debug' and
      options.debug_build_proguard_enabled)):
    DoProguard(options)
  else:
    output_files = [
        options.obfuscated_jar_path,
        options.obfuscated_jar_path + '.info',
        options.obfuscated_jar_path + '.dump',
        options.obfuscated_jar_path + '.seeds',
        options.obfuscated_jar_path + '.usage',
        options.obfuscated_jar_path + '.mapping']
    for f in output_files:
      if os.path.exists(f):
        os.remove(f)
      build_utils.Touch(f)

  if options.stamp:
    build_utils.Touch(options.stamp)

if __name__ == '__main__':
  sys.exit(main(sys.argv[1:]))
