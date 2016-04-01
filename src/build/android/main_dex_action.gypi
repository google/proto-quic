# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# This file is meant to be included into an action to provide a rule that
# generates a list of classes that must be kept in the main dex file.
#
# To use this, create a gyp target with the following form:
#  {
#    'action_name': 'some name for the action'
#    'actions': [
#      'variables': {
#        'jar_paths': ['path to jar', ...],
#        'output_path': 'output path',
#      },
#      'includes': [ 'relative/path/to/main_dex_action.gypi' ],
#    ],
#  },
#

{
  'message': 'Generating main dex classes list for <(jar_path)',
  'variables': {
    'jar_paths%': [],
    'output_path%': '',
    'main_dex_list_script': '<(DEPTH)/build/android/gyp/main_dex_list.py',
    'main_dex_rules_path': '<(DEPTH)/build/android/main_dex_classes.flags',
  },
  'inputs': [
    '<@(jar_paths)',
    '<(main_dex_list_script)',
    '<(main_dex_rules_path)',
    '<(multidex_configuration_path)',
  ],
  'outputs': [
    '<(output_path)',
  ],
  'action': [
    'python', '<(main_dex_list_script)',
    '--main-dex-list-path', '<(output_path)',
    '--android-sdk-tools', '<(android_sdk_tools)',
    '--main-dex-rules-path', '<(main_dex_rules_path)',
    '--multidex-configuration-path', '<(multidex_configuration_path)',
    '<@(jar_paths)',
  ]
}
