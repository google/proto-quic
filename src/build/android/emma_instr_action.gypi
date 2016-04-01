# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# This file is meant to be included into an action to provide a rule that
# instruments either java class files, or jars.

{
  'variables': {
    'input_path%': '',
    'output_path%': '',
    'stamp_path%': '',
    'extra_instr_args': [
      '--coverage-file=<(coverage_file)',
      '--sources-list-file=<(sources_list_file)',
    ],
    'emma_jar': '<(android_sdk_root)/tools/lib/emma.jar',
    'conditions': [
      ['emma_instrument != 0', {
        'extra_instr_args': [
          '--source-dirs=<(java_in_dir)/src >(additional_src_dirs) >(generated_src_dirs)',
          '--src-root=<(DEPTH)',
          '--emma-jar=<(emma_jar)',
          '--filter-string=<(emma_filter)',
        ],
        'instr_action': 'instrument_jar',
      }, {
        'instr_action': 'copy',
        'extra_instr_args': [],
      }]
    ]
  },
  'inputs': [
    '<(DEPTH)/build/android/gyp/emma_instr.py',
    '<(DEPTH)/build/android/gyp/util/build_utils.py',
    '<(DEPTH)/build/android/pylib/utils/command_option_parser.py',
  ],
  'action': [
    'python', '<(DEPTH)/build/android/gyp/emma_instr.py',
    '<(instr_action)',
    '--input-path=<(input_path)',
    '--output-path=<(output_path)',
    '--stamp=<(stamp_path)',
    '<@(extra_instr_args)',
  ]
}
