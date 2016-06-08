# Copyright (c) 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Usage:
# {
#   'target_name': 'your_target_name',
#   'type': 'none',
#   'actions': [
#     {
#       'variables': {
#         'input_file': 'file/to/compress',
#         'output_file': 'file/to/put/compressed',
#       },
#       'includes': ['../third_party/brotli/bro.gypi'],
#     }
#   ],
#   'dependencies': [
#     'path/to:builds_file_to_compress'
#   ],
# },

{
  'action_name': 'genbro',
  'variables': {
    'bro': '<(PRODUCT_DIR)/<(EXECUTABLE_PREFIX)bro<(EXECUTABLE_SUFFIX)',
  },
  'inputs': [
    '<(bro)',
    '<(input_file)',
  ],
  'outputs': [
    '<(output_file)',
  ],
  'action': [
    '<(bro)',
    '--force',
    '--input',
    '<(input_file)',
    '--output',
    '<(output_file)',
  ],
  'dependencies': [
    '<(DEPTH)/third_party/brotli/brotli.gyp:bro#host',
  ],
}
