# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# This file provides an action to generate Java source files from the Google
# API keys using a Python script.

{
  'targets': [
    {
      'target_name': 'google_api_keys_java',
      'type': 'none',
      'variables': {
        # Location where all generated Java sources will be placed.
        'output_dir': '<(SHARED_INTERMEDIATE_DIR)/java_google_api_keys',
        'generator_path': '<(DEPTH)/build/android/gyp/java_google_api_keys.py',
        'output_file': '<(output_dir)/GoogleAPIKeys.java',
      },
      'direct_dependent_settings': {
        'variables': {
          # Ensure that the output directory is used in the class path
          # when building targets that depend on this one.
          'generated_src_dirs': [
            '<(output_dir)/',
          ],
        },
      },
      'actions': [
        {
          'action_name': 'generate_java_google_api_keys',
          'inputs': [
            '<(generator_path)',
          ],
          'outputs': [
            '<(output_file)',
          ],
          'action': [
            'python', '<(generator_path)', '--out', '<(output_file)'
          ],
          'message': 'Generating Java from Google API Keys header',
        },
      ],
    },
  ],
}
