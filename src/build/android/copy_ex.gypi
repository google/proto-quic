# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Copy files to a directory with the option to clear directory first.
#
# Variables:
#   dest_path - directory to copy files to.
#   src_files - optional, a list of files to copy without changing name.
#   clear - optional, if set, clear directory before copying files.
#   renaming_sources - optional, a list of files to copy and rename.
#   renaming_destinations - optional, a list of new file names corresponding to
#                           renaming_sources.
#
# Exmaple
#  {
#    'target_name': 'copy_assets',
#    'type': 'none',
#    'variables': {
#      'dest_path': 'apk/assets/path',
#      'src_files': ['path1/fr.pak'],
#      'clear': 1,
#      # path2/old1 and path3/old2 will be copied to apk/assets/path and
#      # renamed to new1, new2 respectly.
#      'renaming_sources': ['path2/old1', 'path3/old2'],
#      'renaming_destinations': ['new1', 'new2'],
#    },
#    'includes': [ '../build/android/copy_ex.gypi' ],
#  },
#
{
  'variables': {
    'clear%': 0,
    'src_files%': [],
    'renaming_sources%': [],
    'renaming_destinations%': [],
  },
  'actions': [{
    'action_name': '<(_target_name)_copy_ex',
    'variables': {
      'additional_args':[],
      'local_inputs': [],
      'dest_files': [],
      'conditions': [
        ['clear == 1', {
          'additional_args': ['--clear'],
        }],
        ['src_files != []', {
          'additional_args': ['--files', '<(src_files)'],
          'local_inputs': ['<@(src_files)'],
          # src_files will be used to generate destination files path for
          # outputs.
          'dest_files': ['<@(src_files)'],
        }],
        ['renaming_sources != []', {
          'additional_args': [
            '--renaming-sources', '<(renaming_sources)',
            '--renaming-destinations', '<(renaming_destinations)'
          ],
          'local_inputs': ['<@(renaming_sources)'],
          'dest_files': ['<@(renaming_destinations)'],
        }],
      ],
    },
    'inputs': [
      '<(DEPTH)/build/android/gyp/copy_ex.py',
      '<(DEPTH)/build/android/gyp/generate_copy_ex_outputs.py',
      '<@(local_inputs)',
    ],
    'outputs': [
      '<!@pymod_do_main(generate_copy_ex_outputs --dest-path <(dest_path) --src-files <(dest_files))',
    ],
    'action': [
      'python', '<(DEPTH)/build/android/gyp/copy_ex.py',
      '--dest', '<(dest_path)',
      '<@(additional_args)',
    ],
  }],
}
