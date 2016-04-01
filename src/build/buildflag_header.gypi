# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Generates a header with preprocessor defines specified by the build file.
#
# The canonical documentation is in build/buildflag_header.gni. You should
# write the GN build, get it working, and then transform it into GYP.
#
# In every target that uses your generated header you must include a dependency
# on the GYP target that generates the header (this is implicit in GN).
# Otherwise, clean builds may not necessarily create the header before the
# source code is compiled.
#
# Assuming your GN code looks like this:
#
#   buildflag_header("foo_features") {
#     header = "foo_features.h"
#     flags = [
#       "ENABLE_DOOM_MELON=$enable_doom_melon",
#       "ENABLE_SPACE_LASER=true",
#       "SPAM_SERVER_URL=\"http://www.example.com/\"",
#     ]
#   }
#
# Write a GYP target like this:
#
#  {
#    # GN version: //foo:foo_features
#    'target_name': 'foo_foo_features',
#    'includes': [ '../build/buildflag_header.gypi' ],
#    'variables': {
#       'buildflag_header_path': 'foo/foo_features.h',
#       'buildflag_flags': [
#         'ENABLE_DOOM_MELON=<(enable_doom_melon)',
#         'ENABLE_SPACE_LASER=true',
#         'SPAM_SERVER_URL="http://www.example.com/"',
#       ],
#     },
#   }
#
# Variables
#
#   target_name
#       Base this on the GN label, replacing / and : with _ to make it globally
#       unique.
#
#   buildflag_header_path
#       This must be the full path to the header from the source root. In GN
#       you only say "features.h" and it uses the BUILD file's path implicitly.
#       Use the path to BUILD.gn followed by your header name to produce the
#       same output file.
#
#   buildflag_flags (optional)
#       List of the same format as GN's "flags". To expand variables, use
#       "<(foo)" where GN would have used "$foo".
#
#   includes
#       List the relative path to build/buildflag_header.gypi from the .gyp
#       file including this code, Note: If your code is in a .gypi file in a
#       different directory, this must be relative to the .gyp including your
#       file.
#
#
# Grit defines
#
# Follow the same advice as in the buildflag_header.gni, except on the grit
# action use the variable name 'grit_additional_defines' and explicitly add a
# '-D' in front:
#
#   'grit_grd_file': 'foo.grd',
#   'grit_additional_defines': [
#     '-D', 'enable_doom_melon=<(enable_doom_melon)',
#    ],
#
# Put shared lists of defines in a .gypi.

{
  'type': 'none',
  'hard_dependency': 1,

  'actions': [
    {
      'action_name': 'buildflag_header',
      'variables': {
        # Default these values to empty if they're not defined.
        'variables': {
          'buildflag_flags%': [],
        },

        # Writes the flags to a response file with a name based on the name of
        # this target.
        'response_file_name': '<|(<(_target_name)_buildflag_header.rsp --flags <@(buildflag_flags))',

        'build_header_script': '<(DEPTH)/build/write_buildflag_header.py',
      },

      'message': 'Generating build header.',

      'inputs': [
        '<(build_header_script)',
        '<(response_file_name)',
      ],

      'outputs': [
        '<(SHARED_INTERMEDIATE_DIR)/<(buildflag_header_path)',
      ],

      'action': [
        'python', '<(build_header_script)',
        '--output', '<(buildflag_header_path)',
        '--rulename', '<(_target_name)',
        '--gen-dir', '<(SHARED_INTERMEDIATE_DIR)',
        '--definitions', '<(response_file_name)',
      ],
    }
  ],

  # Allow the file to be included based on the given buildflag_header_path.
  'direct_dependent_settings': {
    'include_dirs': [ '<(SHARED_INTERMEDIATE_DIR)' ],
  },
}
