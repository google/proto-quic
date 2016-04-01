# Copyright (c) 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

{
  'variables': {
    'chromium_code': 1,
  },
  'targets': [
    {
      'target_name': 'sdch',
      'type': 'static_library',
      'dependencies': [
        '../base/base.gyp:base',
        '../third_party/zlib/zlib.gyp:zlib',
      ],
      'sources': [
        'logging_forward.h',
        'open-vcdiff/src/addrcache.cc',
        'open-vcdiff/src/blockhash.cc',
        'open-vcdiff/src/blockhash.h',
        'open-vcdiff/src/checksum.h',
        'open-vcdiff/src/codetable.cc',
        'open-vcdiff/src/codetable.h',
        'open-vcdiff/src/compile_assert.h',
        'open-vcdiff/src/decodetable.cc',
        'open-vcdiff/src/decodetable.h',
        'open-vcdiff/src/encodetable.cc',
        'open-vcdiff/src/encodetable.h',
        'open-vcdiff/src/google/output_string.h',
        'open-vcdiff/src/google/vcdecoder.h',
        'open-vcdiff/src/google/vcencoder.h',
        'open-vcdiff/src/headerparser.cc',
        'open-vcdiff/src/headerparser.h',
        'open-vcdiff/src/instruction_map.cc',
        'open-vcdiff/src/instruction_map.h',
        'open-vcdiff/src/jsonwriter.h',
        'open-vcdiff/src/jsonwriter.cc',
        'open-vcdiff/src/rolling_hash.h',
        'open-vcdiff/src/testing.h',
        'open-vcdiff/src/varint_bigendian.cc',
        'open-vcdiff/src/varint_bigendian.h',
        'open-vcdiff/src/vcdecoder.cc',
        'open-vcdiff/src/vcencoder.cc',
        'open-vcdiff/src/vcdiff_defs.h',
        'open-vcdiff/src/vcdiffengine.cc',
        'open-vcdiff/src/vcdiffengine.h',
        'open-vcdiff/vsprojects/config.h',
        'open-vcdiff/vsprojects/stdint.h',
      ],
      'include_dirs': [
        'open-vcdiff/src',
      ],
      'direct_dependent_settings': {
        'include_dirs': [
          'open-vcdiff/src',
        ],
      },
      'conditions': [
        [ 'OS == "linux" or OS == "android"', { 'include_dirs': [ 'linux' ] } ],
        [ 'os_bsd==1 or OS=="solaris"', { 'include_dirs': [ 'bsd' ] } ],
        [ 'OS == "ios"', { 'include_dirs': [ 'ios' ] } ],
        [ 'OS == "mac"', {
          'include_dirs': [ 'mac' ],
          'defines': [ 'OPEN_VCDIFF_USE_AUTO_PTR' ],
        }],
        [ 'OS == "win"', { 'include_dirs': [ 'win' ] } ],
      ],
      # open-vcdiff's logging.h introduces static initializers. This was
      # reported upstream years ago (
      # https://github.com/google/open-vcdiff/issues/33 ). Since
      # upstream won't fix this, work around it on the chromium side:
      # Inject a header that forwards to base/logging.h instead (which doesn't
      # introduce static initializers, and which prevents open-vcdiff's
      # logging.h from being used).
      'variables': {
        'logging_path': 'logging_forward.h',
        'conditions': [
          # gyp leaves unspecified what the cwd is when running the compiler,
          # and gyp/linux doesn't have a built-in way for forcing an include.
          # So hardcode the base directory. If this spreads, provide native
          # support in gyp, like we have for gyp/mac and gyp/windows.
          # path.
          ['"<(GENERATOR)"=="ninja"', { 'logging_dir': '../..' },
                                      { 'logging_dir': '.' }
          ],
        ],
      },
      # GCC_PREFIX_HEADER is relative to the current directory,
      # ForcedIncludeFiles is relative to include_dirs, cflags relative to the
      # build directory.
      'xcode_settings': { 'GCC_PREFIX_HEADER': '<(logging_path)' },
      'msvs_settings': {
        'VCCLCompilerTool': {
          'ForcedIncludeFiles': [
            'sdch/<(logging_path)',
          ]
        }
      },
      'cflags': [
        '-include', '<(logging_dir)/sdch/<(logging_path)',
        # TODO(mostynb): remove this if open-vcdiff is ever updated for c++11:
        '-Wno-deprecated-declarations',
      ],
    },
  ],
}
