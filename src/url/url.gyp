# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

{
  'variables': {
    'chromium_code': 1,
  },
  'includes': [
    'url_srcs.gypi',
  ],
  'targets': [
    {
      # Note, this target_name cannot be 'url', because that will generate
      # 'url.dll' for a Windows component build, and that will confuse Windows,
      # which has a system DLL with the same name.
      'target_name': 'url_lib',
      'type': '<(component)',
      'dependencies': [
        '../base/base.gyp:base',
        '../third_party/icu/icu.gyp:icui18n',
        '../third_party/icu/icu.gyp:icuuc',
      ],
      'sources': [
        '<@(gurl_sources)',
      ],
      'direct_dependent_settings': {
        'include_dirs': [
          '..',
        ],
      },
      'defines': [
        'URL_IMPLEMENTATION',
      ],
      # TODO(jschuh): crbug.com/167187 fix size_t to int truncations.
      'msvs_disabled_warnings': [4267, ],
    },
  ],
}
