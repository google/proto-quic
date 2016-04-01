# Copyright (c) 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

{
  'variables': {
    # A hook that can be overridden in other repositories to add additional
    # compilation targets to 'All'.
    'app_targets%': [],
    # For Android-specific targets.
    'android_app_targets%': [],
  },
#  'includes': [
#    '../third_party/openh264/openh264_args.gypi',
#  ],
  'targets': [
    {
      'target_name': 'All',
      'type': 'none',
      'xcode_create_dependents_test_runner': 1,
      'dependencies': [
        '<@(app_targets)',
        'some.gyp:*',
        '../base/base.gyp:*',
        '../crypto/crypto.gyp:*',
        '../net/net.gyp:*',
        '../sdch/sdch.gyp:*',
        '../third_party/icu/icu.gyp:*',
        '../third_party/zlib/zlib.gyp:*',
        '../url/url.gyp:*',
      ],
      'conditions': [
        ['use_openssl==0', {
          'dependencies': [
            '../net/third_party/nss/ssl.gyp:*',
          ],
        }],
        ['use_openssl==1', {
          'dependencies': [
            '../third_party/boringssl/boringssl.gyp:*',
#            '../third_party/boringssl/boringssl_tests.gyp:*',
          ],
        }],
      ],
    }, # target_name: All
  ],
}
