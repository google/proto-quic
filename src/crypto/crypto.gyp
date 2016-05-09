# Copyright (c) 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

{
  'variables': {
    'chromium_code': 1,
  },
  'includes': [
    'crypto.gypi',
  ],
  'targets': [
    {
      'target_name': 'crypto',
      'type': '<(component)',
      'product_name': 'crcrypto',  # Avoid colliding with OpenSSL's libcrypto
      'dependencies': [
        '../base/base.gyp:base',
#        '../base/third_party/dynamic_annotations/dynamic_annotations.gyp:dynamic_annotations',
        '../third_party/boringssl/boringssl.gyp:boringssl',
      ],
      'defines': [
        'CRYPTO_IMPLEMENTATION',
      ],
      'sources!': [
        'third_party/nss/chromium-nss.h',
        'third_party/nss/chromium-prtypes.h',
        'third_party/nss/chromium-sha256.h',
        'third_party/nss/sha512.cc',
      ],
      'conditions': [
        [ 'os_posix == 1 and OS != "mac" and OS != "ios" and OS != "android"', {
          'dependencies': [
            '../build/linux/system.gyp:ssl',
          ],
          'export_dependent_settings': [
            '../build/linux/system.gyp:ssl',
          ],
          'conditions': [
            [ 'chromeos==1', {
                'sources/': [ ['include', '_chromeos\\.cc$'] ]
              },
            ],
          ],
        }, {  # os_posix != 1 or OS == "mac" or OS == "ios" or OS == "android"
            'sources!': [
              'hmac_win.cc',
            ],
        }],
        [ 'OS != "mac" and OS != "ios"', {
          'sources!': [
            'apple_keychain.h',
            'mock_apple_keychain.cc',
            'mock_apple_keychain.h',
          ],
        }],
        [ 'OS == "android"', {
          'dependencies': [
            '../build/android/ndk.gyp:cpu_features',
          ],
        }],
        [ 'os_bsd==1', {
          'link_settings': {
            'libraries': [
              '-L/usr/local/lib -lexecinfo',
              ],
            },
          },
        ],
        [ 'OS == "mac"', {
          'link_settings': {
            'libraries': [
              '$(SDKROOT)/System/Library/Frameworks/Security.framework',
            ],
          },
        }, {  # OS != "mac"
          'sources!': [
            'cssm_init.cc',
            'cssm_init.h',
            'mac_security_services_lock.cc',
            'mac_security_services_lock.h',
          ],
        }],
        [ 'OS != "win"', {
          'sources!': [
            'capi_util.h',
            'capi_util.cc',
          ],
        }],
        [ 'OS == "win"', {
          'msvs_disabled_warnings': [
            4267,  # TODO(jschuh): crbug.com/167187 fix size_t to int truncations.
          ],
        }],
        [ 'use_nss_certs==0', {
            # Some files are built when NSS is used for the platform certificate library.
            'sources!': [
              'nss_key_util.cc',
              'nss_key_util.h',
              'nss_util.cc',
              'nss_util.h',
              'nss_util_internal.h',
            ],
        },],
      ],
      'sources': [
        '<@(crypto_sources)',
      ],
    },
  ],
  'conditions': [
#    ['OS == "win" and target_arch=="ia32"', {
#      'targets': [
#        {
#          'target_name': 'crypto_nacl_win64',
#          # We use the native APIs for the helper.
#          'type': '<(component)',
#          'dependencies': [
#            '../base/base.gyp:base_win64',
#            '../base/third_party/dynamic_annotations/dynamic_annotations.gyp:dynamic_annotations_win64',
#          ],
#          'sources': [
#            '<@(nacl_win64_sources)',
#          ],
#          'defines': [
#           'CRYPTO_IMPLEMENTATION',
#           '<@(nacl_win64_defines)',
#          ],
#          'configurations': {
#            'Common_Base': {
#              'msvs_target_platform': 'x64',
#            },
#          },
#        },
#      ],
#    }],
  ],
}
