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
      ],
      'defines': [
        'CRYPTO_IMPLEMENTATION',
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
              'symmetric_key_win.cc',
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
        [ 'use_openssl == 0 and (OS == "mac" or OS == "ios" or OS == "win")', {
          'dependencies': [
            '../third_party/nss/nss.gyp:nspr',
            '../third_party/nss/nss.gyp:nss',
          ],
          'export_dependent_settings': [
            '../third_party/nss/nss.gyp:nspr',
            '../third_party/nss/nss.gyp:nss',
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
        [ 'use_openssl==1', {
            'dependencies': [
              '../third_party/boringssl/boringssl.gyp:boringssl',
            ],
            # TODO(joth): Use a glob to match exclude patterns once the
            #             OpenSSL file set is complete.
            'sources!': [
              'curve25519-donna.c',
              'curve25519_nss.cc',
              'ec_private_key_nss.cc',
              'ec_signature_creator_nss.cc',
              'encryptor_nss.cc',
              'hmac_nss.cc',
              'rsa_private_key_nss.cc',
              'secure_hash_default.cc',
              'signature_creator_nss.cc',
              'signature_verifier_nss.cc',
              'symmetric_key_nss.cc',
              'third_party/nss/chromium-blapi.h',
              'third_party/nss/chromium-blapit.h',
              'third_party/nss/chromium-nss.h',
              'third_party/nss/chromium-prtypes.h',
              'third_party/nss/chromium-sha256.h',
              'third_party/nss/pk11akey.cc',
              'third_party/nss/rsawrapr.c',
              'third_party/nss/secsign.cc',
              'third_party/nss/sha512.cc',
            ],
          }, {
            'sources!': [
              'aead_openssl.cc',
              'aead_openssl.h',
              'curve25519_openssl.cc',
              'ec_private_key_openssl.cc',
              'ec_signature_creator_openssl.cc',
              'encryptor_openssl.cc',
              'hmac_openssl.cc',
              'openssl_bio_string.cc',
              'openssl_bio_string.h',
              'openssl_util.cc',
              'openssl_util.h',
              'rsa_private_key_openssl.cc',
              'secure_hash_openssl.cc',
              'signature_creator_openssl.cc',
              'signature_verifier_openssl.cc',
              'symmetric_key_openssl.cc',
            ],
        },],
        [ 'use_openssl==1 and use_nss_certs==0', {
            # Some files are built when NSS is used at all, either for the
            # internal crypto library or the platform certificate library.
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
    ['OS == "win" and target_arch=="ia32"', {
      'targets': [
        {
          'target_name': 'crypto_nacl_win64',
          # We do not want nacl_helper to depend on NSS because this would
          # require including a 64-bit copy of NSS. Thus, use the native APIs
          # for the helper.
          'type': '<(component)',
          'dependencies': [
            '../base/base.gyp:base_win64',
            '../base/third_party/dynamic_annotations/dynamic_annotations.gyp:dynamic_annotations_win64',
          ],
          'sources': [
            '<@(nacl_win64_sources)',
          ],
          'defines': [
           'CRYPTO_IMPLEMENTATION',
           '<@(nacl_win64_defines)',
          ],
          'configurations': {
            'Common_Base': {
              'msvs_target_platform': 'x64',
            },
          },
        },
      ],
    }],
  ],
}
