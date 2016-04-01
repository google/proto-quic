# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

{
  # This target is included in both 'net' and 'net_small'.
  'type': '<(component)',
  'variables': { 'enable_wexit_time_destructors': 1, },
  'dependencies': [
    '../base/base.gyp:base',
    '../base/third_party/dynamic_annotations/dynamic_annotations.gyp:dynamic_annotations',
    '../crypto/crypto.gyp:crypto',
    '../sdch/sdch.gyp:sdch',
    '../third_party/protobuf/protobuf.gyp:protobuf_lite',
    '../third_party/zlib/zlib.gyp:zlib',
    'net_derived_sources',
    'net_quic_proto',
    'net_resources',
  ],
  'sources': [
    '<@(net_nacl_common_sources)',
    '<@(net_non_nacl_sources)',
  ],
  'defines': [
    'NET_IMPLEMENTATION',
  ],
  'export_dependent_settings': [
    '../base/base.gyp:base',
  ],
  'conditions': [
    ['chromeos==1', {
      'sources!': [
         'base/network_change_notifier_linux.cc',
         'base/network_change_notifier_linux.h',
         'base/network_change_notifier_netlink_linux.cc',
         'base/network_change_notifier_netlink_linux.h',
         'proxy/proxy_config_service_linux.cc',
         'proxy/proxy_config_service_linux.h',
      ],
    }],
    ['use_kerberos==1', {
      'defines': [
        'USE_KERBEROS',
      ],
      'conditions': [
        ['OS=="openbsd"', {
          'include_dirs': [
            '/usr/include/kerberosV'
          ],
        }],
        ['linux_link_kerberos==1', {
          'link_settings': {
            'ldflags': [
              '<!@(krb5-config --libs gssapi)',
            ],
          },
        }, { # linux_link_kerberos==0
          'defines': [
            'DLOPEN_KERBEROS',
          ],
        }],
      ],
    }, { # use_kerberos == 0
      'sources!': [
        'http/http_auth_gssapi_posix.cc',
        'http/http_auth_gssapi_posix.h',
        'http/http_auth_handler_negotiate.cc',
        'http/http_auth_handler_negotiate.h',
      ],
    }],
    ['posix_avoid_mmap==1', {
      'defines': [
        'POSIX_AVOID_MMAP',
      ],
      'direct_dependent_settings': {
        'defines': [
          'POSIX_AVOID_MMAP',
        ],
      },
      'sources!': [
        'disk_cache/blockfile/mapped_file_posix.cc',
      ],
    }, { # else
      'sources!': [
        'disk_cache/blockfile/mapped_file_avoid_mmap_posix.cc',
      ],
    }],
    ['disable_file_support!=1', {
      # TODO(mmenke):  Should probably get rid of the dependency on
      # net_resources in this case (It's used in net_util, to format
      # directory listings.  Also used outside of net/).
      'sources': ['<@(net_file_support_sources)']
    }],
    ['disable_ftp_support!=1', {
      'sources': ['<@(net_ftp_support_sources)']
    }],
    ['enable_built_in_dns==1', {
      'defines': [
        'ENABLE_BUILT_IN_DNS',
      ]
    }, { # else
      'sources!': [
        'dns/address_sorter_posix.cc',
        'dns/address_sorter_posix.h',
        'dns/dns_client.cc',
      ],
    }],
    ['use_openssl==1', {
        'sources!': [
          'base/nss_memio.c',
          'base/nss_memio.h',
          'cert/ct_log_verifier_nss.cc',
          'cert/ct_objects_extractor_nss.cc',
          'cert/jwk_serializer_nss.cc',
          'cert/scoped_nss_types.h',
          'cert/x509_certificate_ios.cc',
          'cert/x509_util_nss.cc',
          'quic/crypto/aead_base_decrypter_nss.cc',
          'quic/crypto/aead_base_encrypter_nss.cc',
          'quic/crypto/aes_128_gcm_12_decrypter_nss.cc',
          'quic/crypto/aes_128_gcm_12_encrypter_nss.cc',
          'quic/crypto/chacha20_poly1305_decrypter_nss.cc',
          'quic/crypto/chacha20_poly1305_encrypter_nss.cc',
          'quic/crypto/chacha20_poly1305_rfc7539_decrypter_nss.cc',
          'quic/crypto/chacha20_poly1305_rfc7539_encrypter_nss.cc',
          'quic/crypto/channel_id_nss.cc',
          'quic/crypto/p256_key_exchange_nss.cc',
          'quic/crypto/proof_source_chromium_nss.cc',
          'socket/nss_ssl_util.cc',
          'socket/nss_ssl_util.h',
          'socket/ssl_client_socket_nss.cc',
          'socket/ssl_client_socket_nss.h',
          'socket/ssl_server_socket_nss.cc',
          'socket/ssl_server_socket_nss.h',
          'ssl/token_binding_nss.cc',
        ],
        'dependencies': [
          '../third_party/boringssl/boringssl.gyp:boringssl',
        ],
        'conditions': [
          ['chromecast==1 and use_nss_certs==1', {
            'sources': [
              'ssl/ssl_platform_key_chromecast.cc',
            ],
            'sources!': [
              'ssl/ssl_platform_key_nss.cc',
            ],
          }],
        ],
      },
      {  # else !use_openssl: remove the unneeded files and depend on NSS.
        'sources!': [
          'cert/ct_log_verifier_openssl.cc',
          'cert/ct_objects_extractor_openssl.cc',
          'cert/jwk_serializer_openssl.cc',
          'cert/x509_util_openssl.cc',
          'cert/x509_util_openssl.h',
          'quic/crypto/aead_base_decrypter_openssl.cc',
          'quic/crypto/aead_base_encrypter_openssl.cc',
          'quic/crypto/aes_128_gcm_12_decrypter_openssl.cc',
          'quic/crypto/aes_128_gcm_12_encrypter_openssl.cc',
          'quic/crypto/chacha20_poly1305_decrypter_openssl.cc',
          'quic/crypto/chacha20_poly1305_encrypter_openssl.cc',
          'quic/crypto/chacha20_poly1305_rfc7539_decrypter_openssl.cc',
          'quic/crypto/chacha20_poly1305_rfc7539_encrypter_openssl.cc',
          'quic/crypto/channel_id_openssl.cc',
          'quic/crypto/p256_key_exchange_openssl.cc',
          'quic/crypto/proof_source_chromium_openssl.cc',
          'quic/crypto/scoped_evp_aead_ctx.cc',
          'quic/crypto/scoped_evp_aead_ctx.h',
          'socket/ssl_client_socket_openssl.cc',
          'socket/ssl_client_socket_openssl.h',
          'socket/ssl_server_socket_openssl.cc',
          'socket/ssl_server_socket_openssl.h',
          'ssl/client_key_store.cc',
          'ssl/client_key_store.h',
          'ssl/openssl_ssl_util.cc',
          'ssl/openssl_ssl_util.h',
          'ssl/ssl_client_session_cache_openssl.cc',
          'ssl/ssl_client_session_cache_openssl.h',
          'ssl/ssl_key_logger.cc',
          'ssl/ssl_key_logger.h',
          'ssl/ssl_platform_key.h',
          'ssl/ssl_platform_key_nss.cc',
          'ssl/ssl_platform_key_task_runner.cc',
          'ssl/ssl_platform_key_task_runner.h',
          'ssl/test_ssl_private_key.cc',
          'ssl/test_ssl_private_key.h',
          'ssl/threaded_ssl_private_key.cc',
          'ssl/threaded_ssl_private_key.h',
          'ssl/token_binding_openssl.cc',
        ],
      },
    ],
    [ 'use_nss_verifier == 1', {
        'conditions': [
          # Pull in the bundled or system NSS as appropriate.
          [ 'desktop_linux == 1 or chromeos == 1', {
            'dependencies': [
              '../build/linux/system.gyp:ssl',
            ],
          }, {
            'dependencies': [
#              '../third_party/nss/nss.gyp:nspr',
#              '../third_party/nss/nss.gyp:nss',
#              'third_party/nss/ssl.gyp:libssl',
            ],
          }]
        ],
      }, {
        'sources!': [
          'cert/x509_util_nss.h',
        ],
      },
    ],
    [ 'use_openssl_certs == 0', {
        'sources!': [
          'base/crypto_module_openssl.cc',
          'base/keygen_handler_openssl.cc',
          'base/openssl_private_key_store.h',
          'base/openssl_private_key_store_android.cc',
          'base/openssl_private_key_store_memory.cc',
          'cert/cert_database_openssl.cc',
          'cert/cert_verify_proc_openssl.cc',
          'cert/cert_verify_proc_openssl.h',
          'cert/test_root_certs_openssl.cc',
          'cert/x509_certificate_openssl.cc',
          'ssl/openssl_client_key_store.cc',
          'ssl/openssl_client_key_store.h',
        ],
    }],
    [ 'use_glib == 1', {
        'dependencies': [
          '../build/linux/system.gyp:gconf',
          '../build/linux/system.gyp:gio',
        ],
    }],
    [ 'desktop_linux == 1 or chromeos == 1', {
        'conditions': [
          ['os_bsd==1', {
            'sources!': [
              'base/network_change_notifier_linux.cc',
              'base/network_change_notifier_netlink_linux.cc',
              'proxy/proxy_config_service_linux.cc',
            ],
          },{
            'dependencies': [
              '../build/linux/system.gyp:libresolv',
            ],
          }],
          ['OS=="solaris"', {
            'link_settings': {
              'ldflags': [
                '-R/usr/lib/mps',
              ],
            },
          }],
        ],
      },
    ],
    [ 'use_nss_certs != 1', {
        'sources!': [
          'base/crypto_module_nss.cc',
          'base/keygen_handler_nss.cc',
          'cert/cert_database_nss.cc',
          'cert/nss_cert_database.cc',
          'cert/nss_cert_database.h',
          'cert/nss_cert_database_chromeos.cc',
          'cert/nss_cert_database_chromeos.h',
          'cert/nss_profile_filter_chromeos.cc',
          'cert/nss_profile_filter_chromeos.h',
          'cert/x509_certificate_nss.cc',
          'ssl/client_cert_store_nss.cc',
          'ssl/client_cert_store_nss.h',
          'ssl/client_key_store.cc',
          'ssl/client_key_store.h',
          'ssl/ssl_platform_key_nss.cc',
          'third_party/mozilla_security_manager/nsKeygenHandler.cpp',
          'third_party/mozilla_security_manager/nsKeygenHandler.h',
          'third_party/mozilla_security_manager/nsNSSCertificateDB.cpp',
          'third_party/mozilla_security_manager/nsNSSCertificateDB.h',
          'third_party/mozilla_security_manager/nsPKCS12Blob.cpp',
          'third_party/mozilla_security_manager/nsPKCS12Blob.h',
        ],
      },
    ],
    [ 'use_nss_verifier != 1', {
        'sources!': [
          'cert/cert_verify_proc_nss.cc',
          'cert/cert_verify_proc_nss.h',
          'cert/test_root_certs_nss.cc',
          'cert/x509_util_nss_certs.cc',
          'cert_net/nss_ocsp.cc',
          'cert_net/nss_ocsp.h',
        ],
      },
    ],
    # client_cert_store_nss.c requires NSS_CmpCertChainWCANames from NSS's
    # libssl, but our bundled copy is not built in OpenSSL ports. Pull that
    # file in directly.
    [ 'use_nss_certs == 1 and use_openssl == 1', {
        'sources': [
#          'third_party/nss/ssl/cmpcert.c',
        ],
    }],
    [ 'OS == "ios" and use_nss_verifier == 0', {
        'sources!': [
          'cert/x509_util_ios.cc',
          'cert/x509_util_ios.h',
        ],
    }],
    [ 'enable_websockets == 1', {
        'sources': ['<@(net_websockets_sources)']
    }],
    [ 'enable_mdns != 1', {
        'sources!' : [
          'dns/mdns_cache.cc',
          'dns/mdns_cache.h',
          'dns/mdns_client.cc',
          'dns/mdns_client.h',
          'dns/mdns_client_impl.cc',
          'dns/mdns_client_impl.h',
          'dns/record_parsed.cc',
          'dns/record_parsed.h',
          'dns/record_rdata.cc',
          'dns/record_rdata.h',
        ]
    }],
    [ 'OS == "win"', {
        'sources!': [
          'http/http_auth_handler_ntlm_portable.cc',
        ],
         # TODO(jschuh): crbug.com/167187 fix size_t to int truncations.
        'msvs_disabled_warnings': [4267, ],
      }, { # else: OS != "win"
        'sources!': [
          'base/winsock_init.cc',
          'base/winsock_init.h',
          'base/winsock_util.cc',
          'base/winsock_util.h',
          'proxy/proxy_resolver_winhttp.cc',
          'proxy/proxy_resolver_winhttp.h',
        ],
      },
    ],
    [ 'OS == "mac"', {
        'link_settings': {
          'libraries': [
            '$(SDKROOT)/System/Library/Frameworks/Foundation.framework',
            '$(SDKROOT)/System/Library/Frameworks/Security.framework',
            '$(SDKROOT)/System/Library/Frameworks/SystemConfiguration.framework',
            '$(SDKROOT)/usr/lib/libresolv.dylib',
          ]
        },
      },
    ],
    [ 'OS == "ios"', {
        'sources!': [
          'disk_cache/blockfile/file_posix.cc',
        ],
        'link_settings': {
          'libraries': [
            '$(SDKROOT)/System/Library/Frameworks/CFNetwork.framework',
            '$(SDKROOT)/System/Library/Frameworks/MobileCoreServices.framework',
            '$(SDKROOT)/System/Library/Frameworks/Security.framework',
            '$(SDKROOT)/System/Library/Frameworks/SystemConfiguration.framework',
          ],
          'xcode_settings': {
            'OTHER_LDFLAGS': [
              '-lresolv',
            ],
          },
        },
      },
    ],
    [ 'OS == "ios" or OS == "mac"', {
        'sources': [
          '<@(net_base_mac_ios_sources)',
        ],
      },
    ],
    ['OS=="android" and _toolset=="target"', {
      'dependencies': [
         'net_java',
      ],
    }],
    [ 'OS == "android"', {
        'dependencies': [
          'net_jni_headers',
        ],
        'sources!': [
          'base/openssl_private_key_store_memory.cc',
          'cert/cert_database_openssl.cc',
          'cert/cert_verify_proc_openssl.cc',
          'cert/test_root_certs_openssl.cc',
          'http/http_auth_gssapi_posix.cc',
          'http/http_auth_gssapi_posix.h',
        ],
      },
    ],
  ],
  'target_conditions': [
    # These source files are excluded by default platform rules, but they
    # are needed in specific cases on other platforms. Re-including them can
    # only be done in target_conditions as it is evaluated after the
    # platform rules.
    ['OS == "android"', {
      'sources/': [
        ['include', '^base/platform_mime_util_linux\\.cc$'],
        ['include', '^base/address_tracker_linux\\.cc$'],
        ['include', '^base/address_tracker_linux\\.h$'],
        ['include', '^base/network_interfaces_linux\\.cc$'],
        ['include', '^base/network_interfaces_linux\\.h$'],
      ],
    }],
    ['OS == "ios"', {
      'sources/': [
        ['include', '^base/mac/url_conversions\\.h$'],
        ['include', '^base/mac/url_conversions\\.mm$'],
        ['include', '^base/network_change_notifier_mac\\.cc$'],
        ['include', '^base/network_config_watcher_mac\\.cc$'],
        ['include', '^base/network_interfaces_mac\\.cc$'],
        ['include', '^base/network_interfaces_mac\\.h$'],
        ['include', '^base/platform_mime_util_mac\\.mm$'],
        ['include', '^proxy/proxy_resolver_mac\\.cc$'],
        ['include', '^proxy/proxy_server_mac\\.cc$'],
      ],
    }],
  ],
}
