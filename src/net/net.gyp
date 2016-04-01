# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

{
  'variables': {
    'chromium_code': 1,
    'linux_link_kerberos%': 0,
    'conditions': [
      ['chromeos==1 or embedded==1 or OS=="ios"', {
        # Disable Kerberos on ChromeOS and iOS, at least for now.
        # It needs configuration (krb5.conf and so on).
        'use_kerberos%': 0,
      }, {  # chromeos == 0 and embedded==0 and OS!="ios"
        'use_kerberos%': 1,
      }],
      ['OS=="android" and target_arch != "ia32"', {
        # The way the cache uses mmap() is inefficient on some Android devices.
        # If this flag is set, we hackily avoid using mmap() in the disk cache.
        # We are pretty confident that mmap-ing the index would not hurt any
        # existing x86 android devices, but we cannot be so sure about the
        # variety of ARM devices. So enable it for x86 only for now.
        'posix_avoid_mmap%': 1,
      }, {
        'posix_avoid_mmap%': 0,
      }],
      ['OS=="ios"', {
        # Websockets and socket stream are not used on iOS.
        'enable_websockets%': 0,
        # iOS does not use V8.
        'use_v8_in_net%': 0,
        'enable_built_in_dns%': 0,
      }, {
        'enable_websockets%': 1,
        'use_v8_in_net%': 1,
        'enable_built_in_dns%': 1,
      }],
    ],
  },
  'includes': [
    '../build/win_precompile.gypi',
    'net.gypi',
  ],
  'targets': [
    {
      'target_name': 'net_derived_sources',
      'type': 'none',
      'sources': [
        'base/registry_controlled_domains/effective_tld_names.gperf',
        'base/registry_controlled_domains/effective_tld_names_unittest1.gperf',
        'base/registry_controlled_domains/effective_tld_names_unittest2.gperf',
        'base/registry_controlled_domains/effective_tld_names_unittest3.gperf',
        'base/registry_controlled_domains/effective_tld_names_unittest4.gperf',
        'base/registry_controlled_domains/effective_tld_names_unittest5.gperf',
        'base/registry_controlled_domains/effective_tld_names_unittest6.gperf',
        'base/stale_while_revalidate_experiment_domains.gperf',
      ],
      'rules': [
        {
          'rule_name': 'dafsa',
          'extension': 'gperf',
          'outputs': [
            '<(SHARED_INTERMEDIATE_DIR)/net/<(RULE_INPUT_DIRNAME)/<(RULE_INPUT_ROOT)-inc.cc',
          ],
          'inputs': [
            'tools/dafsa/make_dafsa.py',
          ],
          'action': [
            'python',
            'tools/dafsa/make_dafsa.py',
            '<(RULE_INPUT_PATH)',
            '<(SHARED_INTERMEDIATE_DIR)/net/<(RULE_INPUT_DIRNAME)/<(RULE_INPUT_ROOT)-inc.cc',
          ],
        },
      ],
      'direct_dependent_settings': {
        'include_dirs': [
          '<(SHARED_INTERMEDIATE_DIR)'
        ],
      },
    },
    {
      # Protobuf compiler / generator for QUIC crypto protocol buffer.
      # GN version: //net:net_quic_proto
      'target_name': 'net_quic_proto',
      'type': 'static_library',
      'sources': [
        'quic/proto/cached_network_parameters.proto',
        'quic/proto/source_address_token.proto',
      ],
      'variables': {
        'enable_wexit_time_destructors': 1,
        'proto_in_dir': 'quic/proto',
        'proto_out_dir': 'net/quic/proto',
        'cc_generator_options': 'dllexport_decl=NET_EXPORT_PRIVATE:',
        'cc_include': 'net/base/net_export.h',
      },
      'includes': [
        '../build/protoc.gypi',
      ],
      'defines': [
        'NET_IMPLEMENTATION',
      ],
    },
    {
      # GN version: //net
      'target_name': 'net',
      'dependencies': [
#        '../base/base.gyp:base_i18n',
        '../third_party/brotli/brotli.gyp:brotli',
        '../third_party/icu/icu.gyp:icui18n',
        '../third_party/icu/icu.gyp:icuuc',
        '../third_party/protobuf/protobuf.gyp:protobuf_lite',
        '../url/url.gyp:url_lib',
        'net_quic_proto',
      ],
      'sources': [
#        'base/filename_util_icu.cc',
#        'base/net_string_util_icu.cc',
        'filter/brotli_filter.cc',
      ],
      'includes': [ 'net_common.gypi' ],
    },
    {
      # GN version: //net:net_unittests
      'target_name': 'net_unittests',
      'type': '<(gtest_target_type)',
      'dependencies': [
        '../base/base.gyp:base',
#        '../base/base.gyp:base_i18n',
        '../base/third_party/dynamic_annotations/dynamic_annotations.gyp:dynamic_annotations',
        '../crypto/crypto.gyp:crypto',
#        '../crypto/crypto.gyp:crypto_test_support',
        '../testing/gmock.gyp:gmock',
        '../testing/gtest.gyp:gtest',
        '../third_party/zlib/zlib.gyp:zlib',
        '../url/url.gyp:url_lib',
#        'balsa',
#        'http_server',
        'net',
        'net_quic_proto',
        'net_derived_sources',
        'net_extras',
        'net_test_support',
        'simple_quic_tools',
#        'stale_while_revalidate_experiment_domains',
      ],
      'sources': [
        '<@(net_test_sources)',
      ],
      'conditions': [
        ['os_posix == 1 and OS != "mac" and OS != "ios" and OS != "android"', {
          'dependencies': [
            'epoll_quic_tools',
            'epoll_server',
#            'flip_in_mem_edsm_server_base',
          ],
          'sources': [
#            '<@(net_linux_test_sources)',
          ],
        }],
        ['OS == "mac" or OS == "ios"', {
          'sources': [
            '<@(net_base_test_mac_ios_sources)',
          ],
        }],
        ['chromeos==1', {
          'sources!': [
            'proxy/proxy_config_service_linux_unittest.cc',
          ],
        }],
        [ 'OS == "android"', {
          'sources!': [
            # See bug http://crbug.com/344533.
            'disk_cache/blockfile/index_table_v3_unittest.cc',
          ],
          'dependencies': [
            'net_javatests',
          ],
        }],
        [ 'use_nss_certs != 1', {
          'sources!': [
            'cert/nss_cert_database_unittest.cc',
            'cert/nss_cert_database_chromeos_unittest.cc',
            'cert/nss_profile_filter_chromeos_unittest.cc',
            'ssl/client_cert_store_nss_unittest.cc',
          ],
        }],
        [ 'use_openssl == 1', {
          # Avoid compiling/linking with the system library.
          'dependencies': [
            '../third_party/boringssl/boringssl.gyp:boringssl',
          ],
        }],
        [ 'use_nss_verifier == 1', {
          'conditions': [
            [ 'desktop_linux == 1 or chromeos == 1', {
              'dependencies': [
                '../build/linux/system.gyp:ssl',
              ],
            }, {  # desktop_linux == 0 and chromeos == 0
              'dependencies': [
#                '../third_party/nss/nss.gyp:nspr',
#                '../third_party/nss/nss.gyp:nss',
#                'third_party/nss/ssl.gyp:libssl',
              ],
            }],
          ],
        }],
        [ 'use_kerberos==1', {
          'defines': [
            'USE_KERBEROS',
          ],
        }],
        [ 'use_kerberos==0 or OS == "android"', {
          # These are excluded on Android, because the actual Kerberos support,
          # which these test, is in a separate app on Android.
          'sources!': [
            'http/http_auth_gssapi_posix_unittest.cc',
            'http/mock_gssapi_library_posix.cc',
            'http/mock_gssapi_library_posix.h',
          ],
        }],
       [ 'use_kerberos==0', {
          'sources!': [
            'http/http_auth_handler_negotiate_unittest.cc',
          ],
        }],
        [ 'use_nss_verifier == 0', {
          # Only include this test when using NSS for cert verification.
          'sources!': [
            'cert_net/nss_ocsp_unittest.cc',
          ],
        }],
        [ 'use_nss_verifier == 0 and OS == "ios"', {
          # Only include these files on iOS when using NSS for cert 
          # verification.
          'sources!': [
           'cert/x509_util_ios.cc',
           'cert/x509_util_ios.h',
          ],
        }],
        [ 'use_openssl==1', {
            'sources!': [
              'quic/test_tools/crypto_test_utils_nss.cc',
            ],
          }, {  # else !use_openssl: remove the unneeded files and pull in NSS.
            'sources!': [
              'quic/test_tools/crypto_test_utils_openssl.cc',
              'ssl/ssl_client_session_cache_openssl_unittest.cc',
            ],
          },
        ],
        [ 'use_openssl_certs == 0', {
            'sources!': [
              'ssl/openssl_client_key_store_unittest.cc',
            ],
        }],
        [ 'enable_websockets != 1', {
            'sources/': [
              ['exclude', '^websockets/'],
              ['exclude', '^server/'],
            ],
            'dependencies!': [
              'http_server',
            ],
        }],
        ['disable_file_support==1', {
          'sources!': [
            'base/directory_lister_unittest.cc',
            'base/directory_listing_unittest.cc',
            'url_request/url_request_file_dir_job_unittest.cc',
            'url_request/url_request_file_job_unittest.cc',
          ],
        }],
        [ 'disable_ftp_support==1', {
            'sources/': [
              ['exclude', '^ftp/'],
            ],
            'sources!': [
              'url_request/url_request_ftp_job_unittest.cc',
            ],
          },
        ],
        [ 'enable_built_in_dns!=1', {
            'sources!': [
              'dns/address_sorter_posix_unittest.cc',
              'dns/address_sorter_unittest.cc',
            ],
          },
        ],
        [ 'use_v8_in_net==1', {
            'dependencies': [
              'net_with_v8',
            ],
          }, {  # else: !use_v8_in_net
            'sources!': [
              'proxy/proxy_resolver_v8_tracing_unittest.cc',
              'proxy/proxy_resolver_v8_tracing_wrapper_unittest.cc',
              'proxy/proxy_resolver_v8_unittest.cc',
            ],
          },
        ],

        [ 'use_v8_in_net==1 and OS != "android"', {
            'dependencies': [
              'net_with_v8',
              'net_browser_services',
#              'net_utility_services',
#              '../mojo/mojo_edk.gyp:mojo_system_impl',
            ],
          }, {  # else
            'sources!': [
#              'dns/host_resolver_mojo_unittest.cc',
#              'dns/mojo_host_resolver_impl_unittest.cc',
#              'proxy/mojo_proxy_resolver_factory_impl_unittest.cc',
#              'proxy/mojo_proxy_resolver_impl_unittest.cc',
#              'proxy/mojo_proxy_resolver_v8_tracing_bindings_unittest.cc',
#              'proxy/proxy_resolver_factory_mojo_unittest.cc',
#              'proxy/proxy_service_mojo_unittest.cc',
            ],
          },
        ],

        [ 'enable_mdns != 1', {
            'sources!' : [
              'dns/mdns_cache_unittest.cc',
              'dns/mdns_client_unittest.cc',
              'dns/mdns_query_unittest.cc',
              'dns/record_parsed_unittest.cc',
              'dns/record_rdata_unittest.cc',
            ],
        }],
        [ 'OS == "win"', {
            'sources!': [
              'dns/dns_config_service_posix_unittest.cc',
              'http/http_auth_gssapi_posix_unittest.cc',
            ],
            # TODO(jschuh): crbug.com/167187 fix size_t to int truncations.
            'msvs_disabled_warnings': [4267, ],
            'conditions': [
              [ 'icu_use_data_file_flag == 0', {
                # This is needed to trigger the dll copy step on windows.
                # TODO(mark): Specifying this here shouldn't be necessary.
                'dependencies': [
                  '../third_party/icu/icu.gyp:icudata',
                ],
              }],
            ],
          },
        ],
        [ 'OS == "ios"', {
            'actions': [
              {
                'action_name': 'copy_test_data',
                'variables': {
                  'test_data_files': [
                    'data/certificate_policies_unittest/',
                    'data/name_constraints_unittest/',
                    'data/parse_certificate_unittest/',
                    'data/parse_ocsp_unittest/',
                    'data/ssl/certificates/',
                    'data/test.html',
                    'data/url_request_unittest/',
                    'data/verify_certificate_chain_unittest/',
                    'data/verify_name_match_unittest/names/',
                    'data/verify_signed_data_unittest/',
                  ],
                  'test_data_prefix': 'net',
                },
                'includes': [ '../build/copy_test_data_ios.gypi' ],
              },
            ],
            'sources!': [
              # TODO(droger): The following tests are disabled because the
              # implementation is missing or incomplete.
              # KeygenHandler::GenKeyAndSignChallenge() is not ported to iOS.
              'base/keygen_handler_unittest.cc',
              'disk_cache/backend_unittest.cc',
              'disk_cache/blockfile/block_files_unittest.cc',
              # Need to read input data files.
              'filter/brotli_filter_unittest.cc',
              'filter/gzip_filter_unittest.cc',
              # Need TestServer.
              "cert_net/cert_net_fetcher_impl_unittest.cc",
              'proxy/proxy_script_fetcher_impl_unittest.cc',
              'socket/ssl_client_socket_unittest.cc',
              'socket/ssl_server_socket_unittest.cc',
              'spdy/fuzzing/hpack_fuzz_util_test.cc',
              # Needs GetAppOutput().
              'test/python_utils_unittest.cc',
              'url_request/url_fetcher_impl_unittest.cc',
              'url_request/url_request_context_builder_unittest.cc',

              # The following tests are disabled because they don't apply to
              # iOS.
              # OS is not "linux" or "freebsd" or "openbsd".
              'socket/unix_domain_client_socket_posix_unittest.cc',
              'socket/unix_domain_server_socket_posix_unittest.cc',

              # See bug http://crbug.com/344533.
              'disk_cache/blockfile/index_table_v3_unittest.cc',
            ],
        }],
        ['OS == "android"', {
          # TODO(mmenke):  This depends on test_support_base, which depends on
          #                icu.  Figure out a way to remove that dependency.
          'dependencies': [
            '../testing/android/native_test.gyp:native_test_native_code',
          ]
        }],
        ['use_v8_in_net==1 and v8_use_external_startup_data==1', {
          'dependencies': [
#            '../gin/gin.gyp:gin',
          ]
        }],
      ],
      'target_conditions': [
        # These source files are excluded by default platform rules, but they
        # are needed in specific cases on other platforms. Re-including them can
        # only be done in target_conditions as it is evaluated after the
        # platform rules.
        ['OS == "android"', {
          'sources/': [
            ['include', '^base/address_tracker_linux_unittest\\.cc$'],
          ],
        }],
        ['OS == "ios"', {
          'sources/': [
            ['include', '^base/mac/url_conversions_unittest\\.mm$'],
          ],
        }],
      ],
    },
    {
      'target_name': 'net_perftests',
      'type': 'executable',
      'dependencies': [
        '../base/base.gyp:base',
#        '../base/base.gyp:base_i18n',
#        '../base/base.gyp:test_support_perf',
        '../testing/gtest.gyp:gtest',
        '../url/url.gyp:url_lib',
        'net',
        'net_extras',
        'net_test_support',
      ],
      'sources': [
        'base/mime_sniffer_perftest.cc',
        'cookies/cookie_monster_perftest.cc',
        'disk_cache/blockfile/disk_cache_perftest.cc',
        'extras/sqlite/sqlite_persistent_cookie_store_perftest.cc',
        'proxy/proxy_resolver_perftest.cc',
        'udp/udp_socket_perftest.cc',
        'websockets/websocket_frame_perftest.cc',
      ],
      'conditions': [
        [ 'use_v8_in_net==1', {
            'dependencies': [
              'net_with_v8',
            ],
          }, {  # else: !use_v8_in_net
            'sources!': [
              'proxy/proxy_resolver_perftest.cc',
            ],
          },
        ],
        [ 'OS == "win"', {
            'conditions': [
              [ 'icu_use_data_file_flag == 0', {
                # This is needed to trigger the dll copy step on windows.
                # TODO(mark): Specifying this here shouldn't be necessary.
                'dependencies': [
                  '../third_party/icu/icu.gyp:icudata',
                ],
              }],
            ],
            # TODO(jschuh): crbug.com/167187 fix size_t to int truncations.
            'msvs_disabled_warnings': [4267, ],
        }],
        [ 'enable_websockets != 1', {
          'sources!': [
            'websockets/websocket_frame_perftest.cc',
          ],
        }],
      ],
    },
    {
      'target_name': 'net_test_support',
      'type': 'static_library',
      'dependencies': [
        '../base/base.gyp:base',
        '../base/base.gyp:test_support_base',
        '../crypto/crypto.gyp:crypto',
#        '../net/tools/tld_cleanup/tld_cleanup.gyp:tld_cleanup_util',
        '../testing/gtest.gyp:gtest',
        '../testing/gmock.gyp:gmock',
        '../third_party/boringssl/boringssl.gyp:boringssl',
        '../third_party/icu/icu.gyp:icuuc',
        '../url/url.gyp:url_lib',
        'net',
      ],
      'export_dependent_settings': [
        '../base/base.gyp:base',
        # TODO(mmenke):  This depends on icu, figure out a way to build tests
        #                without icu.
        '../base/base.gyp:test_support_base',
        '../crypto/crypto.gyp:crypto',
        '../testing/gtest.gyp:gtest',
        '../testing/gmock.gyp:gmock',
      ],
      'sources': [
         # Begin additions
         'base/host_mapping_rules.cc',
         'base/host_mapping_rules.h',
         'base/net_string_util_icu.cc',
         'cert/ct_known_logs.cc',
         'cert/ct_known_logs.h',
         'cert/ct_policy_enforcer.cc',
         'cert/ct_policy_enforcer.h',
         'http/http_network_session.cc',
         'http/http_stream_factory_impl.cc',
         'http/bidirectional_stream_impl.cc',
         'http/bidirectional_stream_impl.h',
         'http/http_network_session.h',
         'http/http_server_properties.cc',
         'http/http_server_properties.h',
         'http/http_stream_factory.cc',
         'http/http_stream_factory_impl_job.cc',
         'http/http_stream_factory_impl_request.cc',
         'http/http_auth_cache.cc',
         'http/http_response_body_drainer.cc',
         'http/http_proxy_client_socket_pool.cc',
         'http/http_basic_stream.cc',
         'http/http_proxy_client_socket_wrapper.cc',
         'http/http_basic_state.cc',
         'http/http_stream_parser.cc',
         'http/http_auth_controller.cc',
         'http/http_proxy_client_socket.cc',
         'http/http_chunked_decoder.cc',
         'http/http_auth.cc',
         'http/proxy_client_socket.cc',
         'http/http_auth_handler.cc',
         'http/proxy_connect_redirect_http_stream.cc',
         'http/http_auth_handler_factory.cc',
         'http/http_auth_preferences.cc',
         'http/http_auth_handler_basic.cc',
         'http/http_auth_handler_digest.cc',
         'http/http_auth_handler_factory.cc',
         'http/http_auth_handler_ntlm.cc',
         'http/http_auth_handler_ntlm_portable.cc',
         'http/http_auth_handler_ntlm_win.cc',
         'http/http_auth_filter.cc',
         'http/des.cc',
         'http/des.h',
         'http/md4.cc',
         'http/md4.h',
         'http/url_security_manager_posix.cc',
         'http/url_security_manager_win.cc',
         'http/url_security_manager.cc',
         'proxy/proxy_config_service_fixed.cc',
         'proxy/proxy_config_service_linux.cc',
         'proxy/proxy_config_service_win.cc',
         'proxy/proxy_config_service_mac.cc',
         'proxy/proxy_config_source.cc',
         'proxy/proxy_resolver_script_data.cc',
         'proxy/multi_threaded_proxy_resolver.cc',
         'proxy/multi_threaded_proxy_resolver.h',
         'proxy/proxy_bypass_rules.cc',
         'proxy/proxy_bypass_rules.h',
         'proxy/proxy_config.cc',
         'proxy/proxy_config.h',
         'proxy/proxy_info.cc',
         'proxy/proxy_info.h',
         'proxy/proxy_list.cc',
         'proxy/proxy_list.h',
         'proxy/proxy_resolver_factory.cc',
         'proxy/proxy_resolver_factory.h',
         'proxy/proxy_script_decider.cc',
         'proxy/proxy_script_decider.h',
         'proxy/proxy_server.cc',
         'proxy/proxy_server.h',
         'proxy/proxy_server_mac.cc',
         'proxy/proxy_service.cc',
         'proxy/proxy_service.h',
         'quic/quic_chromium_client_session.cc',
         'quic/quic_chromium_client_session.h',
         'quic/quic_chromium_client_stream.cc',
         'quic/quic_chromium_client_stream.h',
         'socket/client_socket_pool_manager_impl.cc',
         'socket/websocket_transport_connect_sub_job.cc',
         'socket/websocket_endpoint_lock_manager.cc',
         'socket/socks_client_socket_pool.cc',
         'socket/client_socket_pool.cc',
         'socket/client_socket_pool_manager.cc',
         'socket/transport_client_socket_pool.cc',
         'socket/client_socket_pool_base.cc',
         'socket/ssl_client_socket_pool.cc',
         'socket/socks5_client_socket.cc',
         'socket/websocket_transport_client_socket_pool.cc',
         'socket/socks_client_socket.cc',
         'spdy/spdy_session_pool.cc',
         'spdy/spdy_session_pool.h',
         'spdy/spdy_read_queue.cc',
         'spdy/spdy_write_queue.cc',
         'spdy/bidirectional_stream_spdy_impl.cc',
         'spdy/spdy_proxy_client_socket.cc',
         # End additions
#        'base/load_timing_info_test_util.cc',
#        'base/load_timing_info_test_util.h',
#        'base/mock_file_stream.cc',
#        'base/mock_file_stream.h',
        'base/test_completion_callback.cc',
        'base/test_completion_callback.h',
        'base/test_data_directory.cc',
        'base/test_data_directory.h',
        'cert/mock_cert_verifier.cc',
        'cert/mock_cert_verifier.h',
#        'cert/mock_client_cert_verifier.cc',
#        'cert/mock_client_cert_verifier.h',
#        'cookies/cookie_monster_store_test.cc',
#        'cookies/cookie_monster_store_test.h',
#        'cookies/cookie_store_test_callbacks.cc',
#        'cookies/cookie_store_test_callbacks.h',
#        'cookies/cookie_store_test_helpers.cc',
#        'cookies/cookie_store_test_helpers.h',
#        'cookies/cookie_store_unittest.h',
#        'disk_cache/disk_cache_test_base.cc',
#        'disk_cache/disk_cache_test_base.h',
#        'disk_cache/disk_cache_test_util.cc',
#        'disk_cache/disk_cache_test_util.h',
#        'dns/dns_test_util.cc',
#        'dns/dns_test_util.h',
        'dns/mock_host_resolver.cc',
        'dns/mock_host_resolver.h',
#        'dns/mock_mdns_socket_factory.cc',
#        'dns/mock_mdns_socket_factory.h',
#        'http/http_transaction_test_util.cc',
#        'http/http_transaction_test_util.h',
#        'log/test_net_log.cc',
#        'log/test_net_log.h',
#        'log/test_net_log_entry.cc',
#        'log/test_net_log_entry.h',
#        'log/test_net_log_util.cc',
#        'log/test_net_log_util.h',
#        'proxy/mock_proxy_resolver.cc',
#        'proxy/mock_proxy_resolver.h',
#        'proxy/mock_proxy_script_fetcher.cc',
#        'proxy/mock_proxy_script_fetcher.h',
#        'proxy/proxy_config_service_common_unittest.cc',
#        'proxy/proxy_config_service_common_unittest.h',
#        'socket/socket_test_util.cc',
#        'socket/socket_test_util.h',
        'test/cert_test_util.cc',
        'test/cert_test_util.h',
        'test/cert_test_util_nss.cc',
#        'test/channel_id_test_util.cc',
#        'test/channel_id_test_util.h',
        'test/ct_test_util.cc',
        'test/ct_test_util.h',
#        'test/embedded_test_server/default_handlers.cc',
#        'test/embedded_test_server/default_handlers.h',
#        'test/embedded_test_server/embedded_test_server.cc',
#        'test/embedded_test_server/embedded_test_server.h',
#        'test/embedded_test_server/http_connection.cc',
#        'test/embedded_test_server/http_connection.h',
#        'test/embedded_test_server/http_request.cc',
#        'test/embedded_test_server/http_request.h',
#        'test/embedded_test_server/http_response.cc',
#        'test/embedded_test_server/http_response.h',
#        'test/embedded_test_server/request_handler_util.cc',
#        'test/embedded_test_server/request_handler_util.h',
#        'test/event_waiter.h',
        'test/net_test_suite.cc',
        'test/net_test_suite.h',
#        'test/python_utils.cc',
#        'test/python_utils.h',
#        'test/spawned_test_server/base_test_server.cc',
#        'test/spawned_test_server/base_test_server.h',
#        'test/spawned_test_server/local_test_server.cc',
#        'test/spawned_test_server/local_test_server.h',
#        'test/spawned_test_server/local_test_server_posix.cc',
#        'test/spawned_test_server/local_test_server_win.cc',
#        'test/spawned_test_server/spawned_test_server.h',
#        'test/test_certificate_data.h',
#        'test/url_request/ssl_certificate_error_job.cc',
#        'test/url_request/ssl_certificate_error_job.h',
#        'test/url_request/url_request_failed_job.cc',
#        'test/url_request/url_request_failed_job.h',
#        'test/url_request/url_request_mock_data_job.cc',
#        'test/url_request/url_request_mock_data_job.h',
#        'test/url_request/url_request_slow_download_job.cc',
#        'test/url_request/url_request_slow_download_job.h',
#        'url_request/test_url_fetcher_factory.cc',
#        'url_request/test_url_fetcher_factory.h',
#        'url_request/url_request_test_util.cc',
#        'url_request/url_request_test_util.h',
      ],
      'conditions': [
        ['OS != "ios"', {
          'dependencies': [
            '../third_party/protobuf/protobuf.gyp:py_proto',
          ],
        }, {
          'sources!': [
            'test/spawned_test_server/base_test_server.cc',
            'test/spawned_test_server/base_test_server.h',
            'test/spawned_test_server/local_test_server.cc',
            'test/spawned_test_server/local_test_server.h',
            'test/spawned_test_server/local_test_server_posix.cc',
            'test/spawned_test_server/local_test_server_win.cc',
            'test/spawned_test_server/spawned_test_server.h',
          ],
        }],
        ['use_nss_verifier == 1', {
          'conditions': [
            [ 'desktop_linux == 1 or chromeos == 1', {
              'dependencies': [
                '../build/linux/system.gyp:ssl',
              ],
            }, {  # desktop_linux == 0 and chromeos == 0
              'dependencies': [
#                '../third_party/nss/nss.gyp:nspr',
#                '../third_party/nss/nss.gyp:nss',
#                'third_party/nss/ssl.gyp:libssl',
              ],
            }],
          ],
        }],
        ['OS == "android"', {
          'dependencies': [
            'net_test_jni_headers',
          ],
          'sources': [
            'test/embedded_test_server/android/embedded_test_server_android.cc',
            'test/embedded_test_server/android/embedded_test_server_android.h',
            'test/spawned_test_server/remote_test_server.cc',
            'test/spawned_test_server/remote_test_server.h',
            'test/spawned_test_server/spawner_communicator.cc',
            'test/spawned_test_server/spawner_communicator.h',
          ],
        }],
        [ 'use_v8_in_net==1', {
            'dependencies': [
              'net_with_v8',
            ],
          },
        ],
        [ 'enable_mdns != 1', {
            'sources!' : [
              'dns/mock_mdns_socket_factory.cc',
              'dns/mock_mdns_socket_factory.h'
            ]
        }],
        [ 'use_nss_certs != 1', {
            'sources!': [
              'test/cert_test_util_nss.cc',
            ],
        }],
        ['disable_file_support != 1', {
          'sources': [
#            'test/url_request/url_request_mock_http_job.cc',
#            'test/url_request/url_request_mock_http_job.h',
#            'url_request/test_url_request_interceptor.cc',
#            'url_request/test_url_request_interceptor.h',
          ],
        }],
      ],
      # TODO(jschuh): crbug.com/167187 fix size_t to int truncations.
      'msvs_disabled_warnings': [4267, ],
    },
    {
      'target_name': 'net_resources',
      'type': 'none',
      'variables': {
        'grit_out_dir': '<(SHARED_INTERMEDIATE_DIR)/net',
      },
#      'actions': [
#        {
#          'action_name': 'net_resources',
#          'variables': {
#            'grit_grd_file': 'base/net_resources.grd',
#          },
#          'includes': [ '../build/grit_action.gypi' ],
#        },
#      ],
    },
    {
      'target_name': 'net_extras',
      'type': 'static_library',
      'variables': { 'enable_wexit_time_destructors': 1, },
      'dependencies': [
        '../base/base.gyp:base',
#        '../sql/sql.gyp:sql',
        'net',
      ],
      'sources': [
        '<@(net_extras_sources)',
      ],
    },
    {
      'target_name': 'net_docs',
      'type': 'none',
      'actions': [
        {
          'action_name': 'net_docs',
          'variables': {
            'net_docs_input_dir': '.',
          },
          'inputs': [
            '<@(net_docs_sources)',
          ],
          'outputs': [
            '<(net_docs_output_dir)',
          ],
          'action': [
            'python',
            '<(net_docs_script)',
            '--input_path',
            '<(net_docs_input_dir)',
            '--output_path',
            '<(net_docs_output_dir)',
            '<@(net_docs_sources)',
          ],
          'message': 'Rendering network stack documentation',
        }
      ],
    },
    {
      'target_name': 'http_server',
      'type': 'static_library',
      'variables': { 'enable_wexit_time_destructors': 1, },
      'dependencies': [
        '../base/base.gyp:base',
        'net',
      ],
      'sources': [
        'server/http_connection.cc',
        'server/http_connection.h',
        'server/http_server.cc',
        'server/http_server.h',
        'server/http_server_request_info.cc',
        'server/http_server_request_info.h',
        'server/http_server_response_info.cc',
        'server/http_server_response_info.h',
        'server/web_socket.cc',
        'server/web_socket.h',
        'server/web_socket_encoder.cc',
        'server/web_socket_encoder.h',
      ],
      # TODO(jschuh): crbug.com/167187 fix size_t to int truncations.
      'msvs_disabled_warnings': [4267, ],
    },
    { # GN version: //net:balsa
      'target_name': 'balsa',
      'type': 'static_library',
      'dependencies': [
        '../base/base.gyp:base',
        'net',
      ],
      'sources': [
        'tools/balsa/balsa_enums.h',
        'tools/balsa/balsa_frame.cc',
        'tools/balsa/balsa_frame.h',
        'tools/balsa/balsa_headers.cc',
        'tools/balsa/balsa_headers.h',
        'tools/balsa/balsa_headers_token_utils.cc',
        'tools/balsa/balsa_headers_token_utils.h',
        'tools/balsa/balsa_visitor_interface.h',
        'tools/balsa/http_message_constants.cc',
        'tools/balsa/http_message_constants.h',
        'tools/balsa/noop_balsa_visitor.h',
        'tools/balsa/simple_buffer.cc',
        'tools/balsa/simple_buffer.h',
        'tools/balsa/string_piece_utils.h',
        'tools/quic/spdy_balsa_utils.cc',
        'tools/quic/spdy_balsa_utils.h',
      ],
    },
    {
      'target_name': 'cachetool',
      'type': 'executable',
      'dependencies': [
        '../base/base.gyp:base',
        'net',
        'net_test_support',
      ],
      'sources': [
        'tools/cachetool/cachetool.cc',
      ],
    },
    {
      'target_name': 'dump_cache',
      'type': 'executable',
      'dependencies': [
        '../base/base.gyp:base',
        'net',
        'net_test_support',
      ],
      'sources': [
        'tools/dump_cache/dump_cache.cc',
        'tools/dump_cache/dump_files.cc',
        'tools/dump_cache/dump_files.h',
      ],
      # TODO(jschuh): crbug.com/167187 fix size_t to int truncations.
      'msvs_disabled_warnings': [4267, ],
    },
    {
      'target_name': 'simple_quic_tools',
      'type': 'static_library',
      'dependencies': [
        '../base/base.gyp:base',
        '../base/third_party/dynamic_annotations/dynamic_annotations.gyp:dynamic_annotations',
        '../url/url.gyp:url_lib',
        'net',
        'net_quic_proto',
      ],
      'sources': [
        'tools/quic/quic_client_base.cc',
        'tools/quic/quic_client_base.h',
        'tools/quic/quic_client_session.cc',
        'tools/quic/quic_client_session.h',
        'tools/quic/quic_dispatcher.cc',
        'tools/quic/quic_dispatcher.h',
        'tools/quic/quic_in_memory_cache.cc',
        'tools/quic/quic_in_memory_cache.h',
        'tools/quic/quic_per_connection_packet_writer.cc',
        'tools/quic/quic_per_connection_packet_writer.h',
        'tools/quic/quic_process_packet_interface.h',
        'tools/quic/quic_server_session_base.cc',
        'tools/quic/quic_server_session_base.h',
        'tools/quic/quic_simple_client.cc',
        'tools/quic/quic_simple_client.h',
        'tools/quic/quic_simple_per_connection_packet_writer.cc',
        'tools/quic/quic_simple_per_connection_packet_writer.h',
        'tools/quic/quic_simple_server.cc',
        'tools/quic/quic_simple_server.h',
        'tools/quic/quic_simple_server_packet_writer.cc',
        'tools/quic/quic_simple_server_packet_writer.h',
        'tools/quic/quic_simple_server_session.cc',
        'tools/quic/quic_simple_server_session.h',
        'tools/quic/quic_spdy_client_stream.cc',
        'tools/quic/quic_spdy_client_stream.h',
        'tools/quic/quic_simple_server_stream.cc',
        'tools/quic/quic_simple_server_stream.h',
        'tools/quic/quic_time_wait_list_manager.cc',
        'tools/quic/quic_time_wait_list_manager.h',
        'tools/quic/synchronous_host_resolver.cc',
        'tools/quic/synchronous_host_resolver.h',
      ],
    },
    {
      # GN version: //net:stale_while_revalidate_experiment_domains
      'target_name': 'stale_while_revalidate_experiment_domains',
      'type': 'static_library',
      'dependencies': [
        '../base/base.gyp:base',
        'net',
        'net_derived_sources',
      ],
      'sources': [
        'base/stale_while_revalidate_experiment_domains.cc',
        'base/stale_while_revalidate_experiment_domains.h',
      ],
    },
  ],
  'conditions': [
    ['use_v8_in_net == 1', {
      'targets': [
        {
          'target_name': 'net_with_v8',
          'type': '<(component)',
          'variables': { 'enable_wexit_time_destructors': 1, },
          'dependencies': [
            '../base/base.gyp:base',
#            '../gin/gin.gyp:gin',
            '../url/url.gyp:url_lib',
#            '../v8/tools/gyp/v8.gyp:v8',
            'net'
          ],
          'defines': [
            'NET_IMPLEMENTATION',
          ],
          'sources': [
#            'proxy/proxy_resolver_v8.cc',
#            'proxy/proxy_resolver_v8.h',
#            'proxy/proxy_resolver_v8_tracing.cc',
#            'proxy/proxy_resolver_v8_tracing.h',
#            'proxy/proxy_resolver_v8_tracing_wrapper.cc',
#            'proxy/proxy_resolver_v8_tracing_wrapper.h',
#            'proxy/proxy_service_v8.cc',
#            'proxy/proxy_service_v8.h',
          ],
          # TODO(jschuh): crbug.com/167187 fix size_t to int truncations.
          'msvs_disabled_warnings': [4267, ],
        },
      ],
    }],
    ['use_v8_in_net == 1 and OS != "android"', {
      'targets': [
        {
          # GN version: //net/interfaces
          'target_name': 'net_interfaces',
          'type': 'static_library',
          'sources': [
#            'interfaces/host_resolver_service.mojom',
#            'interfaces/proxy_resolver_service.mojom',
          ],
#          'includes': [
#            '../mojo/mojom_bindings_generator.gypi',
#          ],
        },
        {
          # GN version: //net:net_browser_services
          'target_name': 'net_browser_services',
          'type': 'static_library',
          'sources': [
#            'dns/mojo_host_resolver_impl.cc',
#            'dns/mojo_host_resolver_impl.h',
#            'proxy/in_process_mojo_proxy_resolver_factory.cc',
#            'proxy/in_process_mojo_proxy_resolver_factory.h',
#            'proxy/mojo_proxy_resolver_factory.h',
#            'proxy/proxy_resolver_factory_mojo.cc',
#            'proxy/proxy_resolver_factory_mojo.h',
#            'proxy/proxy_service_mojo.cc',
#            'proxy/proxy_service_mojo.h',
          ],
          'dependencies': [
#            'mojo_type_converters',
            'net',
            'net_interfaces',
#            '../mojo/mojo_base.gyp:mojo_common_lib',
#            '../mojo/mojo_base.gyp:mojo_url_type_converters',
#            '../mojo/mojo_public.gyp:mojo_cpp_bindings',
#
            # NOTE(amistry): As long as we support in-process Mojo v8 PAC, we
            # need this dependency since in_process_mojo_proxy_resolver_factory
            # creates the utility process side Mojo services in the browser
            # process.  Ultimately, this will go away when we only support
            # out-of-process.
#            'net_utility_services',
          ],
        },
        {
          # GN version: //net:net_utility_services
          'target_name': 'net_utility_services',
          'type': 'static_library',
          'sources': [
            'dns/host_resolver_mojo.cc',
            'dns/host_resolver_mojo.h',
            'proxy/mojo_proxy_resolver_factory_impl.cc',
            'proxy/mojo_proxy_resolver_factory_impl.h',
            'proxy/mojo_proxy_resolver_impl.cc',
            'proxy/mojo_proxy_resolver_impl.h',
            'proxy/mojo_proxy_resolver_v8_tracing_bindings.h',
          ],
          'dependencies': [
            'mojo_type_converters',
            'net_interfaces',
            'net_with_v8',
#            '../mojo/mojo_base.gyp:mojo_url_type_converters',
#            '../mojo/mojo_public.gyp:mojo_cpp_bindings',
          ],
        },
        {
          # GN version: //net:mojo_type_converters
          'target_name': 'mojo_type_converters',
          'type': 'static_library',
          'sources': [
            'dns/mojo_host_type_converters.cc',
            'dns/mojo_host_type_converters.h',
            'proxy/mojo_proxy_type_converters.cc',
            'proxy/mojo_proxy_type_converters.h',
          ],
          'dependencies': [
            'net',
            'net_interfaces',
#            '../mojo/mojo_public.gyp:mojo_cpp_bindings',
          ],
        },
      ],
    }],
    ['OS != "ios" and OS != "android"', {
      'targets': [
        # iOS doesn't have the concept of simple executables, these targets
        # can't be compiled on the platform.
        {
          'target_name': 'crash_cache',
          'type': 'executable',
          'dependencies': [
            '../base/base.gyp:base',
            'net',
            'net_test_support',
          ],
          'sources': [
            'tools/crash_cache/crash_cache.cc',
          ],
          # TODO(jschuh): crbug.com/167187 fix size_t to int truncations.
          'msvs_disabled_warnings': [4267, ],
        },
        {
          'target_name': 'crl_set_dump',
          'type': 'executable',
          'dependencies': [
            '../base/base.gyp:base',
            'net',
          ],
          'sources': [
            'tools/crl_set_dump/crl_set_dump.cc',
          ],
          # TODO(jschuh): crbug.com/167187 fix size_t to int truncations.
          'msvs_disabled_warnings': [4267, ],
        },
        {
          'target_name': 'dns_fuzz_stub',
          'type': 'executable',
          'dependencies': [
            '../base/base.gyp:base',
            'net',
          ],
          'sources': [
            'tools/dns_fuzz_stub/dns_fuzz_stub.cc',
          ],
          # TODO(jschuh): crbug.com/167187 fix size_t to int truncations.
          'msvs_disabled_warnings': [4267, ],
        },
        {
          'target_name': 'gdig',
          'type': 'executable',
          'dependencies': [
            '../base/base.gyp:base',
            'net',
          ],
          'sources': [
            'tools/gdig/file_net_log.cc',
            'tools/gdig/gdig.cc',
          ],
        },
        {
          'target_name': 'get_server_time',
          'type': 'executable',
          'dependencies': [
            '../base/base.gyp:base',
#            '../base/base.gyp:base_i18n',
            '../url/url.gyp:url_lib',
            'net',
          ],
          'sources': [
            'tools/get_server_time/get_server_time.cc',
          ],
          # TODO(jschuh): crbug.com/167187 fix size_t to int truncations.
          'msvs_disabled_warnings': [4267, ],
        },
        {
          'target_name': 'hpack_example_generator',
          'type': 'executable',
          'dependencies': [
            '../base/base.gyp:base',
            'net',
          ],
          'sources': [
            'spdy/fuzzing/hpack_example_generator.cc',
          ],
          # TODO(jschuh): crbug.com/167187 fix size_t to int truncations.
          'msvs_disabled_warnings': [4267, ],
        },
        {
          'target_name': 'hpack_fuzz_mutator',
          'type': 'executable',
          'dependencies': [
            '../base/base.gyp:base',
            'net',
          ],
          'sources': [
            'spdy/fuzzing/hpack_fuzz_mutator.cc',
          ],
          # TODO(jschuh): crbug.com/167187 fix size_t to int truncations.
          'msvs_disabled_warnings': [4267, ],
        },
        {
          'target_name': 'hpack_fuzz_wrapper',
          'type': 'executable',
          'dependencies': [
            '../base/base.gyp:base',
            'net',
          ],
          'sources': [
            'spdy/fuzzing/hpack_fuzz_wrapper.cc',
          ],
          # TODO(jschuh): crbug.com/167187 fix size_t to int truncations.
          'msvs_disabled_warnings': [4267, ],
        },
        {
          'target_name': 'net_watcher',
          'type': 'executable',
          'dependencies': [
            '../base/base.gyp:base',
            'net',
            'net_with_v8',
          ],
          'conditions': [
            [ 'use_glib == 1', {
                'dependencies': [
                  '../build/linux/system.gyp:gconf',
                  '../build/linux/system.gyp:gio',
                ],
              },
            ],
          ],
          'sources': [
            'tools/net_watcher/net_watcher.cc',
          ],
        },
        {
          'target_name': 'run_testserver',
          'type': 'executable',
          'dependencies': [
            '../base/base.gyp:base',
            '../base/base.gyp:test_support_base',
            '../testing/gtest.gyp:gtest',
            'net_test_support',
          ],
          'sources': [
            'tools/testserver/run_testserver.cc',
          ],
        },
        {
          'target_name': 'quic_client',
          'type': 'executable',
          'dependencies': [
            '../base/base.gyp:base',
            '../url/url.gyp:url_lib',
            'net',
            'simple_quic_tools',
          ],
          'sources': [
            'tools/quic/quic_simple_client_bin.cc',
          ],
        },
        {
          'target_name': 'quic_server',
          'type': 'executable',
          'dependencies': [
            '../base/base.gyp:base',
            'net',
            'net_quic_proto',
            'simple_quic_tools',
          ],
          'sources': [
            'tools/quic/quic_simple_server_bin.cc',
          ],
        },
        {
          'target_name': 'stress_cache',
          'type': 'executable',
          'dependencies': [
            '../base/base.gyp:base',
            'net',
            'net_test_support',
          ],
          'sources': [
            'tools/stress_cache/stress_cache.cc',
          ],
          # TODO(jschuh): crbug.com/167187 fix size_t to int truncations.
          'msvs_disabled_warnings': [4267, ],
        },
        {
          'target_name': 'tld_cleanup',
          'type': 'executable',
          'dependencies': [
            '../base/base.gyp:base',
#            '../base/base.gyp:base_i18n',
#            '../net/tools/tld_cleanup/tld_cleanup.gyp:tld_cleanup_util',
          ],
          'sources': [
            'tools/tld_cleanup/tld_cleanup.cc',
          ],
          # TODO(jschuh): crbug.com/167187 fix size_t to int truncations.
          'msvs_disabled_warnings': [4267, ],
        },
      ],
    }],
    ['os_posix == 1 and OS != "mac" and OS != "ios" and OS != "android"', {
      'targets': [
        {
          'target_name': 'epoll_server',
          'type': 'static_library',
          'dependencies': [
            '../base/base.gyp:base',
            'net',
          ],
          'sources': [
            'tools/epoll_server/epoll_server.cc',
            'tools/epoll_server/epoll_server.h',
          ],
        },
        {
          'target_name': 'flip_in_mem_edsm_server_base',
          'type': 'static_library',
          'cflags': [
            '-Wno-deprecated',
          ],
          'dependencies': [
            '../base/base.gyp:base',
            '../third_party/boringssl/boringssl.gyp:boringssl',
            'balsa',
            'epoll_server',
            'net',
          ],
          'sources': [
            'tools/flip_server/acceptor_thread.cc',
            'tools/flip_server/acceptor_thread.h',
            'tools/flip_server/constants.h',
            'tools/flip_server/flip_config.cc',
            'tools/flip_server/flip_config.h',
            'tools/flip_server/http_interface.cc',
            'tools/flip_server/http_interface.h',
            'tools/flip_server/mem_cache.cc',
            'tools/flip_server/mem_cache.h',
            'tools/flip_server/output_ordering.cc',
            'tools/flip_server/output_ordering.h',
            'tools/flip_server/ring_buffer.cc',
            'tools/flip_server/ring_buffer.h',
            'tools/flip_server/sm_connection.cc',
            'tools/flip_server/sm_connection.h',
            'tools/flip_server/sm_interface.h',
            'tools/flip_server/spdy_interface.cc',
            'tools/flip_server/spdy_interface.h',
            'tools/flip_server/spdy_ssl.cc',
            'tools/flip_server/spdy_ssl.h',
            'tools/flip_server/spdy_util.cc',
            'tools/flip_server/spdy_util.h',
            'tools/flip_server/streamer_interface.cc',
            'tools/flip_server/streamer_interface.h',
            'tools/flip_server/tcp_socket_util.cc',
            'tools/flip_server/tcp_socket_util.h',
            'tools/flip_server/url_to_filename_encoder.cc',
            'tools/flip_server/url_to_filename_encoder.h',
            'tools/flip_server/url_utilities.cc',
            'tools/flip_server/url_utilities.h',
          ],
        },
        {
          'target_name': 'flip_in_mem_edsm_server_unittests',
          'type': 'executable',
          'dependencies': [
              '../testing/gtest.gyp:gtest',
              '../testing/gmock.gyp:gmock',
              '../third_party/boringssl/boringssl.gyp:boringssl',
              'flip_in_mem_edsm_server_base',
              'net',
              'net_test_support',
          ],
          'sources': [
            'tools/flip_server/flip_test_utils.cc',
            'tools/flip_server/flip_test_utils.h',
            'tools/flip_server/http_interface_test.cc',
            'tools/flip_server/mem_cache_test.cc',
            'tools/flip_server/run_all_tests.cc',
            'tools/flip_server/spdy_interface_test.cc',
            'tools/flip_server/url_to_filename_encoder_unittest.cc',
            'tools/flip_server/url_utilities_unittest.cc',
          ],
        },
        {
          'target_name': 'flip_in_mem_edsm_server',
          'type': 'executable',
          'cflags': [
            '-Wno-deprecated',
          ],
          'dependencies': [
            '../base/base.gyp:base',
            'flip_in_mem_edsm_server_base',
            'net',
          ],
          'sources': [
            'tools/flip_server/flip_in_mem_edsm_server.cc',
          ],
        },
        {
          'target_name': 'epoll_quic_tools',
          'type': 'static_library',
          'dependencies': [
            '../base/base.gyp:base',
            '../base/third_party/dynamic_annotations/dynamic_annotations.gyp:dynamic_annotations',
            '../url/url.gyp:url_lib',
            'balsa',
            'epoll_server',
            'net',
            'net_quic_proto',
          ],
          'sources': [
            'tools/quic/quic_client.cc',
            'tools/quic/quic_client.h',
            'tools/quic/quic_default_packet_writer.cc',
            'tools/quic/quic_default_packet_writer.h',
            'tools/quic/quic_epoll_clock.cc',
            'tools/quic/quic_epoll_clock.h',
            'tools/quic/quic_epoll_connection_helper.cc',
            'tools/quic/quic_epoll_connection_helper.h',
            'tools/quic/quic_packet_reader.cc',
            'tools/quic/quic_packet_reader.h',
            'tools/quic/quic_packet_writer_wrapper.cc',
            'tools/quic/quic_packet_writer_wrapper.h',
            'tools/quic/quic_server.cc',
            'tools/quic/quic_server.h',
            'tools/quic/quic_socket_utils.cc',
            'tools/quic/quic_socket_utils.h',
          ],
        },
        {
          'target_name': 'epoll_quic_client',
          'type': 'executable',
          'dependencies': [
            '../base/base.gyp:base',
            'net',
            'epoll_quic_tools',
            'simple_quic_tools',
          ],
          'sources': [
            'tools/quic/quic_client_bin.cc',
          ],
        },
        {
          'target_name': 'epoll_quic_server',
          'type': 'executable',
          'dependencies': [
            '../base/base.gyp:base',
            'net',
            'net_quic_proto',
            'epoll_quic_tools',
            'simple_quic_tools',
          ],
          'sources': [
            'tools/quic/quic_server_bin.cc',
          ],
        },
      ]
    }],
    ['OS=="android"', {
      'targets': [
        { # The same target as 'net', but with smaller binary size due to
          # exclusion of ICU, FTP, FILE and WebSockets support.
          'target_name': 'net_small',
          'variables': {
            'disable_ftp_support': 1,
            'disable_file_support': 1,
            'enable_websockets': 0,
          },
          'dependencies': [
            '../url/url.gyp:url_lib_use_icu_alternatives_on_android',
          ],
          'defines': [
            'USE_ICU_ALTERNATIVES_ON_ANDROID=1',
            'DISABLE_FILE_SUPPORT=1',
            'DISABLE_FTP_SUPPORT=1',
          ],
          'sources': [
            'filter/brotli_filter_disabled.cc',
            'base/net_string_util_icu_alternatives_android.cc',
            'base/net_string_util_icu_alternatives_android.h',
          ],
          'includes': [ 'net_common.gypi' ],
        },
        {
          'target_name': 'net_jni_headers',
          'type': 'none',
          'sources': [
            'android/java/src/org/chromium/net/AndroidCertVerifyResult.java',
            'android/java/src/org/chromium/net/AndroidKeyStore.java',
            'android/java/src/org/chromium/net/AndroidNetworkLibrary.java',
            'android/java/src/org/chromium/net/AndroidTrafficStats.java',
            'android/java/src/org/chromium/net/GURLUtils.java',
            'android/java/src/org/chromium/net/HttpNegotiateAuthenticator.java',
            'android/java/src/org/chromium/net/NetStringUtil.java',
            'android/java/src/org/chromium/net/NetworkChangeNotifier.java',
            'android/java/src/org/chromium/net/ProxyChangeListener.java',
            'android/java/src/org/chromium/net/X509Util.java',
          ],
          'variables': {
            'jni_gen_package': 'net',
          },
          'includes': [ '../build/jni_generator.gypi' ],
        },
        {
          'target_name': 'net_test_jni_headers',
          'type': 'none',
          'sources': [
            'android/javatests/src/org/chromium/net/AndroidKeyStoreTestUtil.java',
            'test/android/javatests/src/org/chromium/net/test/EmbeddedTestServerImpl.java',
            'test/android/javatests/src/org/chromium/net/test/DummySpnegoAuthenticator.java',
          ],
          'variables': {
            'jni_gen_package': 'net/test',
          },
          'includes': [ '../build/jni_generator.gypi' ],
        },
        {
          'target_name': 'net_java',
          'type': 'none',
          'variables': {
            'java_in_dir': '../net/android/java',
          },
          'dependencies': [
            '../base/base.gyp:base',
            'cert_verify_status_android_java',
            'certificate_mime_types_java',
            'network_change_notifier_types_java',
            'network_change_notifier_android_types_java',
            'net_errors_java',
            'private_key_types_java',
            'traffic_stats_error_java',
          ],
          'includes': [ '../build/java.gypi' ],
        },
        {
          'target_name': 'embedded_test_server_aidl',
          'type': 'none',
          'variables': {
            'aidl_interface_file': '../net/test/android/javatests/src/org/chromium/net/test/IEmbeddedTestServerInterface.aidl',
          },
          'sources': [
            '../net/test/android/javatests/src/org/chromium/net/test/IEmbeddedTestServerImpl.aidl',
          ],
          'includes': [ '../build/java_aidl.gypi' ],
        },
        {
          'target_name': 'net_java_test_support',
          'type': 'none',
          'variables': {
            'java_in_dir': '../net/test/android/javatests',
            # TODO(jbudorick): remove chromium_code: 0 line once crbug.com/488192 is fixed.
            'chromium_code': 0,
          },
          'dependencies': [
            'embedded_test_server_aidl',
            'net_java',
            'url_request_failed_job_java',
            '../base/base.gyp:base_java',
            '../base/base.gyp:base_java_test_support',
            '../third_party/android_tools/android_tools.gyp:legacy_http_javalib',
          ],
          'includes': [ '../build/java.gypi' ],
        },
        {
          'target_name': 'libnet_java_test_support',
          'type': 'shared_library',
          'dependencies': [
            'net_test_support',
            '../base/base.gyp:base',
          ],
          'sources': [
            'test/android/net_test_entry_point.cc',
            'test/android/net_test_jni_onload.cc',
            'test/android/net_test_jni_onload.h',
          ],
        },
        {
          'target_name': 'net_test_support_apk',
          'type': 'none',
          'dependencies': [
            'net_java_test_support',
          ],
          'variables': {
            'android_manifest_path': 'test/android/javatests/AndroidManifest.xml',
            'apk_name': 'ChromiumNetTestSupport',
            'is_test_apk': 1,
            'java_in_dir': 'test/android/javatests',
            'java_in_dir_suffix': '/src_dummy',
            'native_lib_target': 'libnet_java_test_support',
            'never_lint': 1,
          },
          'includes': [
            '../build/java_apk.gypi',
          ],
        },
        {
          # Targets that need the net test support APK should depend on this
          # target. It ensures that the APK is built without passing the
          # classpath on to dependent targets.
          'target_name': 'require_net_test_support_apk',
          'type': 'none',
          'actions': [
            {
              'action_name': 'require_ChromiumNetTestSupport',
              'variables': {
                'required_file': '<(PRODUCT_DIR)/net_test_support_apk/ChromiumNetTestSupport.apk.required',
              },
              'inputs': [
                '<(PRODUCT_DIR)/apks/ChromiumNetTestSupport.apk',
              ],
              'outputs': [
                '<(required_file)',
              ],
              'action': [
                'python', '../build/android/gyp/touch.py', '<(required_file)',
              ],
            },
          ],
        },
        {
          'target_name': 'url_request_failed_job_java',
          'type': 'none',
          'variables': {
            'source_file': 'test/url_request/url_request_failed_job.h',
          },
          'includes': [ '../build/android/java_cpp_enum.gypi' ],
        },
        {
          'target_name': 'net_javatests',
          'type': 'none',
          'variables': {
            'java_in_dir': '../net/android/javatests',
          },
          'dependencies': [
            '../base/base.gyp:base',
            '../base/base.gyp:base_java_test_support',
            'net_java',
            'net_java_test_support',
          ],
          'includes': [ '../build/java.gypi' ],
        },
        {
          'target_name': 'net_errors_java',
          'type': 'none',
          'sources': [
            'android/java/NetError.template',
          ],
          'variables': {
            'package_name': 'org/chromium/net',
            'template_deps': ['base/net_error_list.h'],
          },
          'includes': [ '../build/android/java_cpp_template.gypi' ],
        },
        {
          'target_name': 'certificate_mime_types_java',
          'type': 'none',
          'variables': {
            'source_file': 'base/mime_util.h',
          },
          'includes': [ '../build/android/java_cpp_enum.gypi' ],
        },
        {
          'target_name': 'cert_verify_status_android_java',
          'type': 'none',
          'variables': {
            'source_file': 'android/cert_verify_result_android.h',
          },
          'includes': [ '../build/android/java_cpp_enum.gypi' ],
        },
        {
          'target_name': 'network_change_notifier_types_java',
          'type': 'none',
          'variables': {
            'source_file': 'base/network_change_notifier.h',
          },
          'includes': [ '../build/android/java_cpp_enum.gypi' ],
        },
        {
          'target_name': 'network_change_notifier_android_types_java',
          'type': 'none',
          'variables': {
            'source_file': 'android/network_change_notifier_android.cc',
          },
          'includes': [ '../build/android/java_cpp_enum.gypi' ],
        },
        {
          'target_name': 'private_key_types_java',
          'type': 'none',
          'variables': {
            'source_file': 'android/keystore.h',
          },
          'includes': [ '../build/android/java_cpp_enum.gypi' ],
        },
        {
          'target_name': 'traffic_stats_error_java',
          'type': 'none',
          'variables': {
            'source_file': 'android/traffic_stats.cc',
          },
          'includes': [ '../build/android/java_cpp_enum.gypi' ],
        },
        {
          'target_name': 'net_unittests_apk',
          'type': 'none',
          'dependencies': [
            'net_java',
            'net_javatests',
            'net_java_test_support',
            'net_unittests',
          ],
          'conditions': [
            ['v8_use_external_startup_data==1', {
              'dependencies': [
                '../v8/tools/gyp/v8.gyp:v8_external_snapshot',
              ],
              'variables': {
                'dest_path': '<(asset_location)',
                'renaming_sources': [
                  '<(PRODUCT_DIR)/natives_blob.bin',
                  '<(PRODUCT_DIR)/snapshot_blob.bin',
                ],
                'renaming_destinations': [
                  'natives_blob_<(arch_suffix).bin',
                  'snapshot_blob_<(arch_suffix).bin',
                ],
                'clear': 1,
              },
              'includes': ['../build/android/copy_ex.gypi'],
            }],
          ],
          'variables': {
            'test_suite_name': 'net_unittests',
            'isolate_file': 'net_unittests.isolate',
            'android_manifest_path': 'android/unittest_support/AndroidManifest.xml',
            'resource_dir': 'android/unittest_support/res',
            'conditions': [
              ['v8_use_external_startup_data==1', {
                'asset_location': '<(PRODUCT_DIR)/net_unittests_apk/assets',
                'additional_input_paths': [
                  '<(PRODUCT_DIR)/net_unittests_apk/assets/natives_blob_<(arch_suffix).bin',
                  '<(PRODUCT_DIR)/net_unittests_apk/assets/snapshot_blob_<(arch_suffix).bin',
                ],
              }],
            ],
          },
          'includes': [
            '../build/apk_test.gypi',
            '../build/android/v8_external_startup_data_arch_suffix.gypi',
          ],
        },
        {
          'target_name': 'net_junit_tests',
          'type': 'none',
          'dependencies': [
            'net_java',
            '../base/base.gyp:base',
            '../base/base.gyp:base_java_test_support',
            '../base/base.gyp:base_junit_test_support',
            '../testing/android/junit/junit_test.gyp:junit_test_support',
          ],
          'variables': {
            'main_class': 'org.chromium.testing.local.JunitTestMain',
            'src_paths': [
              'android/junit/',
            ],
            'test_type': 'junit',
            'wrapper_script_name': 'helper/<(_target_name)',
          },
          'includes': [
            '../build/android/test_runner.gypi',
            '../build/host_jar.gypi',
          ],
        },
      ],
      'conditions': [
        ['test_isolation_mode != "noop"',
          {
            'targets': [
              {
                'target_name': 'net_unittests_apk_run',
                'type': 'none',
                'dependencies': [
                  'net_unittests_apk',
                ],
                'includes': [
                  '../build/isolate.gypi',
                ],
                'sources': [
                  'net_unittests_apk.isolate',
                ],
              },
            ]
          }
        ],
      ],
    }],
    ['OS == "android" or OS == "linux"', {
      'targets': [
        {
          'target_name': 'disk_cache_memory_test',
          'type': 'executable',
          'dependencies': [
            '../base/base.gyp:base',
            'net',
          ],
          'sources': [
            'tools/disk_cache_memory_test/disk_cache_memory_test.cc',
          ],
        },
      ],
    }],
    ['OS == "linux"', {
      'targets': [
        {
          'target_name': 'content_decoder_tool',
          'type': 'executable',
          'dependencies': [
            '../base/base.gyp:base',
            'net',
          ],
          'sources': [
            'tools/content_decoder_tool/content_decoder_tool.cc',
            'filter/mock_filter_context.cc',
          ],
        }
      ],
    }],
    ['test_isolation_mode != "noop"', {
      'targets': [
        {
          'target_name': 'net_unittests_run',
          'type': 'none',
          'dependencies': [
            'net_unittests',
          ],
          'includes': [
            '../build/isolate.gypi',
          ],
          'sources': [
            'net_unittests.isolate',
          ],
        },
      ],
    }],
  ],
}
