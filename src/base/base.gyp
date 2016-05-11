# Copyright (c) 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

{
  'variables': {
    'chromium_code': 1,
  },
  'includes': [
    '../build/win_precompile.gypi',
    'base.gypi',
  ],
  'targets': [
    {
      'target_name': 'base',
      'type': '<(component)',
      'toolsets': ['host', 'target'],
      'variables': {
        'base_target': 1,
        'enable_wexit_time_destructors': 1,
        'optimize': 'max',
      },
      'dependencies': [
        'allocator/allocator.gyp:allocator',
        'allocator/allocator.gyp:allocator_features#target',
        'base_debugging_flags#target',
        'base_static',
        'base_build_date',
        '../testing/gtest.gyp:gtest_prod',
        '../third_party/modp_b64/modp_b64.gyp:modp_b64',
        'third_party/dynamic_annotations/dynamic_annotations.gyp:dynamic_annotations',
      ],
      # TODO(gregoryd): direct_dependent_settings should be shared with the
      #  64-bit target, but it doesn't work due to a bug in gyp
      'direct_dependent_settings': {
        'include_dirs': [
          '..',
        ],
      },
      'conditions': [
        ['desktop_linux == 1 or chromeos == 1', {
          'conditions': [
            ['chromeos==1', {
              'sources/': [ ['include', '_chromeos\\.cc$'] ]
            }],
          ],
          'dependencies': [
            'symbolize',
          ],
          'defines': [
            'USE_SYMBOLIZE',
          ],
        }, {  # desktop_linux == 0 and chromeos == 0
            'sources/': [
              ['exclude', '/xdg_user_dirs/'],
              ['exclude', '_nss\\.cc$'],
            ],
        }],
        ['use_glib==1', {
          'dependencies': [
            '../build/linux/system.gyp:glib',
          ],
          'export_dependent_settings': [
            '../build/linux/system.gyp:glib',
          ],
        }],
        ['OS == "linux"', {
          'link_settings': {
            'libraries': [
              # We need rt for clock_gettime().
              '-lrt',
              # For 'native_library_linux.cc'
              '-ldl',
            ],
          },
          'conditions': [
            ['use_allocator!="tcmalloc"', {
              'defines': [
                'NO_TCMALLOC',
              ],
              'direct_dependent_settings': {
                'defines': [
                  'NO_TCMALLOC',
                ],
              },
            }],
          ],
        }],
        ['OS != "win" and (OS != "ios" or _toolset == "host")', {
            'dependencies': ['third_party/libevent/libevent.gyp:libevent'],
        },],
      ],
      'sources': [
        'auto_reset.h',
        'linux_util.h',
        'message_loop/message_pump_glib.cc',
        'message_loop/message_pump_glib.h',
        'message_loop/message_pump_io_ios.h',
        'message_loop/message_pump_libevent.h',
        'metrics/field_trial.cc',
        'metrics/field_trial.h',
        'posix/file_descriptor_shuffle.h',
        'sync_socket.h',
        'third_party/xdg_user_dirs/xdg_user_dir_lookup.cc',
        'third_party/xdg_user_dirs/xdg_user_dir_lookup.h',
      ],
      'includes': [
        '../build/android/increase_size_for_speed.gypi',
      ],
    },
    {
      # This is the subset of files from base that should not be used with a
      # dynamic library. Note that this library cannot depend on base because
      # base depends on base_static.
      'target_name': 'base_static',
      'type': 'static_library',
      'variables': {
        'enable_wexit_time_destructors': 1,
        'optimize': 'max',
      },
      'toolsets': ['host', 'target'],
      'sources': [
        'base_switches.cc',
        'base_switches.h',
        'win/pe_image.cc',
        'win/pe_image.h',
      ],
      'include_dirs': [
        '..',
      ],
      'includes': [
        '../build/android/increase_size_for_speed.gypi',
      ],
    },
    {
      'type': 'none',
      'target_name': 'base_build_date',
      'hard_dependency': 1,
      'actions': [{
        'action_name': 'generate_build_date_headers',
        'inputs': [
          '<(DEPTH)/build/write_build_date_header.py',
          '<(DEPTH)/build/util/LASTCHANGE'
        ],
        'outputs': [ '<(SHARED_INTERMEDIATE_DIR)/base/generated_build_date.h' ],
        'action': [
          'python', '<(DEPTH)/build/write_build_date_header.py',
          '<(SHARED_INTERMEDIATE_DIR)/base/generated_build_date.h',
          '<(build_type)'
        ]
      }],
      'conditions': [
        [ 'buildtype == "Official"', {
          'variables': {
            'build_type': 'official'
          }
        }, {
          'variables': {
            'build_type': 'default'
          }
        }],
      ]
    },
    {
      # GN: //base/test:test_support
      'target_name': 'test_support_base',
      'type': 'static_library',
      'dependencies': [
        'base',
        'base_static',
#        'base_i18n',
        '../testing/gmock.gyp:gmock',
        '../testing/gtest.gyp:gtest',
        '../third_party/icu/icu.gyp:icuuc',
        '../third_party/icu/icu.gyp:icui18n',
        '../third_party/libxml/libxml.gyp:libxml',
        'third_party/dynamic_annotations/dynamic_annotations.gyp:dynamic_annotations',
      ],
      'export_dependent_settings': [
        'base',
      ],
      'conditions': [
        ['os_posix==0', {
          'sources!': [
            'test/scoped_locale.cc',
            'test/scoped_locale.h',
          ],
        }],
        ['os_bsd==1', {
          'sources!': [
            'test/test_file_util_linux.cc',
          ],
        }],
        ['OS == "android"', {
          'dependencies': [
            'base_unittests_jni_headers',
            'base_java_unittest_support',
          ],
        }],
        ['OS == "ios"', {
          'toolsets': ['host', 'target'],
        }],
      ],
      'sources': [
        'allocator/allocator_shim.cc',
        'debug/debugger.cc',
        'debug/debugger.h',
        'feature_list.cc',
        'feature_list.h',
        'files/scoped_temp_dir.cc',
        'files/scoped_temp_dir.h',
        'i18n/icu_util.cc',
        'i18n/rtl.cc',
        'i18n/rtl.h',
        'i18n/base_i18n_switches.cc',
        'i18n/base_i18n_switches.h',
        'i18n/icu_string_conversions.cc',
        'i18n/icu_string_conversions.h',
        'i18n/i18n_constants.cc',
        'i18n/i18n_constants.h',
        'json/json_file_value_serializer.cc',
        'json/json_file_value_serializer.h',
        'process/kill.cc',
        'process/kill_posix.cc',
        'process/kill.h',
        'process/launch.cc',
        'process/launch.h',
        'process/launch_posix.cc',
        'process/launch_win.cc',
        'process/memory_linux.cc',
        'process/memory_win.cc',
        'process/process_iterator.cc',
        'process/process_iterator.h',
        'process/process_iterator_linux.cc',
        'process/process_iterator_win.cc',
        'process/process_posix.cc',
        'process/process_win.cc',
        'process/process_handle.cc',
        'process/process_handle_linux.cc',
        'process/process_handle_mac.cc',
        'process/process_handle_posix.cc',
        'process/process_handle_win.cc',
'allocator/allocator_shim_default_dispatch_to_glibc.cc',
'allocator/allocator_shim_default_dispatch_to_tcmalloc.cc',

        'posix/file_descriptor_shuffle.cc',
        'test/gtest_util.cc',
        'test/gtest_util.h',
        'test/gtest_xml_unittest_result_printer.cc',
        'test/gtest_xml_unittest_result_printer.h',
        'test/gtest_xml_util.cc',
        'test/gtest_xml_util.h',
#        'test/histogram_tester.cc',
#        'test/histogram_tester.h',
#        'test/icu_test_util.cc',
#        'test/icu_test_util.h',
#        'test/ios/wait_util.h',
#        'test/ios/wait_util.mm',
        'test/launcher/test_launcher.cc',
        'test/launcher/test_launcher.h',
        'test/launcher/test_result.cc',
        'test/launcher/test_result.h',
        'test/launcher/test_results_tracker.cc',
        'test/launcher/test_results_tracker.h',
        'test/launcher/unit_test_launcher.cc',
        'test/launcher/unit_test_launcher.h',
        'test/launcher/unit_test_launcher_ios.cc',
#        'test/mock_chrome_application_mac.h',
#        'test/mock_chrome_application_mac.mm',
#        'test/mock_devices_changed_observer.cc',
#        'test/mock_devices_changed_observer.h',
#        'test/mock_entropy_provider.cc',
#        'test/mock_entropy_provider.h',
        'test/mock_log.cc',
        'test/mock_log.h',
        'test/multiprocess_test.cc',
        'test/multiprocess_test.h',
#        'test/multiprocess_test_android.cc',
#        'test/null_task_runner.cc',
#        'test/null_task_runner.h',
#        'test/opaque_ref_counted.cc',
#        'test/opaque_ref_counted.h',
#        'test/perf_log.cc',
#        'test/perf_log.h',
#        'test/perf_test_suite.cc',
#        'test/perf_test_suite.h',
#        'test/perf_time_logger.cc',
#        'test/perf_time_logger.h',
#        'test/power_monitor_test_base.cc',
#        'test/power_monitor_test_base.h',
#        'test/scoped_locale.cc',
#        'test/scoped_locale.h',
#        'test/scoped_path_override.cc',
#        'test/scoped_path_override.h',
#        'test/sequenced_task_runner_test_template.cc',
#        'test/sequenced_task_runner_test_template.h',
        'test/sequenced_worker_pool_owner.cc',
        'test/sequenced_worker_pool_owner.h',
#        'test/simple_test_clock.cc',
#        'test/simple_test_clock.h',
#        'test/simple_test_tick_clock.cc',
#        'test/simple_test_tick_clock.h',
#        'test/task_runner_test_template.cc',
#        'test/task_runner_test_template.h',
#        'test/test_discardable_memory_allocator.cc',
#        'test/test_discardable_memory_allocator.h',
#        'test/test_file_util.cc',
#        'test/test_file_util.h',
#        'test/test_file_util_android.cc',
#        'test/test_file_util_linux.cc',
#        'test/test_file_util_mac.cc',
#        'test/test_file_util_posix.cc',
#        'test/test_file_util_win.cc',
#        'test/test_io_thread.cc',
#        'test/test_io_thread.h',
#        'test/test_listener_ios.h',
#        'test/test_listener_ios.mm',
#        'test/test_mock_time_task_runner.cc',
#        'test/test_mock_time_task_runner.h',
#        'test/test_pending_task.cc',
#        'test/test_pending_task.h',
#        'test/test_reg_util_win.cc',
#        'test/test_reg_util_win.h',
#        'test/test_shortcut_win.cc',
#        'test/test_shortcut_win.h',
#        'test/test_simple_task_runner.cc',
#        'test/test_simple_task_runner.h',
        'test/test_suite.cc',
        'test/test_suite.h',
#        'test/test_support_android.cc',
#        'test/test_support_android.h',
#        'test/test_support_ios.h',
#        'test/test_support_ios.mm',
        'test/test_switches.cc',
        'test/test_switches.h',
        'test/test_timeouts.cc',
        'test/test_timeouts.h',
#        'test/test_ui_thread_android.cc',
#        'test/test_ui_thread_android.h',
#        'test/thread_test_helper.cc',
#        'test/thread_test_helper.h',
#        'test/trace_event_analyzer.cc',
#        'test/trace_event_analyzer.h',
        'test/trace_to_file.cc',
        'test/trace_to_file.h',
#        'test/user_action_tester.cc',
#        'test/user_action_tester.h',
#        'test/values_test_util.cc',
#        'test/values_test_util.h',
      ],
      'target_conditions': [
        ['OS == "ios"', {
          'sources/': [
            # Pull in specific Mac files for iOS (which have been filtered out
            # by file name rules).
            ['include', '^test/test_file_util_mac\\.cc$'],
          ],
        }],
        ['OS == "ios" and _toolset == "target"', {
          'sources!': [
            # iOS uses its own unit test launcher.
            'test/launcher/unit_test_launcher.cc',
          ],
        }],
        ['OS == "ios" and _toolset == "host"', {
          'sources!': [
            'test/launcher/unit_test_launcher_ios.cc',
            'test/test_support_ios.h',
            'test/test_support_ios.mm',
          ],
        }],
      ],  # target_conditions
    },
    {
      # GN version: //base/debug:debugging_flags
      # Since this generates a file, it most only be referenced in the target
      # toolchain or there will be multiple rules that generate the header.
      # When referenced from a target that might be compiled in the host
      # toolchain, always refer to 'base_debugging_flags#target'.
      'target_name': 'base_debugging_flags',
      'includes': [ '../build/buildflag_header.gypi' ],
      'variables': {
        'buildflag_header_path': 'base/debug/debugging_flags.h',
        'buildflag_flags': [
          'ENABLE_PROFILING=<(profiling)',
        ],
      },
    },
  ],
  'conditions': [
    ['OS!="ios"', {
      'targets': [
        {
          # GN: //base:check_example
          'target_name': 'check_example',
          'type': 'executable',
          'sources': [
            'check_example.cc',
          ],
          'dependencies': [
            'base',
          ],
        },
        {
          'target_name': 'build_utf8_validator_tables',
          'type': 'executable',
          'toolsets': ['host'],
          'dependencies': [
            'base',
            '../third_party/icu/icu.gyp:icuuc',
          ],
          'sources': [
            'i18n/build_utf8_validator_tables.cc'
          ],
        },
      ],
    }],
    ['os_posix==1 and OS!="mac" and OS!="ios"', {
      'targets': [
        {
          'target_name': 'symbolize',
          'type': 'static_library',
          'toolsets': ['host', 'target'],
          'variables': {
            'chromium_code': 0,
          },
          'conditions': [
            ['OS == "solaris"', {
              'include_dirs': [
                '/usr/gnu/include',
                '/usr/gnu/include/libelf',
              ],
            },],
          ],
          'cflags': [
            '-Wno-sign-compare',
          ],
          'cflags!': [
            '-Wextra',
          ],
          'defines': [
            'GLOG_BUILD_CONFIG_INCLUDE="build/build_config.h"',
          ],
          'sources': [
            'third_party/symbolize/config.h',
            'third_party/symbolize/demangle.cc',
            'third_party/symbolize/demangle.h',
            'third_party/symbolize/glog/logging.h',
            'third_party/symbolize/glog/raw_logging.h',
            'third_party/symbolize/symbolize.cc',
            'third_party/symbolize/symbolize.h',
            'third_party/symbolize/utilities.h',
          ],
          'include_dirs': [
            '..',
          ],
          'includes': [
            '../build/android/increase_size_for_speed.gypi',
          ],
        },
      ],
    }],
    ['OS == "linux"', {
      'targets': [
        {
          'target_name': 'malloc_wrapper',
          'type': 'shared_library',
          'dependencies': [
            'base',
          ],
          'sources': [
            'test/malloc_wrapper.cc',
          ],
        }
      ],
    }],
  ],
}
