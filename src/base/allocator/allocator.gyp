# Copyright (c) 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

{
  'target_defaults': {
    'variables': {
      # This code gets run a lot and debugged rarely, so it should be fast
      # by default. See http://crbug.com/388949.
      'debug_optimize': '2',
      'win_debug_Optimization': '0',
      # Run time checks are incompatible with any level of optimizations.
      'win_debug_RuntimeChecks': '0',
    },
  },
  'variables': {
    'tcmalloc_dir': '../../third_party/tcmalloc/chromium',
    'use_vtable_verify%': 0,
    # Provide a way to force disable debugallocation in Debug builds
    # e.g. for profiling (it's more rare to profile Debug builds,
    # but people sometimes need to do that).
    'disable_debugallocation%': 0,
  },
  'targets': [
    # The only targets that should depend on allocator are 'base' and
    # executables that don't depend, directly or indirectly, on base (a few).
    # All the other targets get a transitive dependency on this target via base.
    {
      'target_name': 'allocator',
      'variables': {
        'conditions': [
          ['use_allocator!="none" or (OS=="win" and win_use_allocator_shim==1)', {
            'allocator_target_type%': 'static_library',
          }, {
            'allocator_target_type%': 'none',
          }],
        ],
      },
      'type': '<(allocator_target_type)',
      'toolsets': ['host', 'target'],
      'conditions': [
        ['OS=="win" and win_use_allocator_shim==1', {
          'msvs_settings': {
            # TODO(sgk):  merge this with build/common.gypi settings
            'VCLibrarianTool': {
              'AdditionalOptions': ['/ignore:4006,4221'],
            },
            'VCLinkerTool': {
              'AdditionalOptions': ['/ignore:4006'],
            },
          },
          'include_dirs': [
            '../..',
          ],
          'sources': [
            'allocator_shim_win.cc',
            'allocator_shim_win.h',
          ],
          'configurations': {
            'Debug_Base': {
              'msvs_settings': {
                'VCCLCompilerTool': {
                  'RuntimeLibrary': '0',
                },
              },
            },
          },
        }],  # OS=="win"
        ['use_allocator=="tcmalloc"', {
          # Disable the heap checker in tcmalloc.
          'defines': [
            'NO_HEAP_CHECK',
          ],
          'dependencies': [
            '../third_party/dynamic_annotations/dynamic_annotations.gyp:dynamic_annotations',
          ],
          # The order of this include_dirs matters, as tc-malloc has its own
          # base/ mini-fork. Do not factor these out of this conditions section.
          'include_dirs': [
            '.',
            '<(tcmalloc_dir)/src/base',
            '<(tcmalloc_dir)/src',
            '../..',
          ],
          'sources': [
            # Generated for our configuration from tcmalloc's build
            # and checked in.
            '<(tcmalloc_dir)/src/config.h',
            '<(tcmalloc_dir)/src/config_android.h',
            '<(tcmalloc_dir)/src/config_linux.h',
            '<(tcmalloc_dir)/src/config_win.h',

            # all tcmalloc native and forked files
            '<(tcmalloc_dir)/src/addressmap-inl.h',
            '<(tcmalloc_dir)/src/base/abort.cc',
            '<(tcmalloc_dir)/src/base/abort.h',
            '<(tcmalloc_dir)/src/base/arm_instruction_set_select.h',
            '<(tcmalloc_dir)/src/base/atomicops-internals-arm-generic.h',
            '<(tcmalloc_dir)/src/base/atomicops-internals-arm-v6plus.h',
            '<(tcmalloc_dir)/src/base/atomicops-internals-linuxppc.h',
            '<(tcmalloc_dir)/src/base/atomicops-internals-macosx.h',
            '<(tcmalloc_dir)/src/base/atomicops-internals-windows.h',
            '<(tcmalloc_dir)/src/base/atomicops-internals-x86.cc',
            '<(tcmalloc_dir)/src/base/atomicops-internals-x86.h',
            '<(tcmalloc_dir)/src/base/atomicops.h',
            '<(tcmalloc_dir)/src/base/commandlineflags.h',
            '<(tcmalloc_dir)/src/base/cycleclock.h',
            # We don't list dynamic_annotations.c since its copy is already
            # present in the dynamic_annotations target.
            '<(tcmalloc_dir)/src/base/dynamic_annotations.h',
            '<(tcmalloc_dir)/src/base/elf_mem_image.cc',
            '<(tcmalloc_dir)/src/base/elf_mem_image.h',
            '<(tcmalloc_dir)/src/base/elfcore.h',
            '<(tcmalloc_dir)/src/base/googleinit.h',
            '<(tcmalloc_dir)/src/base/linux_syscall_support.h',
            '<(tcmalloc_dir)/src/base/linuxthreads.cc',
            '<(tcmalloc_dir)/src/base/linuxthreads.h',
            '<(tcmalloc_dir)/src/base/logging.cc',
            '<(tcmalloc_dir)/src/base/logging.h',
            '<(tcmalloc_dir)/src/base/low_level_alloc.cc',
            '<(tcmalloc_dir)/src/base/low_level_alloc.h',
            '<(tcmalloc_dir)/src/base/simple_mutex.h',
            '<(tcmalloc_dir)/src/base/spinlock.cc',
            '<(tcmalloc_dir)/src/base/spinlock.h',
            '<(tcmalloc_dir)/src/base/spinlock_internal.cc',
            '<(tcmalloc_dir)/src/base/spinlock_internal.h',
            '<(tcmalloc_dir)/src/base/spinlock_linux-inl.h',
            '<(tcmalloc_dir)/src/base/spinlock_posix-inl.h',
            '<(tcmalloc_dir)/src/base/spinlock_win32-inl.h',
            '<(tcmalloc_dir)/src/base/stl_allocator.h',
            '<(tcmalloc_dir)/src/base/synchronization_profiling.h',
            '<(tcmalloc_dir)/src/base/sysinfo.cc',
            '<(tcmalloc_dir)/src/base/sysinfo.h',
            '<(tcmalloc_dir)/src/base/thread_annotations.h',
            '<(tcmalloc_dir)/src/base/thread_lister.c',
            '<(tcmalloc_dir)/src/base/thread_lister.h',
            '<(tcmalloc_dir)/src/base/vdso_support.cc',
            '<(tcmalloc_dir)/src/base/vdso_support.h',
            '<(tcmalloc_dir)/src/central_freelist.cc',
            '<(tcmalloc_dir)/src/central_freelist.h',
            '<(tcmalloc_dir)/src/common.cc',
            '<(tcmalloc_dir)/src/common.h',
            '<(tcmalloc_dir)/src/debugallocation.cc',
            '<(tcmalloc_dir)/src/free_list.cc',
            '<(tcmalloc_dir)/src/free_list.h',
            '<(tcmalloc_dir)/src/getpc.h',
            '<(tcmalloc_dir)/src/gperftools/heap-checker.h',
            '<(tcmalloc_dir)/src/gperftools/heap-profiler.h',
            '<(tcmalloc_dir)/src/gperftools/malloc_extension.h',
            '<(tcmalloc_dir)/src/gperftools/malloc_extension_c.h',
            '<(tcmalloc_dir)/src/gperftools/malloc_hook.h',
            '<(tcmalloc_dir)/src/gperftools/malloc_hook_c.h',
            '<(tcmalloc_dir)/src/gperftools/profiler.h',
            '<(tcmalloc_dir)/src/gperftools/stacktrace.h',
            '<(tcmalloc_dir)/src/gperftools/tcmalloc.h',
            '<(tcmalloc_dir)/src/heap-checker-bcad.cc',
            '<(tcmalloc_dir)/src/heap-checker.cc',
            '<(tcmalloc_dir)/src/heap-profile-table.cc',
            '<(tcmalloc_dir)/src/heap-profile-table.h',
            '<(tcmalloc_dir)/src/heap-profiler.cc',
            '<(tcmalloc_dir)/src/internal_logging.cc',
            '<(tcmalloc_dir)/src/internal_logging.h',
            '<(tcmalloc_dir)/src/libc_override.h',
            '<(tcmalloc_dir)/src/libc_override_gcc_and_weak.h',
            '<(tcmalloc_dir)/src/libc_override_glibc.h',
            '<(tcmalloc_dir)/src/libc_override_osx.h',
            '<(tcmalloc_dir)/src/libc_override_redefine.h',
            '<(tcmalloc_dir)/src/linked_list.h',
            '<(tcmalloc_dir)/src/malloc_extension.cc',
            '<(tcmalloc_dir)/src/malloc_hook-inl.h',
            '<(tcmalloc_dir)/src/malloc_hook.cc',
            '<(tcmalloc_dir)/src/malloc_hook_mmap_freebsd.h',
            '<(tcmalloc_dir)/src/malloc_hook_mmap_linux.h',
            '<(tcmalloc_dir)/src/maybe_threads.cc',
            '<(tcmalloc_dir)/src/maybe_threads.h',
            '<(tcmalloc_dir)/src/memfs_malloc.cc',
            '<(tcmalloc_dir)/src/memory_region_map.cc',
            '<(tcmalloc_dir)/src/memory_region_map.h',
            '<(tcmalloc_dir)/src/packed-cache-inl.h',
            '<(tcmalloc_dir)/src/page_heap.cc',
            '<(tcmalloc_dir)/src/page_heap.h',
            '<(tcmalloc_dir)/src/page_heap_allocator.h',
            '<(tcmalloc_dir)/src/pagemap.h',
            '<(tcmalloc_dir)/src/profile-handler.cc',
            '<(tcmalloc_dir)/src/profile-handler.h',
            '<(tcmalloc_dir)/src/profiledata.cc',
            '<(tcmalloc_dir)/src/profiledata.h',
            '<(tcmalloc_dir)/src/profiler.cc',
            '<(tcmalloc_dir)/src/raw_printer.cc',
            '<(tcmalloc_dir)/src/raw_printer.h',
            '<(tcmalloc_dir)/src/sampler.cc',
            '<(tcmalloc_dir)/src/sampler.h',
            '<(tcmalloc_dir)/src/span.cc',
            '<(tcmalloc_dir)/src/span.h',
            '<(tcmalloc_dir)/src/stack_trace_table.cc',
            '<(tcmalloc_dir)/src/stack_trace_table.h',
            '<(tcmalloc_dir)/src/stacktrace.cc',
            '<(tcmalloc_dir)/src/stacktrace_arm-inl.h',
            '<(tcmalloc_dir)/src/stacktrace_config.h',
            '<(tcmalloc_dir)/src/stacktrace_generic-inl.h',
            '<(tcmalloc_dir)/src/stacktrace_libunwind-inl.h',
            '<(tcmalloc_dir)/src/stacktrace_powerpc-inl.h',
            '<(tcmalloc_dir)/src/stacktrace_win32-inl.h',
            '<(tcmalloc_dir)/src/stacktrace_with_context.cc',
            '<(tcmalloc_dir)/src/stacktrace_x86-inl.h',
            '<(tcmalloc_dir)/src/static_vars.cc',
            '<(tcmalloc_dir)/src/static_vars.h',
            '<(tcmalloc_dir)/src/symbolize.cc',
            '<(tcmalloc_dir)/src/symbolize.h',
            '<(tcmalloc_dir)/src/system-alloc.cc',
            '<(tcmalloc_dir)/src/system-alloc.h',
            '<(tcmalloc_dir)/src/tcmalloc.cc',
            '<(tcmalloc_dir)/src/tcmalloc_guard.h',
            '<(tcmalloc_dir)/src/thread_cache.cc',
            '<(tcmalloc_dir)/src/thread_cache.h',

            'debugallocation_shim.cc',
          ],
          # sources! means that these are not compiled directly.
          'sources!': [
            # We simply don't use these, but list them above so that IDE
            # users can view the full available source for reference, etc.
            '<(tcmalloc_dir)/src/addressmap-inl.h',
            '<(tcmalloc_dir)/src/base/atomicops-internals-linuxppc.h',
            '<(tcmalloc_dir)/src/base/atomicops-internals-macosx.h',
            '<(tcmalloc_dir)/src/base/atomicops-internals-x86-msvc.h',
            '<(tcmalloc_dir)/src/base/atomicops-internals-x86.h',
            '<(tcmalloc_dir)/src/base/atomicops.h',
            '<(tcmalloc_dir)/src/base/commandlineflags.h',
            '<(tcmalloc_dir)/src/base/cycleclock.h',
            '<(tcmalloc_dir)/src/base/elf_mem_image.h',
            '<(tcmalloc_dir)/src/base/elfcore.h',
            '<(tcmalloc_dir)/src/base/googleinit.h',
            '<(tcmalloc_dir)/src/base/linux_syscall_support.h',
            '<(tcmalloc_dir)/src/base/simple_mutex.h',
            '<(tcmalloc_dir)/src/base/spinlock_linux-inl.h',
            '<(tcmalloc_dir)/src/base/spinlock_posix-inl.h',
            '<(tcmalloc_dir)/src/base/spinlock_win32-inl.h',
            '<(tcmalloc_dir)/src/base/stl_allocator.h',
            '<(tcmalloc_dir)/src/base/thread_annotations.h',
            '<(tcmalloc_dir)/src/getpc.h',
            '<(tcmalloc_dir)/src/gperftools/heap-checker.h',
            '<(tcmalloc_dir)/src/gperftools/heap-profiler.h',
            '<(tcmalloc_dir)/src/gperftools/malloc_extension.h',
            '<(tcmalloc_dir)/src/gperftools/malloc_extension_c.h',
            '<(tcmalloc_dir)/src/gperftools/malloc_hook.h',
            '<(tcmalloc_dir)/src/gperftools/malloc_hook_c.h',
            '<(tcmalloc_dir)/src/gperftools/profiler.h',
            '<(tcmalloc_dir)/src/gperftools/stacktrace.h',
            '<(tcmalloc_dir)/src/gperftools/tcmalloc.h',
            '<(tcmalloc_dir)/src/heap-checker-bcad.cc',
            '<(tcmalloc_dir)/src/heap-checker.cc',
            '<(tcmalloc_dir)/src/libc_override.h',
            '<(tcmalloc_dir)/src/libc_override_gcc_and_weak.h',
            '<(tcmalloc_dir)/src/libc_override_glibc.h',
            '<(tcmalloc_dir)/src/libc_override_osx.h',
            '<(tcmalloc_dir)/src/libc_override_redefine.h',
            '<(tcmalloc_dir)/src/malloc_hook_mmap_freebsd.h',
            '<(tcmalloc_dir)/src/malloc_hook_mmap_linux.h',
            '<(tcmalloc_dir)/src/memfs_malloc.cc',
            '<(tcmalloc_dir)/src/packed-cache-inl.h',
            '<(tcmalloc_dir)/src/page_heap_allocator.h',
            '<(tcmalloc_dir)/src/pagemap.h',
            '<(tcmalloc_dir)/src/stacktrace_arm-inl.h',
            '<(tcmalloc_dir)/src/stacktrace_config.h',
            '<(tcmalloc_dir)/src/stacktrace_generic-inl.h',
            '<(tcmalloc_dir)/src/stacktrace_libunwind-inl.h',
            '<(tcmalloc_dir)/src/stacktrace_powerpc-inl.h',
            '<(tcmalloc_dir)/src/stacktrace_win32-inl.h',
            '<(tcmalloc_dir)/src/stacktrace_with_context.cc',
            '<(tcmalloc_dir)/src/stacktrace_x86-inl.h',
            '<(tcmalloc_dir)/src/tcmalloc_guard.h',

            # Included by debugallocation_shim.cc.
            '<(tcmalloc_dir)/src/debugallocation.cc',
            '<(tcmalloc_dir)/src/tcmalloc.cc',
          ],
          'variables': {
            'clang_warning_flags': [
              # tcmalloc initializes some fields in the wrong order.
              '-Wno-reorder',
              # tcmalloc contains some unused local template specializations.
              '-Wno-unused-function',
              # tcmalloc uses COMPILE_ASSERT without static_assert but with
              # typedefs.
              '-Wno-unused-local-typedefs',
              # for magic2_ in debugallocation.cc (only built in Debug builds)
              # typedefs.
              '-Wno-unused-private-field',
            ],
          },
          'conditions': [
            ['OS=="linux" or OS=="freebsd" or OS=="solaris" or OS=="android"', {
              'sources!': [
                '<(tcmalloc_dir)/src/system-alloc.h',
              ],
              # We enable all warnings by default, but upstream disables a few.
              # Keep "-Wno-*" flags in sync with upstream by comparing against:
              # http://code.google.com/p/google-perftools/source/browse/trunk/Makefile.am
              'cflags': [
                '-Wno-sign-compare',
                '-Wno-unused-result',
              ],
              'link_settings': {
                'ldflags': [
                  # Don't let linker rip this symbol out, otherwise the heap&cpu
                  # profilers will not initialize properly on startup.
                  '-Wl,-uIsHeapProfilerRunning,-uProfilerStart',
                  # Do the same for heap leak checker.
                  '-Wl,-u_Z21InitialMallocHook_NewPKvj,-u_Z22InitialMallocHook_MMapPKvS0_jiiix,-u_Z22InitialMallocHook_SbrkPKvi',
                  '-Wl,-u_Z21InitialMallocHook_NewPKvm,-u_Z22InitialMallocHook_MMapPKvS0_miiil,-u_Z22InitialMallocHook_SbrkPKvl',
                  '-Wl,-u_ZN15HeapLeakChecker12IgnoreObjectEPKv,-u_ZN15HeapLeakChecker14UnIgnoreObjectEPKv',
                ],
              },
              # Compiling tcmalloc with -fvisibility=default is only necessary when
              # not using the allocator shim, which provides the correct visibility
              # annotations for those symbols which need to be exported (see
              # //base/allocator/allocator_shim_override_glibc_weak_symbols.h and
              # //base/allocator/allocator_shim_internals.h for the definition of
              # SHIM_ALWAYS_EXPORT).
              'conditions': [
                ['use_experimental_allocator_shim==0', {
                  'cflags!': [
                    '-fvisibility=hidden',
                  ],
                }],
              ],
            }],
            ['profiling!=1', {
              'sources!': [
                # cpuprofiler
                '<(tcmalloc_dir)/src/base/thread_lister.c',
                '<(tcmalloc_dir)/src/base/thread_lister.h',
                '<(tcmalloc_dir)/src/profile-handler.cc',
                '<(tcmalloc_dir)/src/profile-handler.h',
                '<(tcmalloc_dir)/src/profiledata.cc',
                '<(tcmalloc_dir)/src/profiledata.h',
                '<(tcmalloc_dir)/src/profiler.cc',
              ],
            }],
            ['use_experimental_allocator_shim==1', {
              'defines': [
                'TCMALLOC_DONT_REPLACE_SYSTEM_ALLOC',
              ],
            }]
          ],
          'configurations': {
            'Debug_Base': {
              'conditions': [
                ['disable_debugallocation==0', {
                  'defines': [
                    # Use debugallocation for Debug builds to catch problems
                    # early and cleanly, http://crbug.com/30715 .
                    'TCMALLOC_FOR_DEBUGALLOCATION',
                  ],
                }],
              ],
            },
          },
        }],  # use_allocator=="tcmalloc
        # For CrOS builds with vtable verification. According to the author of
        # crrev.com/10854031 this is used in conjuction with some other CrOS
        # build flag, to enable verification of any allocator that uses virtual
        # function calls.
        ['use_vtable_verify==1', {
          'cflags': [
            '-fvtable-verify=preinit',
          ],
        }],
        ['order_profiling != 0', {
          'target_conditions' : [
            ['_toolset=="target"', {
              'cflags!': [ '-finstrument-functions' ],
            }],
          ],
        }],
      ],  # conditions of 'allocator' target.
    },  # 'allocator' target.
    {
      # GN: //base/allocator:features
      # When referenced from a target that might be compiled in the host
      # toolchain, always refer to 'allocator_features#target'.
      'target_name': 'allocator_features',
      'includes': [ '../../build/buildflag_header.gypi' ],
      'variables': {
        'buildflag_header_path': 'base/allocator/features.h',
        'buildflag_flags': [
          'USE_EXPERIMENTAL_ALLOCATOR_SHIM=<(use_experimental_allocator_shim)',
        ],
      },
    },  # 'allocator_features' target.
  ],  # targets.
  'conditions': [
    ['use_experimental_allocator_shim==1', {
      'targets': [
        {
          # GN: //base/allocator:unified_allocator_shim
          'target_name': 'unified_allocator_shim',
          'toolsets': ['host', 'target'],
          'type': 'static_library',
          'defines': [ 'BASE_IMPLEMENTATION' ],
          'sources': [
            'allocator_shim.cc',
            'allocator_shim.h',
            'allocator_shim_internals.h',
            'allocator_shim_override_cpp_symbols.h',
            'allocator_shim_override_libc_symbols.h',
          ],
          'include_dirs': [
            '../..',
          ],
          'conditions': [
            ['OS=="linux" and use_allocator=="tcmalloc"', {
              'sources': [
                'allocator_shim_default_dispatch_to_tcmalloc.cc',
                'allocator_shim_override_glibc_weak_symbols.h',
              ],
            }],
            ['use_allocator=="none" and (OS=="linux" or (OS=="android" and _toolset == "host" and host_os == "linux"))', {
              'sources': [
                'allocator_shim_default_dispatch_to_glibc.cc',
              ],
            }],
            ['OS=="android" and _toolset == "target"', {
              'sources': [
                'allocator_shim_default_dispatch_to_linker_wrapped_symbols.cc',
                'allocator_shim_override_linker_wrapped_symbols.h',
              ],
              # On Android all references to malloc & friends symbols are
              # rewritten, at link time, and routed to the shim.
              # See //base/allocator/README.md.
              'all_dependent_settings': {
                'ldflags': [
                  '-Wl,-wrap,calloc',
                  '-Wl,-wrap,free',
                  '-Wl,-wrap,malloc',
                  '-Wl,-wrap,memalign',
                  '-Wl,-wrap,posix_memalign',
                  '-Wl,-wrap,pvalloc',
                  '-Wl,-wrap,realloc',
                  '-Wl,-wrap,valloc',
                ],
              },
            }],
          ]
        },  # 'unified_allocator_shim' target.
      ],
    }]
  ],
}
