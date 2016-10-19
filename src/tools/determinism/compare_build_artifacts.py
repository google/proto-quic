#!/usr/bin/env python
# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Compare the artifacts from two builds."""

import difflib
import json
import optparse
import os
import re
import shutil
import struct
import subprocess
import sys
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


# List of files that are known to be non deterministic. This is a "temporary"
# workaround to find regression on the deterministic builders.
#
# PNaCl general bug: https://crbug.com/429358
#
# TODO(sebmarchand): Remove this once all the files are deterministic.
WHITELIST = {
  # https://crbug.com/383340
  'android': {
    'flatc',
  },

  # https://crbug.com/330263
  'linux': {
    # Completed.
  },

  # https://crbug.com/330262
  'mac': {
    'accelerated_widget_mac_unittests',
    'accessibility_unittests',
    'angle_end2end_tests',
    'angle_unittests',
    'App Shell',
    'app_shell_unittests',
    'ar_sample_test_driver',
    'audio_unittests',
    'base_unittests',
    'battor_agent_unittests',
    'blink_heap_unittests',
    'blink_platform_perftests',
    'blink_platform_unittests',
    'bluetooth_metrics_hash',
    'boringssl_unittests',
    'browser_tests',
    'cacheinvalidation_unittests',
    'capture_unittests',
    'cast_benchmarks',
    'cast_receiver_app',
    'cast_sender_app',
    'cast_simulator',
    'cast_unittests',
    'cc_blink_unittests',
    'cc_perftests',
    'cc_unittests',
    'chrome_app_unittests',
    'chromedriver',
    'chromedriver_tests',
    'chromedriver_unittests',
    'chromoting_test_driver',
    'command_buffer_gles2_tests',
    'components_browsertests',
    'components_perftests',
    'components_unittests',
    'compositor_unittests',
    'content_browsertests',
    'content_perftests',
    'content_unittests',
    'courgette_unittests',
    'crashpad_handler',
    'crypto_unittests',
    'device_unittests',
    'display_compositor_benchmark',
    'display_compositor_gl_tests',
    'display_unittests',
    'events_unittests',
    'extensions_browsertests',
    'extensions_unittests',
    'ffmpeg_regression_tests',
    'filesystem_service_unittests',
    'filter_fuzz_stub',
    'flatc',
    'gcm_unit_tests',
    'generate_barcode_video',
    'generate_timecode_audio',
    'gfx_unittests',
    'gin_unittests',
    'gles2_conform_support',
    'gles2_conform_test',
    'gl_tests',
    'gl_unittests',
    'gn_unittests',
    'google_apis_unittests',
    'gpu_ipc_service_unittests',
    'gpu_perftests',
    'gpu_unittests',
    'interactive_ui_tests',
    'ipc_fuzzer',
    'ipc_fuzzer_replay',
    'ipc_message_dump.so',
    'ipc_message_list',
    'ipc_message_util',
    'ipc_tests',
    'it2me_standalone_host_main',
    'jingle_unittests',
    'khronos_glcts_test',
    'leveldb_service_unittests',
    'libaddressinput_unittests',
    'libapp_shell_framework.dylib',
    'libcommand_buffer_gles2.dylib',
    'libmedia_library.dylib',
    'libphonenumber_unittests',
    'mac_installer_unittests',
    'macviews_interactive_ui_tests',
    'media_blink_unittests',
    'media_mojo_shell_unittests',
    'media_mojo_unittests',
    'media_perftests',
    'media_pipeline_integration_unittests',
    'media_unittests',
    'message_center_unittests',
    'midi_unittests',
    'mojo_common_unittests',
    'mojo_js_integration_tests',
    'mojo_js_unittests',
    'mojo_public_bindings_unittests',
    'mojo_public_system_unittests',
    'mojo_runner_host_unittests',
    'mojo_system_unittests',
    'nacl_loader_unittests',
    'native_theme_unittests',
    'net_unittests',
    'osmesa.so',
    'performance_browser_tests',
    'ppapi_perftests',
    'ppapi_unittests',
    'printing_unittests',
    'proximity_auth_unittests',
    'remoting_perftests',
    'remoting_start_host',
    'remoting_unittests',
    'sandbox_mac_unittests',
    'service_manager_unittests',
    'shell_dialogs_unittests',
    'skia_unittests',
    'snapshot_unittests',
    'sql_unittests',
    'storage_unittests',
    'sync_client',
    'sync_integration_tests',
    'sync_listen_notifications',
    'sync_performance_tests',
    'sync_unit_tests',
    'udp_proxy',
    'ui_base_unittests',
    'ui_struct_traits_unittests',
    'ui_touch_selection_unittests',
    'unit_tests',
    'url_ipc_unittests',
    'url_unittests',
    'video_encode_accelerator_unittest',
    'views_examples_exe',
    'views_examples_with_content_exe',
    'views_unittests',
    'webkit_unit_tests',
    'wtf_unittests',
  },

  # https://crbug.com/330260
  'win': {
    'accessibility_unittests.exe',
    'angle_end2end_tests.exe',
    'angle_perftests.exe',
    'angle_unittests.exe',
    'app_driver_library.dll',
    'app_list_demo.exe',
    'app_list_presenter_unittests.exe',
    'app_list_unittests.exe',
    'app_shell.exe',
    'app_shell_unittests.exe',
    'ar_sample_test_driver.exe',
    'ash_library.dll',
    'ash_shell_with_content.exe',
    'ash_unittests.exe',
    'audio_unittests.exe',
    'aura_demo.exe',
    'aura_unittests.exe',
    'base_i18n_perftests.exe',
    'base_perftests.exe',
    'base_unittests.exe',
    'blink_converters_unittests.exe',
    'blink_deprecated_test_plugin.dll',
    'blink_heap_unittests.exe',
    'blink_platform_perftests.exe',
    'blink_platform_unittests.exe',
    'blink_test_plugin.dll',
    'bluetooth_metrics_hash.exe',
    'browser_library.dll',
    'browser_tests.exe',
    'capture_unittests.exe',
    'cast_benchmarks.exe',
    'cast_receiver_app.exe',
    'cast_sender_app.exe',
    'cast_simulator.exe',
    'cast_unittests.exe',
    'catalog_viewer_library.dll',
    'cc_blink_unittests.exe',
    'cc_perftests.exe',
    'cctest.exe',
    'cc_unittests.exe',
    'ced_unittests.exe',
    'cert_verify_tool.exe',
    'chrome_app_unittests.exe',
    'chrome_child.dll',
    'chrome.dll',
    'chromedriver.exe',
    'chromedriver_tests.exe',
    'chromedriver_unittests.exe',
    'chrome_elf_unittests.exe',
    'chrome.exe',
    'chromoting_test_driver.exe',
    'command_buffer_gles2.dll',
    'components_browsertests.exe',
    'components_perftests.exe',
    'components_unittests.exe',
    'compositor_unittests.exe',
    'content_browsertests.exe',
    'content_perftests.exe',
    'content_shell.exe',
    'content_unittests.exe',
    'courgette64.exe',
    'crypto_unittests.exe',
    'd8.exe',
    'device_unittests.exe',
    'display_compositor_benchmark.exe',
    'display_compositor_gl_tests.exe',
    'display_unittests.exe',
    'events_unittests.exe',
    'extensions_browsertests.exe',
    'extensions_unittests.exe',
    'ffmpeg_regression_tests.exe',
    'filesystem_service_unittests.exe',
    'filter_fuzz_stub.exe',
    'force_mic_volume_max.exe',
    'gcapi_test.exe',
    'gcm_unit_tests.exe',
    'generate_barcode_video.exe',
    'generate-bytecode-expectations.exe',
    'generate_timecode_audio.exe',
    'get_server_time.exe',
    'gfx_unittests.exe',
    'gin_shell.exe',
    'gin_unittests.exe',
    'gles2_conform_support.exe',
    'gles2_conform_test.exe',
    'gl_tests.exe',
    'gl_unittests.exe',
    'google_apis_unittests.exe',
    'gpu_ipc_service_unittests.exe',
    'gpu_perftests.exe',
    'gpu_unittests.exe',
    'image_operations_bench.exe',
    'input_device_unittests.exe',
    'interactive_ui_tests.exe',
    'ipc_perftests.exe',
    'ipc_tests.exe',
    'it2me_standalone_host_main.exe',
    'jingle_unittests.exe',
    'keyboard_unittests.exe',
    'khronos_glcts_test.exe',
    'leveldb_service_unittests.exe',
    'libaddressinput_unittests.exe',
    'login_library.dll',
    'mash_init_library.dll',
    'mash_unittests.exe',
    'media_blink_unittests.exe',
    'media_library.dll',
    'media_mojo_shell_unittests.exe',
    'media_mojo_unittests.exe',
    'media_perftests.exe',
    'media_pipeline_integration_unittests.exe',
    'media_unittests.exe',
    'message_center_unittests.exe',
    'midi_unittests.exe',
    'mini_installer.exe',
    'mksnapshot.exe',
    'mojo_js_integration_tests.exe',
    'mojo_js_unittests.exe',
    'mojo_message_pipe_perftests.exe',
    'mojo_public_bindings_perftests.exe',
    'mojo_public_bindings_unittests.exe',
    'mojo_public_system_perftests.exe',
    'mojo_public_system_unittests.exe',
    'mojo_system_unittests.exe',
    'mus_clipboard_unittests.exe',
    'mus_demo_library.dll',
    'mus_demo_unittests.exe',
    'mus_gpu_unittests.exe',
    'mus_ime_unittests.exe',
    'mus_public_unittests.exe',
    'mus_ws_unittests.exe',
    'nacl_irt_x86_32.nexe',
    'nacl_irt_x86_64.nexe',
    'nacl_loader_unittests.exe',
    'native_theme_unittests.exe',
    'navigation.exe',
    'navigation_unittests.exe',
    'net_perftests.exe',
    'net_unittests.exe',
    'next_version_mini_installer.exe',
    'pdfium_embeddertests.exe',
    'pdfium_test.exe',
    'performance_browser_tests.exe',
    'power_saver_test_plugin.dll',
    'ppapi_nacl_tests_newlib_x86_32.nexe',
    'ppapi_nacl_tests_newlib_x86_64.nexe',
    'ppapi_nacl_tests_pnacl_newlib_x32.nexe',
    'ppapi_nacl_tests_pnacl_newlib_x32_nonsfi.nexe',
    'ppapi_nacl_tests_pnacl_newlib_x64.nexe',
    'ppapi_perftests.exe',
    'ppapi_tests.dll',
    'ppapi_unittests.exe',
    'printing_unittests.exe',
    'proximity_auth_unittests.exe',
    'quic_client.exe',
    'quick_launch_library.dll',
    'quic_packet_printer.exe',
    'quic_server.exe',
    'remoting_breakpad_tester.exe',
    'remoting_core.dll',
    'remoting_perftests.exe',
    'remoting_unittests.exe',
    'sbox_unittests.exe',
    'screenlock_library.dll',
    'shell_dialogs_unittests.exe',
    'skia_unittests.exe',
    'snapshot_unittests.exe',
    'sql_unittests.exe',
    'storage_unittests.exe',
    'sync_client.exe',
    'sync_integration_tests.exe',
    'sync_listen_notifications.exe',
    'sync_performance_tests.exe',
    'sync_unit_tests.exe',
    'task_viewer_library.dll',
    'test_ime_driver_library.dll',
    'test_wm_library.dll',
    'touch_hud_library.dll',
    'udp_proxy.exe',
    'ui_base_unittests.exe',
    'ui_library.dll',
    'ui_struct_traits_unittests.exe',
    'ui_touch_selection_unittests.exe',
    'unit_tests.exe',
    'unittests.exe',
    'url_unittests.exe',
    'v8_hello_world.exe',
    'v8_parser_shell.exe',
    'v8_sample_process.exe',
    'v8_shell.exe',
    'v8_simple_json_fuzzer.exe',
    'v8_simple_parser_fuzzer.exe',
    'v8_simple_regexp_fuzzer.exe',
    'v8_simple_wasm_asmjs_fuzzer.exe',
    'v8_simple_wasm_fuzzer.exe',
    'video_decode_accelerator_unittest.exe',
    'video_encode_accelerator_unittest.exe',
    'views_examples_exe.exe',
    'views_examples_library.dll',
    'views_examples_with_content_exe.exe',
    'views_mus_interactive_ui_tests.exe',
    'views_mus_unittests.exe',
    'views_unittests.exe',
    'webkit_unit_tests.exe',
    'webtest_library.dll',
    'window_type_launcher_library.dll',
    'wm_unittests.exe',
    'wtf_unittests.exe',
  },
}

def get_files_to_compare(build_dir, recursive=False):
  """Get the list of files to compare."""
  # TODO(maruel): Add '.pdb'.
  allowed = frozenset(
      ('', '.apk', '.app', '.dll', '.dylib', '.exe', '.nexe', '.so'))
  non_x_ok_exts = frozenset(('.apk', '.isolated'))
  def check(f):
    if not os.path.isfile(f):
      return False
    if os.path.basename(f).startswith('.'):
      return False
    ext = os.path.splitext(f)[1]
    if ext in non_x_ok_exts:
      return True
    return ext in allowed and os.access(f, os.X_OK)

  ret_files = set()
  for root, dirs, files in os.walk(build_dir):
    if not recursive:
      dirs[:] = [d for d in dirs if d.endswith('_apk')]
    for f in (f for f in files if check(os.path.join(root, f))):
      ret_files.add(os.path.relpath(os.path.join(root, f), build_dir))
  return ret_files


def diff_dict(a, b):
  """Returns a yaml-like textural diff of two dict.

  It is currently optimized for the .isolated format.
  """
  out = ''
  for key in set(a) | set(b):
    va = a.get(key)
    vb = b.get(key)
    if va.__class__ != vb.__class__:
      out += '- %s:  %r != %r\n' % (key, va, vb)
    elif isinstance(va, dict):
      c = diff_dict(va, vb)
      if c:
        out += '- %s:\n%s\n' % (
            key, '\n'.join('  ' + l for l in c.splitlines()))
    elif va != vb:
      out += '- %s:  %s != %s\n' % (key, va, vb)
  return out.rstrip()


def diff_binary(first_filepath, second_filepath, file_len):
  """Returns a compact binary diff if the diff is small enough."""
  CHUNK_SIZE = 32
  MAX_STREAMS = 10
  diffs = 0
  streams = []
  offset = 0
  with open(first_filepath, 'rb') as lhs:
    with open(second_filepath, 'rb') as rhs:
      # Skip part of Win32 COFF header if timestamps are different.
      #
      # COFF header:
      #   0 -  1: magic.
      #   2 -  3: # sections.
      #   4 -  7: timestamp.
      #   ....
      #
      # COFF BigObj header:
      #   0 -  3: signature (0000 FFFF)
      #   4 -  5: version
      #   6 -  7: machine
      #   8 - 11: timestamp.
      COFF_HEADER_TO_COMPARE_SIZE = 12
      if (sys.platform == 'win32'
          and os.path.splitext(first_filepath)[1] in ('.o', '.obj')
          and file_len > COFF_HEADER_TO_COMPARE_SIZE):
        rhs_data = rhs.read(COFF_HEADER_TO_COMPARE_SIZE)
        lhs_data = lhs.read(COFF_HEADER_TO_COMPARE_SIZE)
        if (lhs_data[0:4] == rhs_data[0:4] and lhs_data[4:8] != rhs_data[4:8]
            and lhs_data[8:12] == rhs_data[8:12]):
          offset += COFF_HEADER_TO_COMPARE_SIZE
        elif (lhs_data[0:4] == '\x00\x00\xff\xff' and
              lhs_data[0:8] == rhs_data[0:8] and
              lhs_data[8:12] != rhs_data[8:12]):
          offset += COFF_HEADER_TO_COMPARE_SIZE
        else:
          lhs.seek(0)
          rhs.seek(0)

      while True:
        lhs_data = lhs.read(CHUNK_SIZE)
        rhs_data = rhs.read(CHUNK_SIZE)
        if not lhs_data:
          break
        if lhs_data != rhs_data:
          diffs += sum(l != r for l, r in zip(lhs_data, rhs_data))
          if streams is not None:
            if len(streams) < MAX_STREAMS:
              streams.append((offset, lhs_data, rhs_data))
            else:
              streams = None
        offset += len(lhs_data)
        del lhs_data
        del rhs_data
  if not diffs:
    return None
  result = '%d out of %d bytes are different (%.2f%%)' % (
        diffs, file_len, 100.0 * diffs / file_len)
  if streams:
    encode = lambda text: ''.join(i if 31 < ord(i) < 128 else '.' for i in text)
    for offset, lhs_data, rhs_data in streams:
      lhs_line = '%s \'%s\'' % (lhs_data.encode('hex'), encode(lhs_data))
      rhs_line = '%s \'%s\'' % (rhs_data.encode('hex'), encode(rhs_data))
      diff = list(difflib.Differ().compare([lhs_line], [rhs_line]))[-1][2:-1]
      result += '\n  0x%-8x: %s\n              %s\n              %s' % (
            offset, lhs_line, rhs_line, diff)
  return result


def compare_files(first_filepath, second_filepath):
  """Compares two binaries and return the number of differences between them.

  Returns None if the files are equal, a string otherwise.
  """
  if first_filepath.endswith('.isolated'):
    with open(first_filepath, 'rb') as f:
      lhs = json.load(f)
    with open(second_filepath, 'rb') as f:
      rhs = json.load(f)
    diff = diff_dict(lhs, rhs)
    if diff:
      return '\n' + '\n'.join('  ' + line for line in diff.splitlines())
    # else, falls through binary comparison, it must be binary equal too.

  file_len = os.stat(first_filepath).st_size
  if file_len != os.stat(second_filepath).st_size:
    return 'different size: %d != %d' % (
        file_len, os.stat(second_filepath).st_size)

  return diff_binary(first_filepath, second_filepath, file_len)


def get_deps(build_dir, target):
  """Returns list of object files needed to build target."""
  NODE_PATTERN = re.compile(r'label="([a-zA-Z0-9_\\/.-]+)"')
  CHECK_EXTS = ('.o', '.obj')

  # Rename to possibly original directory name if possible.
  fixed_build_dir = build_dir
  if build_dir.endswith('.1') or build_dir.endswith('.2'):
    fixed_build_dir = build_dir[:-2]
    if os.path.exists(fixed_build_dir):
      print >> sys.stderr, ('fixed_build_dir %s exists.'
                            ' will try to use orig dir.' % fixed_build_dir)
      fixed_build_dir = build_dir
    else:
      shutil.move(build_dir, fixed_build_dir)

  try:
    out = subprocess.check_output(['ninja', '-C', fixed_build_dir,
                                   '-t', 'graph', target])
  except subprocess.CalledProcessError as e:
    print >> sys.stderr, 'error to get graph for %s: %s' % (target, e)
    return []

  finally:
    # Rename again if we renamed before.
    if fixed_build_dir != build_dir:
      shutil.move(fixed_build_dir, build_dir)

  files = []
  for line in out.splitlines():
    matched = NODE_PATTERN.search(line)
    if matched:
      path = matched.group(1)
      if not os.path.splitext(path)[1] in CHECK_EXTS:
        continue
      if os.path.isabs(path):
        print >> sys.stderr, ('not support abs path %s used for target %s'
                              % (path, target))
        continue
      files.append(path)
  return files


def compare_deps(first_dir, second_dir, targets):
  """Print difference of dependent files."""
  for target in targets:
    first_deps = get_deps(first_dir, target)
    second_deps = get_deps(second_dir, target)
    print 'Checking %s difference: (%s deps)' % (target, len(first_deps))
    if set(first_deps) != set(second_deps):
      # Since we do not thiks this case occur, we do not do anything special
      # for this case.
      print 'deps on %s are different: %s' % (
          target, set(first_deps).symmetric_difference(set(second_deps)))
      continue
    max_filepath_len = max(len(n) for n in first_deps)
    for d in first_deps:
      first_file = os.path.join(first_dir, d)
      second_file = os.path.join(second_dir, d)
      result = compare_files(first_file, second_file)
      if result:
        print('  %-*s: %s' % (max_filepath_len, d, result))


def compare_build_artifacts(first_dir, second_dir, target_platform,
                            recursive=False):
  """Compares the artifacts from two distinct builds."""
  if not os.path.isdir(first_dir):
    print >> sys.stderr, '%s isn\'t a valid directory.' % first_dir
    return 1
  if not os.path.isdir(second_dir):
    print >> sys.stderr, '%s isn\'t a valid directory.' % second_dir
    return 1

  epoch_hex = struct.pack('<I', int(time.time())).encode('hex')
  print('Epoch: %s' %
      ' '.join(epoch_hex[i:i+2] for i in xrange(0, len(epoch_hex), 2)))

  with open(os.path.join(BASE_DIR, 'deterministic_build_blacklist.json')) as f:
    blacklist = frozenset(json.load(f))
  whitelist = WHITELIST[target_platform]

  # The two directories.
  first_list = get_files_to_compare(first_dir, recursive) - blacklist
  second_list = get_files_to_compare(second_dir, recursive) - blacklist

  equals = []
  expected_diffs = []
  unexpected_diffs = []
  unexpected_equals = []
  all_files = sorted(first_list & second_list)
  missing_files = sorted(first_list.symmetric_difference(second_list))
  if missing_files:
    print >> sys.stderr, 'Different list of files in both directories:'
    print >> sys.stderr, '\n'.join('  ' + i for i in missing_files)
    unexpected_diffs.extend(missing_files)

  max_filepath_len = max(len(n) for n in all_files)
  for f in all_files:
    first_file = os.path.join(first_dir, f)
    second_file = os.path.join(second_dir, f)
    result = compare_files(first_file, second_file)
    if not result:
      tag = 'equal'
      equals.append(f)
      if f in whitelist:
        unexpected_equals.append(f)
    else:
      if f in whitelist:
        expected_diffs.append(f)
        tag = 'expected'
      else:
        unexpected_diffs.append(f)
        tag = 'unexpected'
      result = 'DIFFERENT (%s): %s' % (tag, result)
    print('%-*s: %s' % (max_filepath_len, f, result))
  unexpected_diffs.sort()

  print('Equals:           %d' % len(equals))
  print('Expected diffs:   %d' % len(expected_diffs))
  print('Unexpected diffs: %d' % len(unexpected_diffs))
  if unexpected_diffs:
    print('Unexpected files with diffs:\n')
    for u in unexpected_diffs:
      print('  %s' % u)
  if unexpected_equals:
    print('Unexpected files with no diffs:\n')
    for u in unexpected_equals:
      print('  %s' % u)

  all_diffs = expected_diffs + unexpected_diffs
  diffs_to_investigate = sorted(set(all_diffs).difference(missing_files))
  compare_deps(first_dir, second_dir, diffs_to_investigate)

  return int(bool(unexpected_diffs))


def main():
  parser = optparse.OptionParser(usage='%prog [options]')
  parser.add_option(
      '-f', '--first-build-dir', help='The first build directory.')
  parser.add_option(
      '-s', '--second-build-dir', help='The second build directory.')
  parser.add_option('-r', '--recursive', action='store_true', default=False,
                    help='Indicates if the comparison should be recursive.')
  target = {
      'darwin': 'mac', 'linux2': 'linux', 'win32': 'win'
  }.get(sys.platform, sys.platform)
  parser.add_option('-t', '--target-platform', help='The target platform.',
                    default=target, choices=('android', 'mac', 'linux', 'win'))
  options, _ = parser.parse_args()

  if not options.first_build_dir:
    parser.error('--first-build-dir is required')
  if not options.second_build_dir:
    parser.error('--second-build-dir is required')
  if not options.target_platform:
    parser.error('--target-platform is required')

  return compare_build_artifacts(os.path.abspath(options.first_build_dir),
                                 os.path.abspath(options.second_build_dir),
                                 options.target_platform,
                                 options.recursive)


if __name__ == '__main__':
  sys.exit(main())
