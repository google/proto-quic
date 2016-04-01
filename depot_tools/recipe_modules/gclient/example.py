# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

DEPS = [
  'gclient',
  'recipe_engine/path',
  'recipe_engine/properties',
]


TEST_CONFIGS = [
  'android',
  'android_bare',
  'blink',
  'blink_or_chromium',
  'boringssl',
  'build_internal',
  'build_internal_scripts_slave',
  'catapult',
  'chrome_internal',
  'chromium',
  'chromium_lkcr',
  'chromium_lkgr',
  'chromium_skia',
  'chromium_webrtc',
  'chromium_webrtc_tot',
  'crashpad',
  'custom_tabs_client',
  'dart',
  'gerrit_test_cq_normal',
  'gyp',
  'infra',
  'infradata_master_manager',
  'internal_deps',
  'ios',
  'luci_gae',
  'luci_go',
  'luci_py',
  'master_deps',
  'mojo',
  'nacl',
  'pdfium',
  'perf',
  'recipes_py',
  'show_v8_revision',
  'slave_deps',
  'v8_bleeding_edge_git',
  'v8_canary',
  'wasm_llvm',
  'webports',
  'webrtc_test_resources',
  'with_branch_heads',
]


def RunSteps(api):
  for config_name in TEST_CONFIGS:
    api.gclient.make_config(config_name)

  src_cfg = api.gclient.make_config(GIT_MODE=True)
  soln = src_cfg.solutions.add()
  soln.name = 'src'
  soln.url = 'https://chromium.googlesource.com/chromium/src.git'
  soln.revision = api.properties.get('revision')
  src_cfg.parent_got_revision_mapping['parent_got_revision'] = 'got_revision'
  api.gclient.c = src_cfg
  api.gclient.checkout()

  api.gclient.spec_alias = 'WebKit'
  bl_cfg = api.gclient.make_config()
  soln = bl_cfg.solutions.add()
  soln.name = 'WebKit'
  soln.url = 'svn://svn.chromium.org/blink/trunk'
  bl_cfg.revisions['third_party/WebKit'] = '123'

  # Use safesync url for lkgr.
  soln.safesync_url = 'https://blink-status.appspot.com/lkgr'

  bl_cfg.got_revision_mapping['src/blatley'] = 'got_blatley_revision'
  api.gclient.checkout(
      gclient_config=bl_cfg,
      with_branch_heads=True,
      cwd=api.path['slave_build'].join('src', 'third_party'))

  api.gclient.break_locks()

  del api.gclient.spec_alias

  api.gclient.runhooks()

  assert not api.gclient.is_blink_mode


def GenTests(api):
  yield api.test('basic')

  yield api.test('revision') + api.properties(revision='abc')

  yield api.test('tryserver') + api.properties.tryserver()
