#!/usr/bin/env python
# Copyright (c) 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.


def GetConfigurationForBuild(defines):
  '''Returns a configuration dictionary for the given build that contains
  build-specific settings and information.

  Args:
    defines: Definitions coming from the build system.

  Raises:
    Exception: If 'defines' contains an unknown build-type.
  '''
  # The prefix of key names in config determines which writer will use their
  # corresponding values:
  #   win: Both ADM and ADMX.
  #   mac: Only plist.
  #   admx: Only ADMX.
  #   adm: Only ADM.
  #   none/other: Used by all the writers.
  if '_chromium' in defines:
    config = {
      'build': 'chromium',
      'app_name': 'Chromium',
      'frame_name': 'Chromium Frame',
      'os_name': 'Chromium OS',
      'webview_name': 'Chromium WebView',
      'win_reg_mandatory_key_name': 'Software\\Policies\\Chromium',
      'win_reg_recommended_key_name':
          'Software\\Policies\\Chromium\\Recommended',
      'win_mandatory_category_path': ['chromium'],
      'win_recommended_category_path': ['chromium_recommended'],
      'win_category_path_strings': {
        'chromium': 'Chromium',
        'chromium_recommended': 'Chromium - {doc_recommended}'
      },
      'admx_namespace': 'Chromium.Policies.Chromium',
      'admx_prefix': 'chromium',
      'linux_policy_path': '/etc/chromium/policies/',
    }
  elif '_google_chrome' in defines:
    config = {
      'build': 'chrome',
      'app_name': 'Google Chrome',
      'frame_name': 'Google Chrome Frame',
      'os_name': 'Google Chrome OS',
      'webview_name': 'Android System WebView',
      'win_reg_mandatory_key_name': 'Software\\Policies\\Google\\Chrome',
      'win_reg_recommended_key_name':
          'Software\\Policies\\Google\\Chrome\\Recommended',
      # Note: Google:Cat_Google references Google.Policies from external
      # in google.admx file.
      'win_mandatory_category_path': ['Google:Cat_Google', 'googlechrome'],
      'win_recommended_category_path':
          ['Google:Cat_Google', 'googlechrome_recommended'],
      'win_category_path_strings': {
        # Strings in curly braces is looked up from localized 'messages' in
        # policy_templates.json.
        'googlechrome': 'Google Chrome',
        'googlechrome_recommended': 'Google Chrome - {doc_recommended}'
      },
      # The string 'Google' is defined in google.adml for ADMX, but ADM doesn't
      # support external references, so we define this map here.
      'adm_category_path_strings': { 'Google:Cat_Google': 'Google' },
      'admx_namespace': 'Google.Policies.Chrome',
      'admx_prefix': 'chrome',
      'admx_using_namespaces': {
        'Google': 'Google.Policies'  # prefix: namespace
      },
      'linux_policy_path': '/etc/opt/chrome/policies/',
    }
  else:
    raise Exception('Unknown build')
  if 'version' in defines:
    config['version'] = defines['version']
  config['win_group_policy_class'] = 'Both'
  config['win_supported_os'] = 'SUPPORTED_WINXPSP2'
  if 'mac_bundle_id' in defines:
    config['mac_bundle_id'] = defines['mac_bundle_id']
  config['android_webview_restriction_prefix'] = 'com.android.browser:'
  return config
