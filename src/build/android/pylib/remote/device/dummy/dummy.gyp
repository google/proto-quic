# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Running gtests on a remote device via am instrument requires both an "app"
# APK and a "test" APK with different package names. Our gtests only use one
# APK, so we build a dummy APK to upload as the app.

{
  'variables': {
    'remote_device_dummy_apk_name': 'remote_device_dummy',
    'remote_device_dummy_apk_path': '<(PRODUCT_DIR)/apks/<(remote_device_dummy_apk_name).apk',
  },
  'targets': [
    {
      # GN: //build/android/pylib/remote/device/dummy:remote_device_dummy_apk
      'target_name': 'remote_device_dummy_apk',
      'type': 'none',
      'variables': {
        'apk_name': '<(remote_device_dummy_apk_name)',
        'final_apk_path': '<(remote_device_dummy_apk_path)',
        'java_in_dir': '.',
        'never_lint': 1,
        'android_manifest_path': '../../../../../../build/android/AndroidManifest.xml',
      },
      'includes': [
        '../../../../../../build/java_apk.gypi',
      ]
    },
    {
      'target_name': 'require_remote_device_dummy_apk',
      'message': 'Making sure <(remote_device_dummy_apk_path) has been built.',
      'type': 'none',
      'variables': {
        'required_file': '<(PRODUCT_DIR)/remote_device_dummy_apk/<(remote_device_dummy_apk_name).apk.required',
      },
      'inputs': [
        '<(remote_device_dummy_apk_path)',
      ],
      'outputs': [
        '<(required_file)',
      ],
      'action': [
        'python', '../../build/android/gyp/touch.py', '<(required_file)',
      ],
    }
  ]
}
