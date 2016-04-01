# Copyright (c) 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

{
  'variables': {
    'arch_suffix': '<(arch_suffix)',
    'variables': {
      # This help to find out if target_arch is set to something else.
      'arch_suffix': '<(target_arch)',
      'conditions': [
        ['target_arch=="arm" or target_arch=="ia32" or target_arch=="mipsel"', {
          'arch_suffix': '32',
        }],
        ['target_arch=="arm64" or target_arch=="x64" or target_arch=="mips64el"', {
          'arch_suffix':'64'
        }],
      ],
    }
  }
}
