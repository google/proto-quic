# Copyright (c) 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# This file is meant to be included to disable GCC LTO on a target.

{
  'target_conditions': [
    ['_toolset=="target"', {
      'conditions': [
        ['OS=="android" and clang==0 and (use_lto==1 or use_lto_o2==1)', {
          'cflags!': [
            '-flto',
            '-ffat-lto-objects',
          ],
        }],
      ],
    }],
  ],
}
