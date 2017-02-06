# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# H   H EEEEE Y   Y !!
# H   H E      Y Y  !!  compiled_resources.gyp IS DEPRECATED
# HHHHH EEEEE   Y   !!
# H   H E       Y        USE compiled_resources2.gyp INSTEAD
# H   H EEEEE   Y   !!
#
# Add your directory-specific .gyp file to this list for it to be continuously
# typechecked on the builder:
# http://build.chromium.org/p/chromium.fyi/builders/Closure%20Compilation%20Linux
#
# Also, see our guide to Closure compilation in chrome:
# https://chromium.googlesource.com/chromium/src/+/master/docs/closure_compilation.md
{
  'targets': [
    {
      'target_name': 'compiled_resources',
      'type': 'none',
      'dependencies': [
        '../../chrome/browser/resources/bookmark_manager/js/compiled_resources.gyp:*',
        '../../chrome/browser/resources/chromeos/compiled_resources.gyp:*',
        '../../chrome/browser/resources/extensions/compiled_resources.gyp:*',
        '../../chrome/browser/resources/help/compiled_resources.gyp:*',
        '../../chrome/browser/resources/options/compiled_resources.gyp:*',
        '../../chrome/browser/resources/ntp4/compiled_resources.gyp:*',
        # '../../remoting/remoting_webapp_compile.gypi:*',
        '../../ui/file_manager/file_manager/foreground/js/compiled_resources.gyp:*',
        '../../ui/file_manager/gallery/js/compiled_resources.gyp:*',
      ],
    },
  ]
}
