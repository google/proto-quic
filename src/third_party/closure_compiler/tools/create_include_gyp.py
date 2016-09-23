#!/usr/bin/env python
# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# Usage:
#
#   cd third_party/closure_compiler
#   tools/create_include_gyp.py externs > externs/compiled_resources2.gyp
#   tools/create_include_gyp.py interfaces > interfaces/compiled_resources2.gyp

from datetime import date
import os
import sys


_INCLUDE_TEMPLATE = """
# Copyright %d The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

########################################################
#    NOTE: THIS FILE IS GENERATED. DO NOT EDIT IT!     #
# Instead, run create_include_gyp.py to regenerate it. #
########################################################
{
  'targets': [
    %s,
  ],
}""".lstrip()


_TARGET_TEMPLATE = """
    {
      'target_name': '%s',
      'includes': ['../include_js.gypi'],
    }"""


def CreateIncludeGyp(directory):
  include_dir = os.path.join(os.path.dirname(__file__), "..", directory)
  include_files = [f for f in os.listdir(include_dir) if f.endswith('.js')]
  include_files.sort()
  targets = [_TARGET_TEMPLATE % f[:-3] for f in include_files]
  return _INCLUDE_TEMPLATE % (date.today().year, ",".join(targets).strip())


def ShowUsageAndDie():
  print "usage: tools/create_include_gyp.py externs > externs/compiled_resources2.gyp"
  sys.exit(1)


if __name__ == "__main__":
  if len(sys.argv) != 2:
    ShowUsageAndDie()

  print CreateIncludeGyp(sys.argv[1])
