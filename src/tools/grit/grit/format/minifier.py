# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""Framework for stripping whitespace and comments from resource files"""

import subprocess

__js_minifier = None


def SetJsMinifier(minifier):
  global __js_minifier
  __js_minifier = minifier.split()


def Minify(source, file_type):
  if not file_type == '.js' or not __js_minifier:
    return source
  p = subprocess.Popen(
      __js_minifier,
      stdin=subprocess.PIPE,
      stdout=subprocess.PIPE,
      stderr=subprocess.PIPE)
  (stdout, stderr) = p.communicate(source)
  if stderr:
    print stderr
  if p.returncode != 0:
    print 'Minification failed, using original source'
    return source
  return stdout
