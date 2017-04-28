# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os


def GetPackageRelativePath(filename):
  return os.path.relpath(filename, GetSourceRoot(filename))


def GetSourceRoot(filename):
  # If filename is not absolute, then we are going to assume that it is
  # relative to the current directory.
  if not os.path.isabs(filename):
    filename = os.path.abspath(filename)
  if not os.path.exists(filename):
    raise IOError('File not found: {}'.format(filename))
  source_root = os.path.dirname(filename)
  while True:
    gnfile = os.path.join(source_root, 'src', '.gn')
    if os.path.exists(gnfile):
      return source_root

    new_package_root = os.path.dirname(source_root)
    if new_package_root == source_root:
      raise Exception("Can't determine package root")
    source_root = new_package_root
