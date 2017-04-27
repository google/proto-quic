# Copyright (c) 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

""" This code is imported with modifications from
'//infra/recipes-py/recipe_engine/env.py' to import protobuf from third_party
directory instead of the one installed with current python libraries."""

import contextlib
import pkg_resources
import os
import sys


def PrepareProtobuf():
  CHROME_SRC = os.path.abspath(
      os.path.join(os.path.dirname(os.path.realpath(__file__)),
      "..", "..", ".."))
  THIRD_PARTY = os.path.join(CHROME_SRC, 'third_party')
  sys.path.insert(0, os.path.join(THIRD_PARTY, 'protobuf', 'python'))
  sys.path.insert(
      1, os.path.join(THIRD_PARTY, 'protobuf', 'third_party', 'six'))

  @contextlib.contextmanager
  def temp_sys_path():
    orig_path = sys.path[:]
    try:
      yield
    finally:
      sys.path = orig_path

  with temp_sys_path():
    sys.path = [THIRD_PARTY]
    sys.modules.pop('google', None)
    pkg_resources.declare_namespace('google')
    pkg_resources.fixup_namespace_packages(THIRD_PARTY)
