# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""Generators for Chrome profiles for testing purposes."""
import os
import sys

sys.path.insert(1, os.path.abspath(os.path.join(
    __file__, '..', '..')))
from core import path_util


path_util.AddTelemetryToPath()
path_util.AddPyUtilsToPath()
