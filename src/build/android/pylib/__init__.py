# Copyright (c) 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import sys

_DEVIL_PATH = os.path.abspath(os.path.join(
    os.path.dirname(__file__), '..', '..', '..', 'third_party', 'catapult',
    'devil'))

_PYTRACE_PATH = os.path.abspath(os.path.join(
    os.path.dirname(__file__), '..', '..', '..', 'third_party', 'catapult',
    'common', 'py_trace_event'))

if _DEVIL_PATH not in sys.path:
  sys.path.append(_DEVIL_PATH)

if _PYTRACE_PATH not in sys.path:
  sys.path.append(_PYTRACE_PATH)
