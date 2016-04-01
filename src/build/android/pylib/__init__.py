# Copyright (c) 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import sys

_DEVIL_PATH = os.path.abspath(os.path.join(
    os.path.dirname(__file__), '..', '..', '..', 'third_party', 'catapult',
    'devil'))

if _DEVIL_PATH not in sys.path:
  sys.path.append(_DEVIL_PATH)
