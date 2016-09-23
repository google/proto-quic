# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import unittest

import mergetraces

class GroupByProcessAndThreadIdTestBasic(unittest.TestCase):
  def runTest(self):
    # (sec, usec, 'pid:tid', function address).
    input_trace = [
        (100, 10, '2000:2001', 0x5),
        (100, 11, '2000:2001', 0x3),
        (100, 13, '2000:1999', 0x8),
        (100, 14, '2000:2000', 0x7),
        (120, 13, '2001:2003', 0x9),
        (150, 12, '2001:2004', 0x6),
        (180, 11, '2000:2000', 0x1),
    ]

    # Functions should be grouped by thread-id and PIDs should not be
    # interleaved.
    expected_trace = [
        (100, 10, '2000:2001', 0x5),
        (100, 11, '2000:2001', 0x3),
        (100, 13, '2000:1999', 0x8),
        (100, 14, '2000:2000', 0x7),
        (180, 11, '2000:2000', 0x1),
        (120, 13, '2001:2003', 0x9),
        (150, 12, '2001:2004', 0x6),
    ]

    grouped_trace = mergetraces.GroupByProcessAndThreadId(input_trace)

    self.assertEqual(grouped_trace, expected_trace)

class GroupByProcessAndThreadIdFailsWithNonUniqueTIDs(unittest.TestCase):
  def runTest(self):
    # (sec, usec, 'pid:tid', function address).
    input_trace = [
        (100, 10, '1999:2001', 0x5),
        (100, 10, '1988:2001', 0x5),
    ]

    try:
      mergetraces.GroupByProcessAndThreadId(input_trace)
    except Exception:
      return

    self.fail('Multiple processes should not have a same thread-ID.')
