# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import unittest

from bisect_state import BisectState


class BisectStateTest(unittest.TestCase):

  def testCreatesRevisionsStateAfterAReferenceRevision(self):
    bisect_state = BisectState('chromium', ['a', 'b', 'c', 'd'])
    bisect_state.CreateRevisionStatesAfter('webkit', [1, 2, 3], 'chromium', 'b')
    bisect_state.CreateRevisionStatesAfter('v8', [100, 200], 'webkit', 2)

    actual_revisions = bisect_state.GetRevisionStates()
    expected_revisions = [('chromium', 'a'), ('chromium', 'b'), ('webkit', 1),
                          ('webkit', 2), ('v8', 100), ('v8', 200),
                          ('webkit', 3), ('chromium', 'c'), ('chromium', 'd')]
    self.assertEqual(len(expected_revisions), len(actual_revisions))
    for i in xrange(len(actual_revisions)):
      self.assertEqual(i, actual_revisions[i].index)
      self.assertEqual(expected_revisions[i][0], actual_revisions[i].depot)
      self.assertEqual(expected_revisions[i][1], actual_revisions[i].revision)

  # TODO(sergiyb): More tests for the remaining functions.


if __name__ == '__main__':
  unittest.main()
