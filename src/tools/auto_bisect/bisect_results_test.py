# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import unittest

from bisect_results import BisectResults
import source_control


class MockDepotRegistry(object):
  def ChangeToDepotDir(self, depot):
    pass


class MockRevisionState(object):
  def __init__(self, revision, index, depot='chromium', value=None,
               perf_time=0, build_time=0, passed='?', external=None):
    self.depot = depot
    self.revision = revision
    self.index = index
    self.value = value
    self.perf_time = perf_time
    self.build_time = build_time
    self.passed = passed
    self.external = external


class MockBisectState(object):

  def __init__(self):
    self.mock_revision_states = []

    mock_bad_val = {'values': [100, 105, 95]}
    for i, rev in enumerate(['a', 'b']):
      mock_rev_state = MockRevisionState(rev, i, value=mock_bad_val, passed=0)
      self.mock_revision_states.append(mock_rev_state)

    mock_good_val = {'values': [1, 2, 3]}
    for i, rev in enumerate(['c', 'd', 'e'], start=2):
      mock_rev_state = MockRevisionState(rev, i, value=mock_good_val, passed=1)
      self.mock_revision_states.append(mock_rev_state)

  def GetRevisionStates(self):
    return self.mock_revision_states


class MockBisectOptions(object):

  def __init__(self):
    self.repeat_test_count = 3


class BisectResultsTest(unittest.TestCase):

  def setUp(self):
    self.mock_bisect_state = MockBisectState()
    self.mock_depot_registry = MockDepotRegistry()
    self.mock_opts = MockBisectOptions()
    self.mock_warnings = []

    self.original_getcwd = os.getcwd
    self.original_chdir = os.chdir
    self.original_query_revision_info = source_control.QueryRevisionInfo

    os.getcwd = lambda: '/path'
    os.chdir = lambda _: None

    revision_infos = {'b': {'test': 'b'}, 'c': {'test': 'c'}}
    source_control.QueryRevisionInfo = lambda rev: revision_infos[rev]

  def tearDown(self):
    os.getcwd = self.original_getcwd
    os.chdir = self.original_chdir
    source_control.QueryRevisionInfo = self.original_query_revision_info

  def _AssertConfidence(self, score, bad_values, good_values):
    """Checks whether the given sets of values have a given confidence score.

    The score represents our confidence that the two sets of values wouldn't
    be as different as they are just by chance; that is, that some real change
    occurred between the two sets of values.

    Args:
      score: Expected confidence score.
      bad_values: First list of numbers.
      good_values: Second list of numbers.
    """
    confidence = BisectResults.ConfidenceScore(bad_values, good_values)
    self.assertEqual(score, confidence)

  def testConfidenceScoreIsZeroOnTooFewLists(self):
    self._AssertConfidence(0.0, [], [1, 2])
    self._AssertConfidence(0.0, [1, 2], [])
    self._AssertConfidence(0.0, [1], [1, 2])
    self._AssertConfidence(0.0, [1, 2], [1])

  def testConfidenceScore_ZeroConfidence(self):
    # The good and bad sets contain the same values, so the confidence that
    # they're different should be zero.
    self._AssertConfidence(0.0, [4, 5, 7, 6, 8, 7], [8, 7, 6, 7, 5, 4])

  def testConfidenceScore_MediumConfidence(self):
    self._AssertConfidence(80.0, [0, 1, 1, 1, 2, 2], [1, 1, 1, 3, 3, 4])

  def testConfidenceScore_HighConfidence(self):
    self._AssertConfidence(95.0, [0, 1, 1, 1, 2, 2], [1, 2, 2, 3, 3, 4])

  def testConfidenceScore_VeryHighConfidence(self):
    # Confidence is high if the two sets of values have no internal variance.
    self._AssertConfidence(99.9, [1, 1, 1, 1], [1.2, 1.2, 1.2, 1.2])
    self._AssertConfidence(99.9, [1, 1, 1, 1], [1.01, 1.01, 1.01, 1.01])

  def testConfidenceScore_UnbalancedSampleSize(self):
    # The second set of numbers only contains one number, so confidence is 0.
    self._AssertConfidence(0.0, [1.1, 1.2, 1.1, 1.2, 1.0, 1.3, 1.2], [1.4])

  def testConfidenceScore_EmptySample(self):
    # Confidence is zero if either or both samples are empty.
    self._AssertConfidence(0.0, [], [])
    self._AssertConfidence(0.0, [], [1.1, 1.2, 1.1, 1.2, 1.0, 1.3, 1.2, 1.3])
    self._AssertConfidence(0.0, [1.1, 1.2, 1.1, 1.2, 1.0, 1.3, 1.2, 1.3], [])

  def testConfidenceScore_FunctionalTestResults(self):
    self._AssertConfidence(80.0, [1, 1, 0, 1, 1, 1, 0, 1], [0, 0, 1, 0, 1, 0])
    self._AssertConfidence(99.9, [1, 1, 1, 1, 1, 1, 1, 1], [0, 0, 0, 0, 0, 0])

  def testConfidenceScore_RealWorldCases(self):
    """This method contains a set of data from actual bisect results.

    The confidence scores asserted below were all copied from the actual
    results, so the purpose of this test method is mainly to show what the
    results for real cases are, and compare when we change the confidence
    score function in the future.
    """
    self._AssertConfidence(80, [133, 130, 132, 132, 130, 129], [129, 129, 125])
    self._AssertConfidence(99.5, [668, 667], [498, 498, 499])
    self._AssertConfidence(80, [67, 68], [65, 65, 67])
    self._AssertConfidence(0, [514], [514])
    self._AssertConfidence(90, [616, 613, 607, 615], [617, 619, 619, 617])
    self._AssertConfidence(0, [3.5, 5.8, 4.7, 3.5, 3.6], [2.8])
    self._AssertConfidence(90, [3, 3, 3], [2, 2, 2, 3])
    self._AssertConfidence(0, [1999004, 1999627], [223355])
    self._AssertConfidence(90, [1040, 934, 961], [876, 875, 789])
    self._AssertConfidence(90, [309, 305, 304], [302, 302, 299, 303, 298])

  def testCorrectlyFindsBreakingRange(self):
    revision_states = self.mock_bisect_state.mock_revision_states
    revision_states[0].passed = 0
    revision_states[1].passed = 0
    revision_states[2].passed = 1
    revision_states[3].passed = 1
    revision_states[4].passed = 1

    results = BisectResults(self.mock_bisect_state, self.mock_depot_registry,
                            self.mock_opts, self.mock_warnings)
    self.assertEqual(revision_states[2], results.first_working_revision)
    self.assertEqual(revision_states[1], results.last_broken_revision)

  def testCorrectlyFindsBreakingRangeNotInOrder(self):
    revision_states = self.mock_bisect_state.mock_revision_states
    revision_states[0].passed = 0
    revision_states[1].passed = 1
    revision_states[2].passed = 0
    revision_states[3].passed = 1
    revision_states[4].passed = 1

    results = BisectResults(self.mock_bisect_state, self.mock_depot_registry,
                            self.mock_opts, self.mock_warnings)
    self.assertEqual(revision_states[1], results.first_working_revision)
    self.assertEqual(revision_states[2], results.last_broken_revision)

  def testCorrectlyFindsBreakingRangeIncompleteBisect(self):
    revision_states = self.mock_bisect_state.mock_revision_states
    revision_states[0].passed = 0
    revision_states[1].passed = 0
    revision_states[2].passed = '?'
    revision_states[3].passed = 1
    revision_states[4].passed = 1

    results = BisectResults(self.mock_bisect_state, self.mock_depot_registry,
                            self.mock_opts, self.mock_warnings)
    self.assertEqual(revision_states[3], results.first_working_revision)
    self.assertEqual(revision_states[1], results.last_broken_revision)

  def testFindBreakingRangeAllPassed(self):
    revision_states = self.mock_bisect_state.mock_revision_states
    revision_states[0].passed = 1
    revision_states[1].passed = 1
    revision_states[2].passed = 1
    revision_states[3].passed = 1
    revision_states[4].passed = 1

    results = BisectResults(self.mock_bisect_state, self.mock_depot_registry,
                            self.mock_opts, self.mock_warnings)
    self.assertEqual(revision_states[0], results.first_working_revision)
    self.assertIsNone(results.last_broken_revision)

  def testFindBreakingRangeNonePassed(self):
    revision_states = self.mock_bisect_state.mock_revision_states
    revision_states[0].passed = 0
    revision_states[1].passed = 0
    revision_states[2].passed = 0
    revision_states[3].passed = 0
    revision_states[4].passed = 0

    results = BisectResults(self.mock_bisect_state, self.mock_depot_registry,
                            self.mock_opts, self.mock_warnings)
    self.assertIsNone(results.first_working_revision)
    self.assertEqual(revision_states[4], results.last_broken_revision)

  def testCorrectlyComputesRegressionStatistics(self):
    revision_states = self.mock_bisect_state.mock_revision_states
    revision_states[0].passed = 0
    revision_states[0].value = {'values': [1000, 999, 998]}
    revision_states[1].passed = 0
    revision_states[1].value = {'values': [980, 1000, 999]}
    revision_states[2].passed = 1
    revision_states[2].value = {'values': [50, 45, 55]}
    revision_states[3].passed = 1
    revision_states[3].value = {'values': [45, 56, 45]}
    revision_states[4].passed = 1
    revision_states[4].value = {'values': [51, 41, 58]}

    results = BisectResults(self.mock_bisect_state, self.mock_depot_registry,
                            self.mock_opts, self.mock_warnings)
    self.assertAlmostEqual(99.9, results.confidence)
    self.assertAlmostEqual(1909.86547085, results.regression_size)
    self.assertAlmostEqual(7.16625904, results.regression_std_err)

  def testFindsCulpritRevisions(self):
    revision_states = self.mock_bisect_state.mock_revision_states
    revision_states[1].depot = 'chromium'
    revision_states[2].depot = 'webkit'

    results = BisectResults(self.mock_bisect_state, self.mock_depot_registry,
                            self.mock_opts, self.mock_warnings)

    self.assertEqual(1, len(results.culprit_revisions))
    self.assertEqual(('b', {'test': 'b'}, 'chromium'),
                     results.culprit_revisions[0])

  def testNoResultBasedWarningsForNormalState(self):
    results = BisectResults(self.mock_bisect_state, self.mock_depot_registry,
                            self.mock_opts, self.mock_warnings)
    self.assertEqual(0, len(results.warnings))

  def testWarningForMultipleCulpritRevisions(self):
    self.mock_bisect_state.mock_revision_states[2].passed = 'Skipped'
    results = BisectResults(self.mock_bisect_state, self.mock_depot_registry,
                            self.mock_opts, self.mock_warnings)
    self.assertEqual(1, len(results.warnings))

  def testWarningForTooLowRetryLimit(self):
    self.mock_opts.repeat_test_count = 1
    results = BisectResults(self.mock_bisect_state, self.mock_depot_registry,
                            self.mock_opts, self.mock_warnings)
    self.assertEqual(1, len(results.warnings))

  def testWarningForTooLowConfidence(self):
    revision_states = self.mock_bisect_state.mock_revision_states
    revision_states[2].value = {'values': [95, 90, 90]}
    revision_states[3].value = {'values': [95, 90, 90]}
    revision_states[4].value = {'values': [95, 90, 90]}
    results = BisectResults(self.mock_bisect_state, self.mock_depot_registry,
                            self.mock_opts, self.mock_warnings)
    self.assertGreater(results.confidence, 0)
    self.assertEqual(1, len(results.warnings))

  def testWarningForZeroConfidence(self):
    revision_states = self.mock_bisect_state.mock_revision_states
    revision_states[2].value = {'values': [100, 105, 95]}
    revision_states[3].value = {'values': [100, 105, 95]}
    revision_states[4].value = {'values': [100, 105, 95]}
    results = BisectResults(self.mock_bisect_state, self.mock_depot_registry,
                            self.mock_opts, self.mock_warnings)
    self.assertEqual(0, results.confidence)
    self.assertEqual(1, len(results.warnings))


if __name__ == '__main__':
  unittest.main()
