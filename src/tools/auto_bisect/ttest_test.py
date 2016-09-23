# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Unit tests for ttest module."""

import unittest

import ttest


# This test case accesses private functions of the ttest module.
# pylint: disable=W0212
class TTestTest(unittest.TestCase):
  """Tests for the t-test functions."""

  def testWelchsFormula(self):
    """Tests calculation of the t value."""
    # Results can be verified by directly plugging variables into Welch's
    # equation (e.g. using a calculator or the Python interpreter).
    self.assertEqual(
        -0.2796823595120407,
        ttest._TValue(0.299, 0.307, 0.05, 0.08, 150, 165))

    # Note that a negative t value is obtained when the first sample has a
    # smaller mean than the second, otherwise a positive value is returned.
    self.assertEqual(
        0.2796823595120407,
        ttest._TValue(0.307, 0.299, 0.08, 0.05, 165, 150))

  def testWelchSatterthwaiteFormula(self):
    """Tests calculation of estimated degrees of freedom."""
    # Note that since the Welch-Satterthwaite equation gives an estimate of
    # degrees of freedom, the result may not be an integer.
    self.assertEqual(
        307.1987997516727,
        ttest._DegreesOfFreedom(0.05, 0.08, 150, 165))

  def testWelchsTTest(self):
    """Tests the t value and degrees of freedom output of Welch's t-test."""
    # The t-value can be checked with scipy.stats.ttest_ind(equal_var=False).
    t, df, _ = ttest.WelchsTTest([2, 3, 2, 3, 2, 3], [4, 5, 4, 5, 4, 5])
    self.assertAlmostEqual(10.0, df)

    # The t-value produced by scipy.stats.ttest_ind is -6.32455532034.
    # Our function produces slightly different results.
    # Possibly due to differences in rounding error?
    self.assertAlmostEqual(-6.325, t, delta=1.0)

  def testTTestEqualSamples(self):
    """Checks that t = 0 and p = 1 when the samples are the same."""
    t, _, p = ttest.WelchsTTest([1, 2, 3], [1, 2, 3])
    self.assertEqual(0, t)
    self.assertEqual(1, p)

    t, _, p = ttest.WelchsTTest([1, 2], [1, 2])
    self.assertEqual(0, t)
    self.assertEqual(1, p)

  def testTTestVeryDifferentSamples(self):
    """Checks that p is very low when the samples are clearly different."""
    t, _, p = ttest.WelchsTTest(
        [100, 101, 100, 101, 100], [1, 2, 1, 2, 1, 2, 1, 2])
    self.assertGreaterEqual(t, 250)
    self.assertLessEqual(p, 0.01)

  def testTTestVariance(self):
    """Verifies that higher variance -> higher p value."""
    _, _, p_low_var = ttest.WelchsTTest([2, 3, 2, 3], [4, 5, 4, 5])
    _, _, p_high_var = ttest.WelchsTTest([1, 4, 1, 4], [3, 6, 3, 6])
    self.assertLess(p_low_var, p_high_var)

  def testTTestSampleSize(self):
    """Verifies that smaller sample size -> higher p value."""
    _, _, p_larger_sample = ttest.WelchsTTest([2, 3, 2, 3], [4, 5, 4, 5])
    _, _, p_smaller_sample = ttest.WelchsTTest([2, 3, 2, 3], [4, 5])
    self.assertLess(p_larger_sample, p_smaller_sample)

  def testTTestMeanDifference(self):
    """Verifies that smaller difference between means -> higher p value."""
    _, _, p_far_means = ttest.WelchsTTest([2, 3, 2, 3], [5, 6, 5, 6])
    _, _, p_near_means = ttest.WelchsTTest([2, 3, 2, 3], [3, 4, 3, 4])
    self.assertLess(p_far_means, p_near_means)


class LookupTableTest(unittest.TestCase):
  """Tests for functionality related to lookup of p-values in a table."""

  def setUp(self):
    self.original_TWO_TAIL = ttest.TWO_TAIL
    self.original_TABLE = ttest.TABLE
    ttest.TWO_TAIL = [1, 0.2, 0.1, 0.05, 0.02, 0.01]
    ttest.TABLE = {
        1: [0, 6.314, 12.71, 31.82, 63.66, 318.31],
        2: [0, 2.920, 4.303, 6.965, 9.925, 22.327],
        3: [0, 2.353, 3.182, 4.541, 5.841, 10.215],
        4: [0, 2.132, 2.776, 3.747, 4.604, 7.173],
    }

  def tearDown(self):
    ttest.TWO_TAIL = self.original_TWO_TAIL
    ttest.TABLE = self.original_TABLE

  def testLookupExactMatch(self):
    """Tests a lookup when there is an exact match."""
    self.assertEqual(0.1, ttest._LookupPValue(3.182, 3))
    self.assertEqual(0.1, ttest._LookupPValue(-3.182, 3))

  def testLookupAbove(self):
    """Tests a lookup when the given value is above an entry in the table."""
    self.assertEqual(0.2, ttest._LookupPValue(3.1, 2))
    self.assertEqual(0.2, ttest._LookupPValue(-3.1, 2))

  def testLookupLargeTValue(self):
    """Tests a lookup when the given t-value is very large."""
    self.assertEqual(0.01, ttest._LookupPValue(500.0, 1))
    self.assertEqual(0.01, ttest._LookupPValue(-500.0, 1))

  def testLookupZeroTValue(self):
    """Tests a lookup when the given t-value is zero."""
    self.assertEqual(1, ttest._LookupPValue(0.0, 1))
    self.assertEqual(1, ttest._LookupPValue(0.0, 2))

  def testLookupLargeDF(self):
    """Tests a lookup when the given degrees of freedom is large."""
    self.assertEqual(0.02, ttest._LookupPValue(5.0, 50))


if __name__ == '__main__':
  unittest.main()
