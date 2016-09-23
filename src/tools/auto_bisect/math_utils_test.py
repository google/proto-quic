# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import math
import unittest

import math_utils


class MathUtilsTest(unittest.TestCase):
  """Tests for mathematical utility functions."""

  def testTruncatedMean_EmptyList(self):
    # TruncatedMean raises an error when passed an empty list.
    self.assertRaises(TypeError, math_utils.TruncatedMean, [], 0)

  def testTruncatedMean_TruncateTooMuch(self):
    # An exception is raised if 50% or more is truncated from both sides.
    self.assertRaises(TypeError, math_utils.TruncatedMean, [1, 2, 3], 1.0)
    self.assertRaises(
        ZeroDivisionError, math_utils.TruncatedMean, [1, 2, 3], 0.5)

  def testTruncatedMean_AlwaysKeepsAtLeastTwoValues(self):
    # If the length of the input is 1 or 2, nothing is truncated and
    # the average is returned.
    self.assertEqual(5.0, math_utils.TruncatedMean([5.0], 0.0))
    self.assertEqual(5.0, math_utils.TruncatedMean([5.0], 0.25))
    self.assertEqual(5.0, math_utils.TruncatedMean([5.0], 0.5))
    self.assertEqual(5.5, math_utils.TruncatedMean([5.0, 6.0], 0.0))
    self.assertEqual(5.5, math_utils.TruncatedMean([5.0, 6.0], 0.25))
    self.assertEqual(5.5, math_utils.TruncatedMean([5.0, 6.0], 0.5))

  def testTruncatedMean_Interquartile_NumValuesDivisibleByFour(self):
    self.assertEqual(5.0, math_utils.TruncatedMean([1, 4, 6, 100], 0.25))
    self.assertEqual(
        6.5, math_utils.TruncatedMean([1, 2, 5, 6, 7, 8, 40, 50], 0.25))

  def testTruncatedMean_Weighting(self):
    # In the list [0, 1, 4, 5, 20, 100], when 25% of the list at the start
    # and end are discarded, the part that's left is [1, 4, 5, 20], but
    # first and last values are weighted so that they only count for half
    # as much. So the truncated mean is (1/2 + 4 + 5 + 20/2) / 5.0.
    self.assertEqual(6.5, (0.5 + 4 + 5 + 10) / 3.0)
    self.assertEqual(6.5, math_utils.TruncatedMean([0, 1, 4, 5, 20, 100], 0.25))

  def testMean_OneValue(self):
    self.assertEqual(3.0, math_utils.Mean([3]))

  def testMean_ShortList(self):
    self.assertEqual(0.5, math_utils.Mean([-3, 0, 1, 4]))

  def testMean_CompareAlternateImplementation(self):
    """Tests Mean by comparing against an alternate implementation."""
    def AlternateMean(values):
      return sum(values) / float(len(values))
    test_value_lists = [
        [1],
        [5, 6.5, 1.2, 3],
        [-3, 0, 1, 4],
        [-3, -1, 0.12, 0.752, 3.33, 8, 16, 32, 439],
    ]
    for value_list in test_value_lists:
      self.assertEqual(AlternateMean(value_list), math_utils.Mean(value_list))

  def testRelativeChange_NonZero(self):
    # The change is relative to the first value, regardless of which is bigger.
    self.assertEqual(0.5, math_utils.RelativeChange(1.0, 1.5))
    self.assertEqual(0.5, math_utils.RelativeChange(2.0, 1.0))

  def testRelativeChange_FromZero(self):
    # If the first number is zero, then the result is not a number.
    self.assertEqual(0, math_utils.RelativeChange(0, 0))
    self.assertTrue(math.isnan(math_utils.RelativeChange(0, 1)))
    self.assertTrue(math.isnan(math_utils.RelativeChange(0, -1)))

  def testRelativeChange_Negative(self):
    # Note that the return value of RelativeChange is always positive.
    self.assertEqual(3.0, math_utils.RelativeChange(-1, 2))
    self.assertEqual(3.0, math_utils.RelativeChange(1, -2))
    self.assertEqual(1.0, math_utils.RelativeChange(-1, -2))

  def testVariance_EmptyList(self):
    self.assertRaises(TypeError, math_utils.Variance, [])

  def testVariance_OneValue(self):
    self.assertEqual(0, math_utils.Variance([0]))
    self.assertEqual(0, math_utils.Variance([4.3]))

  def testVariance_ShortList(self):
    # Population variance is the average of squared deviations from the mean.
    # The deviations from the mean in this example are [3.5, 0.5, -0.5, -3.5],
    # and the squared deviations are [12.25, 0.25, 0.25, 12.25].
    # With sample variance, however, 1 is subtracted from the sample size.
    # So the sample variance is sum([12.25, 0.25, 0.25, 12.25]) / 3.0.
    self.assertAlmostEqual(8.333333334, sum([12.25, 0.25, 0.25, 12.25]) / 3.0)
    self.assertAlmostEqual(8.333333334, math_utils.Variance([-3, 0, 1, 4]))

  def testStandardDeviation(self):
    # Standard deviation is the square root of variance.
    self.assertRaises(TypeError, math_utils.StandardDeviation, [])
    self.assertEqual(0.0, math_utils.StandardDeviation([4.3]))
    self.assertAlmostEqual(2.88675135, math.sqrt(8.33333333333333))
    self.assertAlmostEqual(2.88675135,
                           math_utils.StandardDeviation([-3, 0, 1, 4]))

  def testStandardError(self):
    # Standard error is std. dev. divided by square root of sample size.
    self.assertEqual(0.0, math_utils.StandardError([]))
    self.assertEqual(0.0, math_utils.StandardError([4.3]))
    self.assertAlmostEqual(1.44337567, 2.88675135 / math.sqrt(4))
    self.assertAlmostEqual(1.44337567, math_utils.StandardError([-3, 0, 1, 4]))

if __name__ == '__main__':
  unittest.main()
