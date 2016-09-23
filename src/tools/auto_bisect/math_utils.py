# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""General statistical or mathematical functions."""

import math


def TruncatedMean(data_set, truncate_proportion):
  """Calculates the truncated mean of a set of values.

  Note that this isn't just the mean of the set of values with the highest
  and lowest values discarded; the non-discarded values are also weighted
  differently depending how many values are discarded.

  NOTE: If there's not much benefit from this keeping and weighting
  partial values, it might be better to use a simplified truncated mean
  function without weighting.

  Args:
    data_set: Non-empty list of values.
    truncate_proportion: How much of the upper and lower portions of the data
        set to discard, expressed as a value in the range [0, 1].
        Note: a value of 0.5 or greater would be meaningless

  Returns:
    The truncated mean as a float.

  Raises:
    TypeError: The data set was empty after discarding values.
  """
  if len(data_set) > 2:
    data_set = sorted(data_set)

    discard_num_float = len(data_set) * truncate_proportion
    discard_num_int = int(math.floor(discard_num_float))
    kept_weight = len(data_set) - (discard_num_float * 2)

    data_set = data_set[discard_num_int:len(data_set)-discard_num_int]

    weight_left = 1.0 - (discard_num_float - discard_num_int)

    if weight_left < 1:
      # If the % to discard leaves a fractional portion, need to weight those
      # values.
      unweighted_vals = data_set[1:len(data_set)-1]
      weighted_vals = [data_set[0], data_set[len(data_set)-1]]
      weighted_vals = [w * weight_left for w in weighted_vals]
      data_set = weighted_vals + unweighted_vals
  else:
    kept_weight = len(data_set)

  data_sum = reduce(lambda x, y: float(x) + float(y), data_set)
  truncated_mean = data_sum / kept_weight
  return truncated_mean


def Mean(values):
  """Calculates the arithmetic mean of a list of values."""
  return TruncatedMean(values, 0.0)


def Variance(values):
  """Calculates the sample variance."""
  if len(values) == 1:
    return 0.0
  mean = Mean(values)
  differences_from_mean = [float(x) - mean for x in values]
  squared_differences = [float(x * x) for x in differences_from_mean]
  variance = sum(squared_differences) / (len(values) - 1)
  return variance


def StandardDeviation(values):
  """Calculates the sample standard deviation of the given list of values."""
  return math.sqrt(Variance(values))


def RelativeChange(before, after):
  """Returns the relative change of before and after, relative to before.

  There are several different ways to define relative difference between
  two numbers; sometimes it is defined as relative to the smaller number,
  or to the mean of the two numbers. This version returns the difference
  relative to the first of the two numbers.

  Args:
    before: A number representing an earlier value.
    after: Another number, representing a later value.

  Returns:
    A non-negative floating point number; 0.1 represents a 10% change.
  """
  if before == after:
    return 0.0
  if before == 0:
    return float('nan')
  difference = after - before
  return math.fabs(difference / before)


def PooledStandardError(work_sets):
  """Calculates the pooled sample standard error for a set of samples.

  Args:
    work_sets: A collection of collections of numbers.

  Returns:
    Pooled sample standard error.
  """
  numerator = 0.0
  denominator1 = 0.0
  denominator2 = 0.0

  for current_set in work_sets:
    std_dev = StandardDeviation(current_set)
    numerator += (len(current_set) - 1) * std_dev ** 2
    denominator1 += len(current_set) - 1
    if len(current_set) > 0:
      denominator2 += 1.0 / len(current_set)

  if denominator1 == 0:
    return 0.0

  return math.sqrt(numerator / denominator1) * math.sqrt(denominator2)


# Redefining built-in 'StandardError'
# pylint: disable=W0622
def StandardError(values):
  """Calculates the standard error of a list of values."""
  # NOTE: This behavior of returning 0.0 in the case of an empty list is
  # inconsistent with Variance and StandardDeviation above.
  if len(values) <= 1:
    return 0.0
  std_dev = StandardDeviation(values)
  return std_dev / math.sqrt(len(values))
