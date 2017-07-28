// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/metrics/histogram_functions.h"

#include "base/metrics/histogram_macros.h"
#include "base/test/histogram_tester.h"
#include "base/time/time.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace base {

enum UmaHistogramTestingEnum {
  UMA_HISTOGRAM_TESTING_ENUM_FIRST,
  UMA_HISTOGRAM_TESTING_ENUM_SECOND,
  UMA_HISTOGRAM_TESTING_ENUM_THIRD
};

TEST(HistogramFunctionsTest, HistogramExactLinear) {
  std::string histogram("Testing.UMA.HistogramExactLinear");
  HistogramTester tester;
  UmaHistogramExactLinear(histogram, 10, 100);
  tester.ExpectUniqueSample(histogram, 10, 1);
  UmaHistogramExactLinear(histogram, 20, 100);
  UmaHistogramExactLinear(histogram, 10, 100);
  tester.ExpectBucketCount(histogram, 10, 2);
  tester.ExpectBucketCount(histogram, 20, 1);
  tester.ExpectTotalCount(histogram, 3);
  // Test linear buckets overflow.
  UmaHistogramExactLinear(histogram, 200, 100);
  tester.ExpectBucketCount(histogram, 101, 1);
  tester.ExpectTotalCount(histogram, 4);
  // Test linear buckets underflow.
  UmaHistogramExactLinear(histogram, 0, 100);
  tester.ExpectBucketCount(histogram, 0, 1);
  tester.ExpectTotalCount(histogram, 5);
}

TEST(HistogramFunctionsTest, HistogramEnumeration) {
  std::string histogram("Testing.UMA.HistogramEnumeration");
  HistogramTester tester;
  UmaHistogramEnumeration(histogram, UMA_HISTOGRAM_TESTING_ENUM_FIRST,
                          UMA_HISTOGRAM_TESTING_ENUM_THIRD);
  tester.ExpectUniqueSample(histogram, UMA_HISTOGRAM_TESTING_ENUM_FIRST, 1);

  // Verify the overflow & underflow bucket exists.
  UMA_HISTOGRAM_ENUMERATION(
      histogram, static_cast<int>(UMA_HISTOGRAM_TESTING_ENUM_THIRD) + 10,
      static_cast<int>(UMA_HISTOGRAM_TESTING_ENUM_THIRD));
  tester.ExpectBucketCount(
      histogram, static_cast<int>(UMA_HISTOGRAM_TESTING_ENUM_THIRD) + 1, 1);
  tester.ExpectTotalCount(histogram, 2);
}

TEST(HistogramFunctionsTest, HistogramBoolean) {
  std::string histogram("Testing.UMA.HistogramBoolean");
  HistogramTester tester;
  UmaHistogramBoolean(histogram, true);
  tester.ExpectUniqueSample(histogram, 1, 1);
  UmaHistogramBoolean(histogram, false);
  tester.ExpectBucketCount(histogram, 0, 1);
  tester.ExpectTotalCount(histogram, 2);
}

TEST(HistogramFunctionsTest, HistogramPercentage) {
  std::string histogram("Testing.UMA.HistogramPercentage");
  HistogramTester tester;
  UmaHistogramPercentage(histogram, 50);
  tester.ExpectUniqueSample(histogram, 50, 1);
  // Test overflows.
  UmaHistogramPercentage(histogram, 110);
  tester.ExpectBucketCount(histogram, 101, 1);
  tester.ExpectTotalCount(histogram, 2);
}

TEST(HistogramFunctionsTest, HistogramCounts) {
  std::string histogram("Testing.UMA.HistogramCount.Custom");
  HistogramTester tester;
  UmaHistogramCustomCounts(histogram, 10, 1, 100, 10);
  tester.ExpectUniqueSample(histogram, 10, 1);
  UmaHistogramCustomCounts(histogram, 20, 1, 100, 10);
  UmaHistogramCustomCounts(histogram, 20, 1, 100, 10);
  UmaHistogramCustomCounts(histogram, 20, 1, 100, 10);
  tester.ExpectBucketCount(histogram, 20, 3);
  tester.ExpectTotalCount(histogram, 4);
  UmaHistogramCustomCounts(histogram, 110, 1, 100, 10);
  tester.ExpectBucketCount(histogram, 101, 1);
  tester.ExpectTotalCount(histogram, 5);
}

TEST(HistogramFunctionsTest, HistogramTimes) {
  std::string histogram("Testing.UMA.HistogramTimes");
  HistogramTester tester;
  UmaHistogramTimes(histogram, TimeDelta::FromSeconds(1));
  tester.ExpectTimeBucketCount(histogram, TimeDelta::FromSeconds(1), 1);
  tester.ExpectTotalCount(histogram, 1);
  UmaHistogramTimes(histogram, TimeDelta::FromSeconds(9));
  tester.ExpectTimeBucketCount(histogram, TimeDelta::FromSeconds(9), 1);
  tester.ExpectTotalCount(histogram, 2);
  UmaHistogramTimes(histogram, TimeDelta::FromSeconds(10));  // Overflows
  tester.ExpectTimeBucketCount(histogram, TimeDelta::FromSeconds(10), 1);
  UmaHistogramTimes(histogram, TimeDelta::FromSeconds(20));  // Overflows.
  // Check the value by picking any overflow time.
  tester.ExpectTimeBucketCount(histogram, TimeDelta::FromSeconds(11), 2);
  tester.ExpectTotalCount(histogram, 4);
}

}  // namespace base.
