// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <limits>

#include "base/logging.h"
#include "base/macros.h"
#include "base/numerics/saturated_arithmetic.h"
#include "build/build_config.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace base {

TEST(SaturatedArithmeticTest, Addition) {
  int int_max = std::numeric_limits<int>::max();
  int int_min = std::numeric_limits<int>::min();

  EXPECT_EQ(0, SaturatedAddition(0, 0));
  EXPECT_EQ(1, SaturatedAddition(0, 1));
  EXPECT_EQ(100, SaturatedAddition(0, 100));
  EXPECT_EQ(150, SaturatedAddition(100, 50));

  EXPECT_EQ(-1, SaturatedAddition(0, -1));
  EXPECT_EQ(0, SaturatedAddition(1, -1));
  EXPECT_EQ(50, SaturatedAddition(100, -50));
  EXPECT_EQ(-50, SaturatedAddition(50, -100));

  EXPECT_EQ(int_max - 1, SaturatedAddition(int_max - 1, 0));
  EXPECT_EQ(int_max, SaturatedAddition(int_max - 1, 1));
  EXPECT_EQ(int_max, SaturatedAddition(int_max - 1, 2));
  EXPECT_EQ(int_max - 1, SaturatedAddition(0, int_max - 1));
  EXPECT_EQ(int_max, SaturatedAddition(1, int_max - 1));
  EXPECT_EQ(int_max, SaturatedAddition(2, int_max - 1));
  EXPECT_EQ(int_max, SaturatedAddition(int_max - 1, int_max - 1));
  EXPECT_EQ(int_max, SaturatedAddition(int_max, int_max));

  EXPECT_EQ(int_min, SaturatedAddition(int_min, 0));
  EXPECT_EQ(int_min + 1, SaturatedAddition(int_min + 1, 0));
  EXPECT_EQ(int_min + 2, SaturatedAddition(int_min + 1, 1));
  EXPECT_EQ(int_min + 3, SaturatedAddition(int_min + 1, 2));
  EXPECT_EQ(int_min, SaturatedAddition(int_min + 1, -1));
  EXPECT_EQ(int_min, SaturatedAddition(int_min + 1, -2));
  EXPECT_EQ(int_min + 1, SaturatedAddition(0, int_min + 1));
  EXPECT_EQ(int_min, SaturatedAddition(-1, int_min + 1));
  EXPECT_EQ(int_min, SaturatedAddition(-2, int_min + 1));

  EXPECT_EQ(int_max / 2 + 10000, SaturatedAddition(int_max / 2, 10000));
  EXPECT_EQ(int_max, SaturatedAddition(int_max / 2 + 1, int_max / 2 + 1));
  EXPECT_EQ(-1, SaturatedAddition(int_min, int_max));
}

TEST(SaturatedArithmeticTest, Subtraction) {
  int int_max = std::numeric_limits<int>::max();
  int int_min = std::numeric_limits<int>::min();

  EXPECT_EQ(0, SaturatedSubtraction(0, 0));
  EXPECT_EQ(-1, SaturatedSubtraction(0, 1));
  EXPECT_EQ(-100, SaturatedSubtraction(0, 100));
  EXPECT_EQ(50, SaturatedSubtraction(100, 50));

  EXPECT_EQ(1, SaturatedSubtraction(0, -1));
  EXPECT_EQ(2, SaturatedSubtraction(1, -1));
  EXPECT_EQ(150, SaturatedSubtraction(100, -50));
  EXPECT_EQ(150, SaturatedSubtraction(50, -100));

  EXPECT_EQ(int_max, SaturatedSubtraction(int_max, 0));
  EXPECT_EQ(int_max - 1, SaturatedSubtraction(int_max, 1));
  EXPECT_EQ(int_max - 1, SaturatedSubtraction(int_max - 1, 0));
  EXPECT_EQ(int_max, SaturatedSubtraction(int_max - 1, -1));
  EXPECT_EQ(int_max, SaturatedSubtraction(int_max - 1, -2));
  EXPECT_EQ(-int_max + 1, SaturatedSubtraction(0, int_max - 1));
  EXPECT_EQ(-int_max, SaturatedSubtraction(-1, int_max - 1));
  EXPECT_EQ(-int_max - 1, SaturatedSubtraction(-2, int_max - 1));
  EXPECT_EQ(-int_max - 1, SaturatedSubtraction(-3, int_max - 1));

  EXPECT_EQ(int_min, SaturatedSubtraction(int_min, 0));
  EXPECT_EQ(int_min + 1, SaturatedSubtraction(int_min + 1, 0));
  EXPECT_EQ(int_min, SaturatedSubtraction(int_min + 1, 1));
  EXPECT_EQ(int_min, SaturatedSubtraction(int_min + 1, 2));

  EXPECT_EQ(0, SaturatedSubtraction(int_min, int_min));
  EXPECT_EQ(0, SaturatedSubtraction(int_max, int_max));
  EXPECT_EQ(int_max, SaturatedSubtraction(int_max, int_min));
}

TEST(SaturatedArithmeticTest, SetSigned) {
  int int_max = std::numeric_limits<int>::max();
  int int_min = std::numeric_limits<int>::min();

  const int kFractionBits = 6;
  const int kIntMaxForLayoutUnit = int_max >> kFractionBits;
  const int kIntMinForLayoutUnit = int_min >> kFractionBits;

  EXPECT_EQ(0, SaturatedSet<kFractionBits>(0));

  // Internally the max number we can represent (without saturating)
  // is all the (non-sign) bits set except for the bottom n fraction bits
  const int max_internal_representation = int_max ^ ((1 << kFractionBits) - 1);
  EXPECT_EQ(max_internal_representation,
            SaturatedSet<kFractionBits>(kIntMaxForLayoutUnit));

  EXPECT_EQ(GetMaxSaturatedSetResultForTesting(kFractionBits),
            SaturatedSet<kFractionBits>(kIntMaxForLayoutUnit + 100));

  EXPECT_EQ((kIntMaxForLayoutUnit - 100) << kFractionBits,
            SaturatedSet<kFractionBits>(kIntMaxForLayoutUnit - 100));

  EXPECT_EQ(GetMinSaturatedSetResultForTesting(kFractionBits),
            SaturatedSet<kFractionBits>(kIntMinForLayoutUnit));

  EXPECT_EQ(GetMinSaturatedSetResultForTesting(kFractionBits),
            SaturatedSet<kFractionBits>(kIntMinForLayoutUnit - 100));

  // Shifting negative numbers left has undefined behavior, so use
  // multiplication instead of direct shifting here.
  EXPECT_EQ((kIntMinForLayoutUnit + 100) * (1 << kFractionBits),
            SaturatedSet<kFractionBits>(kIntMinForLayoutUnit + 100));
}

TEST(SaturatedArithmeticTest, SetUnsigned) {
  int int_max = std::numeric_limits<int>::max();

  const int kFractionBits = 6;
  const int kIntMaxForLayoutUnit = int_max >> kFractionBits;

  EXPECT_EQ(0, SaturatedSet<kFractionBits>((unsigned)0));

  EXPECT_EQ(GetMaxSaturatedSetResultForTesting(kFractionBits),
            SaturatedSet<kFractionBits>((unsigned)kIntMaxForLayoutUnit));

  const unsigned kOverflowed = kIntMaxForLayoutUnit + 100;
  EXPECT_EQ(GetMaxSaturatedSetResultForTesting(kFractionBits),
            SaturatedSet<kFractionBits>(kOverflowed));

  const unsigned kNotOverflowed = kIntMaxForLayoutUnit - 100;
  EXPECT_EQ((kIntMaxForLayoutUnit - 100) << kFractionBits,
            SaturatedSet<kFractionBits>(kNotOverflowed));
}

}  // namespace base
