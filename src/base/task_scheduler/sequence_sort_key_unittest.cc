// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/task_scheduler/sequence_sort_key.h"

#include "base/task_scheduler/task_traits.h"
#include "base/time/time.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace base {
namespace internal {

TEST(TaskSchedulerSequenceSortKeyTest, OperatorLessThan) {
  SequenceSortKey key_a(TaskPriority::USER_BLOCKING,
                        TimeTicks::FromInternalValue(1000));
  SequenceSortKey key_b(TaskPriority::USER_BLOCKING,
                        TimeTicks::FromInternalValue(2000));
  SequenceSortKey key_c(TaskPriority::USER_VISIBLE,
                        TimeTicks::FromInternalValue(1000));
  SequenceSortKey key_d(TaskPriority::USER_VISIBLE,
                        TimeTicks::FromInternalValue(2000));
  SequenceSortKey key_e(TaskPriority::BACKGROUND,
                        TimeTicks::FromInternalValue(1000));
  SequenceSortKey key_f(TaskPriority::BACKGROUND,
                        TimeTicks::FromInternalValue(2000));

  EXPECT_FALSE(key_a < key_a);
  EXPECT_LT(key_b, key_a);
  EXPECT_LT(key_c, key_a);
  EXPECT_LT(key_d, key_a);
  EXPECT_LT(key_e, key_a);
  EXPECT_LT(key_f, key_a);

  EXPECT_FALSE(key_a < key_b);
  EXPECT_FALSE(key_b < key_b);
  EXPECT_LT(key_c, key_b);
  EXPECT_LT(key_d, key_b);
  EXPECT_LT(key_e, key_b);
  EXPECT_LT(key_f, key_b);

  EXPECT_FALSE(key_a < key_c);
  EXPECT_FALSE(key_b < key_c);
  EXPECT_FALSE(key_c < key_c);
  EXPECT_LT(key_d, key_c);
  EXPECT_LT(key_e, key_c);
  EXPECT_LT(key_f, key_c);

  EXPECT_FALSE(key_a < key_d);
  EXPECT_FALSE(key_b < key_d);
  EXPECT_FALSE(key_c < key_d);
  EXPECT_FALSE(key_d < key_d);
  EXPECT_LT(key_e, key_d);
  EXPECT_LT(key_f, key_d);

  EXPECT_FALSE(key_a < key_e);
  EXPECT_FALSE(key_b < key_e);
  EXPECT_FALSE(key_c < key_e);
  EXPECT_FALSE(key_d < key_e);
  EXPECT_FALSE(key_e < key_e);
  EXPECT_LT(key_f, key_e);

  EXPECT_FALSE(key_a < key_f);
  EXPECT_FALSE(key_b < key_f);
  EXPECT_FALSE(key_c < key_f);
  EXPECT_FALSE(key_d < key_f);
  EXPECT_FALSE(key_e < key_f);
  EXPECT_FALSE(key_f < key_f);
}

TEST(TaskSchedulerSequenceSortKeyTest, OperatorGreaterThan) {
  SequenceSortKey key_a(TaskPriority::USER_BLOCKING,
                        TimeTicks::FromInternalValue(1000));
  SequenceSortKey key_b(TaskPriority::USER_BLOCKING,
                        TimeTicks::FromInternalValue(2000));
  SequenceSortKey key_c(TaskPriority::USER_VISIBLE,
                        TimeTicks::FromInternalValue(1000));
  SequenceSortKey key_d(TaskPriority::USER_VISIBLE,
                        TimeTicks::FromInternalValue(2000));
  SequenceSortKey key_e(TaskPriority::BACKGROUND,
                        TimeTicks::FromInternalValue(1000));
  SequenceSortKey key_f(TaskPriority::BACKGROUND,
                        TimeTicks::FromInternalValue(2000));

  EXPECT_FALSE(key_a > key_a);
  EXPECT_FALSE(key_b > key_a);
  EXPECT_FALSE(key_c > key_a);
  EXPECT_FALSE(key_d > key_a);
  EXPECT_FALSE(key_e > key_a);
  EXPECT_FALSE(key_f > key_a);

  EXPECT_GT(key_a, key_b);
  EXPECT_FALSE(key_b > key_b);
  EXPECT_FALSE(key_c > key_b);
  EXPECT_FALSE(key_d > key_b);
  EXPECT_FALSE(key_e > key_b);
  EXPECT_FALSE(key_f > key_b);

  EXPECT_GT(key_a, key_c);
  EXPECT_GT(key_b, key_c);
  EXPECT_FALSE(key_c > key_c);
  EXPECT_FALSE(key_d > key_c);
  EXPECT_FALSE(key_e > key_c);
  EXPECT_FALSE(key_f > key_c);

  EXPECT_GT(key_a, key_d);
  EXPECT_GT(key_b, key_d);
  EXPECT_GT(key_c, key_d);
  EXPECT_FALSE(key_d > key_d);
  EXPECT_FALSE(key_e > key_d);
  EXPECT_FALSE(key_f > key_d);

  EXPECT_GT(key_a, key_e);
  EXPECT_GT(key_b, key_e);
  EXPECT_GT(key_c, key_e);
  EXPECT_GT(key_d, key_e);
  EXPECT_FALSE(key_e > key_e);
  EXPECT_FALSE(key_f > key_e);

  EXPECT_GT(key_a, key_f);
  EXPECT_GT(key_b, key_f);
  EXPECT_GT(key_c, key_f);
  EXPECT_GT(key_d, key_f);
  EXPECT_GT(key_e, key_f);
  EXPECT_FALSE(key_f > key_f);
}

TEST(TaskSchedulerSequenceSortKeyTest, OperatorEqual) {
  SequenceSortKey key_a(TaskPriority::USER_BLOCKING,
                        TimeTicks::FromInternalValue(1000));
  SequenceSortKey key_b(TaskPriority::USER_BLOCKING,
                        TimeTicks::FromInternalValue(2000));
  SequenceSortKey key_c(TaskPriority::USER_VISIBLE,
                        TimeTicks::FromInternalValue(1000));
  SequenceSortKey key_d(TaskPriority::USER_VISIBLE,
                        TimeTicks::FromInternalValue(2000));
  SequenceSortKey key_e(TaskPriority::BACKGROUND,
                        TimeTicks::FromInternalValue(1000));
  SequenceSortKey key_f(TaskPriority::BACKGROUND,
                        TimeTicks::FromInternalValue(2000));

  EXPECT_EQ(key_a, key_a);
  EXPECT_FALSE(key_b == key_a);
  EXPECT_FALSE(key_c == key_a);
  EXPECT_FALSE(key_d == key_a);
  EXPECT_FALSE(key_e == key_a);
  EXPECT_FALSE(key_f == key_a);

  EXPECT_FALSE(key_a == key_b);
  EXPECT_EQ(key_b, key_b);
  EXPECT_FALSE(key_c == key_b);
  EXPECT_FALSE(key_d == key_b);
  EXPECT_FALSE(key_e == key_b);
  EXPECT_FALSE(key_f == key_b);

  EXPECT_FALSE(key_a == key_c);
  EXPECT_FALSE(key_b == key_c);
  EXPECT_EQ(key_c, key_c);
  EXPECT_FALSE(key_d == key_c);
  EXPECT_FALSE(key_e == key_c);
  EXPECT_FALSE(key_f == key_c);

  EXPECT_FALSE(key_a == key_d);
  EXPECT_FALSE(key_b == key_d);
  EXPECT_FALSE(key_c == key_d);
  EXPECT_EQ(key_d, key_d);
  EXPECT_FALSE(key_e == key_d);
  EXPECT_FALSE(key_f == key_d);

  EXPECT_FALSE(key_a == key_e);
  EXPECT_FALSE(key_b == key_e);
  EXPECT_FALSE(key_c == key_e);
  EXPECT_FALSE(key_d == key_e);
  EXPECT_EQ(key_e, key_e);
  EXPECT_FALSE(key_f == key_e);

  EXPECT_FALSE(key_a == key_f);
  EXPECT_FALSE(key_b == key_f);
  EXPECT_FALSE(key_c == key_f);
  EXPECT_FALSE(key_d == key_f);
  EXPECT_FALSE(key_e == key_f);
  EXPECT_EQ(key_f, key_f);
}

TEST(TaskSchedulerSequenceSortKeyTest, OperatorNotEqual) {
  SequenceSortKey key_a(TaskPriority::USER_BLOCKING,
                        TimeTicks::FromInternalValue(1000));
  SequenceSortKey key_b(TaskPriority::USER_BLOCKING,
                        TimeTicks::FromInternalValue(2000));
  SequenceSortKey key_c(TaskPriority::USER_VISIBLE,
                        TimeTicks::FromInternalValue(1000));
  SequenceSortKey key_d(TaskPriority::USER_VISIBLE,
                        TimeTicks::FromInternalValue(2000));
  SequenceSortKey key_e(TaskPriority::BACKGROUND,
                        TimeTicks::FromInternalValue(1000));
  SequenceSortKey key_f(TaskPriority::BACKGROUND,
                        TimeTicks::FromInternalValue(2000));

  EXPECT_FALSE(key_a != key_a);
  EXPECT_NE(key_b, key_a);
  EXPECT_NE(key_c, key_a);
  EXPECT_NE(key_d, key_a);
  EXPECT_NE(key_e, key_a);
  EXPECT_NE(key_f, key_a);

  EXPECT_NE(key_a, key_b);
  EXPECT_FALSE(key_b != key_b);
  EXPECT_NE(key_c, key_b);
  EXPECT_NE(key_d, key_b);
  EXPECT_NE(key_e, key_b);
  EXPECT_NE(key_f, key_b);

  EXPECT_NE(key_a, key_c);
  EXPECT_NE(key_b, key_c);
  EXPECT_FALSE(key_c != key_c);
  EXPECT_NE(key_d, key_c);
  EXPECT_NE(key_e, key_c);
  EXPECT_NE(key_f, key_c);

  EXPECT_NE(key_a, key_d);
  EXPECT_NE(key_b, key_d);
  EXPECT_NE(key_c, key_d);
  EXPECT_FALSE(key_d != key_d);
  EXPECT_NE(key_e, key_d);
  EXPECT_NE(key_f, key_d);

  EXPECT_NE(key_a, key_e);
  EXPECT_NE(key_b, key_e);
  EXPECT_NE(key_c, key_e);
  EXPECT_NE(key_d, key_e);
  EXPECT_FALSE(key_e != key_e);
  EXPECT_NE(key_f, key_e);

  EXPECT_NE(key_a, key_f);
  EXPECT_NE(key_b, key_f);
  EXPECT_NE(key_c, key_f);
  EXPECT_NE(key_d, key_f);
  EXPECT_NE(key_e, key_f);
  EXPECT_FALSE(key_f != key_f);
}

}  // namespace internal
}  // namespace base
