// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/base/percentile_estimator.h"

#include "base/bind.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace {

// A number to turn sawtooth ramps from 0->100 into something that looks more
// random to the algorithm.
const int kPrimeMultipleToRandomizeRamps = 71;

// Random numbers (fixed here for repeatability of tests).  Generated originally
// by using python's random module with randrange(0,100).
int random_numbers[] = {
    83, 11, 33, 98, 49, 54, 83, 19, 93, 37, 98, 39, 59, 13, 51, 39, 69, 18, 17,
    17, 6,  85, 95, 51, 83, 39, 18, 82, 88, 47, 69, 27, 20, 82, 86, 38, 98, 65,
    53, 13, 71, 66, 29, 40, 70, 28, 64, 35, 47, 50, 84, 90, 36, 54, 15, 93, 98,
    51, 82, 50, 17, 46, 12, 18, 26, 39, 95, 61, 52, 63, 97, 92, 12, 71, 7,  15,
    74, 10, 64, 57, 25, 82, 95, 40, 76, 8,  28, 83, 58, 1,  22, 58, 17, 33, 61,
    94, 40, 50, 84, 47, 81, 9,  79, 16, 45, 78, 15, 3,  97, 60, 70, 25, 11, 11,
    68, 64, 61, 84, 52, 64, 54, 72, 24, 46, 48, 4,  46, 34, 10, 97, 2,  42, 13,
    9,  95, 75, 11, 99, 92, 33, 65, 48, 19, 72, 63, 39, 0,  10, 83, 62, 12, 99,
    67, 98, 99, 83, 40, 45, 34, 80, 13, 94, 22, 74, 8,  11, 11, 98, 35, 86, 80,
    94, 87, 60, 16, 46, 9,  25, 75, 50, 54, 23, 31, 63, 9,  50, 5,  18, 87, 16,
    47, 72, 24, 93, 14, 1,  26, 41, 50, 49, 41, 77, 54, 48, 50, 3,  50, 16, 54,
    97, 57, 63, 83, 33, 65, 90, 48, 55, 44, 11, 71, 6,  86, 29, 46, 61, 20, 8,
    88, 3,  70, 76, 84, 59, 36, 50, 77, 63, 10, 55, 32, 82, 58, 19, 97, 8,  73,
    47, 55, 74, 46, 52, 62, 19, 65, 75, 57, 23, 98, 39, 63, 19, 75, 48, 93, 58,
    29, 96, 57, 31, 17, 33, 8,  69, 89, 90, 17, 79, 59, 67, 34, 20, 44, 80, 71,
    79, 24, 63, 13, 27, 28, 61, 38, 67, 82, 46, 9,  4,  69, 41, 49, 49, 10, 3,
    93, 46, 57, 96, 78, 51, 45, 37, 0,  6,  99, 93, 87, 18, 72, 83, 95, 39, 54,
    84, 12, 47, 14, 55, 15, 27, 95, 6,  13, 80, 40, 8,  39, 18, 15, 52, 31, 66,
    59, 67, 90, 12, 61, 77, 66, 61, 33, 89, 47, 40, 86, 34, 98, 13, 76, 30, 43,
    56, 57, 88, 34, 48, 67, 6,  29, 92, 38, 11, 23, 74, 45, 38, 35, 94, 15, 72,
    65, 20, 94, 72, 97, 78, 61, 79, 75, 0,  45, 38, 32, 94, 3,  5,  67, 91, 34,
    37, 12, 11, 15, 75, 14, 73, 34, 55, 78, 64, 52, 29, 60, 62, 16, 51, 44, 78,
    0,  15, 41, 5,  52, 4,  68, 53, 39, 39, 68, 71, 66, 68, 97, 65, 55, 39, 94,
    57, 43, 81, 67, 22, 30, 64, 37, 42, 35, 60, 61, 2,  51, 49, 43, 82, 61, 70,
    63, 47, 57, 8,  55, 96, 68, 7,  46, 69, 8,  43, 18, 9,  25, 8,  97, 98, 83,
    79, 19, 92, 54, 90, 72, 80, 92, 94, 26, 48, 94, 74, 32, 29, 44, 34, 55, 56,
    97, 40, 86, 35, 64, 25, 85, 13, 57, 2,  29, 77, 19, 94, 46, 85, 15, 71, 81,
    25, 45, 2,  1,  62, 77, 28, 95, 72, 72, 28, 3,  36, 76, 81, 56, 52, 27, 62,
    8,  5,  62, 1,  43, 68, 40, 68, 22, 65, 30, 50, 36, 89, 5,  71, 68, 99, 53,
    22, 26, 0,  1,  72, 76, 79, 50, 2,  32, 39, 40, 6,  99, 60, 59, 55, 28, 17,
    12, 94, 51, 3,  4,  71, 36, 88, 26, 99, 25, 13, 80, 53, 4,  57, 55, 44, 26,
    82, 4,  53, 34, 47, 16, 97, 56, 30, 0,  73, 85, 59, 86, 24, 70, 73, 53, 68,
    15, 91, 90, 74, 39, 61, 32, 98, 14, 82, 99, 31, 7,  99, 34, 6,  3,  30, 57,
    44, 58, 86, 37, 12, 63, 82, 78, 94, 4,  93, 89, 92, 59, 40, 94, 88, 97, 95,
    5,  88, 40, 80, 79, 0,  2,  46, 86, 46, 75, 87, 86, 8,  23, 35, 62, 79, 66,
    16, 16, 45, 11, 78, 76, 40, 73, 85, 28, 44, 33, 34, 22, 11, 62, 8,  35, 88,
    92, 35, 53, 50, 51, 54, 75, 41, 21, 83, 57, 82, 80, 84, 65, 19, 11, 85, 41,
    80, 86, 62, 34, 54, 54, 79, 81, 52, 87, 54, 54, 43, 17, 44, 63, 54, 14, 88,
    84, 86, 73, 58, 44, 2,  70, 86, 80, 94, 13, 85, 78, 6,  44, 11, 11, 97, 67,
    65, 28, 42, 40, 84, 92, 66, 85, 75, 29, 84, 82, 54, 50, 26, 12, 83, 57, 90,
    9,  40, 69, 38, 70, 65, 76, 85, 76, 4,  30, 86, 43, 79, 77, 69, 53, 35, 12,
    98, 7,  47, 12, 63, 10, 81, 39, 88, 12, 16, 88, 22, 72, 25, 41, 22, 34, 87,
    68, 51, 86, 45, 27, 51, 80, 69, 89, 64, 89, 68, 61, 80, 6,  83, 47, 18, 86,
    73, 16, 61, 89, 47, 5,  33, 59, 47, 75, 15, 60, 28, 18, 59, 65, 51, 13, 28,
    26, 84, 89, 80, 51, 15, 92, 36, 89, 83, 28, 56, 65, 25, 44, 84, 70, 26, 10,
    74, 91, 55, 85, 73, 25, 24, 64, 11, 1,  55, 32, 45, 74, 4,  55, 98, 42, 91,
    88, 18, 79, 37, 15, 5,  98, 63, 65, 77, 66, 18, 99, 1,  78, 96, 15, 16, 16,
    51, 11, 47, 58, 1,  12, 46, 5,  56, 34, 40, 36, 20, 4,  89, 59, 4,  13, 3,
    8,  74, 41, 21, 64, 88, 97, 42, 14, 29, 38, 53, 65, 55, 67, 33, 69, 17, 79,
    45, 2,  63, 2,  97, 47, 73, 22, 86, 32, 31, 95, 90, 84, 25, 86, 91, 77, 1,
    5,  6,  22, 91, 3,  94, 52, 2,  95, 17, 1,  19, 22, 34, 49, 96, 88, 63, 26,
    5,  25, 75, 23, 25, 80, 21, 83, 86, 81, 11, 70, 67, 11, 95, 81, 57, 63, 8,
    43, 60, 40, 42, 67, 50, 2,  51, 43, 34, 7,  1,  90, 59, 74, 87, 23, 23, 71,
    20, 89, 2,  75, 21, 91, 32, 87, 67, 98, 99, 22, 31, 59, 50, 64, 55, 22, 84,
    9,  31, 31, 84, 36, 92, 60, 37, 85, 18, 12, 38, 55, 55, 93, 36, 9,  46, 48,
    24, 91, 60, 95, 55, 73, 63, 27, 55, 96, 79, 50, 41, 5,  67, 85, 99, 95, 3,
    97, 28, 27, 78, 38, 11, 77, 11, 64, 25, 22, 88, 34, 86, 30, 78, 95, 17, 9,
    29, 58, 35, 22, 99, 28, 66, 35, 60, 10, 7,  51, 64, 86, 30, 27, 97, 63, 0,
    36, 87, 52, 16, 5,  90, 8,  66, 58, 91, 85, 3,  95, 31, 73, 87, 30, 78, 46,
    30, 75, 36, 44, 52, 76, 24, 58, 8,  70, 58, 95, 88, 0,  35, 86, 21, 96, 90,
    54, 85, 56, 30, 37, 30, 62, 56, 63, 91, 25, 56, 20, 56, 23, 12, 8,  70, 56,
    83, 49, 70, 67, 61, 95, 50, 41, 88, 37, 89, 37, 21, 63, 25, 46, 16, 75, 73,
    86, 39, 4,  55, 41, 39, 45, 31, 97, 6,  81, 68, 38, 49, 80, 9,  87, 22, 37,
    41, 28, 47, 74, 76, 34, 72, 65, 34, 41, 59, 42, 73, 32, 75, 25, 18, 26, 71,
    93, 92, 12, 76, 93, 84, 44, 43, 4,  9,  3,  90, 91, 45, 0,  10, 43, 45, 65,
    34, 82, 54, 1,  78, 36, 74, 58, 3,  26, 89, 21, 57, 42, 37, 12, 90, 97, 48,
    27, 75, 40, 69, 61, 56, 44, 75, 77, 55, 31, 0,  77, 12, 23, 16, 98, 77, 8,
    96, 92, 91, 26, 50, 42, 65, 38, 58, 41, 45, 69, 42, 37, 89, 92, 40, 74, 68,
    86, 80, 49, 16, 48, 74, 50, 92, 54, 6,  82, 21, 35, 57, 81, 29, 10, 60, 74,
    41, 70, 18, 65, 44, 77, 64, 8,  87, 90, 24, 52, 67, 58, 56, 89, 47, 15, 20,
    4,  87, 72, 87, 13, 79, 3,  26, 43, 52, 72, 83, 17, 99, 29, 10, 61, 62, 42,
    35, 47, 42, 40, 17, 71, 54, 30, 99, 64, 78, 70, 75, 38, 32, 51, 2,  49, 47,
    0,  41, 50, 41, 64, 57, 78, 22, 17, 94, 24, 65, 84, 38, 75, 3,  58, 18, 51,
    91, 72, 91, 55, 6,  70, 76, 73, 30, 54, 73, 77, 45, 85, 88, 58, 25, 80, 35,
    99, 57, 73, 15, 55, 71, 44, 44, 79, 20, 63, 29, 14, 51, 10, 46, 80, 36, 47,
    80, 53, 15, 64, 42, 59, 94, 55, 99, 28, 76, 80, 51, 4,  98, 98, 38, 59, 71,
    9,  93, 91, 46, 74, 63, 10, 39, 1,  43, 11, 64, 39, 59, 54, 9,  44, 78, 52,
    98, 9,  73, 24, 15, 40, 5,  55, 23, 83, 67, 10, 58, 45, 64, 41, 92, 85, 72,
    18, 67, 65, 30, 56, 84, 63, 96, 51, 55, 19, 70, 48, 81, 2,  37, 85, 77};

class PercentileEstimatorTest : public testing::Test {
 public:
  PercentileEstimatorTest() : index_(0) {}

  // Create a new estimator with the given parameters.
  void SetUpEstimator(int percentile, int initial_estimate) {
    estimator_.reset(
        new net::PercentileEstimator(percentile, initial_estimate));
    estimator_->SetRandomNumberGeneratorForTesting(
        base::Bind(&PercentileEstimatorTest::GetRandomNumber,
                   // Safe since |estimator_| is owned by and
                   // will not survive destruction of |this|.
                   base::Unretained(this)));
  }

  int CurrentEstimate() { return estimator_->current_estimate(); }
  void AddSample(int sample) { estimator_->AddSample(sample); }

  // Add the sample until there's a change in the estimate, then return the
  // new estimate.  To get around the randomness of whether samples are
  // incorporated or not.
  int AddSampleUntilRegistered(int sample) {
    int old_estimate = estimator_->current_estimate();
    while (old_estimate == estimator_->current_estimate())
      estimator_->AddSample(sample);

    return estimator_->current_estimate();
  }

  int GetRandomNumber() {
    int result = random_numbers[index_];
    ++index_;
    if (static_cast<unsigned long>(index_) >=
        sizeof(random_numbers) / sizeof(int)) {
      index_ = 0;
    }
    return result;
  }

 private:
  int index_;
  std::unique_ptr<net::PercentileEstimator> estimator_;

  DISALLOW_COPY_AND_ASSIGN(PercentileEstimatorTest);
};

// Converges upwards fairly quickly.
TEST_F(PercentileEstimatorTest, MedianConvergesUpwards) {
  SetUpEstimator(50, 100);

  for (int i = 0; i < 40; ++i)
    AddSample(150);

  EXPECT_EQ(150, CurrentEstimate());
}

// Converges downwards fairly quickly.
TEST_F(PercentileEstimatorTest, MedianConvergesDownwards) {
  SetUpEstimator(50, 100);

  for (int i = 0; i < 40; ++i)
    AddSample(50);

  EXPECT_EQ(50, CurrentEstimate());
}

// Stable if the value is bouncing around.
TEST_F(PercentileEstimatorTest, BounceStable) {
  SetUpEstimator(50, 100);

  for (int i = 0; i < 20; ++i)
    AddSample(50 + (i % 2) * 100);

  EXPECT_LE(97, CurrentEstimate());
  EXPECT_LE(CurrentEstimate(), 103);
}

// Correctly converges to a 90%l value upwards.
TEST_F(PercentileEstimatorTest, NinetythConvergesUpwards) {
  SetUpEstimator(90, 50);

  for (int i = 0; i < 10000; ++i)
    AddSample((i * kPrimeMultipleToRandomizeRamps) % 100);

  EXPECT_LE(86, CurrentEstimate());
  EXPECT_LE(CurrentEstimate(), 94);
}

// Correctly converges to a 90%l value downwards.
TEST_F(PercentileEstimatorTest, NinetythConvergesDownwards) {
  SetUpEstimator(90, 150);

  for (int i = 0; i < 1000; ++i)
    AddSample((i * kPrimeMultipleToRandomizeRamps) % 100);

  EXPECT_LT(86, CurrentEstimate());
  EXPECT_LT(CurrentEstimate(), 94);
}

// Doesn't overshoot sample heading upwards.
TEST_F(PercentileEstimatorTest, NoUpwardsOvershoot) {
  SetUpEstimator(50, 100);

  // Crank up the step size
  for (int i = 0; i < 20; ++i)
    AddSample(1000);

  // Derive the step size.
  int e1 = CurrentEstimate();
  int e2 = AddSampleUntilRegistered(1000);
  int step_size = e2 - e1;
  ASSERT_GT(step_size, 1);

  // Increment by less than the current step size.
  int new_sample = e2 + step_size / 2;
  AddSampleUntilRegistered(new_sample);
  EXPECT_EQ(new_sample, CurrentEstimate());
  AddSampleUntilRegistered(1000);
  EXPECT_GT(new_sample + step_size, CurrentEstimate());
}

// Doesn't overshoot sample heading downwards
TEST_F(PercentileEstimatorTest, NoDownwardsOvershoot) {
  SetUpEstimator(50, 1000);

  // Crank up the step size
  for (int i = 0; i < 20; ++i)
    AddSample(100);

  // Derive the step size.
  int e1 = CurrentEstimate();
  int e2 = AddSampleUntilRegistered(100);
  int step_size = e1 - e2;
  ASSERT_GT(step_size, 1);

  // Increment by less than the current step size.
  int new_sample = e2 - step_size / 2;
  AddSampleUntilRegistered(new_sample);
  EXPECT_EQ(new_sample, CurrentEstimate());
  AddSampleUntilRegistered(100);
  EXPECT_LT(new_sample - step_size, CurrentEstimate());
}

}  // namespace
