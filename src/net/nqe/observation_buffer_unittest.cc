// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/nqe/observation_buffer.h"

#include <stddef.h>

#include <memory>
#include <utility>
#include <vector>

#include "base/logging.h"
#include "base/macros.h"
#include "base/memory/ptr_util.h"
#include "base/test/simple_test_tick_clock.h"
#include "base/time/time.h"
#include "net/nqe/network_quality_observation.h"
#include "net/nqe/network_quality_observation_source.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace nqe {

namespace internal {

namespace {

// Verify that the buffer size is never exceeded.
TEST(NetworkQualityObservationBufferTest, BoundedBuffer) {
  ObservationBuffer observation_buffer(1.0, 1.0);
  const base::TimeTicks now =
      base::TimeTicks() + base::TimeDelta::FromSeconds(1);
  for (int i = 1; i <= 1000; ++i) {
    observation_buffer.AddObservation(
        Observation(i, now, INT32_MIN, NETWORK_QUALITY_OBSERVATION_SOURCE_TCP));
    // The number of entries should be at most the maximum buffer size.
    EXPECT_GE(300u, observation_buffer.Size());
  }
}

// Test disabled on OS_WIN to avoid linking errors when calling
// SetTickClockForTesting.
// TODO(tbansal): crbug.com/651963. Pass the clock through NQE's constructor.
#if !defined(OS_WIN)
// Verify that the percentiles are monotonically non-decreasing when a weight is
// applied.
TEST(NetworkQualityObservationBufferTest, GetPercentileWithWeights) {
  std::unique_ptr<base::SimpleTestTickClock> tick_clock(
      new base::SimpleTestTickClock());
  base::SimpleTestTickClock* tick_clock_ptr = tick_clock.get();

  ObservationBuffer observation_buffer(0.98, 1.0);
  observation_buffer.SetTickClockForTesting(std::move(tick_clock));
  const base::TimeTicks now = tick_clock_ptr->NowTicks();
  for (int i = 1; i <= 100; ++i) {
    tick_clock_ptr->Advance(base::TimeDelta::FromSeconds(1));
    observation_buffer.AddObservation(
        Observation(i, tick_clock_ptr->NowTicks(), INT32_MIN,
                    NETWORK_QUALITY_OBSERVATION_SOURCE_TCP));
  }
  EXPECT_EQ(100U, observation_buffer.Size());

  int32_t result_lowest = INT32_MAX;
  int32_t result_highest = INT32_MIN;

  for (int i = 1; i <= 100; ++i) {
    // Verify that i'th percentile is more than i-1'th percentile.
    base::Optional<int32_t> result_i = observation_buffer.GetPercentile(
        now, INT32_MIN, i, std::vector<NetworkQualityObservationSource>());
    ASSERT_TRUE(result_i.has_value());
    result_lowest = std::min(result_lowest, result_i.value());

    result_highest = std::max(result_highest, result_i.value());

    base::Optional<int32_t> result_i_1 = observation_buffer.GetPercentile(
        now, INT32_MIN, i - 1, std::vector<NetworkQualityObservationSource>());
    ASSERT_TRUE(result_i_1.has_value());

    EXPECT_LE(result_i_1.value(), result_i.value());
  }
  EXPECT_LT(result_lowest, result_highest);
}
#endif

// Verifies that the percentiles are correctly computed. All observations have
// the same timestamp.
TEST(NetworkQualityObservationBufferTest, PercentileSameTimestamps) {
  ObservationBuffer buffer(0.5, 1.0);
  ASSERT_EQ(0u, buffer.Size());
  ASSERT_LT(0u, buffer.Capacity());

  const base::TimeTicks now = base::TimeTicks::Now();

  // Percentiles should be unavailable when no observations are available.
  EXPECT_FALSE(
      buffer
          .GetPercentile(base::TimeTicks(), INT32_MIN, 50,
                         std::vector<NetworkQualityObservationSource>())
          .has_value());

  // Insert samples from {1,2,3,..., 100}. First insert odd samples, then even
  // samples. This helps in verifying that the order of samples does not matter.
  for (int i = 1; i <= 99; i += 2) {
    buffer.AddObservation(Observation(i, now, INT32_MIN,
                                      NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP));
    EXPECT_TRUE(
        buffer
            .GetPercentile(base::TimeTicks(), INT32_MIN, 50,
                           std::vector<NetworkQualityObservationSource>())
            .has_value());
    ASSERT_EQ(static_cast<size_t>(i / 2 + 1), buffer.Size());
  }

  for (int i = 2; i <= 100; i += 2) {
    buffer.AddObservation(Observation(i, now, INT32_MIN,
                                      NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP));
    EXPECT_TRUE(
        buffer
            .GetPercentile(base::TimeTicks(), INT32_MIN, 50,
                           std::vector<NetworkQualityObservationSource>())
            .has_value());
    ASSERT_EQ(static_cast<size_t>(i / 2 + 50), buffer.Size());
  }

  ASSERT_EQ(100u, buffer.Size());

  for (int i = 0; i <= 100; ++i) {
    // Checks if the difference between actual result and the computed result is
    // less than 1. This is required because computed percentiles may be
    // slightly different from what is expected due to floating point
    // computation errors and integer rounding off errors.
    base::Optional<int32_t> result =
        buffer.GetPercentile(base::TimeTicks(), INT32_MIN, i,
                             std::vector<NetworkQualityObservationSource>());
    EXPECT_TRUE(result.has_value());
    EXPECT_NEAR(result.value(), i, 1.0);
  }

  EXPECT_FALSE(
      buffer
          .GetPercentile(now + base::TimeDelta::FromSeconds(1), INT32_MIN, 50,
                         std::vector<NetworkQualityObservationSource>())
          .has_value());

  // Percentiles should be unavailable when no observations are available.
  buffer.Clear();
  EXPECT_FALSE(
      buffer
          .GetPercentile(base::TimeTicks(), INT32_MIN, 50,
                         std::vector<NetworkQualityObservationSource>())
          .has_value());
}

// Verifies that the percentiles are correctly computed. Observations have
// different timestamps with half the observations being very old and the rest
// of them being very recent. Percentiles should factor in recent observations
// much more heavily than older samples.
TEST(NetworkQualityObservationBufferTest, PercentileDifferentTimestamps) {
  ObservationBuffer buffer(0.5, 1.0);
  const base::TimeTicks now = base::TimeTicks::Now();
  const base::TimeTicks very_old = now - base::TimeDelta::FromDays(7);

  // Network quality should be unavailable when no observations are available.
  EXPECT_FALSE(
      buffer
          .GetPercentile(base::TimeTicks(), INT32_MIN, 50,
                         std::vector<NetworkQualityObservationSource>())
          .has_value());

  // First 50 samples have very old timestamps.
  for (int i = 1; i <= 50; ++i) {
    buffer.AddObservation(Observation(i, very_old, INT32_MIN,
                                      NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP));
  }

  // Next 50 (i.e., from 51 to 100) have recent timestamps.
  for (int i = 51; i <= 100; ++i) {
    buffer.AddObservation(Observation(i, now, INT32_MIN,
                                      NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP));
  }

  // Older samples have very little weight. So, all percentiles are >= 51
  // (lowest value among recent observations).
  for (int i = 1; i < 100; ++i) {
    // Checks if the difference between the two integers is less than 1. This is
    // required because computed percentiles may be slightly different from
    // what is expected due to floating point computation errors and integer
    // rounding off errors.
    base::Optional<int32_t> result = buffer.GetPercentile(
        very_old, INT32_MIN, i, std::vector<NetworkQualityObservationSource>());
    EXPECT_TRUE(result.has_value());
    EXPECT_NEAR(result.value(), 51 + 0.49 * i, 1);
  }

  EXPECT_FALSE(
      buffer.GetPercentile(now + base::TimeDelta::FromSeconds(1), INT32_MIN, 50,
                           std::vector<NetworkQualityObservationSource>()));
}

// Verifies that the percentiles are correctly computed. All observations have
// same timestamp with half the observations taken at low RSSI, and half the
// observations with high RSSI. Percentiles should be computed based on the
// current RSSI and the RSSI of the observations.
TEST(NetworkQualityObservationBufferTest, PercentileDifferentRSSI) {
  ObservationBuffer buffer(1.0, 0.5);
  const base::TimeTicks now = base::TimeTicks::Now();
  int32_t high_rssi = 0;
  int32_t low_rssi = -100;

  // Network quality should be unavailable when no observations are available.
  EXPECT_FALSE(
      buffer
          .GetPercentile(base::TimeTicks(), INT32_MIN, 50,
                         std::vector<NetworkQualityObservationSource>())
          .has_value());

  // First 50 samples have very low RSSI.
  for (int i = 1; i <= 50; ++i) {
    buffer.AddObservation(
        Observation(i, now, low_rssi, NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP));
  }

  // Next 50 (i.e., from 51 to 100) have high RSSI.
  for (int i = 51; i <= 100; ++i) {
    buffer.AddObservation(Observation(i, now, high_rssi,
                                      NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP));
  }

  // When the current RSSI is |high_rssi|, higher weight should be assigned
  // to observations that were taken at |high_rssi|.
  for (int i = 1; i < 100; ++i) {
    base::Optional<int32_t> result = buffer.GetPercentile(
        now, high_rssi, i, std::vector<NetworkQualityObservationSource>());
    EXPECT_TRUE(result.has_value());
    EXPECT_NEAR(result.value(), 51 + 0.49 * i, 1);
  }

  // When the current RSSI is |low_rssi|, higher weight should be assigned
  // to observations that were taken at |low_rssi|.
  for (int i = 1; i < 100; ++i) {
    base::Optional<int32_t> result = buffer.GetPercentile(
        now, low_rssi, i, std::vector<NetworkQualityObservationSource>());
    EXPECT_TRUE(result.has_value());
    EXPECT_NEAR(result.value(), i / 2, 1);
  }
}

#if !defined(OS_WIN)
// Disabled on OS_WIN since the GetUnweightedAverage() and
// GetUnweightedAverage() functions are not yet called outside tests, and so the
// compiler on Windows does not generate the object code for these functions.
// TODO(tbansal): crbug.com/656170 Enable these tests on Windows once these
// functions are called outside the tests.
TEST(NetworkQualityObservationBufferTest,
     UnweightedAverageDifferentTimestamps) {
  ObservationBuffer buffer(0.5, 1.0);
  const base::TimeTicks now = base::TimeTicks::Now();
  const base::TimeTicks very_old = now - base::TimeDelta::FromDays(7);

  // Network quality should be unavailable when no observations are available.
  EXPECT_FALSE(
      buffer
          .GetUnweightedAverage(base::TimeTicks(), INT32_MIN,
                                std::vector<NetworkQualityObservationSource>())
          .has_value());

  // The first 50 samples have very old timestamps.
  for (int i = 1; i <= 50; ++i) {
    buffer.AddObservation(Observation(i, very_old, INT32_MIN,
                                      NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP));
  }

  // The next 50 (i.e., from 51 to 100) samples have recent timestamps.
  for (int i = 51; i <= 100; ++i) {
    buffer.AddObservation(Observation(i, now, INT32_MIN,
                                      NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP));
  }

  // All samples have equal weight. So, the unweighted average is the average of
  // all samples.
  base::Optional<int32_t> result = buffer.GetUnweightedAverage(
      very_old, INT32_MIN, std::vector<NetworkQualityObservationSource>());
  EXPECT_TRUE(result.has_value());
  EXPECT_NEAR(result.value(), (1 + 100) / 2, 1);

  EXPECT_FALSE(buffer
                   .GetUnweightedAverage(
                       now + base::TimeDelta::FromSeconds(1), INT32_MIN,
                       std::vector<NetworkQualityObservationSource>())
                   .has_value());
}

TEST(NetworkQualityObservationBufferTest, WeightedAverageDifferentTimestamps) {
  ObservationBuffer buffer(0.5, 1.0);
  const base::TimeTicks now = base::TimeTicks::Now();
  const base::TimeTicks very_old = now - base::TimeDelta::FromDays(7);

  // Network quality should be unavailable when no observations are available.
  EXPECT_FALSE(
      buffer
          .GetWeightedAverage(base::TimeTicks(), INT32_MIN,
                              std::vector<NetworkQualityObservationSource>())
          .has_value());

  // The first 50 samples have very old timestamps.
  for (int i = 1; i <= 50; ++i) {
    buffer.AddObservation(Observation(i, very_old, INT32_MIN,
                                      NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP));
  }

  // The next 50 (i.e., from 51 to 100) samples have recent timestamps.
  for (int i = 51; i <= 100; ++i) {
    buffer.AddObservation(Observation(i, now, INT32_MIN,
                                      NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP));
  }

  // The older samples have very little weight, and so the weighted average must
  // be approximately equal to the average of all recent samples.
  base::Optional<int32_t> result = buffer.GetWeightedAverage(
      very_old, INT32_MIN, std::vector<NetworkQualityObservationSource>());

  EXPECT_TRUE(result.has_value());
  EXPECT_NEAR(result.value(), (51 + 100) / 2, 1);

  EXPECT_FALSE(
      buffer
          .GetWeightedAverage(now + base::TimeDelta::FromSeconds(1), INT32_MIN,
                              std::vector<NetworkQualityObservationSource>())
          .has_value());
}
#endif  // !defined(OS_WIN)

// Verifies that the percentiles are correctly computed when some of the
// observation sources are disallowed. All observations have the same timestamp.
TEST(NetworkQualityObservationBufferTest, DisallowedObservationSources) {
  ObservationBuffer buffer(0.5, 1.0);
  const base::TimeTicks now = base::TimeTicks::Now();

  // Network quality should be unavailable when no observations are available.
  EXPECT_FALSE(
      buffer
          .GetPercentile(base::TimeTicks(), INT32_MIN, 50,
                         std::vector<NetworkQualityObservationSource>())
          .has_value());

  // Insert samples from {1,2,3,..., 100}. First insert odd samples, then even
  // samples. This helps in verifying that the order of samples does not matter.
  for (int i = 1; i <= 99; i += 2) {
    buffer.AddObservation(Observation(i, now, INT32_MIN,
                                      NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP));
  }

  // Add samples for TCP and QUIC observations which should not be taken into
  // account when computing the percentile.
  for (int i = 1; i <= 99; i += 2) {
    buffer.AddObservation(Observation(10000, now, INT32_MIN,
                                      NETWORK_QUALITY_OBSERVATION_SOURCE_TCP));
    buffer.AddObservation(Observation(10000, now, INT32_MIN,
                                      NETWORK_QUALITY_OBSERVATION_SOURCE_QUIC));
  }

  for (int i = 2; i <= 100; i += 2) {
    buffer.AddObservation(Observation(i, now, INT32_MIN,
                                      NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP));
  }

  std::vector<NetworkQualityObservationSource> disallowed_observation_sources;
  disallowed_observation_sources.push_back(
      NETWORK_QUALITY_OBSERVATION_SOURCE_TCP);
  disallowed_observation_sources.push_back(
      NETWORK_QUALITY_OBSERVATION_SOURCE_QUIC);

  for (int i = 0; i <= 100; ++i) {
    // Checks if the difference between the two integers is less than 1. This is
    // required because computed percentiles may be slightly different from
    // what is expected due to floating point computation errors and integer
    // rounding off errors.
    base::Optional<int32_t> result = buffer.GetPercentile(
        base::TimeTicks(), INT32_MIN, i, disallowed_observation_sources);
    EXPECT_TRUE(result.has_value());
    EXPECT_NEAR(result.value(), i, 1);
  }

  // Now check the percentile value for TCP and QUIC observations.
  disallowed_observation_sources.clear();
  disallowed_observation_sources.push_back(
      NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP);
  for (int i = 0; i <= 100; ++i) {
    // Checks if the difference between the two integers is less than 1. This is
    // required because computed percentiles may be slightly different from
    // what is expected due to floating point computation errors and integer
    // rounding off errors.
    base::Optional<int32_t> result = buffer.GetPercentile(
        base::TimeTicks(), INT32_MIN, i, disallowed_observation_sources);
    EXPECT_TRUE(result.has_value());
    EXPECT_NEAR(result.value(), 10000, 1);
  }
}

TEST(NetworkQualityObservationBufferTest, TestGetMedianRTTSince) {
  ObservationBuffer buffer(0.5, 1.0);
  base::TimeTicks now = base::TimeTicks::Now();
  base::TimeTicks old = now - base::TimeDelta::FromMilliseconds(1);
  ASSERT_NE(old, now);

  // First sample has very old timestamp.
  buffer.AddObservation(
      Observation(1, old, INT32_MIN, NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP));

  buffer.AddObservation(Observation(100, now, INT32_MIN,
                                    NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP));

  const struct {
    base::TimeTicks start_timestamp;
    bool expect_network_quality_available;
    base::TimeDelta expected_url_request_rtt;
  } tests[] = {
      {now + base::TimeDelta::FromSeconds(10), false,
       base::TimeDelta::FromMilliseconds(0)},
      {now, true, base::TimeDelta::FromMilliseconds(100)},
      {now - base::TimeDelta::FromMicroseconds(500), true,
       base::TimeDelta::FromMilliseconds(100)},

  };

  for (const auto& test : tests) {
    std::vector<NetworkQualityObservationSource> disallowed_observation_sources;

    base::Optional<int32_t> url_request_rtt = buffer.GetPercentile(
        test.start_timestamp, INT32_MIN, 50, disallowed_observation_sources);
    EXPECT_EQ(test.expect_network_quality_available,
              url_request_rtt.has_value());

    if (test.expect_network_quality_available) {
      EXPECT_EQ(test.expected_url_request_rtt.InMillisecondsF(),
                url_request_rtt.value());
    }
  }
}

}  // namespace

}  // namespace internal

}  // namespace nqe

}  // namespace net
