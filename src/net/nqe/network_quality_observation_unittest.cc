// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/nqe/network_quality_observation.h"

#include <stddef.h>

#include <vector>

#include "base/logging.h"
#include "base/macros.h"
#include "base/time/time.h"
#include "net/nqe/network_quality_observation_source.h"
#include "net/nqe/observation_buffer.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace nqe {

namespace {

// Verifies that the percentiles are correctly computed. All observations have
// the same timestamp.
TEST(NetworkQualityObservationTest, PercentileSameTimestamps) {
  internal::ObservationBuffer<int32_t> int_buffer(0.5);
  internal::ObservationBuffer<base::TimeDelta> time_delta_buffer(0.5);
  ASSERT_EQ(0u, int_buffer.Size());
  ASSERT_LT(0u, int_buffer.Capacity());
  ASSERT_EQ(0u, time_delta_buffer.Size());
  ASSERT_LT(0u, time_delta_buffer.Capacity());

  const base::TimeTicks now = base::TimeTicks::Now();

  int32_t result;
  base::TimeDelta time_delta_result;

  // Percentiles should be unavailable when no observations are available.
  EXPECT_FALSE(
      int_buffer.GetPercentile(base::TimeTicks(), &result, 50,
                               std::vector<NetworkQualityObservationSource>()));
  EXPECT_FALSE(time_delta_buffer.GetPercentile(
      base::TimeTicks(), &time_delta_result, 50,
      std::vector<NetworkQualityObservationSource>()));

  // Insert samples from {1,2,3,..., 100}. First insert odd samples, then even
  // samples. This helps in verifying that the order of samples does not matter.
  for (int i = 1; i <= 99; i += 2) {
    int_buffer.AddObservation(internal::Observation<int32_t>(
        i, now, NETWORK_QUALITY_OBSERVATION_SOURCE_URL_REQUEST));
    time_delta_buffer.AddObservation(internal::Observation<base::TimeDelta>(
        base::TimeDelta::FromMilliseconds(i), now,
        NETWORK_QUALITY_OBSERVATION_SOURCE_URL_REQUEST));
    EXPECT_TRUE(int_buffer.GetPercentile(
        base::TimeTicks(), &result, 50,
        std::vector<NetworkQualityObservationSource>()));
    ASSERT_EQ(static_cast<size_t>(i / 2 + 1), int_buffer.Size());
    EXPECT_TRUE(time_delta_buffer.GetPercentile(
        base::TimeTicks(), &time_delta_result, 50,
        std::vector<NetworkQualityObservationSource>()));
    ASSERT_EQ(static_cast<size_t>(i / 2 + 1), time_delta_buffer.Size());
  }

  for (int i = 2; i <= 100; i += 2) {
    int_buffer.AddObservation(internal::Observation<int32_t>(
        i, now, NETWORK_QUALITY_OBSERVATION_SOURCE_URL_REQUEST));
    time_delta_buffer.AddObservation(internal::Observation<base::TimeDelta>(
        base::TimeDelta::FromMilliseconds(i), now,
        NETWORK_QUALITY_OBSERVATION_SOURCE_URL_REQUEST));
    EXPECT_TRUE(int_buffer.GetPercentile(
        base::TimeTicks(), &result, 50,
        std::vector<NetworkQualityObservationSource>()));
    ASSERT_EQ(static_cast<size_t>(i / 2 + 50), int_buffer.Size());
    EXPECT_TRUE(time_delta_buffer.GetPercentile(
        base::TimeTicks(), &time_delta_result, 50,
        std::vector<NetworkQualityObservationSource>()));
    ASSERT_EQ(static_cast<size_t>(i / 2 + 50), time_delta_buffer.Size());
  }

  ASSERT_EQ(100u, int_buffer.Size());
  ASSERT_EQ(100u, time_delta_buffer.Size());

  for (int i = 0; i <= 100; ++i) {
    // Checks if the difference between the two integers is less than 1. This is
    // required because computed percentiles may be slightly different from
    // what is expected due to floating point computation errors and integer
    // rounding off errors.
    EXPECT_TRUE(int_buffer.GetPercentile(
        base::TimeTicks(), &result, i,
        std::vector<NetworkQualityObservationSource>()));
    EXPECT_TRUE(time_delta_buffer.GetPercentile(
        base::TimeTicks(), &time_delta_result, i,
        std::vector<NetworkQualityObservationSource>()));
    EXPECT_NEAR(result, i, 1);
    EXPECT_NEAR(time_delta_result.InMilliseconds(), i, 1);
  }

  EXPECT_FALSE(int_buffer.GetPercentile(
      now + base::TimeDelta::FromSeconds(1), &result, 50,
      std::vector<NetworkQualityObservationSource>()));
  EXPECT_FALSE(time_delta_buffer.GetPercentile(
      now + base::TimeDelta::FromSeconds(1), &time_delta_result, 50,
      std::vector<NetworkQualityObservationSource>()));

  // Percentiles should be unavailable when no observations are available.
  int_buffer.Clear();
  time_delta_buffer.Clear();
  EXPECT_FALSE(
      int_buffer.GetPercentile(base::TimeTicks(), &result, 50,
                               std::vector<NetworkQualityObservationSource>()));
  EXPECT_FALSE(time_delta_buffer.GetPercentile(
      base::TimeTicks(), &time_delta_result, 50,
      std::vector<NetworkQualityObservationSource>()));
}

// Verifies that the percentiles are correctly computed. Observations have
// different timestamps with half the observations being very old and the rest
// of them being very recent. Percentiles should factor in recent observations
// much more heavily than older samples.
TEST(NetworkQualityObservationTest, PercentileDifferentTimestamps) {
  internal::ObservationBuffer<int32_t> int_buffer(0.5);
  internal::ObservationBuffer<base::TimeDelta> time_delta_buffer(0.5);
  const base::TimeTicks now = base::TimeTicks::Now();
  const base::TimeTicks very_old = now - base::TimeDelta::FromDays(365);

  int32_t result;
  base::TimeDelta time_delta_result;

  // Network quality should be unavailable when no observations are available.
  EXPECT_FALSE(
      int_buffer.GetPercentile(base::TimeTicks(), &result, 50,
                               std::vector<NetworkQualityObservationSource>()));
  EXPECT_FALSE(time_delta_buffer.GetPercentile(
      base::TimeTicks(), &time_delta_result, 50,
      std::vector<NetworkQualityObservationSource>()));

  // First 50 samples have very old timestamp.
  for (int i = 1; i <= 50; ++i) {
    int_buffer.AddObservation(internal::Observation<int32_t>(
        i, very_old, NETWORK_QUALITY_OBSERVATION_SOURCE_URL_REQUEST));
    time_delta_buffer.AddObservation(internal::Observation<base::TimeDelta>(
        base::TimeDelta::FromMilliseconds(i), very_old,
        NETWORK_QUALITY_OBSERVATION_SOURCE_URL_REQUEST));
  }

  // Next 50 (i.e., from 51 to 100) have recent timestamp.
  for (int i = 51; i <= 100; ++i) {
    int_buffer.AddObservation(internal::Observation<int32_t>(
        i, now, NETWORK_QUALITY_OBSERVATION_SOURCE_URL_REQUEST));
    time_delta_buffer.AddObservation(internal::Observation<base::TimeDelta>(
        base::TimeDelta::FromMilliseconds(i), now,
        NETWORK_QUALITY_OBSERVATION_SOURCE_URL_REQUEST));
  }

  // Older samples have very little weight. So, all percentiles are >= 51
  // (lowest value among recent observations).
  for (int i = 1; i < 100; ++i) {
    // Checks if the difference between the two integers is less than 1. This is
    // required because computed percentiles may be slightly different from
    // what is expected due to floating point computation errors and integer
    // rounding off errors.
    EXPECT_TRUE(int_buffer.GetPercentile(
        base::TimeTicks(), &result, i,
        std::vector<NetworkQualityObservationSource>()));
    EXPECT_NEAR(result, 51 + 0.49 * i, 1);

    EXPECT_TRUE(time_delta_buffer.GetPercentile(
        base::TimeTicks(), &time_delta_result, i,
        std::vector<NetworkQualityObservationSource>()));
    EXPECT_NEAR(time_delta_result.InMilliseconds(), 51 + 0.49 * i, 1);
  }

  EXPECT_FALSE(int_buffer.GetPercentile(
      now + base::TimeDelta::FromSeconds(1), &result, 50,
      std::vector<NetworkQualityObservationSource>()));
  EXPECT_FALSE(time_delta_buffer.GetPercentile(
      now + base::TimeDelta::FromSeconds(1), &time_delta_result, 50,
      std::vector<NetworkQualityObservationSource>()));
}

// Verifies that the percentiles are correctly computed when some of the
// observation sources are disallowed. All observations have the same timestamp.
TEST(NetworkQualityObservationTest, DisallowedObservationSources) {
  internal::ObservationBuffer<int32_t> int_buffer(0.5);
  internal::ObservationBuffer<base::TimeDelta> time_delta_buffer(0.5);
  const base::TimeTicks now = base::TimeTicks::Now();

  int32_t result;
  base::TimeDelta time_delta_result;

  // Network quality should be unavailable when no observations are available.
  EXPECT_FALSE(
      int_buffer.GetPercentile(base::TimeTicks(), &result, 50,
                               std::vector<NetworkQualityObservationSource>()));
  EXPECT_FALSE(time_delta_buffer.GetPercentile(
      base::TimeTicks(), &time_delta_result, 50,
      std::vector<NetworkQualityObservationSource>()));

  // Insert samples from {1,2,3,..., 100}. First insert odd samples, then even
  // samples. This helps in verifying that the order of samples does not matter.
  for (int i = 1; i <= 99; i += 2) {
    int_buffer.AddObservation(internal::Observation<int32_t>(
        i, now, NETWORK_QUALITY_OBSERVATION_SOURCE_URL_REQUEST));
    time_delta_buffer.AddObservation(internal::Observation<base::TimeDelta>(
        base::TimeDelta::FromMilliseconds(i), now,
        NETWORK_QUALITY_OBSERVATION_SOURCE_URL_REQUEST));
  }

  // Add samples for TCP and QUIC observations which should not be taken into
  // account when computing the percentile.
  for (int i = 1; i <= 99; i += 2) {
    int_buffer.AddObservation(internal::Observation<int32_t>(
        10000, now, NETWORK_QUALITY_OBSERVATION_SOURCE_TCP));
    int_buffer.AddObservation(internal::Observation<int32_t>(
        10000, now, NETWORK_QUALITY_OBSERVATION_SOURCE_QUIC));
    time_delta_buffer.AddObservation(internal::Observation<base::TimeDelta>(
        base::TimeDelta::FromMilliseconds(10000), now,
        NETWORK_QUALITY_OBSERVATION_SOURCE_TCP));
    time_delta_buffer.AddObservation(internal::Observation<base::TimeDelta>(
        base::TimeDelta::FromMilliseconds(10000), now,
        NETWORK_QUALITY_OBSERVATION_SOURCE_QUIC));
  }

  for (int i = 2; i <= 100; i += 2) {
    int_buffer.AddObservation(internal::Observation<int32_t>(
        i, now, NETWORK_QUALITY_OBSERVATION_SOURCE_URL_REQUEST));
    time_delta_buffer.AddObservation(internal::Observation<base::TimeDelta>(
        base::TimeDelta::FromMilliseconds(i), now,
        NETWORK_QUALITY_OBSERVATION_SOURCE_URL_REQUEST));
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
    EXPECT_TRUE(int_buffer.GetPercentile(base::TimeTicks(), &result, i,
                                         disallowed_observation_sources));
    EXPECT_NEAR(result, i, 1);
    EXPECT_TRUE(
        time_delta_buffer.GetPercentile(base::TimeTicks(), &time_delta_result,
                                        i, disallowed_observation_sources));
    EXPECT_NEAR(time_delta_result.InMilliseconds(), i, 1);
  }

  // Now check the percentile value for TCP and QUIC observations.
  disallowed_observation_sources.clear();
  disallowed_observation_sources.push_back(
      NETWORK_QUALITY_OBSERVATION_SOURCE_URL_REQUEST);
  for (int i = 0; i <= 100; ++i) {
    // Checks if the difference between the two integers is less than 1. This is
    // required because computed percentiles may be slightly different from
    // what is expected due to floating point computation errors and integer
    // rounding off errors.
    EXPECT_TRUE(int_buffer.GetPercentile(base::TimeTicks(), &result, i,
                                         disallowed_observation_sources));
    EXPECT_NEAR(result, 10000, 1);
    EXPECT_TRUE(
        time_delta_buffer.GetPercentile(base::TimeTicks(), &time_delta_result,
                                        i, disallowed_observation_sources));
    EXPECT_NEAR(time_delta_result.InMilliseconds(), 10000, 1);
  }
}

TEST(NetworkQualityObservationTest, TestGetMedianRTTSince) {
  internal::ObservationBuffer<int32_t> int_buffer(0.5);
  internal::ObservationBuffer<base::TimeDelta> time_delta_buffer(0.5);
  base::TimeTicks now = base::TimeTicks::Now();
  base::TimeTicks old = now - base::TimeDelta::FromMilliseconds(1);
  ASSERT_NE(old, now);

  // First sample has very old timestamp.
  int_buffer.AddObservation(internal::Observation<int32_t>(
      1, old, NETWORK_QUALITY_OBSERVATION_SOURCE_URL_REQUEST));
  time_delta_buffer.AddObservation(internal::Observation<base::TimeDelta>(
      base::TimeDelta::FromMilliseconds(1), old,
      NETWORK_QUALITY_OBSERVATION_SOURCE_URL_REQUEST));

  int_buffer.AddObservation(internal::Observation<int32_t>(
      100, now, NETWORK_QUALITY_OBSERVATION_SOURCE_URL_REQUEST));
  time_delta_buffer.AddObservation(internal::Observation<base::TimeDelta>(
      base::TimeDelta::FromMilliseconds(100), now,
      NETWORK_QUALITY_OBSERVATION_SOURCE_URL_REQUEST));

  const struct {
    base::TimeTicks start_timestamp;
    bool expect_network_quality_available;
    base::TimeDelta expected_url_request_rtt;
    int32_t expected_downstream_throughput;
  } tests[] = {
      {now + base::TimeDelta::FromSeconds(10), false,
       base::TimeDelta::FromMilliseconds(0), 0},
      {now, true, base::TimeDelta::FromMilliseconds(100), 100},
      {now - base::TimeDelta::FromMicroseconds(500), true,
       base::TimeDelta::FromMilliseconds(100), 100},

  };

  for (const auto& test : tests) {
    base::TimeDelta url_request_rtt;
    int32_t downstream_throughput_kbps;
    std::vector<NetworkQualityObservationSource> disallowed_observation_sources;

    EXPECT_EQ(
        test.expect_network_quality_available,
        time_delta_buffer.GetPercentile(test.start_timestamp, &url_request_rtt,
                                        50, disallowed_observation_sources));
    EXPECT_EQ(test.expect_network_quality_available,
              int_buffer.GetPercentile(test.start_timestamp,
                                       &downstream_throughput_kbps, 50,
                                       disallowed_observation_sources));

    if (test.expect_network_quality_available) {
      EXPECT_EQ(test.expected_url_request_rtt, url_request_rtt);
      EXPECT_EQ(test.expected_downstream_throughput,
                downstream_throughput_kbps);
    }
  }
}

}  // namespace

}  // namespace nqe

}  // namespace net