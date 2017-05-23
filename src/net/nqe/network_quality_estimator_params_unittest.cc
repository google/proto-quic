// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/nqe/network_quality_estimator_params.h"

#include <map>
#include <string>

#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace nqe {

namespace internal {

namespace {

// Tests if |weight_multiplier_per_second()| returns correct value for various
// values of half life parameter.
TEST(NetworkQualityEstimatorParamsTest, HalfLifeParam) {
  std::map<std::string, std::string> variation_params;

  const struct {
    std::string description;
    std::string variation_params_value;
    double expected_weight_multiplier;
  } tests[] = {
      {"Half life parameter is not set, default value should be used",
       std::string(), 0.988},
      {"Half life parameter is set to negative, default value should be used",
       "-100", 0.988},
      {"Half life parameter is set to zero, default value should be used", "0",
       0.988},
      {"Half life parameter is set correctly", "10", 0.933},
  };

  for (const auto& test : tests) {
    variation_params["HalfLifeSeconds"] = test.variation_params_value;
    NetworkQualityEstimatorParams params(variation_params);
    EXPECT_NEAR(test.expected_weight_multiplier,
                params.weight_multiplier_per_second(), 0.001)
        << test.description;
  }
}

// Test that the typical network qualities are set correctly.
TEST(NetworkQualityEstimatorParamsTest, TypicalNetworkQualities) {
  std::map<std::string, std::string> variation_params;
  NetworkQualityEstimatorParams params(variation_params);

  // Typical network quality should not be set for Unknown and Offline.
  for (size_t i = EFFECTIVE_CONNECTION_TYPE_UNKNOWN;
       i <= EFFECTIVE_CONNECTION_TYPE_OFFLINE; ++i) {
    EffectiveConnectionType ect = static_cast<EffectiveConnectionType>(i);
    EXPECT_EQ(nqe::internal::InvalidRTT(),
              params.TypicalNetworkQuality(ect).http_rtt());

    EXPECT_EQ(nqe::internal::InvalidRTT(),
              params.TypicalNetworkQuality(ect).transport_rtt());
  }

  // Typical network quality should be set for other effective connection
  // types.
  for (size_t i = EFFECTIVE_CONNECTION_TYPE_SLOW_2G;
       i <= EFFECTIVE_CONNECTION_TYPE_3G; ++i) {
    EffectiveConnectionType ect = static_cast<EffectiveConnectionType>(i);
    // The typical RTT for an effective connection type should be at least as
    // much as the threshold RTT.
    EXPECT_NE(nqe::internal::InvalidRTT(),
              params.TypicalNetworkQuality(ect).http_rtt());
    EXPECT_GT(params.TypicalNetworkQuality(ect).http_rtt(),
              params.ConnectionThreshold(ect).http_rtt());

    EXPECT_NE(nqe::internal::InvalidRTT(),
              params.TypicalNetworkQuality(ect).transport_rtt());
    EXPECT_GT(params.TypicalNetworkQuality(ect).transport_rtt(),
              params.ConnectionThreshold(ect).transport_rtt());

    // The typical throughput for an effective connection type should not be
    // more than the threshold throughput.
    if (params.ConnectionThreshold(ect).downstream_throughput_kbps() !=
        nqe::internal::kInvalidThroughput) {
      EXPECT_LT(params.TypicalNetworkQuality(ect).downstream_throughput_kbps(),
                params.ConnectionThreshold(ect).downstream_throughput_kbps());
    }
  }

  // The typical network quality of 4G connection should be at least as fast
  // as the threshold for 3G connection.
  EXPECT_LT(
      params.TypicalNetworkQuality(EFFECTIVE_CONNECTION_TYPE_4G).http_rtt(),
      params.ConnectionThreshold(EFFECTIVE_CONNECTION_TYPE_3G).http_rtt());
  EXPECT_LT(
      params.TypicalNetworkQuality(EFFECTIVE_CONNECTION_TYPE_4G)
          .transport_rtt(),
      params.ConnectionThreshold(EFFECTIVE_CONNECTION_TYPE_3G).transport_rtt());
  if (params.ConnectionThreshold(EFFECTIVE_CONNECTION_TYPE_3G)
          .downstream_throughput_kbps() != nqe::internal::kInvalidThroughput) {
    EXPECT_GT(params.TypicalNetworkQuality(EFFECTIVE_CONNECTION_TYPE_4G)
                  .downstream_throughput_kbps(),
              params.ConnectionThreshold(EFFECTIVE_CONNECTION_TYPE_3G)
                  .downstream_throughput_kbps());
  }
}

}  // namespace

}  // namespace internal

}  // namespace nqe

}  // namespace net