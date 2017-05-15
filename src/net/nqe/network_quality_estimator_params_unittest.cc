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

}  // namespace

}  // namespace internal

}  // namespace nqe

}  // namespace net