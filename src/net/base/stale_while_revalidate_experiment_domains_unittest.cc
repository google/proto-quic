// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/base/stale_while_revalidate_experiment_domains.h"

#include <iosfwd>

#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

using ::testing::TestWithParam;
using ::testing::ValuesIn;

const struct Expectation {
  const char* host;
  bool result;
} kExpectations[] = {
    {"wordpress.com", true},
    {"tf1.fr", true},
    {"wordpress.com.", true},
    {"www.wordpress.com", true},
    {"www.wordpress.com.", true},
    {"a.b.wordpress.com", true},
    {"a.b.c.d.wordpress.com", true},
    {"www..wordpress.com", true},
    {"www.wordpress..com", false},
    {"a-b-wordpress.com", false},
    {"com", false},
    {".", false},
    {"", false},
    {"..", false},
    {"ordpress.com", false},
    {"wordpress.co", false},
    {"a", false},
    {"a.b", false},
    {"a.b.c", false},
    {"a.b.c.d.e", false},
};

void PrintTo(const Expectation& expectation, std::ostream* os) {
  *os << "{\"" << expectation.host << "\" ," << std::boolalpha
      << expectation.result << "}";
}

class MatchTest : public TestWithParam<Expectation> {};

TEST_P(MatchTest, CheckExpectation) {
  const Expectation& expectation = GetParam();
  EXPECT_EQ(expectation.result,
            IsHostInStaleWhileRevalidateExperimentDomain(expectation.host));
}

INSTANTIATE_TEST_CASE_P(StaleWhileRevalidateExperimentDomainsTest,
                        MatchTest,
                        ValuesIn(kExpectations));

}  // namespace

}  // namespace net
