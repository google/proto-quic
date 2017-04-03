// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/reporting/reporting_endpoint_manager.h"

#include <string>

#include "base/test/simple_test_tick_clock.h"
#include "base/time/time.h"
#include "net/base/backoff_entry.h"
#include "net/reporting/reporting_cache.h"
#include "net/reporting/reporting_client.h"
#include "net/reporting/reporting_test_util.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"
#include "url/origin.h"

namespace net {
namespace {

class ReportingEndpointManagerTest : public ::testing::Test {
 protected:
  ReportingEndpointManagerTest()
      : manager_(&clock_, &cache_, &backoff_policy_) {
    backoff_policy_.num_errors_to_ignore = 0;
    backoff_policy_.initial_delay_ms = 60000;
    backoff_policy_.multiply_factor = 2.0;
    backoff_policy_.jitter_factor = 0.0;
    backoff_policy_.maximum_backoff_ms = -1;
    backoff_policy_.entry_lifetime_ms = 0;
    backoff_policy_.always_use_initial_delay = false;
  }

  base::TimeTicks yesterday() {
    return clock_.NowTicks() - base::TimeDelta::FromDays(1);
  }

  base::TimeTicks tomorrow() {
    return clock_.NowTicks() + base::TimeDelta::FromDays(1);
  }

  const url::Origin kOrigin_ = url::Origin(GURL("https://origin/"));
  const GURL kEndpoint_ = GURL("https://endpoint/");
  const std::string kGroup_ = "group";

  base::SimpleTestTickClock clock_;
  ReportingCache cache_;
  BackoffEntry::Policy backoff_policy_;
  ReportingEndpointManager manager_;
};

TEST_F(ReportingEndpointManagerTest, NoEndpoint) {
  GURL endpoint_url;
  bool found_endpoint =
      manager_.FindEndpointForOriginAndGroup(kOrigin_, kGroup_, &endpoint_url);
  EXPECT_FALSE(found_endpoint);
}

TEST_F(ReportingEndpointManagerTest, Endpoint) {
  cache_.SetClient(kOrigin_, kEndpoint_, ReportingClient::Subdomains::EXCLUDE,
                   kGroup_, tomorrow());

  GURL endpoint_url;
  bool found_endpoint =
      manager_.FindEndpointForOriginAndGroup(kOrigin_, kGroup_, &endpoint_url);
  EXPECT_TRUE(found_endpoint);
  EXPECT_EQ(kEndpoint_, endpoint_url);
}

TEST_F(ReportingEndpointManagerTest, ExpiredEndpoint) {
  cache_.SetClient(kOrigin_, kEndpoint_, ReportingClient::Subdomains::EXCLUDE,
                   kGroup_, yesterday());

  GURL endpoint_url;
  bool found_endpoint =
      manager_.FindEndpointForOriginAndGroup(kOrigin_, kGroup_, &endpoint_url);
  EXPECT_FALSE(found_endpoint);
}

TEST_F(ReportingEndpointManagerTest, PendingEndpoint) {
  cache_.SetClient(kOrigin_, kEndpoint_, ReportingClient::Subdomains::EXCLUDE,
                   kGroup_, tomorrow());

  manager_.SetEndpointPending(kEndpoint_);

  GURL endpoint_url;
  bool found_endpoint =
      manager_.FindEndpointForOriginAndGroup(kOrigin_, kGroup_, &endpoint_url);
  EXPECT_FALSE(found_endpoint);

  manager_.ClearEndpointPending(kEndpoint_);

  found_endpoint =
      manager_.FindEndpointForOriginAndGroup(kOrigin_, kGroup_, &endpoint_url);
  EXPECT_TRUE(found_endpoint);
  EXPECT_EQ(kEndpoint_, endpoint_url);
}

TEST_F(ReportingEndpointManagerTest, BackedOffEndpoint) {
  ASSERT_EQ(2.0, backoff_policy_.multiply_factor);

  cache_.SetClient(kOrigin_, kEndpoint_, ReportingClient::Subdomains::EXCLUDE,
                   kGroup_, tomorrow());

  manager_.InformOfEndpointRequest(kEndpoint_, false);

  // After one failure, endpoint is in exponential backoff.
  GURL endpoint_url;
  bool found_endpoint =
      manager_.FindEndpointForOriginAndGroup(kOrigin_, kGroup_, &endpoint_url);
  EXPECT_FALSE(found_endpoint);

  // After initial delay, endpoint is usable again.
  clock_.Advance(
      base::TimeDelta::FromMilliseconds(backoff_policy_.initial_delay_ms));

  found_endpoint =
      manager_.FindEndpointForOriginAndGroup(kOrigin_, kGroup_, &endpoint_url);
  EXPECT_TRUE(found_endpoint);
  EXPECT_EQ(kEndpoint_, endpoint_url);

  manager_.InformOfEndpointRequest(kEndpoint_, false);

  // After a second failure, endpoint is backed off again.
  found_endpoint =
      manager_.FindEndpointForOriginAndGroup(kOrigin_, kGroup_, &endpoint_url);
  EXPECT_FALSE(found_endpoint);

  clock_.Advance(
      base::TimeDelta::FromMilliseconds(backoff_policy_.initial_delay_ms));

  // Next backoff is longer -- 2x the first -- so endpoint isn't usable yet.
  found_endpoint =
      manager_.FindEndpointForOriginAndGroup(kOrigin_, kGroup_, &endpoint_url);
  EXPECT_FALSE(found_endpoint);

  clock_.Advance(
      base::TimeDelta::FromMilliseconds(backoff_policy_.initial_delay_ms));

  // After 2x the initial delay, the endpoint is usable again.
  found_endpoint =
      manager_.FindEndpointForOriginAndGroup(kOrigin_, kGroup_, &endpoint_url);
  EXPECT_TRUE(found_endpoint);
  EXPECT_EQ(kEndpoint_, endpoint_url);

  manager_.InformOfEndpointRequest(kEndpoint_, true);
  manager_.InformOfEndpointRequest(kEndpoint_, true);

  // Two more successful requests should reset the backoff to the initial delay
  // again.
  manager_.InformOfEndpointRequest(kEndpoint_, false);

  found_endpoint =
      manager_.FindEndpointForOriginAndGroup(kOrigin_, kGroup_, &endpoint_url);
  EXPECT_FALSE(found_endpoint);

  clock_.Advance(
      base::TimeDelta::FromMilliseconds(backoff_policy_.initial_delay_ms));

  found_endpoint =
      manager_.FindEndpointForOriginAndGroup(kOrigin_, kGroup_, &endpoint_url);
  EXPECT_TRUE(found_endpoint);
}

// Make sure that multiple endpoints will all be returned at some point, to
// avoid accidentally or intentionally implementing any priority ordering.
TEST_F(ReportingEndpointManagerTest, RandomEndpoint) {
  static const GURL kEndpoint1("https://endpoint1/");
  static const GURL kEndpoint2("https://endpoint2/");
  static const int kMaxAttempts = 20;

  cache_.SetClient(kOrigin_, kEndpoint1, ReportingClient::Subdomains::EXCLUDE,
                   kGroup_, tomorrow());
  cache_.SetClient(kOrigin_, kEndpoint2, ReportingClient::Subdomains::EXCLUDE,
                   kGroup_, tomorrow());

  bool endpoint1_seen = false;
  bool endpoint2_seen = false;

  for (int i = 0; i < kMaxAttempts; i++) {
    GURL endpoint_url;
    bool found_endpoint = manager_.FindEndpointForOriginAndGroup(
        kOrigin_, kGroup_, &endpoint_url);
    ASSERT_TRUE(found_endpoint);
    ASSERT_TRUE(endpoint_url == kEndpoint1 || endpoint_url == kEndpoint2);

    if (endpoint_url == kEndpoint1)
      endpoint1_seen = true;
    else if (endpoint_url == kEndpoint2)
      endpoint2_seen = true;

    if (endpoint1_seen && endpoint2_seen)
      break;
  }

  EXPECT_TRUE(endpoint1_seen);
  EXPECT_TRUE(endpoint2_seen);
}

}  // namespace
}  // namespace net
