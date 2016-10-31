// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/base/network_throttle_manager.h"

#include <memory>

#include "net/base/request_priority.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

#include "testing/gtest/include/gtest/gtest.h"

class NetworkThrottleManagerTest : public testing::Test,
                                   NetworkThrottleManager::ThrottleDelegate {
 public:
  NetworkThrottleManagerTest()
      : throttler_(NetworkThrottleManager::CreateThrottler()) {}

 protected:
  std::unique_ptr<NetworkThrottleManager::Throttle> CreateThrottle(
      net::RequestPriority priority,
      bool expected_throttle_state) {
    std::unique_ptr<NetworkThrottleManager::Throttle> throttle(
        throttler_->CreateThrottle(this, priority, false));
    EXPECT_EQ(expected_throttle_state, throttle->IsThrottled());
    return throttle;
  }

 private:
  // NetworkThrottleManager::Delegate
  void OnThrottleStateChanged() override { ADD_FAILURE(); }

  std::unique_ptr<NetworkThrottleManager> throttler_;
};

// Check to confirm that all created throttles start unthrottled for the
// current null implementation.
TEST_F(NetworkThrottleManagerTest, AllUnthrottled) {
  for (int i = MINIMUM_PRIORITY; i <= MAXIMUM_PRIORITY; ++i) {
    CreateThrottle(static_cast<RequestPriority>(i), false);
  }
}

}  // namespace

}  // namespace net
