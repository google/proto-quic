// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/congestion_control/cubic_bytes.h"

#include "base/logging.h"
#include "net/quic/quic_connection_stats.h"
#include "net/quic/test_tools/mock_clock.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {
namespace test {

const float kBeta = 0.7f;  // Default Cubic backoff factor.
const uint32_t kNumConnections = 2;
const float kNConnectionBeta = (kNumConnections - 1 + kBeta) / kNumConnections;
const float kNConnectionAlpha = 3 * kNumConnections * kNumConnections *
                                (1 - kNConnectionBeta) / (1 + kNConnectionBeta);

class CubicBytesTest : public ::testing::Test {
 protected:
  CubicBytesTest()
      : one_ms_(QuicTime::Delta::FromMilliseconds(1)),
        hundred_ms_(QuicTime::Delta::FromMilliseconds(100)),
        cubic_(&clock_) {}
  const QuicTime::Delta one_ms_;
  const QuicTime::Delta hundred_ms_;
  MockClock clock_;
  CubicBytes cubic_;
};

TEST_F(CubicBytesTest, AboveOrigin) {
  // Convex growth.
  const QuicTime::Delta rtt_min = hundred_ms_;
  QuicByteCount current_cwnd = 10 * kDefaultTCPMSS;
  QuicByteCount expected_cwnd = current_cwnd + kDefaultTCPMSS;
  // Initialize the state.
  clock_.AdvanceTime(one_ms_);
  EXPECT_EQ(expected_cwnd, cubic_.CongestionWindowAfterAck(
                               kDefaultTCPMSS, current_cwnd, rtt_min));
  current_cwnd = expected_cwnd;
  // Normal TCP phase.
  for (int i = 0; i < 48; ++i) {
    for (QuicPacketCount n = 1;
         n < current_cwnd / kDefaultTCPMSS / kNConnectionAlpha; ++n) {
      // Call once per ACK.
      EXPECT_NEAR(current_cwnd, cubic_.CongestionWindowAfterAck(
                                    kDefaultTCPMSS, current_cwnd, rtt_min),
                  kDefaultTCPMSS);
    }
    clock_.AdvanceTime(hundred_ms_);
    current_cwnd =
        cubic_.CongestionWindowAfterAck(kDefaultTCPMSS, current_cwnd, rtt_min);
    EXPECT_NEAR(expected_cwnd, current_cwnd, kDefaultTCPMSS);
    expected_cwnd += kDefaultTCPMSS;
  }
  // Cubic phase.
  for (int i = 0; i < 52; ++i) {
    for (QuicPacketCount n = 1; n < current_cwnd / kDefaultTCPMSS; ++n) {
      // Call once per ACK.
      EXPECT_NEAR(current_cwnd, cubic_.CongestionWindowAfterAck(
                                    kDefaultTCPMSS, current_cwnd, rtt_min),
                  kDefaultTCPMSS);
    }
    clock_.AdvanceTime(hundred_ms_);
    current_cwnd =
        cubic_.CongestionWindowAfterAck(kDefaultTCPMSS, current_cwnd, rtt_min);
  }
  // Total time elapsed so far; add min_rtt (0.1s) here as well.
  float elapsed_time_s = 10.0f + 0.1f;
  // |expected_cwnd| is initial value of cwnd + K * t^3, where K = 0.4.
  expected_cwnd =
      11 + (elapsed_time_s * elapsed_time_s * elapsed_time_s * 410) / 1024;
  EXPECT_EQ(expected_cwnd, current_cwnd / kDefaultTCPMSS);
}

TEST_F(CubicBytesTest, CwndIncreaseStatsDuringConvexRegion) {
  const QuicTime::Delta rtt_min = hundred_ms_;
  QuicByteCount current_cwnd = 10 * kDefaultTCPMSS;
  QuicByteCount expected_cwnd = current_cwnd + kDefaultTCPMSS;
  // Initialize controller state.
  clock_.AdvanceTime(one_ms_);
  expected_cwnd =
      cubic_.CongestionWindowAfterAck(kDefaultTCPMSS, current_cwnd, rtt_min);
  current_cwnd = expected_cwnd;
  // Testing Reno mode increase.
  for (int i = 0; i < 48; ++i) {
    for (QuicPacketCount n = 1;
         n < current_cwnd / kDefaultTCPMSS / kNConnectionAlpha; ++n) {
      // Call once per ACK, causing cwnd growth in Reno mode.
      cubic_.CongestionWindowAfterAck(kDefaultTCPMSS, current_cwnd, rtt_min);
    }
    // Advance current time so that cwnd update is allowed to happen by Cubic.
    clock_.AdvanceTime(hundred_ms_);
    current_cwnd =
        cubic_.CongestionWindowAfterAck(kDefaultTCPMSS, current_cwnd, rtt_min);
    expected_cwnd += kDefaultTCPMSS;
  }

  // Testing Cubic mode increase.
  for (int i = 0; i < 52; ++i) {
    for (QuicPacketCount n = 1; n < current_cwnd / kDefaultTCPMSS; ++n) {
      // Call once per ACK.
      cubic_.CongestionWindowAfterAck(kDefaultTCPMSS, current_cwnd, rtt_min);
    }
    clock_.AdvanceTime(hundred_ms_);
    current_cwnd =
        cubic_.CongestionWindowAfterAck(kDefaultTCPMSS, current_cwnd, rtt_min);
  }
}

TEST_F(CubicBytesTest, LossEvents) {
  const QuicTime::Delta rtt_min = hundred_ms_;
  QuicByteCount current_cwnd = 422 * kDefaultTCPMSS;
  QuicPacketCount expected_cwnd = current_cwnd + kDefaultTCPMSS;
  // Initialize the state.
  clock_.AdvanceTime(one_ms_);
  EXPECT_EQ(expected_cwnd, cubic_.CongestionWindowAfterAck(
                               kDefaultTCPMSS, current_cwnd, rtt_min));
  expected_cwnd = static_cast<QuicPacketCount>(current_cwnd * kNConnectionBeta);
  EXPECT_EQ(expected_cwnd,
            cubic_.CongestionWindowAfterPacketLoss(current_cwnd));
  expected_cwnd = static_cast<QuicPacketCount>(current_cwnd * kNConnectionBeta);
  EXPECT_EQ(expected_cwnd,
            cubic_.CongestionWindowAfterPacketLoss(current_cwnd));
}

TEST_F(CubicBytesTest, BelowOrigin) {
  // Concave growth.
  const QuicTime::Delta rtt_min = hundred_ms_;
  QuicByteCount current_cwnd = 422 * kDefaultTCPMSS;
  QuicPacketCount expected_cwnd = current_cwnd + kDefaultTCPMSS;
  // Initialize the state.
  clock_.AdvanceTime(one_ms_);
  EXPECT_EQ(expected_cwnd, cubic_.CongestionWindowAfterAck(
                               kDefaultTCPMSS, current_cwnd, rtt_min));
  expected_cwnd = static_cast<QuicPacketCount>(current_cwnd * kNConnectionBeta);
  EXPECT_EQ(expected_cwnd,
            cubic_.CongestionWindowAfterPacketLoss(current_cwnd));
  current_cwnd = expected_cwnd;
  // First update after loss to initialize the epoch.
  current_cwnd =
      cubic_.CongestionWindowAfterAck(kDefaultTCPMSS, current_cwnd, rtt_min);
  // Cubic phase.
  for (int i = 0; i < 40; ++i) {
    clock_.AdvanceTime(hundred_ms_);
    current_cwnd =
        cubic_.CongestionWindowAfterAck(kDefaultTCPMSS, current_cwnd, rtt_min);
  }
  expected_cwnd = 422 * kDefaultTCPMSS;
  EXPECT_EQ(expected_cwnd, current_cwnd);
}

}  // namespace test
}  // namespace net
