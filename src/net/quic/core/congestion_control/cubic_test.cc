// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/congestion_control/cubic.h"

#include "base/logging.h"
#include "net/quic/core/quic_flags.h"
#include "net/quic/test_tools/mock_clock.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {
namespace test {

const float kBeta = 0.7f;  // Default Cubic backoff factor.
const uint32_t kNumConnections = 2;
const float kNConnectionBeta = (kNumConnections - 1 + kBeta) / kNumConnections;
const float kNConnectionAlpha = 3 * kNumConnections * kNumConnections *
                                (1 - kNConnectionBeta) / (1 + kNConnectionBeta);

// TODO(jokulik): Once we've rolled out the cubic convex fix, we will
// no longer need a parameterized test.
class CubicTest : public ::testing::TestWithParam<bool> {
 protected:
  CubicTest()
      : one_ms_(QuicTime::Delta::FromMilliseconds(1)),
        hundred_ms_(QuicTime::Delta::FromMilliseconds(100)),
        cubic_(&clock_) {
    fix_convex_mode_ = GetParam();
    cubic_.SetFixConvexMode(fix_convex_mode_);
  }
  const QuicTime::Delta one_ms_;
  const QuicTime::Delta hundred_ms_;
  MockClock clock_;
  Cubic cubic_;
  bool fix_convex_mode_;
};

INSTANTIATE_TEST_CASE_P(CubicTests, CubicTest, testing::Bool());

TEST_P(CubicTest, AboveOrigin) {
  // Convex growth.
  const QuicTime::Delta rtt_min = hundred_ms_;
  const float rtt_min_s = rtt_min.ToMilliseconds() / 1000.0;
  QuicPacketCount current_cwnd = 10;
  // Without the signed-integer, cubic-convex fix, we mistakenly
  // increment cwnd after only one_ms_ and a single ack.
  QuicPacketCount expected_cwnd =
      fix_convex_mode_ ? current_cwnd : current_cwnd + 1;
  // Initialize the state.
  clock_.AdvanceTime(one_ms_);
  const QuicTime initial_time = clock_.ApproximateNow();
  current_cwnd = cubic_.CongestionWindowAfterAck(current_cwnd, rtt_min);
  ASSERT_EQ(expected_cwnd, current_cwnd);
  const QuicPacketCount initial_cwnd = current_cwnd;
  // Normal TCP phase.
  // The maximum number of expected reno RTTs can be calculated by
  // finding the point where the cubic curve and the reno curve meet.
  const int max_reno_rtts =
      std::sqrt(kNConnectionAlpha / (.4 * rtt_min_s * rtt_min_s * rtt_min_s)) -
      1;
  for (int i = 0; i < max_reno_rtts; ++i) {
    const QuicByteCount max_per_ack_cwnd = current_cwnd;
    for (QuicPacketCount n = 1; n < max_per_ack_cwnd / kNConnectionAlpha; ++n) {
      // Call once per ACK.
      const QuicByteCount next_cwnd =
          cubic_.CongestionWindowAfterAck(current_cwnd, rtt_min);
      ASSERT_EQ(current_cwnd, next_cwnd);
    }
    clock_.AdvanceTime(hundred_ms_);
    current_cwnd = cubic_.CongestionWindowAfterAck(current_cwnd, rtt_min);
    if (fix_convex_mode_) {
      // When we fix convex mode and the uint64 arithmetic, we
      // increase the expected_cwnd only after after the first 100ms,
      // rather than after the initial 1ms.
      expected_cwnd++;
      ASSERT_EQ(expected_cwnd, current_cwnd);
    } else {
      ASSERT_EQ(expected_cwnd, current_cwnd);
      expected_cwnd++;
    }
  }
  // Cubic phase.
  for (int i = 0; i < 52; ++i) {
    for (QuicPacketCount n = 1; n < current_cwnd; ++n) {
      // Call once per ACK.
      ASSERT_EQ(current_cwnd,
                cubic_.CongestionWindowAfterAck(current_cwnd, rtt_min));
    }
    clock_.AdvanceTime(hundred_ms_);
    current_cwnd = cubic_.CongestionWindowAfterAck(current_cwnd, rtt_min);
  }
  // Total time elapsed so far; add min_rtt (0.1s) here as well.
  const float elapsed_time_ms =
      (clock_.ApproximateNow() - initial_time).ToMilliseconds() +
      rtt_min.ToMilliseconds();
  const float elapsed_time_s = elapsed_time_ms / 1000.0;
  // |expected_cwnd| is initial value of cwnd + K * t^3, where K = 0.4.
  expected_cwnd =
      initial_cwnd +
      (elapsed_time_s * elapsed_time_s * elapsed_time_s * 410) / 1024;
  EXPECT_EQ(expected_cwnd, current_cwnd);
}

TEST_P(CubicTest, LossEvents) {
  const QuicTime::Delta rtt_min = hundred_ms_;
  QuicPacketCount current_cwnd = 422;
  // Without the signed-integer, cubic-convex fix, we mistakenly
  // increment cwnd after only one_ms_ and a single ack.
  QuicPacketCount expected_cwnd =
      fix_convex_mode_ ? current_cwnd : current_cwnd + 1;
  // Initialize the state.
  clock_.AdvanceTime(one_ms_);
  EXPECT_EQ(expected_cwnd,
            cubic_.CongestionWindowAfterAck(current_cwnd, rtt_min));
  expected_cwnd = static_cast<QuicPacketCount>(current_cwnd * kNConnectionBeta);
  EXPECT_EQ(expected_cwnd,
            cubic_.CongestionWindowAfterPacketLoss(current_cwnd));
  expected_cwnd = static_cast<QuicPacketCount>(current_cwnd * kNConnectionBeta);
  EXPECT_EQ(expected_cwnd,
            cubic_.CongestionWindowAfterPacketLoss(current_cwnd));
}

TEST_P(CubicTest, BelowOrigin) {
  // Concave growth.
  const QuicTime::Delta rtt_min = hundred_ms_;
  QuicPacketCount current_cwnd = 422;
  // Without the signed-integer, cubic-convex fix, we mistakenly
  // increment cwnd after only one_ms_ and a single ack.
  QuicPacketCount expected_cwnd =
      fix_convex_mode_ ? current_cwnd : current_cwnd + 1;
  // Initialize the state.
  clock_.AdvanceTime(one_ms_);
  EXPECT_EQ(expected_cwnd,
            cubic_.CongestionWindowAfterAck(current_cwnd, rtt_min));
  expected_cwnd = static_cast<QuicPacketCount>(current_cwnd * kNConnectionBeta);
  EXPECT_EQ(expected_cwnd,
            cubic_.CongestionWindowAfterPacketLoss(current_cwnd));
  current_cwnd = expected_cwnd;
  // First update after loss to initialize the epoch.
  current_cwnd = cubic_.CongestionWindowAfterAck(current_cwnd, rtt_min);
  // Cubic phase.
  for (int i = 0; i < 40; ++i) {
    clock_.AdvanceTime(hundred_ms_);
    current_cwnd = cubic_.CongestionWindowAfterAck(current_cwnd, rtt_min);
  }
  expected_cwnd = 399;
  EXPECT_EQ(expected_cwnd, current_cwnd);
}

}  // namespace test
}  // namespace net
