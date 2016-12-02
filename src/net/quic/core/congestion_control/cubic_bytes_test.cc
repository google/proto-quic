// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/congestion_control/cubic_bytes.h"

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

class CubicBytesTest : public ::testing::TestWithParam<bool> {
 protected:
  CubicBytesTest()
      : one_ms_(QuicTime::Delta::FromMilliseconds(1)),
        hundred_ms_(QuicTime::Delta::FromMilliseconds(100)),
        cubic_(&clock_),
        fix_convex_mode_(GetParam()) {
    cubic_.SetFixConvexMode(fix_convex_mode_);
  }

  QuicByteCount RenoCwndInBytes(QuicByteCount current_cwnd) {
    QuicByteCount reno_estimated_cwnd =
        current_cwnd +
        kDefaultTCPMSS * (kNConnectionAlpha * kDefaultTCPMSS) / current_cwnd;
    return reno_estimated_cwnd;
  }

  QuicByteCount ConservativeCwndInBytes(QuicByteCount current_cwnd) {
    QuicByteCount conservative_cwnd = current_cwnd + kDefaultTCPMSS / 2;
    return conservative_cwnd;
  }

  QuicByteCount CubicConvexCwndInBytes(QuicByteCount initial_cwnd,
                                       int64_t rtt_ms,
                                       int64_t elapsed_time_ms) {
    const int64_t offset = ((elapsed_time_ms + rtt_ms) << 10) / 1000;
    const QuicByteCount delta_congestion_window =
        ((410 * offset * offset * offset) >> 40) * kDefaultTCPMSS;
    const QuicByteCount cubic_cwnd = initial_cwnd + delta_congestion_window;
    return cubic_cwnd;
  }

  const QuicTime::Delta one_ms_;
  const QuicTime::Delta hundred_ms_;
  MockClock clock_;
  CubicBytes cubic_;
  bool fix_convex_mode_;
};

INSTANTIATE_TEST_CASE_P(CubicBytesTests, CubicBytesTest, testing::Bool());

// TODO(jokulik): The original "AboveOrigin" test, below, is very
// loose.  It's nearly impossible to make the test tighter without
// deploying the fix for convex mode.  Once cubic convex is deployed,
// replace "AboveOrigin" with this test.
TEST_P(CubicBytesTest, AboveOriginWithTighterBounds) {
  if (!fix_convex_mode_) {
    // Without convex mode fixed, the behavior of the algorithm is so
    // far from expected, there's no point in doing a tighter test.
    return;
  }
  // Convex growth.
  const QuicTime::Delta rtt_min = hundred_ms_;
  int64_t rtt_min_ms = rtt_min.ToMilliseconds();
  float rtt_min_s = rtt_min_ms / 1000.0;
  QuicByteCount current_cwnd = 10 * kDefaultTCPMSS;
  const QuicByteCount initial_cwnd = current_cwnd;

  clock_.AdvanceTime(one_ms_);
  const QuicTime initial_time = clock_.ApproximateNow();
  const QuicByteCount expected_first_cwnd = RenoCwndInBytes(current_cwnd);
  current_cwnd =
      cubic_.CongestionWindowAfterAck(kDefaultTCPMSS, current_cwnd, rtt_min);
  ASSERT_EQ(expected_first_cwnd, current_cwnd);

  // Normal TCP phase.
  // The maximum number of expected Reno RTTs is calculated by
  // finding the point where the cubic curve and the reno curve meet.
  const int max_reno_rtts =
      std::sqrt(kNConnectionAlpha / (.4 * rtt_min_s * rtt_min_s * rtt_min_s)) -
      1;
  for (int i = 0; i < max_reno_rtts; ++i) {
    // Alternatively, we expect it to increase by one, every time we
    // receive current_cwnd/Alpha acks back.  (This is another way of
    // saying we expect cwnd to increase by approximately Alpha once
    // we receive current_cwnd number ofacks back).
    const uint64_t num_acks_this_epoch =
        current_cwnd / kDefaultTCPMSS / kNConnectionAlpha;
    const QuicByteCount initial_cwnd_this_epoch = current_cwnd;
    for (QuicPacketCount n = 0; n < num_acks_this_epoch; ++n) {
      // Call once per ACK.
      const QuicByteCount expected_next_cwnd = RenoCwndInBytes(current_cwnd);
      current_cwnd = cubic_.CongestionWindowAfterAck(kDefaultTCPMSS,
                                                     current_cwnd, rtt_min);
      ASSERT_EQ(expected_next_cwnd, current_cwnd);
    }
    // Our byte-wise Reno implementation is an estimate.  We expect
    // the cwnd to increase by approximately one MSS every
    // cwnd/kDefaultTCPMSS/Alpha acks, but it may be off by as much as
    // half a packet for smaller values of current_cwnd.
    const QuicByteCount cwnd_change_this_epoch =
        current_cwnd - initial_cwnd_this_epoch;
    ASSERT_NEAR(kDefaultTCPMSS, cwnd_change_this_epoch, kDefaultTCPMSS / 2);
    clock_.AdvanceTime(hundred_ms_);
  }

  // Because our byte-wise Reno under-estimates the cwnd, we switch to
  // conservative increases for a few acks before switching to true
  // cubic increases.
  for (int i = 0; i < 3; ++i) {
    const QuicByteCount next_expected_cwnd =
        ConservativeCwndInBytes(current_cwnd);
    current_cwnd =
        cubic_.CongestionWindowAfterAck(kDefaultTCPMSS, current_cwnd, rtt_min);
    ASSERT_EQ(next_expected_cwnd, current_cwnd);
  }

  for (int i = 0; i < 54; ++i) {
    const uint64_t max_acks_this_epoch = current_cwnd / kDefaultTCPMSS;
    const int elapsed_time_ms =
        (clock_.ApproximateNow() - initial_time).ToMilliseconds();
    const QuicByteCount expected_cwnd = CubicConvexCwndInBytes(
        initial_cwnd, rtt_min.ToMilliseconds(), elapsed_time_ms);
    current_cwnd =
        cubic_.CongestionWindowAfterAck(kDefaultTCPMSS, current_cwnd, rtt_min);
    ASSERT_EQ(expected_cwnd, current_cwnd);

    for (QuicPacketCount n = 1; n < max_acks_this_epoch; ++n) {
      // Call once per ACK.
      ASSERT_EQ(current_cwnd, cubic_.CongestionWindowAfterAck(
                                  kDefaultTCPMSS, current_cwnd, rtt_min));
    }
    clock_.AdvanceTime(hundred_ms_);
  }
  const int elapsed_time_ms =
      (clock_.ApproximateNow() - initial_time).ToMilliseconds();
  const QuicByteCount expected_cwnd = CubicConvexCwndInBytes(
      initial_cwnd, rtt_min.ToMilliseconds(), elapsed_time_ms);
  current_cwnd =
      cubic_.CongestionWindowAfterAck(kDefaultTCPMSS, current_cwnd, rtt_min);
  ASSERT_EQ(expected_cwnd, current_cwnd);
}

TEST_P(CubicBytesTest, AboveOrigin) {
  // Convex growth.
  const QuicTime::Delta rtt_min = hundred_ms_;
  QuicByteCount current_cwnd = 10 * kDefaultTCPMSS;
  // Without the signed-integer, cubic-convex fix, we start out in the
  // wrong mode.
  QuicPacketCount expected_cwnd = fix_convex_mode_
                                      ? RenoCwndInBytes(current_cwnd)
                                      : ConservativeCwndInBytes(current_cwnd);
  // Initialize the state.
  clock_.AdvanceTime(one_ms_);
  ASSERT_EQ(expected_cwnd, cubic_.CongestionWindowAfterAck(
                               kDefaultTCPMSS, current_cwnd, rtt_min));
  current_cwnd = expected_cwnd;
  const QuicPacketCount initial_cwnd = expected_cwnd;
  // Normal TCP phase.
  for (int i = 0; i < 48; ++i) {
    for (QuicPacketCount n = 1;
         n < current_cwnd / kDefaultTCPMSS / kNConnectionAlpha; ++n) {
      // Call once per ACK.
      ASSERT_NEAR(current_cwnd, cubic_.CongestionWindowAfterAck(
                                    kDefaultTCPMSS, current_cwnd, rtt_min),
                  kDefaultTCPMSS);
    }
    clock_.AdvanceTime(hundred_ms_);
    current_cwnd =
        cubic_.CongestionWindowAfterAck(kDefaultTCPMSS, current_cwnd, rtt_min);
    if (fix_convex_mode_) {
      // When we fix convex mode and the uint64 arithmetic, we
      // increase the expected_cwnd only after after the first 100ms,
      // rather than after the initial 1ms.
      expected_cwnd += kDefaultTCPMSS;
      ASSERT_NEAR(expected_cwnd, current_cwnd, kDefaultTCPMSS);
    } else {
      ASSERT_NEAR(expected_cwnd, current_cwnd, kDefaultTCPMSS);
      expected_cwnd += kDefaultTCPMSS;
    }
  }
  // Cubic phase.
  for (int i = 0; i < 52; ++i) {
    for (QuicPacketCount n = 1; n < current_cwnd / kDefaultTCPMSS; ++n) {
      // Call once per ACK.
      ASSERT_NEAR(current_cwnd, cubic_.CongestionWindowAfterAck(
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
      initial_cwnd / kDefaultTCPMSS +
      (elapsed_time_s * elapsed_time_s * elapsed_time_s * 410) / 1024;
  // Without the convex mode fix, the result is off by one.
  if (!fix_convex_mode_) {
    ++expected_cwnd;
  }
  EXPECT_EQ(expected_cwnd, current_cwnd / kDefaultTCPMSS);
}

TEST_P(CubicBytesTest, LossEvents) {
  const QuicTime::Delta rtt_min = hundred_ms_;
  QuicByteCount current_cwnd = 422 * kDefaultTCPMSS;
  // Without the signed-integer, cubic-convex fix, we mistakenly
  // increment cwnd after only one_ms_ and a single ack.
  QuicPacketCount expected_cwnd = fix_convex_mode_
                                      ? RenoCwndInBytes(current_cwnd)
                                      : current_cwnd + kDefaultTCPMSS / 2;
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

TEST_P(CubicBytesTest, BelowOrigin) {
  // Concave growth.
  const QuicTime::Delta rtt_min = hundred_ms_;
  QuicByteCount current_cwnd = 422 * kDefaultTCPMSS;
  // Without the signed-integer, cubic-convex fix, we mistakenly
  // increment cwnd after only one_ms_ and a single ack.
  QuicPacketCount expected_cwnd = fix_convex_mode_
                                      ? RenoCwndInBytes(current_cwnd)
                                      : current_cwnd + kDefaultTCPMSS / 2;
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
  expected_cwnd = 553632;
  EXPECT_EQ(expected_cwnd, current_cwnd);
}

}  // namespace test
}  // namespace net
