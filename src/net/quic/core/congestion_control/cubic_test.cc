// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/congestion_control/cubic.h"

#include <cstdint>

#include "net/quic/platform/api/quic_flags.h"
#include "net/quic/platform/api/quic_str_cat.h"
#include "net/quic/platform/api/quic_test.h"
#include "net/quic/test_tools/mock_clock.h"

using std::string;

namespace net {
namespace test {
namespace {

const float kBeta = 0.7f;          // Default Cubic backoff factor.
const float kBetaLastMax = 0.85f;  // Default Cubic backoff factor.
const uint32_t kNumConnections = 2;
const float kNConnectionBeta = (kNumConnections - 1 + kBeta) / kNumConnections;
const float kNConnectionBetaLastMax =
    (kNumConnections - 1 + kBetaLastMax) / kNumConnections;
const float kNConnectionAlpha = 3 * kNumConnections * kNumConnections *
                                (1 - kNConnectionBeta) / (1 + kNConnectionBeta);

struct TestParams {
  TestParams(bool fix_convex_mode,
             bool fix_beta_last_max,
             bool allow_per_ack_updates)
      : fix_convex_mode(fix_convex_mode),
        fix_beta_last_max(fix_beta_last_max),
        allow_per_ack_updates(allow_per_ack_updates) {}

  friend std::ostream& operator<<(std::ostream& os, const TestParams& p) {
    os << "{ fix_convex_mode: " << p.fix_convex_mode
       << "  fix_beta_last_max: " << p.fix_beta_last_max
       << "  allow_per_ack_updates: " << p.allow_per_ack_updates << " }";
    return os;
  }

  bool fix_convex_mode;
  bool fix_beta_last_max;
  bool allow_per_ack_updates;
};

string TestParamToString(const testing::TestParamInfo<TestParams>& params) {
  return QuicStrCat("convex_mode_", params.param.fix_convex_mode, "_",
                    "beta_last_max_", params.param.fix_beta_last_max, "_",
                    "allow_per_ack_updates_",
                    params.param.allow_per_ack_updates);
}

std::vector<TestParams> GetTestParams() {
  std::vector<TestParams> params;
  for (bool fix_convex_mode : {true, false}) {
    for (bool fix_beta_last_max : {true, false}) {
      for (bool allow_per_ack_updates : {true, false}) {
        if (!FLAGS_quic_reloadable_flag_quic_fix_cubic_convex_mode &&
            fix_convex_mode) {
          continue;
        }
        if (!FLAGS_quic_reloadable_flag_quic_fix_beta_last_max &&
            fix_beta_last_max) {
          continue;
        }
        if (!FLAGS_quic_reloadable_flag_quic_enable_cubic_per_ack_updates &&
            allow_per_ack_updates) {
          continue;
        }
        TestParams param(fix_convex_mode, fix_beta_last_max,
                         allow_per_ack_updates);
        params.push_back(param);
      }
    }
  }
  return params;
}

}  // namespace

// TODO(jokulik): Once we've rolled out the cubic convex fix, we will
// no longer need a parameterized test.
class CubicTest : public QuicTestWithParam<TestParams> {
 protected:
  CubicTest()
      : one_ms_(QuicTime::Delta::FromMilliseconds(1)),
        hundred_ms_(QuicTime::Delta::FromMilliseconds(100)),
        cubic_(&clock_) {
    cubic_.SetFixConvexMode(GetParam().fix_convex_mode);
    cubic_.SetFixBetaLastMax(GetParam().fix_beta_last_max);
    cubic_.SetAllowPerAckUpdates(GetParam().allow_per_ack_updates);
  }

  QuicByteCount LastMaxCongestionWindow() {
    return cubic_.last_max_congestion_window();
  }

  QuicPacketCount CubicConvexCwnd(QuicByteCount initial_cwnd,
                                  QuicTime::Delta rtt,
                                  QuicTime::Delta elapsed_time) {
    const int64_t offset =
        ((elapsed_time + rtt).ToMicroseconds() << 10) / 1000000;
    const QuicPacketCount delta_congestion_window =
        (410 * offset * offset * offset) >> 40;
    const QuicPacketCount cubic_cwnd = initial_cwnd + delta_congestion_window;
    return cubic_cwnd;
  }

  QuicTime::Delta MaxCubicTimeInterval() {
    return cubic_.MaxCubicTimeInterval();
  }

  const QuicTime::Delta one_ms_;
  const QuicTime::Delta hundred_ms_;
  MockClock clock_;
  Cubic cubic_;
};

INSTANTIATE_TEST_CASE_P(CubicTests,
                        CubicTest,
                        ::testing::ValuesIn(GetTestParams()),
                        TestParamToString);

TEST_P(CubicTest, AboveOrigin) {
  if (GetParam().allow_per_ack_updates) {
    // Don't even test a scenario where we fix per ack updates without
    // the signing bug fix.
    return;
  }

  // Convex growth.
  const QuicTime::Delta rtt_min = hundred_ms_;
  const float rtt_min_s = rtt_min.ToMilliseconds() / 1000.0;
  QuicPacketCount current_cwnd = 10;
  // Without the signed-integer, cubic-convex fix, we mistakenly
  // increment cwnd after only one_ms_ and a single ack.
  QuicPacketCount expected_cwnd =
      GetParam().fix_convex_mode ? current_cwnd : current_cwnd + 1;
  // Initialize the state.
  clock_.AdvanceTime(one_ms_);
  const QuicTime initial_time = clock_.ApproximateNow();
  current_cwnd =
      cubic_.CongestionWindowAfterAck(current_cwnd, rtt_min, initial_time);
  ASSERT_EQ(expected_cwnd, current_cwnd);
  const QuicPacketCount initial_cwnd = current_cwnd;
  // Normal TCP phase.
  // The maximum number of expected reno RTTs can be calculated by
  // finding the point where the cubic curve and the reno curve meet.
  int max_reno_rtts =
      std::sqrt(kNConnectionAlpha / (.4 * rtt_min_s * rtt_min_s * rtt_min_s)) -
      1;
  QuicPacketCount reno_acked_packet_count = 1;
  for (int i = 0; i < max_reno_rtts; ++i) {
    const QuicPacketCount max_acks_before_increase =
        current_cwnd / kNConnectionAlpha;
    while (reno_acked_packet_count < max_acks_before_increase - 1) {
      // Call once per ACK.
      const QuicByteCount next_cwnd = cubic_.CongestionWindowAfterAck(
          current_cwnd, rtt_min, clock_.ApproximateNow());
      ASSERT_EQ(current_cwnd, next_cwnd);
      ++reno_acked_packet_count;
    }
    if (!GetParam().allow_per_ack_updates) {
      // If we do not allow per-ack updates, the clock must be
      // advanced in order for the window updates to take affect.
      clock_.AdvanceTime(hundred_ms_);
    }
    // If we allow per-ack updates, the window can increase even
    // before the clock has.
    current_cwnd = cubic_.CongestionWindowAfterAck(current_cwnd, rtt_min,
                                                   clock_.ApproximateNow());
    if (GetParam().fix_convex_mode) {
      if (GetParam().allow_per_ack_updates) {
        // If we allow per-ack updates, the cwnd can increase even after
        // the ack.
        clock_.AdvanceTime(hundred_ms_);
      }
      // When we fix convex mode and the uint64 arithmetic, we
      // increase the expected_cwnd only after the first 100ms, rather
      // than after the initial 1ms.
      expected_cwnd++;
      ASSERT_EQ(expected_cwnd, current_cwnd);
    } else {
      ASSERT_EQ(expected_cwnd, current_cwnd);
      expected_cwnd++;
    }
    reno_acked_packet_count = 0;
  }
  // Cubic phase.
  for (int i = 0; i < 52; ++i) {
    for (QuicPacketCount n = 1; n < current_cwnd; ++n) {
      // Call once per ACK.
      const QuicPacketCount next_cwnd = cubic_.CongestionWindowAfterAck(
          current_cwnd, rtt_min, clock_.ApproximateNow());
      ;
      if (GetParam().allow_per_ack_updates) {
        // If we allow per-ack increases, the cwnd may gently increase
        // up to the cubic value, rather than jumping up after a 30ms
        // delay.
        ASSERT_LE(current_cwnd, next_cwnd);
        current_cwnd = next_cwnd;
      } else {
        ASSERT_EQ(current_cwnd, next_cwnd);
      }
    }
    if (!GetParam().allow_per_ack_updates) {
      // If we do not allow per-ack increases, we have to artificially
      // move the clock past the MaxCubicTimeInterval() in order for
      // the increases to take effect.
      clock_.AdvanceTime(hundred_ms_);
    }
    const QuicTime::Delta elapsed_time = clock_.ApproximateNow() - initial_time;
    const QuicPacketCount expected_cwnd =
        CubicConvexCwnd(initial_cwnd, rtt_min, elapsed_time);
    current_cwnd = cubic_.CongestionWindowAfterAck(current_cwnd, rtt_min,
                                                   clock_.ApproximateNow());
    if (GetParam().allow_per_ack_updates) {
      ASSERT_EQ(expected_cwnd, current_cwnd);
      clock_.AdvanceTime(hundred_ms_);
    }
  }
  if (!GetParam().allow_per_ack_updates) {
    QuicTime::Delta elapsed_time = clock_.ApproximateNow() - initial_time;
    const QuicPacketCount final_cwnd =
        CubicConvexCwnd(initial_cwnd, rtt_min, elapsed_time);
    ASSERT_EQ(final_cwnd, current_cwnd);
  }
}

// Constructs an artificial scenario to show what happens when we
// allow per-ack updates, rather than limiting update freqency.  In
// this scenario, the first two acks of the epoch produce the same
// cwnd.  When we limit per-ack updates, this would cause the
// cessation of cubic updates for 30ms, which is longer than an RTT.
// When we allow per-ack updates, the window continues to grow on
// every ack.
TEST_P(CubicTest, PerAckUpdates) {
  if (!GetParam().fix_convex_mode) {
    // Without this fix, this test cannot pass.
    return;
  }

  // Pick an RTT smaller than the MaxCubicTimeInterval()
  QuicPacketCount current_cwnd = 5;
  const QuicTime::Delta rtt_min = 20 * one_ms_;
  ASSERT_LT(rtt_min, MaxCubicTimeInterval());

  // Initialize the epoch
  clock_.AdvanceTime(one_ms_);
  current_cwnd = cubic_.CongestionWindowAfterAck(current_cwnd, rtt_min,
                                                 clock_.ApproximateNow());
  const QuicPacketCount initial_cwnd = current_cwnd;

  // Simulate the return of cwnd packets over the course of an RTT,
  // which is less than the MaxCubicTimeInterval()
  const QuicPacketCount max_acks = current_cwnd / kNConnectionAlpha - 1;
  const QuicTime::Delta interval = QuicTime::Delta::FromMicroseconds(
      rtt_min.ToMicroseconds() / (max_acks + 2));
  for (QuicPacketCount n = 1; n < max_acks; ++n) {
    clock_.AdvanceTime(interval);
    ASSERT_EQ(current_cwnd,
              cubic_.CongestionWindowAfterAck(current_cwnd, rtt_min,
                                              clock_.ApproximateNow()));
  }
  clock_.AdvanceTime(interval);
  current_cwnd = cubic_.CongestionWindowAfterAck(current_cwnd, rtt_min,
                                                 clock_.ApproximateNow());

  if (GetParam().allow_per_ack_updates) {
    // After all the acks are returned from the epoch, we expect the
    // cwnd to have increased by one.
    EXPECT_EQ(initial_cwnd + 1, current_cwnd);
  } else {
    // If we do not allow per-ack updates, no increases occur at all
    // because we have not moved pass the MaxCubicTimeInterval()
    EXPECT_EQ(initial_cwnd, current_cwnd);
  }
}

TEST_P(CubicTest, LossEvents) {
  const QuicTime::Delta rtt_min = hundred_ms_;
  QuicPacketCount current_cwnd = 422;
  // Without the signed-integer, cubic-convex fix, we mistakenly
  // increment cwnd after only one_ms_ and a single ack.
  QuicPacketCount expected_cwnd =
      GetParam().fix_convex_mode ? current_cwnd : current_cwnd + 1;
  // Initialize the state.
  clock_.AdvanceTime(one_ms_);
  EXPECT_EQ(expected_cwnd, cubic_.CongestionWindowAfterAck(
                               current_cwnd, rtt_min, clock_.ApproximateNow()));

  // On the first loss, the last max congestion window is set to the
  // congestion window before the loss.
  QuicByteCount pre_loss_cwnd = current_cwnd;
  expected_cwnd = static_cast<QuicPacketCount>(current_cwnd * kNConnectionBeta);
  ASSERT_EQ(0u, LastMaxCongestionWindow());
  EXPECT_EQ(expected_cwnd,
            cubic_.CongestionWindowAfterPacketLoss(current_cwnd));
  ASSERT_EQ(pre_loss_cwnd, LastMaxCongestionWindow());
  current_cwnd = expected_cwnd;

  // On the second loss, the current congestion window is
  // significantly lower than the last max congestion window.  The
  // last max congestion window will be reduced by an additional
  // backoff factor to allow for competition.
  pre_loss_cwnd = current_cwnd;
  expected_cwnd = static_cast<QuicPacketCount>(current_cwnd * kNConnectionBeta);
  ASSERT_EQ(expected_cwnd,
            cubic_.CongestionWindowAfterPacketLoss(current_cwnd));
  current_cwnd = expected_cwnd;
  EXPECT_GT(pre_loss_cwnd, LastMaxCongestionWindow());
  QuicByteCount expected_last_max =
      GetParam().fix_beta_last_max
          ? static_cast<QuicPacketCount>(pre_loss_cwnd *
                                         kNConnectionBetaLastMax)
          : static_cast<QuicPacketCount>(pre_loss_cwnd * kBetaLastMax);
  EXPECT_EQ(expected_last_max, LastMaxCongestionWindow());
  if (GetParam().fix_beta_last_max) {
    EXPECT_LT(expected_cwnd, LastMaxCongestionWindow());
  } else {
    // If we don't scale kLastBetaMax, the current window is exactly
    // equal to the last max congestion window, which would cause us
    // to land above the origin on the next increase.
    EXPECT_EQ(expected_cwnd, LastMaxCongestionWindow());
  }
  // Simulate an increase, and check that we are below the origin.
  current_cwnd = cubic_.CongestionWindowAfterAck(current_cwnd, rtt_min,
                                                 clock_.ApproximateNow());
  if (GetParam().fix_beta_last_max) {
    EXPECT_GT(LastMaxCongestionWindow(), current_cwnd);
  } else {
    // Without the bug fix, we will be at or above the origin.
    EXPECT_LE(LastMaxCongestionWindow(), current_cwnd);
  }

  // On the final loss, simulate the condition where the congestion
  // window had a chance to grow back to the last congestion window.
  current_cwnd = LastMaxCongestionWindow();
  pre_loss_cwnd = current_cwnd;
  expected_cwnd = static_cast<QuicPacketCount>(current_cwnd * kNConnectionBeta);
  EXPECT_EQ(expected_cwnd,
            cubic_.CongestionWindowAfterPacketLoss(current_cwnd));
  ASSERT_EQ(pre_loss_cwnd, LastMaxCongestionWindow());
}

TEST_P(CubicTest, BelowOrigin) {
  // Concave growth.
  const QuicTime::Delta rtt_min = hundred_ms_;
  QuicPacketCount current_cwnd = 422;
  // Without the signed-integer, cubic-convex fix, we mistakenly
  // increment cwnd after only one_ms_ and a single ack.
  QuicPacketCount expected_cwnd =
      GetParam().fix_convex_mode ? current_cwnd : current_cwnd + 1;
  // Initialize the state.
  clock_.AdvanceTime(one_ms_);
  EXPECT_EQ(expected_cwnd, cubic_.CongestionWindowAfterAck(
                               current_cwnd, rtt_min, clock_.ApproximateNow()));
  expected_cwnd = static_cast<QuicPacketCount>(current_cwnd * kNConnectionBeta);
  EXPECT_EQ(expected_cwnd,
            cubic_.CongestionWindowAfterPacketLoss(current_cwnd));
  current_cwnd = expected_cwnd;
  // First update after loss to initialize the epoch.
  current_cwnd = cubic_.CongestionWindowAfterAck(current_cwnd, rtt_min,
                                                 clock_.ApproximateNow());
  // Cubic phase.
  for (int i = 0; i < 40; ++i) {
    clock_.AdvanceTime(hundred_ms_);
    current_cwnd = cubic_.CongestionWindowAfterAck(current_cwnd, rtt_min,
                                                   clock_.ApproximateNow());
  }
  expected_cwnd = 399;
  EXPECT_EQ(expected_cwnd, current_cwnd);
}

}  // namespace test
}  // namespace net
