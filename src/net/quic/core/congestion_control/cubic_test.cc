// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/congestion_control/cubic.h"

#include <cstdint>

#include "net/quic/core/quic_flags.h"
#include "net/quic/platform/api/quic_str_cat.h"
#include "net/quic/test_tools/mock_clock.h"
#include "testing/gtest/include/gtest/gtest.h"

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
  TestParams(bool fix_convex_mode, bool fix_beta_last_max)
      : fix_convex_mode(fix_convex_mode),
        fix_beta_last_max(fix_beta_last_max) {}

  friend std::ostream& operator<<(std::ostream& os, const TestParams& p) {
    os << "{ fix_convex_mode: " << p.fix_convex_mode
       << "  fix_beta_last_max: " << p.fix_beta_last_max;
    os << " }";
    return os;
  }

  bool fix_convex_mode;
  bool fix_beta_last_max;
};

string TestParamToString(const testing::TestParamInfo<TestParams>& params) {
  return QuicStrCat("convex_mode_", params.param.fix_convex_mode, "_",
                    "beta_last_max_", params.param.fix_beta_last_max);
}

std::vector<TestParams> GetTestParams() {
  std::vector<TestParams> params;
  for (bool fix_convex_mode : {true, false}) {
    for (bool fix_beta_last_max : {true, false}) {
      if (!FLAGS_quic_reloadable_flag_quic_fix_cubic_convex_mode &&
          fix_convex_mode) {
        continue;
      }
      if (!FLAGS_quic_reloadable_flag_quic_fix_beta_last_max &&
          fix_beta_last_max) {
        continue;
      }
      TestParams param(fix_convex_mode, fix_beta_last_max);
      params.push_back(param);
    }
  }
  return params;
}

}  // namespace

// TODO(jokulik): Once we've rolled out the cubic convex fix, we will
// no longer need a parameterized test.
class CubicTest : public ::testing::TestWithParam<TestParams> {
 protected:
  CubicTest()
      : one_ms_(QuicTime::Delta::FromMilliseconds(1)),
        hundred_ms_(QuicTime::Delta::FromMilliseconds(100)),
        cubic_(&clock_) {
    cubic_.SetFixConvexMode(GetParam().fix_convex_mode);
    cubic_.SetFixBetaLastMax(GetParam().fix_beta_last_max);
  }

  QuicByteCount LastMaxCongestionWindow() {
    return cubic_.last_max_congestion_window();
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
  const int max_reno_rtts =
      std::sqrt(kNConnectionAlpha / (.4 * rtt_min_s * rtt_min_s * rtt_min_s)) -
      1;
  for (int i = 0; i < max_reno_rtts; ++i) {
    const QuicByteCount max_per_ack_cwnd = current_cwnd;
    for (QuicPacketCount n = 1; n < max_per_ack_cwnd / kNConnectionAlpha; ++n) {
      // Call once per ACK.
      const QuicByteCount next_cwnd = cubic_.CongestionWindowAfterAck(
          current_cwnd, rtt_min, clock_.ApproximateNow());
      ASSERT_EQ(current_cwnd, next_cwnd);
    }
    clock_.AdvanceTime(hundred_ms_);
    current_cwnd = cubic_.CongestionWindowAfterAck(current_cwnd, rtt_min,
                                                   clock_.ApproximateNow());
    if (GetParam().fix_convex_mode) {
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
                cubic_.CongestionWindowAfterAck(current_cwnd, rtt_min,
                                                clock_.ApproximateNow()));
    }
    clock_.AdvanceTime(hundred_ms_);
    current_cwnd = cubic_.CongestionWindowAfterAck(current_cwnd, rtt_min,
                                                   clock_.ApproximateNow());
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
