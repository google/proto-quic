// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/congestion_control/cubic_bytes.h"

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
  TestParams(bool fix_convex_mode,
             bool fix_cubic_quantization,
             bool fix_beta_last_max)
      : fix_convex_mode(fix_convex_mode),
        fix_cubic_quantization(fix_cubic_quantization),
        fix_beta_last_max(fix_beta_last_max) {}

  friend std::ostream& operator<<(std::ostream& os, const TestParams& p) {
    os << "{ fix_convex_mode: " << p.fix_convex_mode
       << "  fix_cubic_quantization: " << p.fix_cubic_quantization
       << "  fix_beta_last_max: " << p.fix_beta_last_max;
    os << " }";
    return os;
  }

  bool fix_convex_mode;
  bool fix_cubic_quantization;
  bool fix_beta_last_max;
};

string TestParamToString(const testing::TestParamInfo<TestParams>& params) {
  return QuicStrCat("convex_mode_", params.param.fix_convex_mode, "_",
                    "cubic_quantization_", params.param.fix_cubic_quantization,
                    "_", "beta_last_max_", params.param.fix_beta_last_max);
}

std::vector<TestParams> GetTestParams() {
  std::vector<TestParams> params;
  for (bool fix_convex_mode : {true, false}) {
    for (bool fix_cubic_quantization : {true, false}) {
      for (bool fix_beta_last_max : {true, false}) {
        if (!FLAGS_quic_reloadable_flag_quic_fix_cubic_convex_mode &&
            fix_convex_mode) {
          continue;
        }
        if (!FLAGS_quic_reloadable_flag_quic_fix_cubic_bytes_quantization &&
            fix_cubic_quantization) {
          continue;
        }
        if (!FLAGS_quic_reloadable_flag_quic_fix_beta_last_max &&
            fix_beta_last_max) {
          continue;
        }
        TestParams param(fix_convex_mode, fix_cubic_quantization,
                         fix_beta_last_max);
        params.push_back(param);
      }
    }
  }
  return params;
}

}  // namespace

class CubicBytesTest : public ::testing::TestWithParam<TestParams> {
 protected:
  CubicBytesTest()
      : one_ms_(QuicTime::Delta::FromMilliseconds(1)),
        hundred_ms_(QuicTime::Delta::FromMilliseconds(100)),
        cubic_(&clock_) {
    cubic_.SetFixConvexMode(GetParam().fix_convex_mode);
    cubic_.SetFixCubicQuantization(GetParam().fix_cubic_quantization);
    cubic_.SetFixBetaLastMax(GetParam().fix_beta_last_max);
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
                                       QuicTime::Delta rtt,
                                       QuicTime::Delta elapsed_time) {
    const int64_t offset =
        ((elapsed_time + rtt).ToMicroseconds() << 10) / 1000000;
    const QuicByteCount delta_congestion_window =
        GetParam().fix_cubic_quantization
            ? ((410 * offset * offset * offset) * kDefaultTCPMSS >> 40)
            : ((410 * offset * offset * offset) >> 40) * kDefaultTCPMSS;
    const QuicByteCount cubic_cwnd = initial_cwnd + delta_congestion_window;
    return cubic_cwnd;
  }

  QuicByteCount LastMaxCongestionWindow() {
    return cubic_.last_max_congestion_window();
  }

  const QuicTime::Delta one_ms_;
  const QuicTime::Delta hundred_ms_;
  MockClock clock_;
  CubicBytes cubic_;
};

INSTANTIATE_TEST_CASE_P(CubicBytesTests,
                        CubicBytesTest,
                        ::testing::ValuesIn(GetTestParams()),
                        TestParamToString);

// TODO(jokulik): The original "AboveOrigin" test, below, is very
// loose.  It's nearly impossible to make the test tighter without
// deploying the fix for convex mode.  Once cubic convex is deployed,
// replace "AboveOrigin" with this test.
TEST_P(CubicBytesTest, AboveOriginWithTighterBounds) {
  if (!GetParam().fix_convex_mode) {
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
  current_cwnd = cubic_.CongestionWindowAfterAck(kDefaultTCPMSS, current_cwnd,
                                                 rtt_min, initial_time);
  ASSERT_EQ(expected_first_cwnd, current_cwnd);

  // Normal TCP phase.
  // The maximum number of expected Reno RTTs is calculated by
  // finding the point where the cubic curve and the reno curve meet.
  const int max_reno_rtts =
      GetParam().fix_cubic_quantization
          ? std::sqrt(kNConnectionAlpha /
                      (.4 * rtt_min_s * rtt_min_s * rtt_min_s)) -
                2
          : std::sqrt(kNConnectionAlpha /
                      (.4 * rtt_min_s * rtt_min_s * rtt_min_s)) -
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
      current_cwnd = cubic_.CongestionWindowAfterAck(
          kDefaultTCPMSS, current_cwnd, rtt_min, clock_.ApproximateNow());
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

  if (!GetParam().fix_cubic_quantization) {
    // Because our byte-wise Reno under-estimates the cwnd, we switch to
    // conservative increases for a few acks before switching to true
    // cubic increases.
    for (int i = 0; i < 3; ++i) {
      const QuicByteCount next_expected_cwnd =
          ConservativeCwndInBytes(current_cwnd);
      current_cwnd = cubic_.CongestionWindowAfterAck(
          kDefaultTCPMSS, current_cwnd, rtt_min, clock_.ApproximateNow());
      ASSERT_EQ(next_expected_cwnd, current_cwnd);
    }
  }

  for (int i = 0; i < 54; ++i) {
    const uint64_t max_acks_this_epoch = current_cwnd / kDefaultTCPMSS;
    const QuicByteCount expected_cwnd = CubicConvexCwndInBytes(
        initial_cwnd, rtt_min, (clock_.ApproximateNow() - initial_time));
    current_cwnd = cubic_.CongestionWindowAfterAck(
        kDefaultTCPMSS, current_cwnd, rtt_min, clock_.ApproximateNow());
    ASSERT_EQ(expected_cwnd, current_cwnd);

    for (QuicPacketCount n = 1; n < max_acks_this_epoch; ++n) {
      // Call once per ACK.
      ASSERT_EQ(current_cwnd, cubic_.CongestionWindowAfterAck(
                                  kDefaultTCPMSS, current_cwnd, rtt_min,
                                  clock_.ApproximateNow()));
    }
    clock_.AdvanceTime(hundred_ms_);
  }
  const QuicByteCount expected_cwnd = CubicConvexCwndInBytes(
      initial_cwnd, rtt_min, (clock_.ApproximateNow() - initial_time));
  current_cwnd = cubic_.CongestionWindowAfterAck(
      kDefaultTCPMSS, current_cwnd, rtt_min, clock_.ApproximateNow());
  ASSERT_EQ(expected_cwnd, current_cwnd);
}

TEST_P(CubicBytesTest, AboveOrigin) {
  if (!GetParam().fix_convex_mode && GetParam().fix_cubic_quantization) {
    // Without convex mode fixed, the behavior of the algorithm does
    // not fit the exact pattern of this test.
    // TODO(jokulik): Once the convex mode fix becomes default, this
    // test can be replaced with the better AboveOriginTighterBounds
    // test.
    return;
  }
  // Convex growth.
  const QuicTime::Delta rtt_min = hundred_ms_;
  QuicByteCount current_cwnd = 10 * kDefaultTCPMSS;
  // Without the signed-integer, cubic-convex fix, we start out in the
  // wrong mode.
  QuicPacketCount expected_cwnd = GetParam().fix_convex_mode
                                      ? RenoCwndInBytes(current_cwnd)
                                      : ConservativeCwndInBytes(current_cwnd);
  // Initialize the state.
  clock_.AdvanceTime(one_ms_);
  ASSERT_EQ(expected_cwnd,
            cubic_.CongestionWindowAfterAck(kDefaultTCPMSS, current_cwnd,
                                            rtt_min, clock_.ApproximateNow()));
  current_cwnd = expected_cwnd;
  const QuicPacketCount initial_cwnd = expected_cwnd;
  // Normal TCP phase.
  for (int i = 0; i < 48; ++i) {
    for (QuicPacketCount n = 1;
         n < current_cwnd / kDefaultTCPMSS / kNConnectionAlpha; ++n) {
      // Call once per ACK.
      ASSERT_NEAR(current_cwnd, cubic_.CongestionWindowAfterAck(
                                    kDefaultTCPMSS, current_cwnd, rtt_min,
                                    clock_.ApproximateNow()),
                  kDefaultTCPMSS);
    }
    clock_.AdvanceTime(hundred_ms_);
    current_cwnd = cubic_.CongestionWindowAfterAck(
        kDefaultTCPMSS, current_cwnd, rtt_min, clock_.ApproximateNow());
    if (GetParam().fix_convex_mode) {
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
                                    kDefaultTCPMSS, current_cwnd, rtt_min,
                                    clock_.ApproximateNow()),
                  kDefaultTCPMSS);
    }
    clock_.AdvanceTime(hundred_ms_);
    current_cwnd = cubic_.CongestionWindowAfterAck(
        kDefaultTCPMSS, current_cwnd, rtt_min, clock_.ApproximateNow());
  }
  // Total time elapsed so far; add min_rtt (0.1s) here as well.
  float elapsed_time_s = 10.0f + 0.1f;
  // |expected_cwnd| is initial value of cwnd + K * t^3, where K = 0.4.
  expected_cwnd =
      initial_cwnd / kDefaultTCPMSS +
      (elapsed_time_s * elapsed_time_s * elapsed_time_s * 410) / 1024;
  // Without the convex mode fix, the result is off by one.
  if (!GetParam().fix_convex_mode) {
    ++expected_cwnd;
  }
  EXPECT_EQ(expected_cwnd, current_cwnd / kDefaultTCPMSS);
}

// Constructs an artificial scenario to ensure that cubic-convex
// increases are truly fine-grained:
//
// - After starting the epoch, this test advances the elapsed time
// sufficiently far that cubic will do small increases at less than
// MaxCubicTimeInterval() intervals.
//
// - Sets an artificially large initial cwnd to prevent Reno from the
// convex increases on every ack.
TEST_P(CubicBytesTest, AboveOriginFineGrainedCubing) {
  if (!GetParam().fix_convex_mode || !GetParam().fix_cubic_quantization) {
    // Without these two fixes, this test cannot pass.
    return;
  }

  // Start the test with an artificially large cwnd to prevent Reno
  // from over-taking cubic.
  QuicByteCount current_cwnd = 1000 * kDefaultTCPMSS;
  const QuicByteCount initial_cwnd = current_cwnd;
  const QuicTime::Delta rtt_min = hundred_ms_;
  clock_.AdvanceTime(one_ms_);
  QuicTime initial_time = clock_.ApproximateNow();

  // Start the epoch and then artificially advance the time.
  current_cwnd = cubic_.CongestionWindowAfterAck(
      kDefaultTCPMSS, current_cwnd, rtt_min, clock_.ApproximateNow());
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(600));
  current_cwnd = cubic_.CongestionWindowAfterAck(
      kDefaultTCPMSS, current_cwnd, rtt_min, clock_.ApproximateNow());

  // We expect the algorithm to perform only non-zero, fine-grained cubic
  // increases on every ack in this case.
  for (int i = 0; i < 100; ++i) {
    clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(10));
    const QuicByteCount expected_cwnd = CubicConvexCwndInBytes(
        initial_cwnd, rtt_min, (clock_.ApproximateNow() - initial_time));
    const QuicByteCount next_cwnd = cubic_.CongestionWindowAfterAck(
        kDefaultTCPMSS, current_cwnd, rtt_min, clock_.ApproximateNow());
    // Make sure we are performing cubic increases.
    ASSERT_EQ(expected_cwnd, next_cwnd);
    // Make sure that these are non-zero, less-than-packet sized
    // increases.
    ASSERT_GT(next_cwnd, current_cwnd);
    const QuicByteCount cwnd_delta = next_cwnd - current_cwnd;
    ASSERT_GT(kDefaultTCPMSS * .1, cwnd_delta);

    current_cwnd = next_cwnd;
  }
}

TEST_P(CubicBytesTest, LossEvents) {
  const QuicTime::Delta rtt_min = hundred_ms_;
  QuicByteCount current_cwnd = 422 * kDefaultTCPMSS;
  // Without the signed-integer, cubic-convex fix, we mistakenly
  // increment cwnd after only one_ms_ and a single ack.
  QuicPacketCount expected_cwnd = GetParam().fix_convex_mode
                                      ? RenoCwndInBytes(current_cwnd)
                                      : current_cwnd + kDefaultTCPMSS / 2;
  // Initialize the state.
  clock_.AdvanceTime(one_ms_);
  EXPECT_EQ(expected_cwnd,
            cubic_.CongestionWindowAfterAck(kDefaultTCPMSS, current_cwnd,
                                            rtt_min, clock_.ApproximateNow()));

  // On the first loss, the last max congestion window is set to the
  // congestion window before the loss.
  QuicByteCount pre_loss_cwnd = current_cwnd;
  ASSERT_EQ(0u, LastMaxCongestionWindow());
  expected_cwnd = static_cast<QuicByteCount>(current_cwnd * kNConnectionBeta);
  EXPECT_EQ(expected_cwnd,
            cubic_.CongestionWindowAfterPacketLoss(current_cwnd));
  ASSERT_EQ(pre_loss_cwnd, LastMaxCongestionWindow());
  current_cwnd = expected_cwnd;

  // On the second loss, the current congestion window has not yet
  // reached the last max congestion window.  The last max congestion
  // window will be reduced by an additional backoff factor to allow
  // for competition.
  pre_loss_cwnd = current_cwnd;
  expected_cwnd = static_cast<QuicByteCount>(current_cwnd * kNConnectionBeta);
  ASSERT_EQ(expected_cwnd,
            cubic_.CongestionWindowAfterPacketLoss(current_cwnd));
  current_cwnd = expected_cwnd;
  EXPECT_GT(pre_loss_cwnd, LastMaxCongestionWindow());
  QuicByteCount expected_last_max =
      GetParam().fix_beta_last_max
          ? static_cast<QuicByteCount>(pre_loss_cwnd * kNConnectionBetaLastMax)
          : static_cast<QuicByteCount>(pre_loss_cwnd * kBetaLastMax);
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
  current_cwnd = cubic_.CongestionWindowAfterAck(
      kDefaultTCPMSS, current_cwnd, rtt_min, clock_.ApproximateNow());
  if (GetParam().fix_beta_last_max) {
    EXPECT_GT(LastMaxCongestionWindow(), current_cwnd);
  } else {
    // Without the bug fix, we will be at or above the origin.
    EXPECT_LE(LastMaxCongestionWindow(), current_cwnd);
  }

  // On the final loss, simulate the condition where the congestion
  // window had a chance to grow nearly to the last congestion window.
  current_cwnd = LastMaxCongestionWindow() - 1;
  pre_loss_cwnd = current_cwnd;
  expected_cwnd = static_cast<QuicByteCount>(current_cwnd * kNConnectionBeta);
  EXPECT_EQ(expected_cwnd,
            cubic_.CongestionWindowAfterPacketLoss(current_cwnd));
  expected_last_max =
      GetParam().fix_beta_last_max
          ? pre_loss_cwnd
          : static_cast<QuicByteCount>(pre_loss_cwnd * kBetaLastMax);
  ASSERT_EQ(expected_last_max, LastMaxCongestionWindow());
}

TEST_P(CubicBytesTest, BelowOrigin) {
  // Concave growth.
  const QuicTime::Delta rtt_min = hundred_ms_;
  QuicByteCount current_cwnd = 422 * kDefaultTCPMSS;
  // Without the signed-integer, cubic-convex fix, we mistakenly
  // increment cwnd after only one_ms_ and a single ack.
  QuicPacketCount expected_cwnd = GetParam().fix_convex_mode
                                      ? RenoCwndInBytes(current_cwnd)
                                      : current_cwnd + kDefaultTCPMSS / 2;
  // Initialize the state.
  clock_.AdvanceTime(one_ms_);
  EXPECT_EQ(expected_cwnd,
            cubic_.CongestionWindowAfterAck(kDefaultTCPMSS, current_cwnd,
                                            rtt_min, clock_.ApproximateNow()));
  expected_cwnd = static_cast<QuicPacketCount>(current_cwnd * kNConnectionBeta);
  EXPECT_EQ(expected_cwnd,
            cubic_.CongestionWindowAfterPacketLoss(current_cwnd));
  current_cwnd = expected_cwnd;
  // First update after loss to initialize the epoch.
  current_cwnd = cubic_.CongestionWindowAfterAck(
      kDefaultTCPMSS, current_cwnd, rtt_min, clock_.ApproximateNow());
  // Cubic phase.
  for (int i = 0; i < 40; ++i) {
    clock_.AdvanceTime(hundred_ms_);
    current_cwnd = cubic_.CongestionWindowAfterAck(
        kDefaultTCPMSS, current_cwnd, rtt_min, clock_.ApproximateNow());
  }
  expected_cwnd = 553632;
  EXPECT_EQ(expected_cwnd, current_cwnd);
}

}  // namespace test
}  // namespace net
