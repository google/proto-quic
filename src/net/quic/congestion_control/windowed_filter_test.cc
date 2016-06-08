// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
#include "net/quic/congestion_control/windowed_filter.h"

#include "base/logging.h"
#include "net/quic/congestion_control/rtt_stats.h"
#include "net/quic/quic_bandwidth.h"
#include "net/quic/quic_protocol.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {
namespace test {
namespace {

class WindowedFilterTest : public ::testing::Test {
 public:
  // Set the window to 99ms, so 25ms is more than a quarter rtt.
  WindowedFilterTest()
      : windowed_min_rtt_(QuicTime::Delta::FromMilliseconds(99),
                          QuicTime::Delta::Zero()),
        windowed_max_bw_(QuicTime::Delta::FromMilliseconds(99),
                         QuicBandwidth::Zero()) {}

  // Sets up windowed_min_rtt_ to have the following values:
  // Best = 20ms, recorded at 25ms
  // Second best = 40ms, recorded at 75ms
  // Third best = 50ms, recorded at 100ms
  void InitializeMinFilter() {
    QuicTime now = QuicTime::Zero();
    QuicTime::Delta rtt_sample = QuicTime::Delta::FromMilliseconds(10);
    for (int i = 0; i < 5; ++i) {
      windowed_min_rtt_.Update(rtt_sample, now);
      VLOG(1) << "i: " << i << " sample: " << rtt_sample.ToMilliseconds()
              << " mins: "
              << " " << windowed_min_rtt_.GetBest().ToMilliseconds() << " "
              << windowed_min_rtt_.GetSecondBest().ToMilliseconds() << " "
              << windowed_min_rtt_.GetThirdBest().ToMilliseconds();
      now = now.Add(QuicTime::Delta::FromMilliseconds(25));
      rtt_sample = rtt_sample.Add(QuicTime::Delta::FromMilliseconds(10));
    }
    EXPECT_EQ(QuicTime::Delta::FromMilliseconds(20),
              windowed_min_rtt_.GetBest());
    EXPECT_EQ(QuicTime::Delta::FromMilliseconds(40),
              windowed_min_rtt_.GetSecondBest());
    EXPECT_EQ(QuicTime::Delta::FromMilliseconds(50),
              windowed_min_rtt_.GetThirdBest());
  }

  // Sets up windowed_max_bw_ to have the following values:
  // Best = 900 bps, recorded at 25ms
  // Second best = 700 bps, recorded at 75ms
  // Third best = 600 bps, recorded at 100ms
  void InitializeMaxFilter() {
    QuicTime now = QuicTime::Zero();
    QuicBandwidth bw_sample = QuicBandwidth::FromBitsPerSecond(1000);
    for (int i = 0; i < 5; ++i) {
      windowed_max_bw_.Update(bw_sample, now);
      VLOG(1) << "i: " << i << " sample: " << bw_sample.ToBitsPerSecond()
              << " maxs: "
              << " " << windowed_max_bw_.GetBest().ToBitsPerSecond() << " "
              << windowed_max_bw_.GetSecondBest().ToBitsPerSecond() << " "
              << windowed_max_bw_.GetThirdBest().ToBitsPerSecond();
      now = now.Add(QuicTime::Delta::FromMilliseconds(25));
      bw_sample = bw_sample.Subtract(QuicBandwidth::FromBitsPerSecond(100));
    }
    EXPECT_EQ(QuicBandwidth::FromBitsPerSecond(900),
              windowed_max_bw_.GetBest());
    EXPECT_EQ(QuicBandwidth::FromBitsPerSecond(700),
              windowed_max_bw_.GetSecondBest());
    EXPECT_EQ(QuicBandwidth::FromBitsPerSecond(600),
              windowed_max_bw_.GetThirdBest());
  }

 protected:
  WindowedFilter<QuicTime::Delta, MinFilter<QuicTime::Delta>> windowed_min_rtt_;
  WindowedFilter<QuicBandwidth, MaxFilter<QuicBandwidth>> windowed_max_bw_;
};

TEST_F(WindowedFilterTest, UninitializedEstimates) {
  EXPECT_EQ(QuicTime::Delta::Zero(), windowed_min_rtt_.GetBest());
  EXPECT_EQ(QuicTime::Delta::Zero(), windowed_min_rtt_.GetSecondBest());
  EXPECT_EQ(QuicTime::Delta::Zero(), windowed_min_rtt_.GetThirdBest());
  EXPECT_EQ(QuicBandwidth::Zero(), windowed_max_bw_.GetBest());
  EXPECT_EQ(QuicBandwidth::Zero(), windowed_max_bw_.GetSecondBest());
  EXPECT_EQ(QuicBandwidth::Zero(), windowed_max_bw_.GetThirdBest());
}

TEST_F(WindowedFilterTest, MonotonicallyIncreasingMin) {
  QuicTime now = QuicTime::Zero();
  QuicTime::Delta rtt_sample = QuicTime::Delta::FromMilliseconds(10);
  windowed_min_rtt_.Update(rtt_sample, now);
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(10), windowed_min_rtt_.GetBest());

  // Gradually increase the rtt samples and ensure the windowed min rtt starts
  // rising.
  for (int i = 0; i < 6; ++i) {
    now = now.Add(QuicTime::Delta::FromMilliseconds(25));
    rtt_sample = rtt_sample.Add(QuicTime::Delta::FromMilliseconds(10));
    windowed_min_rtt_.Update(rtt_sample, now);
    VLOG(1) << "i: " << i << " sample: " << rtt_sample.ToMilliseconds()
            << " mins: "
            << " " << windowed_min_rtt_.GetBest().ToMilliseconds() << " "
            << windowed_min_rtt_.GetSecondBest().ToMilliseconds() << " "
            << windowed_min_rtt_.GetThirdBest().ToMilliseconds();
    if (i < 3) {
      EXPECT_EQ(QuicTime::Delta::FromMilliseconds(10),
                windowed_min_rtt_.GetBest());
    } else if (i == 3) {
      EXPECT_EQ(QuicTime::Delta::FromMilliseconds(20),
                windowed_min_rtt_.GetBest());
    } else if (i < 6) {
      EXPECT_EQ(QuicTime::Delta::FromMilliseconds(40),
                windowed_min_rtt_.GetBest());
    }
  }
}

TEST_F(WindowedFilterTest, MonotonicallyDecreasingMax) {
  QuicTime now = QuicTime::Zero();
  QuicBandwidth bw_sample = QuicBandwidth::FromBitsPerSecond(1000);
  windowed_max_bw_.Update(bw_sample, now);
  EXPECT_EQ(QuicBandwidth::FromBitsPerSecond(1000), windowed_max_bw_.GetBest());

  // Gradually decrease the bw samples and ensure the windowed max bw starts
  // decreasing.
  for (int i = 0; i < 6; ++i) {
    now = now.Add(QuicTime::Delta::FromMilliseconds(25));
    bw_sample = bw_sample.Subtract(QuicBandwidth::FromBitsPerSecond(100));
    windowed_max_bw_.Update(bw_sample, now);
    VLOG(1) << "i: " << i << " sample: " << bw_sample.ToBitsPerSecond()
            << " maxs: "
            << " " << windowed_max_bw_.GetBest().ToBitsPerSecond() << " "
            << windowed_max_bw_.GetSecondBest().ToBitsPerSecond() << " "
            << windowed_max_bw_.GetThirdBest().ToBitsPerSecond();
    if (i < 3) {
      EXPECT_EQ(QuicBandwidth::FromBitsPerSecond(1000),
                windowed_max_bw_.GetBest());
    } else if (i == 3) {
      EXPECT_EQ(QuicBandwidth::FromBitsPerSecond(900),
                windowed_max_bw_.GetBest());
    } else if (i < 6) {
      EXPECT_EQ(QuicBandwidth::FromBitsPerSecond(700),
                windowed_max_bw_.GetBest());
    }
  }
}

TEST_F(WindowedFilterTest, SampleChangesThirdBestMin) {
  InitializeMinFilter();
  // RTT sample lower than the third-choice min-rtt sets that, but nothing else.
  QuicTime::Delta rtt_sample = windowed_min_rtt_.GetThirdBest().Subtract(
      QuicTime::Delta::FromMilliseconds(5));
  // This assert is necessary to avoid triggering -Wstrict-overflow
  // See crbug/616957
  ASSERT_GT(windowed_min_rtt_.GetThirdBest(),
            QuicTime::Delta::FromMilliseconds(5));
  // Latest sample was recorded at 100ms.
  QuicTime now = QuicTime::Zero().Add(QuicTime::Delta::FromMilliseconds(101));
  windowed_min_rtt_.Update(rtt_sample, now);
  EXPECT_EQ(rtt_sample, windowed_min_rtt_.GetThirdBest());
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(40),
            windowed_min_rtt_.GetSecondBest());
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(20), windowed_min_rtt_.GetBest());
}

TEST_F(WindowedFilterTest, SampleChangesThirdBestMax) {
  InitializeMaxFilter();
  // BW sample higher than the third-choice max sets that, but nothing else.
  QuicBandwidth bw_sample =
      windowed_max_bw_.GetThirdBest().Add(QuicBandwidth::FromBitsPerSecond(50));
  // Latest sample was recorded at 100ms.
  QuicTime now = QuicTime::Zero().Add(QuicTime::Delta::FromMilliseconds(101));
  windowed_max_bw_.Update(bw_sample, now);
  EXPECT_EQ(bw_sample, windowed_max_bw_.GetThirdBest());
  EXPECT_EQ(QuicBandwidth::FromBitsPerSecond(700),
            windowed_max_bw_.GetSecondBest());
  EXPECT_EQ(QuicBandwidth::FromBitsPerSecond(900), windowed_max_bw_.GetBest());
}

TEST_F(WindowedFilterTest, SampleChangesSecondBestMin) {
  InitializeMinFilter();
  // RTT sample lower than the second-choice min sets that and also
  // the third-choice min.
  QuicTime::Delta rtt_sample = windowed_min_rtt_.GetSecondBest().Subtract(
      QuicTime::Delta::FromMilliseconds(5));
  // This assert is necessary to avoid triggering -Wstrict-overflow
  // See crbug/616957
  ASSERT_GT(windowed_min_rtt_.GetSecondBest(),
            QuicTime::Delta::FromMilliseconds(5));
  // Latest sample was recorded at 100ms.
  QuicTime now = QuicTime::Zero().Add(QuicTime::Delta::FromMilliseconds(101));
  windowed_min_rtt_.Update(rtt_sample, now);
  EXPECT_EQ(rtt_sample, windowed_min_rtt_.GetThirdBest());
  EXPECT_EQ(rtt_sample, windowed_min_rtt_.GetSecondBest());
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(20), windowed_min_rtt_.GetBest());
}

TEST_F(WindowedFilterTest, SampleChangesSecondBestMax) {
  InitializeMaxFilter();
  // BW sample higher than the second-choice max sets that and also
  // the third-choice max.
  QuicBandwidth bw_sample = windowed_max_bw_.GetSecondBest().Add(
      QuicBandwidth::FromBitsPerSecond(50));
  // Latest sample was recorded at 100ms.
  QuicTime now = QuicTime::Zero().Add(QuicTime::Delta::FromMilliseconds(101));
  windowed_max_bw_.Update(bw_sample, now);
  EXPECT_EQ(bw_sample, windowed_max_bw_.GetThirdBest());
  EXPECT_EQ(bw_sample, windowed_max_bw_.GetSecondBest());
  EXPECT_EQ(QuicBandwidth::FromBitsPerSecond(900), windowed_max_bw_.GetBest());
}

TEST_F(WindowedFilterTest, SampleChangesAllMins) {
  InitializeMinFilter();
  // RTT sample lower than the first-choice min-rtt sets that and also
  // the second and third-choice mins.
  QuicTime::Delta rtt_sample = windowed_min_rtt_.GetBest().Subtract(
      QuicTime::Delta::FromMilliseconds(5));
  // This assert is necessary to avoid triggering -Wstrict-overflow
  // See crbug/616957
  ASSERT_GT(windowed_min_rtt_.GetBest(), QuicTime::Delta::FromMilliseconds(5));
  // Latest sample was recorded at 100ms.
  QuicTime now = QuicTime::Zero().Add(QuicTime::Delta::FromMilliseconds(101));
  windowed_min_rtt_.Update(rtt_sample, now);
  EXPECT_EQ(rtt_sample, windowed_min_rtt_.GetThirdBest());
  EXPECT_EQ(rtt_sample, windowed_min_rtt_.GetSecondBest());
  EXPECT_EQ(rtt_sample, windowed_min_rtt_.GetBest());
}

TEST_F(WindowedFilterTest, SampleChangesAllMaxs) {
  InitializeMaxFilter();
  // BW sample higher than the first-choice max sets that and also
  // the second and third-choice maxs.
  QuicBandwidth bw_sample =
      windowed_max_bw_.GetBest().Add(QuicBandwidth::FromBitsPerSecond(50));
  // Latest sample was recorded at 100ms.
  QuicTime now = QuicTime::Zero().Add(QuicTime::Delta::FromMilliseconds(101));
  windowed_max_bw_.Update(bw_sample, now);
  EXPECT_EQ(bw_sample, windowed_max_bw_.GetThirdBest());
  EXPECT_EQ(bw_sample, windowed_max_bw_.GetSecondBest());
  EXPECT_EQ(bw_sample, windowed_max_bw_.GetBest());
}

TEST_F(WindowedFilterTest, ExpireBestMin) {
  InitializeMinFilter();
  QuicTime::Delta old_third_best = windowed_min_rtt_.GetThirdBest();
  QuicTime::Delta old_second_best = windowed_min_rtt_.GetSecondBest();
  QuicTime::Delta rtt_sample =
      old_third_best.Add(QuicTime::Delta::FromMilliseconds(5));
  // Best min sample was recorded at 25ms, so expiry time is 124ms.
  QuicTime now = QuicTime::Zero().Add(QuicTime::Delta::FromMilliseconds(125));
  windowed_min_rtt_.Update(rtt_sample, now);
  EXPECT_EQ(rtt_sample, windowed_min_rtt_.GetThirdBest());
  EXPECT_EQ(old_third_best, windowed_min_rtt_.GetSecondBest());
  EXPECT_EQ(old_second_best, windowed_min_rtt_.GetBest());
}

TEST_F(WindowedFilterTest, ExpireBestMax) {
  InitializeMaxFilter();
  QuicBandwidth old_third_best = windowed_max_bw_.GetThirdBest();
  QuicBandwidth old_second_best = windowed_max_bw_.GetSecondBest();
  QuicBandwidth bw_sample =
      old_third_best.Subtract(QuicBandwidth::FromBitsPerSecond(50));
  // Best max sample was recorded at 25ms, so expiry time is 124ms.
  QuicTime now = QuicTime::Zero().Add(QuicTime::Delta::FromMilliseconds(125));
  windowed_max_bw_.Update(bw_sample, now);
  EXPECT_EQ(bw_sample, windowed_max_bw_.GetThirdBest());
  EXPECT_EQ(old_third_best, windowed_max_bw_.GetSecondBest());
  EXPECT_EQ(old_second_best, windowed_max_bw_.GetBest());
}

TEST_F(WindowedFilterTest, ExpireSecondBestMin) {
  InitializeMinFilter();
  QuicTime::Delta old_third_best = windowed_min_rtt_.GetThirdBest();
  QuicTime::Delta rtt_sample =
      old_third_best.Add(QuicTime::Delta::FromMilliseconds(5));
  // Second best min sample was recorded at 75ms, so expiry time is 174ms.
  QuicTime now = QuicTime::Zero().Add(QuicTime::Delta::FromMilliseconds(175));
  windowed_min_rtt_.Update(rtt_sample, now);
  EXPECT_EQ(rtt_sample, windowed_min_rtt_.GetThirdBest());
  EXPECT_EQ(rtt_sample, windowed_min_rtt_.GetSecondBest());
  EXPECT_EQ(old_third_best, windowed_min_rtt_.GetBest());
}

TEST_F(WindowedFilterTest, ExpireSecondBestMax) {
  InitializeMaxFilter();
  QuicBandwidth old_third_best = windowed_max_bw_.GetThirdBest();
  QuicBandwidth bw_sample =
      old_third_best.Subtract(QuicBandwidth::FromBitsPerSecond(50));
  // Second best max sample was recorded at 75ms, so expiry time is 174ms.
  QuicTime now = QuicTime::Zero().Add(QuicTime::Delta::FromMilliseconds(175));
  windowed_max_bw_.Update(bw_sample, now);
  EXPECT_EQ(bw_sample, windowed_max_bw_.GetThirdBest());
  EXPECT_EQ(bw_sample, windowed_max_bw_.GetSecondBest());
  EXPECT_EQ(old_third_best, windowed_max_bw_.GetBest());
}

TEST_F(WindowedFilterTest, ExpireAllMins) {
  InitializeMinFilter();
  QuicTime::Delta rtt_sample = windowed_min_rtt_.GetThirdBest().Add(
      QuicTime::Delta::FromMilliseconds(5));
  // This assert is necessary to avoid triggering -Wstrict-overflow
  // See crbug/616957
  ASSERT_LT(windowed_min_rtt_.GetThirdBest(),
            QuicTime::Delta::Infinite().Subtract(
                QuicTime::Delta::FromMilliseconds(5)));
  // Third best min sample was recorded at 100ms, so expiry time is 199ms.
  QuicTime now = QuicTime::Zero().Add(QuicTime::Delta::FromMilliseconds(200));
  windowed_min_rtt_.Update(rtt_sample, now);
  EXPECT_EQ(rtt_sample, windowed_min_rtt_.GetThirdBest());
  EXPECT_EQ(rtt_sample, windowed_min_rtt_.GetSecondBest());
  EXPECT_EQ(rtt_sample, windowed_min_rtt_.GetBest());
}

TEST_F(WindowedFilterTest, ExpireAllMaxs) {
  InitializeMaxFilter();
  QuicBandwidth bw_sample = windowed_max_bw_.GetThirdBest().Subtract(
      QuicBandwidth::FromBitsPerSecond(50));
  // Third best max sample was recorded at 100ms, so expiry time is 199ms.
  QuicTime now = QuicTime::Zero().Add(QuicTime::Delta::FromMilliseconds(200));
  windowed_max_bw_.Update(bw_sample, now);
  EXPECT_EQ(bw_sample, windowed_max_bw_.GetThirdBest());
  EXPECT_EQ(bw_sample, windowed_max_bw_.GetSecondBest());
  EXPECT_EQ(bw_sample, windowed_max_bw_.GetBest());
}

}  // namespace
}  // namespace test
}  // namespace net
