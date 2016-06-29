// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/congestion_control/rtt_stats.h"

#include <vector>

#include "base/logging.h"
#include "base/test/mock_log.h"
#include "net/quic/quic_flags.h"
#include "net/quic/test_tools/rtt_stats_peer.h"
#include "testing/gtest/include/gtest/gtest.h"

using logging::LOG_WARNING;
using std::vector;
using testing::HasSubstr;
using testing::Message;
using testing::_;

namespace net {
namespace test {

class RttStatsTest : public ::testing::Test {
 protected:
  RttStats rtt_stats_;
};

TEST_F(RttStatsTest, DefaultsBeforeUpdate) {
  EXPECT_LT(0u, rtt_stats_.initial_rtt_us());
  EXPECT_EQ(QuicTime::Delta::Zero(), rtt_stats_.min_rtt());
  EXPECT_EQ(QuicTime::Delta::Zero(), rtt_stats_.smoothed_rtt());
}

TEST_F(RttStatsTest, SmoothedRtt) {
  // Verify that ack_delay is corrected for in Smoothed RTT.
  rtt_stats_.UpdateRtt(QuicTime::Delta::FromMilliseconds(300),
                       QuicTime::Delta::FromMilliseconds(100),
                       QuicTime::Zero());
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(200), rtt_stats_.latest_rtt());
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(200), rtt_stats_.smoothed_rtt());
  // Verify that effective RTT of zero does not change Smoothed RTT.
  rtt_stats_.UpdateRtt(QuicTime::Delta::FromMilliseconds(200),
                       QuicTime::Delta::FromMilliseconds(200),
                       QuicTime::Zero());
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(200), rtt_stats_.latest_rtt());
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(200), rtt_stats_.smoothed_rtt());
  // Verify that large erroneous ack_delay does not change Smoothed RTT.
  rtt_stats_.UpdateRtt(QuicTime::Delta::FromMilliseconds(200),
                       QuicTime::Delta::FromMilliseconds(300),
                       QuicTime::Zero());
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(200), rtt_stats_.latest_rtt());
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(200), rtt_stats_.smoothed_rtt());
}

TEST_F(RttStatsTest, PreviousSmoothedRtt) {
  // Verify that ack_delay is corrected for in Smoothed RTT.
  rtt_stats_.UpdateRtt(QuicTime::Delta::FromMilliseconds(300),
                       QuicTime::Delta::FromMilliseconds(100),
                       QuicTime::Zero());
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(200), rtt_stats_.latest_rtt());
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(200), rtt_stats_.smoothed_rtt());
  EXPECT_EQ(QuicTime::Delta::Zero(), rtt_stats_.previous_srtt());
  // Ensure the previous SRTT is 200ms after a 100ms sample.
  rtt_stats_.UpdateRtt(QuicTime::Delta::FromMilliseconds(100),
                       QuicTime::Delta::Zero(), QuicTime::Zero());
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(100), rtt_stats_.latest_rtt());
  EXPECT_EQ(QuicTime::Delta::FromMicroseconds(187500).ToMicroseconds(),
            rtt_stats_.smoothed_rtt().ToMicroseconds());
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(200), rtt_stats_.previous_srtt());
}

TEST_F(RttStatsTest, MinRtt) {
  rtt_stats_.UpdateRtt(QuicTime::Delta::FromMilliseconds(200),
                       QuicTime::Delta::Zero(), QuicTime::Zero());
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(200), rtt_stats_.min_rtt());
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(200),
            rtt_stats_.WindowedMinRtt());
  rtt_stats_.UpdateRtt(
      QuicTime::Delta::FromMilliseconds(10), QuicTime::Delta::Zero(),
      QuicTime::Zero().Add(QuicTime::Delta::FromMilliseconds(10)));
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(10), rtt_stats_.min_rtt());
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(10), rtt_stats_.WindowedMinRtt());
  rtt_stats_.UpdateRtt(
      QuicTime::Delta::FromMilliseconds(50), QuicTime::Delta::Zero(),
      QuicTime::Zero().Add(QuicTime::Delta::FromMilliseconds(20)));
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(10), rtt_stats_.min_rtt());
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(10), rtt_stats_.WindowedMinRtt());
  rtt_stats_.UpdateRtt(
      QuicTime::Delta::FromMilliseconds(50), QuicTime::Delta::Zero(),
      QuicTime::Zero().Add(QuicTime::Delta::FromMilliseconds(30)));
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(10), rtt_stats_.min_rtt());
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(10), rtt_stats_.WindowedMinRtt());
  rtt_stats_.UpdateRtt(
      QuicTime::Delta::FromMilliseconds(50), QuicTime::Delta::Zero(),
      QuicTime::Zero().Add(QuicTime::Delta::FromMilliseconds(40)));
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(10), rtt_stats_.min_rtt());
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(10), rtt_stats_.WindowedMinRtt());
  // Verify that ack_delay does not go into recording of min_rtt_.
  rtt_stats_.UpdateRtt(
      QuicTime::Delta::FromMilliseconds(7),
      QuicTime::Delta::FromMilliseconds(2),
      QuicTime::Zero().Add(QuicTime::Delta::FromMilliseconds(50)));
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(7), rtt_stats_.min_rtt());
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(7), rtt_stats_.WindowedMinRtt());
}

TEST_F(RttStatsTest, WindowedMinRtt) {
  rtt_stats_.UpdateRtt(QuicTime::Delta::FromMilliseconds(10),
                       QuicTime::Delta::Zero(), QuicTime::Zero());
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(10), rtt_stats_.min_rtt());
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(10), rtt_stats_.WindowedMinRtt());

  rtt_stats_.SampleNewWindowedMinRtt(4);
  for (int i = 0; i < 3; ++i) {
    rtt_stats_.UpdateRtt(QuicTime::Delta::FromMilliseconds(50),
                         QuicTime::Delta::Zero(), QuicTime::Zero());
    EXPECT_EQ(QuicTime::Delta::FromMilliseconds(10), rtt_stats_.min_rtt());
    EXPECT_EQ(QuicTime::Delta::FromMilliseconds(10),
              rtt_stats_.WindowedMinRtt());
  }
  rtt_stats_.UpdateRtt(QuicTime::Delta::FromMilliseconds(50),
                       QuicTime::Delta::Zero(), QuicTime::Zero());
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(10), rtt_stats_.min_rtt());
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(50), rtt_stats_.WindowedMinRtt());
}

TEST_F(RttStatsTest, ExpireSmoothedMetrics) {
  QuicTime::Delta initial_rtt = QuicTime::Delta::FromMilliseconds(10);
  rtt_stats_.UpdateRtt(initial_rtt, QuicTime::Delta::Zero(), QuicTime::Zero());
  EXPECT_EQ(initial_rtt, rtt_stats_.min_rtt());
  EXPECT_EQ(initial_rtt, rtt_stats_.WindowedMinRtt());
  EXPECT_EQ(initial_rtt, rtt_stats_.smoothed_rtt());

  EXPECT_EQ(initial_rtt.Multiply(0.5), rtt_stats_.mean_deviation());

  // Update once with a 20ms RTT.
  QuicTime::Delta doubled_rtt = initial_rtt.Multiply(2);
  rtt_stats_.UpdateRtt(doubled_rtt, QuicTime::Delta::Zero(), QuicTime::Zero());
  EXPECT_EQ(initial_rtt.Multiply(1.125), rtt_stats_.smoothed_rtt());

  // Expire the smoothed metrics, increasing smoothed rtt and mean deviation.
  rtt_stats_.ExpireSmoothedMetrics();
  EXPECT_EQ(doubled_rtt, rtt_stats_.smoothed_rtt());
  EXPECT_EQ(initial_rtt.Multiply(0.875), rtt_stats_.mean_deviation());

  // Now go back down to 5ms and expire the smoothed metrics, and ensure the
  // mean deviation increases to 15ms.
  QuicTime::Delta half_rtt = initial_rtt.Multiply(0.5);
  rtt_stats_.UpdateRtt(half_rtt, QuicTime::Delta::Zero(), QuicTime::Zero());
  EXPECT_GT(doubled_rtt, rtt_stats_.smoothed_rtt());
  EXPECT_LT(initial_rtt, rtt_stats_.mean_deviation());
}

TEST_F(RttStatsTest, UpdateRttWithBadSendDeltas) {
  // Make sure we ignore bad RTTs.
  base::test::MockLog log;

  QuicTime::Delta initial_rtt = QuicTime::Delta::FromMilliseconds(10);
  rtt_stats_.UpdateRtt(initial_rtt, QuicTime::Delta::Zero(), QuicTime::Zero());
  EXPECT_EQ(initial_rtt, rtt_stats_.min_rtt());
  EXPECT_EQ(initial_rtt, rtt_stats_.WindowedMinRtt());
  EXPECT_EQ(initial_rtt, rtt_stats_.smoothed_rtt());

  vector<QuicTime::Delta> bad_send_deltas;
  bad_send_deltas.push_back(QuicTime::Delta::Zero());
  bad_send_deltas.push_back(QuicTime::Delta::Infinite());
  bad_send_deltas.push_back(QuicTime::Delta::FromMicroseconds(-1000));
  log.StartCapturingLogs();

  for (QuicTime::Delta bad_send_delta : bad_send_deltas) {
    SCOPED_TRACE(Message() << "bad_send_delta = "
                           << bad_send_delta.ToMicroseconds());
    EXPECT_CALL(log, Log(LOG_WARNING, _, _, _, HasSubstr("Ignoring")));
    rtt_stats_.UpdateRtt(bad_send_delta, QuicTime::Delta::Zero(),
                         QuicTime::Zero());
    EXPECT_EQ(initial_rtt, rtt_stats_.min_rtt());
    EXPECT_EQ(initial_rtt, rtt_stats_.WindowedMinRtt());
    EXPECT_EQ(initial_rtt, rtt_stats_.smoothed_rtt());
  }
}

TEST_F(RttStatsTest, ResetAfterConnectionMigrations) {
  rtt_stats_.UpdateRtt(QuicTime::Delta::FromMilliseconds(300),
                       QuicTime::Delta::FromMilliseconds(100),
                       QuicTime::Zero());
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(200), rtt_stats_.latest_rtt());
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(200), rtt_stats_.smoothed_rtt());
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(300), rtt_stats_.min_rtt());
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(300),
            rtt_stats_.WindowedMinRtt());

  // Reset rtt stats on connection migrations.
  rtt_stats_.OnConnectionMigration();
  EXPECT_EQ(QuicTime::Delta::Zero(), rtt_stats_.latest_rtt());
  EXPECT_EQ(QuicTime::Delta::Zero(), rtt_stats_.smoothed_rtt());
  EXPECT_EQ(QuicTime::Delta::Zero(), rtt_stats_.min_rtt());
  EXPECT_EQ(QuicTime::Delta::Zero(), rtt_stats_.WindowedMinRtt());
}

}  // namespace test
}  // namespace net
