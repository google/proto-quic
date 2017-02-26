// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/quic_received_packet_manager.h"

#include <algorithm>
#include <ostream>
#include <vector>

#include "net/quic/core/quic_connection_stats.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {
namespace test {
namespace {

struct TestParams {
  explicit TestParams(QuicVersion version) : version(version) {}

  friend std::ostream& operator<<(std::ostream& os, const TestParams& p) {
    os << "{ version: " << QuicVersionToString(p.version) << " }";
    return os;
  }

  QuicVersion version;
};

std::vector<TestParams> GetTestParams() {
  std::vector<TestParams> params;
  QuicVersionVector all_supported_versions = AllSupportedVersions();
  for (size_t i = 0; i < all_supported_versions.size(); ++i) {
    params.push_back(TestParams(all_supported_versions[i]));
  }
  return params;
}

class QuicReceivedPacketManagerTest
    : public ::testing::TestWithParam<TestParams> {
 protected:
  QuicReceivedPacketManagerTest() : received_manager_(&stats_) {}

  void RecordPacketReceipt(QuicPacketNumber packet_number) {
    RecordPacketReceipt(packet_number, QuicTime::Zero());
  }

  void RecordPacketReceipt(QuicPacketNumber packet_number,
                           QuicTime receipt_time) {
    QuicPacketHeader header;
    header.packet_number = packet_number;
    received_manager_.RecordPacketReceived(header, receipt_time);
  }

  QuicConnectionStats stats_;
  QuicReceivedPacketManager received_manager_;
};

INSTANTIATE_TEST_CASE_P(QuicReceivedPacketManagerTest,
                        QuicReceivedPacketManagerTest,
                        ::testing::ValuesIn(GetTestParams()));

TEST_P(QuicReceivedPacketManagerTest, DontWaitForPacketsBefore) {
  QuicPacketHeader header;
  header.packet_number = 2u;
  received_manager_.RecordPacketReceived(header, QuicTime::Zero());
  header.packet_number = 7u;
  received_manager_.RecordPacketReceived(header, QuicTime::Zero());
  EXPECT_TRUE(received_manager_.IsAwaitingPacket(3u));
  EXPECT_TRUE(received_manager_.IsAwaitingPacket(6u));
  received_manager_.DontWaitForPacketsBefore(4);
  EXPECT_FALSE(received_manager_.IsAwaitingPacket(3u));
  EXPECT_TRUE(received_manager_.IsAwaitingPacket(6u));
}

TEST_P(QuicReceivedPacketManagerTest, GetUpdatedAckFrame) {
  QuicPacketHeader header;
  header.packet_number = 2u;
  QuicTime two_ms = QuicTime::Zero() + QuicTime::Delta::FromMilliseconds(2);
  EXPECT_FALSE(received_manager_.ack_frame_updated());
  received_manager_.RecordPacketReceived(header, two_ms);
  EXPECT_TRUE(received_manager_.ack_frame_updated());

  QuicFrame ack = received_manager_.GetUpdatedAckFrame(QuicTime::Zero());
  EXPECT_FALSE(received_manager_.ack_frame_updated());
  // When UpdateReceivedPacketInfo with a time earlier than the time of the
  // largest observed packet, make sure that the delta is 0, not negative.
  EXPECT_EQ(QuicTime::Delta::Zero(), ack.ack_frame->ack_delay_time);
  EXPECT_EQ(1u, ack.ack_frame->received_packet_times.size());

  QuicTime four_ms = QuicTime::Zero() + QuicTime::Delta::FromMilliseconds(4);
  ack = received_manager_.GetUpdatedAckFrame(four_ms);
  EXPECT_FALSE(received_manager_.ack_frame_updated());
  // When UpdateReceivedPacketInfo after not having received a new packet,
  // the delta should still be accurate.
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(2),
            ack.ack_frame->ack_delay_time);
  // And received packet times won't have change.
  EXPECT_EQ(1u, ack.ack_frame->received_packet_times.size());

  header.packet_number = 999u;
  received_manager_.RecordPacketReceived(header, two_ms);
  header.packet_number = 4u;
  received_manager_.RecordPacketReceived(header, two_ms);
  header.packet_number = 1000u;
  received_manager_.RecordPacketReceived(header, two_ms);
  EXPECT_TRUE(received_manager_.ack_frame_updated());
  ack = received_manager_.GetUpdatedAckFrame(two_ms);
  EXPECT_FALSE(received_manager_.ack_frame_updated());
  // UpdateReceivedPacketInfo should discard any times which can't be
  // expressed on the wire.
  EXPECT_EQ(2u, ack.ack_frame->received_packet_times.size());
}

TEST_P(QuicReceivedPacketManagerTest, UpdateReceivedConnectionStats) {
  EXPECT_FALSE(received_manager_.ack_frame_updated());
  RecordPacketReceipt(1);
  EXPECT_TRUE(received_manager_.ack_frame_updated());
  RecordPacketReceipt(6);
  RecordPacketReceipt(2,
                      QuicTime::Zero() + QuicTime::Delta::FromMilliseconds(1));

  EXPECT_EQ(4u, stats_.max_sequence_reordering);
  EXPECT_EQ(1000, stats_.max_time_reordering_us);
  EXPECT_EQ(1u, stats_.packets_reordered);
}

}  // namespace
}  // namespace test
}  // namespace net
