// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/congestion_control/general_loss_algorithm.h"

#include <algorithm>
#include <cstdint>

#include "base/stl_util.h"
#include "net/quic/core/congestion_control/rtt_stats.h"
#include "net/quic/core/quic_flags.h"
#include "net/quic/core/quic_unacked_packet_map.h"
#include "net/quic/test_tools/mock_clock.h"
#include "net/quic/test_tools/quic_test_utils.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {
namespace test {
namespace {

// Default packet length.
const uint32_t kDefaultLength = 1000;

class GeneralLossAlgorithmTest : public ::testing::Test {
 protected:
  GeneralLossAlgorithmTest() {
    rtt_stats_.UpdateRtt(QuicTime::Delta::FromMilliseconds(100),
                         QuicTime::Delta::Zero(), clock_.Now());
    EXPECT_LT(0, rtt_stats_.smoothed_rtt().ToMicroseconds());
  }

  ~GeneralLossAlgorithmTest() override {}

  void SendDataPacket(QuicPacketNumber packet_number) {
    QuicStreamFrame* frame = new QuicStreamFrame();
    frame->stream_id = kHeadersStreamId;
    SerializedPacket packet(kDefaultPathId, packet_number,
                            PACKET_1BYTE_PACKET_NUMBER, nullptr, kDefaultLength,
                            false, false);
    packet.retransmittable_frames.push_back(QuicFrame(frame));
    unacked_packets_.AddSentPacket(&packet, 0, NOT_RETRANSMISSION, clock_.Now(),
                                   true);
  }

  void SendAckPacket(QuicPacketNumber packet_number) {
    SerializedPacket packet(kDefaultPathId, packet_number,
                            PACKET_1BYTE_PACKET_NUMBER, nullptr, kDefaultLength,
                            true, false);
    unacked_packets_.AddSentPacket(&packet, 0, NOT_RETRANSMISSION, clock_.Now(),
                                   false);
  }

  void VerifyLosses(QuicPacketNumber largest_newly_acked,
                    QuicPacketNumber* losses_expected,
                    size_t num_losses) {
    if (largest_newly_acked > unacked_packets_.largest_observed()) {
      unacked_packets_.IncreaseLargestObserved(largest_newly_acked);
    }
    SendAlgorithmInterface::CongestionVector lost_packets;
    loss_algorithm_.DetectLosses(unacked_packets_, clock_.Now(), rtt_stats_,
                                 largest_newly_acked, &lost_packets);
    EXPECT_EQ(num_losses, lost_packets.size());
    for (size_t i = 0; i < num_losses; ++i) {
      EXPECT_EQ(lost_packets[i].first, losses_expected[i]);
    }
  }

  QuicFlagSaver flags_;  // Save/restore all QUIC flag values.
  QuicUnackedPacketMap unacked_packets_;
  GeneralLossAlgorithm loss_algorithm_;
  RttStats rtt_stats_;
  MockClock clock_;
};

TEST_F(GeneralLossAlgorithmTest, NackRetransmit1Packet) {
  const size_t kNumSentPackets = 5;
  // Transmit 5 packets.
  for (size_t i = 1; i <= kNumSentPackets; ++i) {
    SendDataPacket(i);
  }
  // No loss on one ack.
  unacked_packets_.RemoveFromInFlight(2);
  VerifyLosses(2, nullptr, 0);
  // No loss on two acks.
  unacked_packets_.RemoveFromInFlight(3);
  VerifyLosses(3, nullptr, 0);
  // Loss on three acks.
  unacked_packets_.RemoveFromInFlight(4);
  QuicPacketNumber lost[] = {1};
  VerifyLosses(4, lost, arraysize(lost));
  EXPECT_EQ(QuicTime::Zero(), loss_algorithm_.GetLossTimeout());
}

// A stretch ack is an ack that covers more than 1 packet of previously
// unacknowledged data.
TEST_F(GeneralLossAlgorithmTest, NackRetransmit1PacketWith1StretchAck) {
  const size_t kNumSentPackets = 10;
  // Transmit 10 packets.
  for (size_t i = 1; i <= kNumSentPackets; ++i) {
    SendDataPacket(i);
  }

  // Nack the first packet 3 times in a single StretchAck.
  unacked_packets_.RemoveFromInFlight(2);
  unacked_packets_.RemoveFromInFlight(3);
  unacked_packets_.RemoveFromInFlight(4);
  QuicPacketNumber lost[] = {1};
  VerifyLosses(4, lost, arraysize(lost));
  EXPECT_EQ(QuicTime::Zero(), loss_algorithm_.GetLossTimeout());
}

// Ack a packet 3 packets ahead, causing a retransmit.
TEST_F(GeneralLossAlgorithmTest, NackRetransmit1PacketSingleAck) {
  const size_t kNumSentPackets = 10;
  // Transmit 10 packets.
  for (size_t i = 1; i <= kNumSentPackets; ++i) {
    SendDataPacket(i);
  }

  // Nack the first packet 3 times in an AckFrame with three missing packets.
  unacked_packets_.RemoveFromInFlight(4);
  QuicPacketNumber lost[] = {1};
  VerifyLosses(4, lost, arraysize(lost));
  EXPECT_EQ(QuicTime::Zero(), loss_algorithm_.GetLossTimeout());
}

TEST_F(GeneralLossAlgorithmTest, EarlyRetransmit1Packet) {
  const size_t kNumSentPackets = 2;
  // Transmit 2 packets.
  for (size_t i = 1; i <= kNumSentPackets; ++i) {
    SendDataPacket(i);
  }
  // Early retransmit when the final packet gets acked and the first is nacked.
  unacked_packets_.RemoveFromInFlight(2);
  VerifyLosses(2, nullptr, 0);
  EXPECT_EQ(clock_.Now() + 1.25 * rtt_stats_.smoothed_rtt(),
            loss_algorithm_.GetLossTimeout());

  clock_.AdvanceTime(1.25 * rtt_stats_.latest_rtt());
  QuicPacketNumber lost[] = {1};
  VerifyLosses(2, lost, arraysize(lost));
  EXPECT_EQ(QuicTime::Zero(), loss_algorithm_.GetLossTimeout());
}

TEST_F(GeneralLossAlgorithmTest, EarlyRetransmitAllPackets) {
  const size_t kNumSentPackets = 5;
  for (size_t i = 1; i <= kNumSentPackets; ++i) {
    SendDataPacket(i);
    // Advance the time 1/4 RTT between 3 and 4.
    if (i == 3) {
      clock_.AdvanceTime(0.25 * rtt_stats_.smoothed_rtt());
    }
  }

  // Early retransmit when the final packet gets acked and 1.25 RTTs have
  // elapsed since the packets were sent.
  unacked_packets_.RemoveFromInFlight(kNumSentPackets);
  // This simulates a single ack following multiple missing packets with FACK.
  QuicPacketNumber lost[] = {1, 2};
  VerifyLosses(kNumSentPackets, lost, arraysize(lost));
  // The time has already advanced 1/4 an RTT, so ensure the timeout is set
  // 1.25 RTTs after the earliest pending packet(3), not the last(4).
  EXPECT_EQ(clock_.Now() + rtt_stats_.smoothed_rtt(),
            loss_algorithm_.GetLossTimeout());

  clock_.AdvanceTime(rtt_stats_.smoothed_rtt());
  QuicPacketNumber lost2[] = {1, 2, 3};
  VerifyLosses(kNumSentPackets, lost2, arraysize(lost2));
  EXPECT_EQ(clock_.Now() + 0.25 * rtt_stats_.smoothed_rtt(),
            loss_algorithm_.GetLossTimeout());
  clock_.AdvanceTime(0.25 * rtt_stats_.smoothed_rtt());
  QuicPacketNumber lost3[] = {1, 2, 3, 4};
  VerifyLosses(kNumSentPackets, lost3, arraysize(lost3));
  EXPECT_EQ(QuicTime::Zero(), loss_algorithm_.GetLossTimeout());
}

TEST_F(GeneralLossAlgorithmTest, DontEarlyRetransmitNeuteredPacket) {
  const size_t kNumSentPackets = 2;
  // Transmit 2 packets.
  for (size_t i = 1; i <= kNumSentPackets; ++i) {
    SendDataPacket(i);
  }
  // Neuter packet 1.
  unacked_packets_.RemoveRetransmittability(1);

  // Early retransmit when the final packet gets acked and the first is nacked.
  unacked_packets_.IncreaseLargestObserved(2);
  unacked_packets_.RemoveFromInFlight(2);
  VerifyLosses(2, nullptr, 0);
  EXPECT_EQ(QuicTime::Zero(), loss_algorithm_.GetLossTimeout());
}

TEST_F(GeneralLossAlgorithmTest, EarlyRetransmitWithLargerUnackablePackets) {
  // Transmit 2 data packets and one ack.
  SendDataPacket(1);
  SendDataPacket(2);
  SendAckPacket(3);
  clock_.AdvanceTime(rtt_stats_.smoothed_rtt());

  // Early retransmit when the final packet gets acked and the first is nacked.
  unacked_packets_.IncreaseLargestObserved(2);
  unacked_packets_.RemoveFromInFlight(2);
  VerifyLosses(2, nullptr, 0);
  EXPECT_EQ(clock_.Now() + 0.25 * rtt_stats_.smoothed_rtt(),
            loss_algorithm_.GetLossTimeout());

  // The packet should be lost once the loss timeout is reached.
  clock_.AdvanceTime(0.25 * rtt_stats_.latest_rtt());
  QuicPacketNumber lost[] = {1};
  VerifyLosses(2, lost, arraysize(lost));
  EXPECT_EQ(QuicTime::Zero(), loss_algorithm_.GetLossTimeout());
}

TEST_F(GeneralLossAlgorithmTest, AlwaysLosePacketSent1RTTEarlier) {
  // Transmit 1 packet and then wait an rtt plus 1ms.
  SendDataPacket(1);
  clock_.AdvanceTime(rtt_stats_.smoothed_rtt() +
                     QuicTime::Delta::FromMilliseconds(1));

  // Transmit 2 packets.
  SendDataPacket(2);
  SendDataPacket(3);

  // Wait another RTT and ack 2.
  clock_.AdvanceTime(rtt_stats_.smoothed_rtt());
  unacked_packets_.IncreaseLargestObserved(2);
  unacked_packets_.RemoveFromInFlight(2);
  QuicPacketNumber lost[] = {1};
  VerifyLosses(2, lost, arraysize(lost));
}

// NoFack loss detection tests.
TEST_F(GeneralLossAlgorithmTest, LazyFackNackRetransmit1Packet) {
  loss_algorithm_.SetLossDetectionType(kLazyFack);
  const size_t kNumSentPackets = 5;
  // Transmit 5 packets.
  for (size_t i = 1; i <= kNumSentPackets; ++i) {
    SendDataPacket(i);
  }
  // No loss on one ack.
  unacked_packets_.RemoveFromInFlight(2);
  VerifyLosses(2, nullptr, 0);
  // No loss on two acks.
  unacked_packets_.RemoveFromInFlight(3);
  VerifyLosses(3, nullptr, 0);
  // Loss on three acks.
  unacked_packets_.RemoveFromInFlight(4);
  QuicPacketNumber lost[] = {1};
  VerifyLosses(4, lost, arraysize(lost));
  EXPECT_EQ(QuicTime::Zero(), loss_algorithm_.GetLossTimeout());
}

// A stretch ack is an ack that covers more than 1 packet of previously
// unacknowledged data.
TEST_F(GeneralLossAlgorithmTest,
       LazyFackNoNackRetransmit1PacketWith1StretchAck) {
  loss_algorithm_.SetLossDetectionType(kLazyFack);
  const size_t kNumSentPackets = 10;
  // Transmit 10 packets.
  for (size_t i = 1; i <= kNumSentPackets; ++i) {
    SendDataPacket(i);
  }

  // Nack the first packet 3 times in a single StretchAck.
  unacked_packets_.RemoveFromInFlight(2);
  unacked_packets_.RemoveFromInFlight(3);
  unacked_packets_.RemoveFromInFlight(4);
  VerifyLosses(4, nullptr, 0);
  // The timer isn't set because we expect more acks.
  EXPECT_EQ(QuicTime::Zero(), loss_algorithm_.GetLossTimeout());
  // Process another ack and then packet 1 will be lost.
  unacked_packets_.RemoveFromInFlight(5);
  QuicPacketNumber lost[] = {1};
  VerifyLosses(5, lost, arraysize(lost));
  EXPECT_EQ(QuicTime::Zero(), loss_algorithm_.GetLossTimeout());
}

// Ack a packet 3 packets ahead does not cause a retransmit.
TEST_F(GeneralLossAlgorithmTest, LazyFackNackRetransmit1PacketSingleAck) {
  loss_algorithm_.SetLossDetectionType(kLazyFack);
  const size_t kNumSentPackets = 10;
  // Transmit 10 packets.
  for (size_t i = 1; i <= kNumSentPackets; ++i) {
    SendDataPacket(i);
  }

  // Nack the first packet 3 times in an AckFrame with three missing packets.
  unacked_packets_.RemoveFromInFlight(4);
  VerifyLosses(4, nullptr, 0);
  // The timer isn't set because we expect more acks.
  EXPECT_EQ(QuicTime::Zero(), loss_algorithm_.GetLossTimeout());
  // Process another ack and then packet 1 and 2 will be lost.
  unacked_packets_.RemoveFromInFlight(5);
  QuicPacketNumber lost[] = {1, 2};
  VerifyLosses(5, lost, arraysize(lost));
  EXPECT_EQ(QuicTime::Zero(), loss_algorithm_.GetLossTimeout());
}

// Time-based loss detection tests.
TEST_F(GeneralLossAlgorithmTest, NoLossFor500Nacks) {
  loss_algorithm_.SetLossDetectionType(kTime);
  const size_t kNumSentPackets = 5;
  // Transmit 5 packets.
  for (size_t i = 1; i <= kNumSentPackets; ++i) {
    SendDataPacket(i);
  }
  unacked_packets_.RemoveFromInFlight(2);
  for (size_t i = 1; i < 500; ++i) {
    VerifyLosses(2, nullptr, 0);
  }
  EXPECT_EQ(1.25 * rtt_stats_.smoothed_rtt(),
            loss_algorithm_.GetLossTimeout() - clock_.Now());
}

TEST_F(GeneralLossAlgorithmTest, NoLossUntilTimeout) {
  loss_algorithm_.SetLossDetectionType(kTime);
  const size_t kNumSentPackets = 10;
  // Transmit 10 packets at 1/10th an RTT interval.
  for (size_t i = 1; i <= kNumSentPackets; ++i) {
    SendDataPacket(i);
    clock_.AdvanceTime(0.1 * rtt_stats_.smoothed_rtt());
  }
  // Expect the timer to not be set.
  EXPECT_EQ(QuicTime::Zero(), loss_algorithm_.GetLossTimeout());
  // The packet should not be lost until 1.25 RTTs pass.
  unacked_packets_.RemoveFromInFlight(2);
  VerifyLosses(2, nullptr, 0);
  // Expect the timer to be set to 0.25 RTT's in the future.
  EXPECT_EQ(0.25 * rtt_stats_.smoothed_rtt(),
            loss_algorithm_.GetLossTimeout() - clock_.Now());
  VerifyLosses(2, nullptr, 0);
  clock_.AdvanceTime(0.25 * rtt_stats_.smoothed_rtt());
  QuicPacketNumber lost[] = {1};
  VerifyLosses(2, lost, arraysize(lost));
  EXPECT_EQ(QuicTime::Zero(), loss_algorithm_.GetLossTimeout());
}

TEST_F(GeneralLossAlgorithmTest, NoLossWithoutNack) {
  loss_algorithm_.SetLossDetectionType(kTime);
  const size_t kNumSentPackets = 10;
  // Transmit 10 packets at 1/10th an RTT interval.
  for (size_t i = 1; i <= kNumSentPackets; ++i) {
    SendDataPacket(i);
    clock_.AdvanceTime(0.1 * rtt_stats_.smoothed_rtt());
  }
  // Expect the timer to not be set.
  EXPECT_EQ(QuicTime::Zero(), loss_algorithm_.GetLossTimeout());
  // The packet should not be lost without a nack.
  unacked_packets_.RemoveFromInFlight(1);
  VerifyLosses(1, nullptr, 0);
  // The timer should still not be set.
  EXPECT_EQ(QuicTime::Zero(), loss_algorithm_.GetLossTimeout());
  clock_.AdvanceTime(0.25 * rtt_stats_.smoothed_rtt());
  VerifyLosses(1, nullptr, 0);
  clock_.AdvanceTime(rtt_stats_.smoothed_rtt());
  VerifyLosses(1, nullptr, 0);

  EXPECT_EQ(QuicTime::Zero(), loss_algorithm_.GetLossTimeout());
}

TEST_F(GeneralLossAlgorithmTest, MultipleLossesAtOnce) {
  loss_algorithm_.SetLossDetectionType(kTime);
  const size_t kNumSentPackets = 10;
  // Transmit 10 packets at once and then go forward an RTT.
  for (size_t i = 1; i <= kNumSentPackets; ++i) {
    SendDataPacket(i);
  }
  clock_.AdvanceTime(rtt_stats_.smoothed_rtt());
  // Expect the timer to not be set.
  EXPECT_EQ(QuicTime::Zero(), loss_algorithm_.GetLossTimeout());
  // The packet should not be lost until 1.25 RTTs pass.
  unacked_packets_.RemoveFromInFlight(10);
  VerifyLosses(10, nullptr, 0);
  // Expect the timer to be set to 0.25 RTT's in the future.
  EXPECT_EQ(0.25 * rtt_stats_.smoothed_rtt(),
            loss_algorithm_.GetLossTimeout() - clock_.Now());
  clock_.AdvanceTime(0.25 * rtt_stats_.smoothed_rtt());
  QuicPacketNumber lost[] = {1, 2, 3, 4, 5, 6, 7, 8, 9};
  VerifyLosses(10, lost, arraysize(lost));
  EXPECT_EQ(QuicTime::Zero(), loss_algorithm_.GetLossTimeout());
}

TEST_F(GeneralLossAlgorithmTest, NoSpuriousLossesFromLargeReordering) {
  loss_algorithm_.SetLossDetectionType(kTime);
  const size_t kNumSentPackets = 10;
  // Transmit 10 packets at once and then go forward an RTT.
  for (size_t i = 1; i <= kNumSentPackets; ++i) {
    SendDataPacket(i);
  }
  clock_.AdvanceTime(rtt_stats_.smoothed_rtt());
  // Expect the timer to not be set.
  EXPECT_EQ(QuicTime::Zero(), loss_algorithm_.GetLossTimeout());
  // The packet should not be lost until 1.25 RTTs pass.

  unacked_packets_.RemoveFromInFlight(10);
  VerifyLosses(10, nullptr, 0);
  // Expect the timer to be set to 0.25 RTT's in the future.
  EXPECT_EQ(0.25 * rtt_stats_.smoothed_rtt(),
            loss_algorithm_.GetLossTimeout() - clock_.Now());
  clock_.AdvanceTime(0.25 * rtt_stats_.smoothed_rtt());
  // Now ack packets 1 to 9 and ensure the timer is no longer set and no packets
  // are lost.
  for (QuicPacketNumber i = 1; i <= 9; ++i) {
    unacked_packets_.RemoveFromInFlight(i);
    VerifyLosses(i, nullptr, 0);
    EXPECT_EQ(QuicTime::Zero(), loss_algorithm_.GetLossTimeout());
  }
}

TEST_F(GeneralLossAlgorithmTest, IncreaseThresholdUponSpuriousLoss) {
  loss_algorithm_.SetLossDetectionType(kAdaptiveTime);
  EXPECT_EQ(4, loss_algorithm_.reordering_shift());
  const size_t kNumSentPackets = 10;
  // Transmit 2 packets at 1/10th an RTT interval.
  for (size_t i = 1; i <= kNumSentPackets; ++i) {
    SendDataPacket(i);
    clock_.AdvanceTime(0.1 * rtt_stats_.smoothed_rtt());
  }
  EXPECT_EQ(QuicTime::Zero() + rtt_stats_.smoothed_rtt(), clock_.Now());

  // Expect the timer to not be set.
  EXPECT_EQ(QuicTime::Zero(), loss_algorithm_.GetLossTimeout());
  // Packet 1 should not be lost until 1/16 RTTs pass.
  unacked_packets_.RemoveFromInFlight(2);
  VerifyLosses(2, nullptr, 0);
  // Expect the timer to be set to 1/16 RTT's in the future.
  EXPECT_EQ(rtt_stats_.smoothed_rtt() * (1.0f / 16),
            loss_algorithm_.GetLossTimeout() - clock_.Now());
  VerifyLosses(2, nullptr, 0);
  clock_.AdvanceTime(rtt_stats_.smoothed_rtt() * (1.0f / 16));
  QuicPacketNumber lost[] = {1};
  VerifyLosses(2, lost, arraysize(lost));
  EXPECT_EQ(QuicTime::Zero(), loss_algorithm_.GetLossTimeout());
  // Retransmit packet 1 as 11 and 2 as 12.
  SendDataPacket(11);
  SendDataPacket(12);

  // Advance the time 1/4 RTT and indicate the loss was spurious.
  // The new threshold should be 1/2 RTT.
  clock_.AdvanceTime(rtt_stats_.smoothed_rtt() * (1.0f / 4));
  loss_algorithm_.SpuriousRetransmitDetected(unacked_packets_, clock_.Now(),
                                             rtt_stats_, 11);
  EXPECT_EQ(1, loss_algorithm_.reordering_shift());

  // Detect another spurious retransmit and ensure the threshold doesn't
  // increase again.
  loss_algorithm_.SpuriousRetransmitDetected(unacked_packets_, clock_.Now(),
                                             rtt_stats_, 12);
  EXPECT_EQ(1, loss_algorithm_.reordering_shift());
}

}  // namespace
}  // namespace test
}  // namespace net
