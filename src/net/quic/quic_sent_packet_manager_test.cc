// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_sent_packet_manager.h"

#include <memory>

#include "base/stl_util.h"
#include "net/quic/quic_flags.h"
#include "net/quic/test_tools/quic_config_peer.h"
#include "net/quic/test_tools/quic_sent_packet_manager_peer.h"
#include "net/quic/test_tools/quic_test_utils.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using std::vector;
using testing::AnyNumber;
using testing::ElementsAre;
using testing::IsEmpty;
using testing::Not;
using testing::Pair;
using testing::Pointwise;
using testing::Return;
using testing::StrictMock;
using testing::_;

namespace net {
namespace test {
namespace {

// Default packet length.
const uint32_t kDefaultLength = 1000;

// Stream ID for data sent in CreatePacket().
const QuicStreamId kStreamId = 7;

// Minimum number of consecutive RTOs before path is considered to be degrading.
const size_t kMinTimeoutsBeforePathDegrading = 2;

// Matcher to check the key of the key-value pair it receives as first argument
// equals its second argument.
MATCHER(KeyEq, "") {
  return std::tr1::get<0>(arg).first == std::tr1::get<1>(arg);
}

class MockDebugDelegate : public QuicSentPacketManager::DebugDelegate {
 public:
  MOCK_METHOD2(OnSpuriousPacketRetransmission,
               void(TransmissionType transmission_type,
                    QuicByteCount byte_size));
  MOCK_METHOD3(OnPacketLoss,
               void(QuicPacketNumber lost_packet_number,
                    TransmissionType transmission_type,
                    QuicTime detection_time));
};

class QuicSentPacketManagerTest : public ::testing::TestWithParam<bool> {
 protected:
  QuicSentPacketManagerTest()
      : manager_(Perspective::IS_SERVER,
                 kDefaultPathId,
                 &clock_,
                 &stats_,
                 kCubic,
                 kNack,
                 /*delegate=*/nullptr),
        send_algorithm_(new StrictMock<MockSendAlgorithm>),
        network_change_visitor_(new StrictMock<MockNetworkChangeVisitor>) {
    // These tests only work with pacing enabled.
    saved_FLAGS_quic_disable_pacing_ = FLAGS_quic_disable_pacing;
    FLAGS_quic_disable_pacing = false;

    QuicSentPacketManagerPeer::SetSendAlgorithm(&manager_, send_algorithm_);
    // Disable tail loss probes for most tests.
    QuicSentPacketManagerPeer::SetMaxTailLossProbes(&manager_, 0);
    // Advance the time 1s so the send times are never QuicTime::Zero.
    clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(1000));
    manager_.set_network_change_visitor(network_change_visitor_.get());

    EXPECT_CALL(*send_algorithm_, HasReliableBandwidthEstimate())
        .Times(AnyNumber());
    EXPECT_CALL(*send_algorithm_, BandwidthEstimate())
        .Times(AnyNumber())
        .WillRepeatedly(Return(QuicBandwidth::Zero()));
    EXPECT_CALL(*send_algorithm_, InSlowStart()).Times(AnyNumber());
    EXPECT_CALL(*send_algorithm_, InRecovery()).Times(AnyNumber());
  }

  ~QuicSentPacketManagerTest() override {
    STLDeleteElements(&packets_);
    FLAGS_quic_disable_pacing = saved_FLAGS_quic_disable_pacing_;
  }

  QuicByteCount BytesInFlight() {
    return QuicSentPacketManagerPeer::GetBytesInFlight(&manager_);
  }
  void VerifyUnackedPackets(QuicPacketNumber* packets, size_t num_packets) {
    if (num_packets == 0) {
      EXPECT_FALSE(manager_.HasUnackedPackets());
      EXPECT_EQ(0u, QuicSentPacketManagerPeer::GetNumRetransmittablePackets(
                        &manager_));
      return;
    }

    EXPECT_TRUE(manager_.HasUnackedPackets());
    EXPECT_EQ(packets[0], manager_.GetLeastUnacked());
    for (size_t i = 0; i < num_packets; ++i) {
      EXPECT_TRUE(manager_.IsUnacked(packets[i])) << packets[i];
    }
  }

  void VerifyRetransmittablePackets(QuicPacketNumber* packets,
                                    size_t num_packets) {
    EXPECT_EQ(
        num_packets,
        QuicSentPacketManagerPeer::GetNumRetransmittablePackets(&manager_));
    for (size_t i = 0; i < num_packets; ++i) {
      EXPECT_TRUE(manager_.HasRetransmittableFrames(packets[i]))
          << " packets[" << i << "]:" << packets[i];
    }
  }

  void ExpectAck(QuicPacketNumber largest_observed) {
    EXPECT_CALL(
        *send_algorithm_,
        OnCongestionEvent(true, _, ElementsAre(Pair(largest_observed, _)),
                          IsEmpty()));
    EXPECT_CALL(*network_change_visitor_, OnCongestionWindowChange());
    EXPECT_CALL(*network_change_visitor_, OnRttChange());
  }

  void ExpectUpdatedRtt(QuicPacketNumber largest_observed) {
    EXPECT_CALL(*send_algorithm_,
                OnCongestionEvent(true, _, IsEmpty(), IsEmpty()));
    EXPECT_CALL(*network_change_visitor_, OnCongestionWindowChange());
    EXPECT_CALL(*network_change_visitor_, OnRttChange());
  }

  void ExpectAckAndLoss(bool rtt_updated,
                        QuicPacketNumber largest_observed,
                        QuicPacketNumber lost_packet) {
    EXPECT_CALL(*send_algorithm_,
                OnCongestionEvent(rtt_updated, _,
                                  ElementsAre(Pair(largest_observed, _)),
                                  ElementsAre(Pair(lost_packet, _))));
    EXPECT_CALL(*network_change_visitor_, OnCongestionWindowChange());
    EXPECT_CALL(*network_change_visitor_, OnRttChange());
  }

  // |packets_acked| and |packets_lost| should be in packet number order.
  void ExpectAcksAndLosses(bool rtt_updated,
                           QuicPacketNumber* packets_acked,
                           size_t num_packets_acked,
                           QuicPacketNumber* packets_lost,
                           size_t num_packets_lost) {
    vector<QuicPacketNumber> ack_vector;
    for (size_t i = 0; i < num_packets_acked; ++i) {
      ack_vector.push_back(packets_acked[i]);
    }
    vector<QuicPacketNumber> lost_vector;
    for (size_t i = 0; i < num_packets_lost; ++i) {
      lost_vector.push_back(packets_lost[i]);
    }
    EXPECT_CALL(
        *send_algorithm_,
        OnCongestionEvent(rtt_updated, _, Pointwise(KeyEq(), ack_vector),
                          Pointwise(KeyEq(), lost_vector)));
    EXPECT_CALL(*network_change_visitor_, OnCongestionWindowChange())
        .Times(AnyNumber());
    EXPECT_CALL(*network_change_visitor_, OnRttChange()).Times(AnyNumber());
  }

  void RetransmitAndSendPacket(QuicPacketNumber old_packet_number,
                               QuicPacketNumber new_packet_number) {
    QuicSentPacketManagerPeer::MarkForRetransmission(
        &manager_, old_packet_number, TLP_RETRANSMISSION);
    EXPECT_TRUE(manager_.HasPendingRetransmissions());
    PendingRetransmission next_retransmission =
        manager_.NextPendingRetransmission();
    EXPECT_EQ(old_packet_number, next_retransmission.packet_number);
    EXPECT_EQ(TLP_RETRANSMISSION, next_retransmission.transmission_type);

    EXPECT_CALL(*send_algorithm_,
                OnPacketSent(_, BytesInFlight(), new_packet_number,
                             kDefaultLength, HAS_RETRANSMITTABLE_DATA))
        .WillOnce(Return(true));
    SerializedPacket packet(CreatePacket(new_packet_number, false));
    manager_.OnPacketSent(&packet, old_packet_number, clock_.Now(),
                          TLP_RETRANSMISSION, HAS_RETRANSMITTABLE_DATA);
    EXPECT_TRUE(QuicSentPacketManagerPeer::IsRetransmission(&manager_,
                                                            new_packet_number));
  }

  SerializedPacket CreateDataPacket(QuicPacketNumber packet_number) {
    return CreatePacket(packet_number, true);
  }

  SerializedPacket CreatePacket(QuicPacketNumber packet_number,
                                bool retransmittable) {
    SerializedPacket packet(kDefaultPathId, packet_number,
                            PACKET_6BYTE_PACKET_NUMBER, nullptr, kDefaultLength,
                            0u, false, false);
    if (retransmittable) {
      packet.retransmittable_frames.push_back(
          QuicFrame(new QuicStreamFrame(kStreamId, false, 0, StringPiece())));
    }
    return packet;
  }

  void SendDataPacket(QuicPacketNumber packet_number) {
    EXPECT_CALL(*send_algorithm_,
                OnPacketSent(_, BytesInFlight(), packet_number, _, _))
        .Times(1)
        .WillOnce(Return(true));
    SerializedPacket packet(CreateDataPacket(packet_number));
    manager_.OnPacketSent(&packet, 0, clock_.Now(), NOT_RETRANSMISSION,
                          HAS_RETRANSMITTABLE_DATA);
  }

  void SendCryptoPacket(QuicPacketNumber packet_number) {
    EXPECT_CALL(*send_algorithm_,
                OnPacketSent(_, BytesInFlight(), packet_number, kDefaultLength,
                             HAS_RETRANSMITTABLE_DATA))
        .Times(1)
        .WillOnce(Return(true));
    SerializedPacket packet(CreateDataPacket(packet_number));
    packet.retransmittable_frames.push_back(
        QuicFrame(new QuicStreamFrame(1, false, 0, StringPiece())));
    packet.has_crypto_handshake = IS_HANDSHAKE;
    manager_.OnPacketSent(&packet, 0, clock_.Now(), NOT_RETRANSMISSION,
                          HAS_RETRANSMITTABLE_DATA);
  }

  void SendAckPacket(QuicPacketNumber packet_number) {
    EXPECT_CALL(*send_algorithm_,
                OnPacketSent(_, BytesInFlight(), packet_number, kDefaultLength,
                             NO_RETRANSMITTABLE_DATA))
        .Times(1)
        .WillOnce(Return(false));
    SerializedPacket packet(CreatePacket(packet_number, false));
    manager_.OnPacketSent(&packet, 0, clock_.Now(), NOT_RETRANSMISSION,
                          NO_RETRANSMITTABLE_DATA);
  }

  // Based on QuicConnection's WritePendingRetransmissions.
  void RetransmitNextPacket(QuicPacketNumber retransmission_packet_number) {
    EXPECT_TRUE(manager_.HasPendingRetransmissions());
    EXPECT_CALL(*send_algorithm_,
                OnPacketSent(_, _, retransmission_packet_number, kDefaultLength,
                             HAS_RETRANSMITTABLE_DATA))
        .Times(1)
        .WillOnce(Return(true));
    const PendingRetransmission pending = manager_.NextPendingRetransmission();
    SerializedPacket packet(CreatePacket(retransmission_packet_number, false));
    manager_.OnPacketSent(&packet, pending.packet_number, clock_.Now(),
                          pending.transmission_type, HAS_RETRANSMITTABLE_DATA);
  }

  QuicSentPacketManager manager_;
  vector<QuicEncryptedPacket*> packets_;
  MockClock clock_;
  QuicConnectionStats stats_;
  MockSendAlgorithm* send_algorithm_;
  std::unique_ptr<MockNetworkChangeVisitor> network_change_visitor_;
  bool saved_FLAGS_quic_disable_pacing_;
};

TEST_F(QuicSentPacketManagerTest, IsUnacked) {
  VerifyUnackedPackets(nullptr, 0);
  SendDataPacket(1);

  QuicPacketNumber unacked[] = {1};
  VerifyUnackedPackets(unacked, arraysize(unacked));
  QuicPacketNumber retransmittable[] = {1};
  VerifyRetransmittablePackets(retransmittable, arraysize(retransmittable));
}

TEST_F(QuicSentPacketManagerTest, IsUnAckedRetransmit) {
  SendDataPacket(1);
  RetransmitAndSendPacket(1, 2);

  EXPECT_TRUE(QuicSentPacketManagerPeer::IsRetransmission(&manager_, 2));
  QuicPacketNumber unacked[] = {1, 2};
  VerifyUnackedPackets(unacked, arraysize(unacked));
  QuicPacketNumber retransmittable[] = {2};
  VerifyRetransmittablePackets(retransmittable, arraysize(retransmittable));
}

TEST_F(QuicSentPacketManagerTest, RetransmitThenAck) {
  SendDataPacket(1);
  RetransmitAndSendPacket(1, 2);

  // Ack 2 but not 1.
  QuicAckFrame ack_frame;
  ack_frame.largest_observed = 2;
  ack_frame.missing_packets.Add(1);
  ExpectAck(2);
  manager_.OnIncomingAck(ack_frame, clock_.Now());

  // Packet 1 is unacked, pending, but not retransmittable.
  QuicPacketNumber unacked[] = {1};
  VerifyUnackedPackets(unacked, arraysize(unacked));
  EXPECT_TRUE(QuicSentPacketManagerPeer::HasPendingPackets(&manager_));
  VerifyRetransmittablePackets(nullptr, 0);
}

TEST_F(QuicSentPacketManagerTest, RetransmitThenAckBeforeSend) {
  SendDataPacket(1);
  QuicSentPacketManagerPeer::MarkForRetransmission(&manager_, 1,
                                                   TLP_RETRANSMISSION);
  EXPECT_TRUE(manager_.HasPendingRetransmissions());

  // Ack 1.
  QuicAckFrame ack_frame;
  ack_frame.largest_observed = 1;
  ExpectAck(1);
  manager_.OnIncomingAck(ack_frame, clock_.Now());

  // There should no longer be a pending retransmission.
  EXPECT_FALSE(manager_.HasPendingRetransmissions());

  // No unacked packets remain.
  VerifyUnackedPackets(nullptr, 0);
  VerifyRetransmittablePackets(nullptr, 0);
  EXPECT_EQ(0u, stats_.packets_spuriously_retransmitted);
}

TEST_F(QuicSentPacketManagerTest, RetransmitThenStopRetransmittingBeforeSend) {
  SendDataPacket(1);
  QuicSentPacketManagerPeer::MarkForRetransmission(&manager_, 1,
                                                   TLP_RETRANSMISSION);
  EXPECT_TRUE(manager_.HasPendingRetransmissions());

  manager_.CancelRetransmissionsForStream(kStreamId);

  // There should no longer be a pending retransmission.
  EXPECT_FALSE(manager_.HasPendingRetransmissions());

  QuicPacketNumber unacked[] = {1};
  VerifyUnackedPackets(unacked, arraysize(unacked));
  VerifyRetransmittablePackets(nullptr, 0);
  EXPECT_EQ(0u, stats_.packets_spuriously_retransmitted);
}

TEST_F(QuicSentPacketManagerTest, RetransmitThenAckPrevious) {
  SendDataPacket(1);
  RetransmitAndSendPacket(1, 2);
  QuicTime::Delta rtt = QuicTime::Delta::FromMilliseconds(15);
  clock_.AdvanceTime(rtt);

  // Ack 1 but not 2.
  ExpectAck(1);
  QuicAckFrame ack_frame;
  ack_frame.largest_observed = 1;
  manager_.OnIncomingAck(ack_frame, clock_.ApproximateNow());

  // 2 remains unacked, but no packets have retransmittable data.
  QuicPacketNumber unacked[] = {2};
  VerifyUnackedPackets(unacked, arraysize(unacked));
  EXPECT_TRUE(QuicSentPacketManagerPeer::HasPendingPackets(&manager_));
  VerifyRetransmittablePackets(nullptr, 0);

  EXPECT_EQ(1u, stats_.packets_spuriously_retransmitted);
}

TEST_F(QuicSentPacketManagerTest, RetransmitThenAckPreviousThenNackRetransmit) {
  SendDataPacket(1);
  RetransmitAndSendPacket(1, 2);
  QuicTime::Delta rtt = QuicTime::Delta::FromMilliseconds(15);
  clock_.AdvanceTime(rtt);

  // First, ACK packet 1 which makes packet 2 non-retransmittable.
  ExpectAck(1);
  QuicAckFrame ack_frame;
  ack_frame.largest_observed = 1;
  manager_.OnIncomingAck(ack_frame, clock_.ApproximateNow());

  SendDataPacket(3);
  SendDataPacket(4);
  SendDataPacket(5);
  clock_.AdvanceTime(rtt);

  // Next, NACK packet 2 three times.
  ack_frame.largest_observed = 3;
  ack_frame.missing_packets.Add(2);
  ExpectAck(3);
  manager_.OnIncomingAck(ack_frame, clock_.ApproximateNow());

  ack_frame.largest_observed = 4;
  ExpectAck(4);
  manager_.OnIncomingAck(ack_frame, clock_.ApproximateNow());

  ack_frame.largest_observed = 5;
  ExpectAckAndLoss(true, 5, 2);
  manager_.OnIncomingAck(ack_frame, clock_.ApproximateNow());

  // No packets remain unacked.
  VerifyUnackedPackets(nullptr, 0);
  EXPECT_FALSE(QuicSentPacketManagerPeer::HasPendingPackets(&manager_));
  VerifyRetransmittablePackets(nullptr, 0);

  // Verify that the retransmission alarm would not fire,
  // since there is no retransmittable data outstanding.
  EXPECT_EQ(QuicTime::Zero(), manager_.GetRetransmissionTime());
}

TEST_F(QuicSentPacketManagerTest,
       DISABLED_RetransmitTwiceThenAckPreviousBeforeSend) {
  SendDataPacket(1);
  RetransmitAndSendPacket(1, 2);

  // Fire the RTO, which will mark 2 for retransmission (but will not send it).
  EXPECT_CALL(*send_algorithm_, OnRetransmissionTimeout(true));
  EXPECT_CALL(*network_change_visitor_, OnCongestionWindowChange());
  manager_.OnRetransmissionTimeout();
  EXPECT_TRUE(manager_.HasPendingRetransmissions());

  // Ack 1 but not 2, before 2 is able to be sent.
  // Since 1 has been retransmitted, it has already been lost, and so the
  // send algorithm is not informed that it has been ACK'd.
  QuicAckFrame ack_frame;
  ack_frame.largest_observed = 1;
  ExpectUpdatedRtt(1);
  EXPECT_CALL(*send_algorithm_, RevertRetransmissionTimeout());
  manager_.OnIncomingAck(ack_frame, clock_.ApproximateNow());

  // Since 2 was marked for retransmit, when 1 is acked, 2 is kept for RTT.
  QuicPacketNumber unacked[] = {2};
  VerifyUnackedPackets(unacked, arraysize(unacked));
  EXPECT_FALSE(QuicSentPacketManagerPeer::HasPendingPackets(&manager_));
  VerifyRetransmittablePackets(nullptr, 0);

  // Verify that the retransmission alarm would not fire,
  // since there is no retransmittable data outstanding.
  EXPECT_EQ(QuicTime::Zero(), manager_.GetRetransmissionTime());
}

TEST_F(QuicSentPacketManagerTest, RetransmitTwiceThenAckFirst) {
  StrictMock<MockDebugDelegate> debug_delegate;
  EXPECT_CALL(debug_delegate, OnSpuriousPacketRetransmission(TLP_RETRANSMISSION,
                                                             kDefaultLength))
      .Times(2);
  manager_.set_debug_delegate(&debug_delegate);

  SendDataPacket(1);
  RetransmitAndSendPacket(1, 2);
  RetransmitAndSendPacket(2, 3);
  QuicTime::Delta rtt = QuicTime::Delta::FromMilliseconds(15);
  clock_.AdvanceTime(rtt);

  // Ack 1 but not 2 or 3.
  ExpectAck(1);
  QuicAckFrame ack_frame;
  ack_frame.largest_observed = 1;
  manager_.OnIncomingAck(ack_frame, clock_.ApproximateNow());

  // 2 and 3 remain unacked, but no packets have retransmittable data.
  QuicPacketNumber unacked[] = {2, 3};
  VerifyUnackedPackets(unacked, arraysize(unacked));
  EXPECT_TRUE(QuicSentPacketManagerPeer::HasPendingPackets(&manager_));
  VerifyRetransmittablePackets(nullptr, 0);

  // Ensure packet 2 is lost when 4 is sent and 3 and 4 are acked.
  SendDataPacket(4);
  ack_frame.largest_observed = 4;
  ack_frame.missing_packets.Add(2);
  QuicPacketNumber acked[] = {3, 4};
  ExpectAcksAndLosses(true, acked, arraysize(acked), nullptr, 0);
  manager_.OnIncomingAck(ack_frame, clock_.ApproximateNow());

  QuicPacketNumber unacked2[] = {2};
  VerifyUnackedPackets(unacked2, arraysize(unacked2));
  EXPECT_TRUE(QuicSentPacketManagerPeer::HasPendingPackets(&manager_));

  SendDataPacket(5);
  ack_frame.largest_observed = 5;
  ExpectAckAndLoss(true, 5, 2);
  EXPECT_CALL(debug_delegate, OnPacketLoss(2, LOSS_RETRANSMISSION, _));
  manager_.OnIncomingAck(ack_frame, clock_.ApproximateNow());

  VerifyUnackedPackets(nullptr, 0);
  EXPECT_FALSE(QuicSentPacketManagerPeer::HasPendingPackets(&manager_));
  EXPECT_EQ(2u, stats_.packets_spuriously_retransmitted);
}

TEST_F(QuicSentPacketManagerTest, AckPreviousTransmissionThenTruncatedAck) {
  SendDataPacket(1);
  RetransmitAndSendPacket(1, 2);
  RetransmitAndSendPacket(2, 3);
  RetransmitAndSendPacket(3, 4);
  SendDataPacket(5);
  SendDataPacket(6);
  SendDataPacket(7);
  SendDataPacket(8);
  SendDataPacket(9);

  // Ack previous transmission
  {
    QuicAckFrame ack_frame;
    ack_frame.largest_observed = 2;
    ack_frame.missing_packets.Add(1);
    ExpectAck(2);
    manager_.OnIncomingAck(ack_frame, clock_.Now());
    EXPECT_TRUE(manager_.IsUnacked(4));
  }

  // Truncated ack with 4 NACKs
  {
    QuicAckFrame ack_frame;
    ack_frame.largest_observed = 6;
    ack_frame.missing_packets.Add(3, 7);
    ack_frame.is_truncated = true;
    ExpectAckAndLoss(true, 1, 3);
    manager_.OnIncomingAck(ack_frame, clock_.Now());
  }

  // High water mark will be raised.
  QuicPacketNumber unacked[] = {4, 5, 6, 7, 8, 9};
  VerifyUnackedPackets(unacked, arraysize(unacked));
  QuicPacketNumber retransmittable[] = {5, 6, 7, 8, 9};
  VerifyRetransmittablePackets(retransmittable, arraysize(retransmittable));
}

TEST_F(QuicSentPacketManagerTest, GetLeastUnacked) {
  EXPECT_EQ(1u, manager_.GetLeastUnacked());
}

TEST_F(QuicSentPacketManagerTest, GetLeastUnackedUnacked) {
  SendDataPacket(1);
  EXPECT_EQ(1u, manager_.GetLeastUnacked());
}

TEST_F(QuicSentPacketManagerTest, AckAckAndUpdateRtt) {
  SendDataPacket(1);
  SendAckPacket(2);

  // Now ack the ack and expect an RTT update.
  QuicAckFrame ack_frame;
  ack_frame.largest_observed = 2;
  ack_frame.ack_delay_time = QuicTime::Delta::FromMilliseconds(5);

  ExpectAck(1);
  manager_.OnIncomingAck(ack_frame, clock_.Now());

  SendAckPacket(3);

  // Now ack the ack and expect only an RTT update.
  ack_frame.largest_observed = 3;
  ExpectUpdatedRtt(3);
  manager_.OnIncomingAck(ack_frame, clock_.Now());
}

TEST_F(QuicSentPacketManagerTest, Rtt) {
  QuicPacketNumber packet_number = 1;
  QuicTime::Delta expected_rtt = QuicTime::Delta::FromMilliseconds(15);
  SendDataPacket(packet_number);
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(20));

  ExpectAck(packet_number);
  QuicAckFrame ack_frame;
  ack_frame.largest_observed = packet_number;
  ack_frame.ack_delay_time = QuicTime::Delta::FromMilliseconds(5);
  manager_.OnIncomingAck(ack_frame, clock_.Now());
  EXPECT_EQ(expected_rtt,
            QuicSentPacketManagerPeer::GetRttStats(&manager_)->latest_rtt());
}

TEST_F(QuicSentPacketManagerTest, RttWithInvalidDelta) {
  // Expect that the RTT is equal to the local time elapsed, since the
  // ack_delay_time is larger than the local time elapsed
  // and is hence invalid.
  QuicPacketNumber packet_number = 1;
  QuicTime::Delta expected_rtt = QuicTime::Delta::FromMilliseconds(10);
  SendDataPacket(packet_number);
  clock_.AdvanceTime(expected_rtt);

  ExpectAck(packet_number);
  QuicAckFrame ack_frame;
  ack_frame.largest_observed = packet_number;
  ack_frame.ack_delay_time = QuicTime::Delta::FromMilliseconds(11);
  manager_.OnIncomingAck(ack_frame, clock_.Now());
  EXPECT_EQ(expected_rtt,
            QuicSentPacketManagerPeer::GetRttStats(&manager_)->latest_rtt());
}

TEST_F(QuicSentPacketManagerTest, RttWithInfiniteDelta) {
  // Expect that the RTT is equal to the local time elapsed, since the
  // ack_delay_time is infinite, and is hence invalid.
  QuicPacketNumber packet_number = 1;
  QuicTime::Delta expected_rtt = QuicTime::Delta::FromMilliseconds(10);
  SendDataPacket(packet_number);
  clock_.AdvanceTime(expected_rtt);

  ExpectAck(packet_number);
  QuicAckFrame ack_frame;
  ack_frame.largest_observed = packet_number;
  ack_frame.ack_delay_time = QuicTime::Delta::Infinite();
  manager_.OnIncomingAck(ack_frame, clock_.Now());
  EXPECT_EQ(expected_rtt,
            QuicSentPacketManagerPeer::GetRttStats(&manager_)->latest_rtt());
}

TEST_F(QuicSentPacketManagerTest, RttZeroDelta) {
  // Expect that the RTT is the time between send and receive since the
  // ack_delay_time is zero.
  QuicPacketNumber packet_number = 1;
  QuicTime::Delta expected_rtt = QuicTime::Delta::FromMilliseconds(10);
  SendDataPacket(packet_number);
  clock_.AdvanceTime(expected_rtt);

  ExpectAck(packet_number);
  QuicAckFrame ack_frame;
  ack_frame.largest_observed = packet_number;
  ack_frame.ack_delay_time = QuicTime::Delta::Zero();
  manager_.OnIncomingAck(ack_frame, clock_.Now());
  EXPECT_EQ(expected_rtt,
            QuicSentPacketManagerPeer::GetRttStats(&manager_)->latest_rtt());
}

TEST_F(QuicSentPacketManagerTest, TailLossProbeTimeout) {
  QuicSentPacketManagerPeer::SetMaxTailLossProbes(&manager_, 2);

  // Send 1 packet.
  QuicPacketNumber packet_number = 1;
  SendDataPacket(packet_number);

  // The first tail loss probe retransmits 1 packet.
  manager_.OnRetransmissionTimeout();
  EXPECT_EQ(QuicTime::Delta::Zero(),
            manager_.TimeUntilSend(clock_.Now(), HAS_RETRANSMITTABLE_DATA));
  EXPECT_FALSE(manager_.HasPendingRetransmissions());
  manager_.MaybeRetransmitTailLossProbe();
  EXPECT_TRUE(manager_.HasPendingRetransmissions());
  RetransmitNextPacket(2);
  EXPECT_FALSE(manager_.HasPendingRetransmissions());

  // The second tail loss probe retransmits 1 packet.
  manager_.OnRetransmissionTimeout();
  EXPECT_EQ(QuicTime::Delta::Zero(),
            manager_.TimeUntilSend(clock_.Now(), HAS_RETRANSMITTABLE_DATA));
  EXPECT_FALSE(manager_.HasPendingRetransmissions());
  manager_.MaybeRetransmitTailLossProbe();
  EXPECT_TRUE(manager_.HasPendingRetransmissions());
  RetransmitNextPacket(3);
  EXPECT_CALL(*send_algorithm_, TimeUntilSend(_, _))
      .WillOnce(Return(QuicTime::Delta::Infinite()));
  EXPECT_EQ(QuicTime::Delta::Infinite(),
            manager_.TimeUntilSend(clock_.Now(), HAS_RETRANSMITTABLE_DATA));
  EXPECT_FALSE(manager_.HasPendingRetransmissions());

  // Ack the third and ensure the first two are still pending.
  ExpectAck(3);
  QuicAckFrame ack_frame;
  ack_frame.largest_observed = 3;
  ack_frame.missing_packets.Add(1, 3);
  manager_.OnIncomingAck(ack_frame, clock_.ApproximateNow());

  EXPECT_TRUE(QuicSentPacketManagerPeer::HasPendingPackets(&manager_));

  // Acking two more packets will lose both of them due to nacks.
  ack_frame.largest_observed = 5;
  QuicPacketNumber lost[] = {1, 2};
  ExpectAcksAndLosses(false, nullptr, 0, lost, arraysize(lost));
  manager_.OnIncomingAck(ack_frame, clock_.ApproximateNow());

  EXPECT_FALSE(manager_.HasPendingRetransmissions());
  EXPECT_FALSE(QuicSentPacketManagerPeer::HasPendingPackets(&manager_));
  EXPECT_EQ(2u, stats_.tlp_count);
  EXPECT_EQ(0u, stats_.rto_count);
}

TEST_F(QuicSentPacketManagerTest, TailLossProbeThenRTO) {
  QuicSentPacketManagerPeer::SetMaxTailLossProbes(&manager_, 2);

  // Send 100 packets.
  const size_t kNumSentPackets = 100;
  for (size_t i = 1; i <= kNumSentPackets; ++i) {
    SendDataPacket(i);
  }
  QuicTime rto_packet_time = clock_.Now();
  // Advance the time.
  clock_.AdvanceTime(manager_.GetRetransmissionTime().Subtract(clock_.Now()));

  // The first tail loss probe retransmits 1 packet.
  manager_.OnRetransmissionTimeout();
  EXPECT_EQ(QuicTime::Delta::Zero(),
            manager_.TimeUntilSend(clock_.Now(), HAS_RETRANSMITTABLE_DATA));
  EXPECT_FALSE(manager_.HasPendingRetransmissions());
  manager_.MaybeRetransmitTailLossProbe();
  EXPECT_TRUE(manager_.HasPendingRetransmissions());
  RetransmitNextPacket(101);
  EXPECT_CALL(*send_algorithm_, TimeUntilSend(_, _))
      .WillOnce(Return(QuicTime::Delta::Infinite()));
  EXPECT_EQ(QuicTime::Delta::Infinite(),
            manager_.TimeUntilSend(clock_.Now(), HAS_RETRANSMITTABLE_DATA));
  EXPECT_FALSE(manager_.HasPendingRetransmissions());
  clock_.AdvanceTime(manager_.GetRetransmissionTime().Subtract(clock_.Now()));

  // The second tail loss probe retransmits 1 packet.
  manager_.OnRetransmissionTimeout();
  EXPECT_EQ(QuicTime::Delta::Zero(),
            manager_.TimeUntilSend(clock_.Now(), HAS_RETRANSMITTABLE_DATA));
  EXPECT_FALSE(manager_.HasPendingRetransmissions());
  EXPECT_TRUE(manager_.MaybeRetransmitTailLossProbe());
  EXPECT_TRUE(manager_.HasPendingRetransmissions());
  RetransmitNextPacket(102);
  EXPECT_CALL(*send_algorithm_, TimeUntilSend(_, _))
      .WillOnce(Return(QuicTime::Delta::Infinite()));
  EXPECT_EQ(QuicTime::Delta::Infinite(),
            manager_.TimeUntilSend(clock_.Now(), HAS_RETRANSMITTABLE_DATA));

  // Ensure the RTO is set based on the correct packet.
  rto_packet_time = clock_.Now();
  EXPECT_CALL(*send_algorithm_, RetransmissionDelay())
      .WillOnce(Return(QuicTime::Delta::FromSeconds(1)));
  EXPECT_EQ(rto_packet_time.Add(QuicTime::Delta::FromSeconds(1)),
            manager_.GetRetransmissionTime());

  // Advance the time enough to ensure all packets are RTO'd.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(1000));

  manager_.OnRetransmissionTimeout();
  EXPECT_TRUE(manager_.HasPendingRetransmissions());
  EXPECT_EQ(2u, stats_.tlp_count);
  EXPECT_EQ(1u, stats_.rto_count);

  // Send and Ack the RTO and ensure OnRetransmissionTimeout is called.
  EXPECT_EQ(102 * kDefaultLength,
            QuicSentPacketManagerPeer::GetBytesInFlight(&manager_));

  RetransmitNextPacket(103);
  QuicAckFrame ack_frame;
  ack_frame.largest_observed = 103;
  ack_frame.missing_packets.Add(0, 103);
  EXPECT_CALL(*send_algorithm_, OnRetransmissionTimeout(true));
  EXPECT_CALL(*send_algorithm_,
              OnCongestionEvent(true, _, ElementsAre(Pair(103, _)), _));
  EXPECT_CALL(*network_change_visitor_, OnCongestionWindowChange());
  EXPECT_CALL(*network_change_visitor_, OnRttChange());
  manager_.OnIncomingAck(ack_frame, clock_.ApproximateNow());
  // All packets before 103 should be lost.
  EXPECT_EQ(0u, QuicSentPacketManagerPeer::GetBytesInFlight(&manager_));
}

TEST_F(QuicSentPacketManagerTest, CryptoHandshakeTimeout) {
  // Send 2 crypto packets and 3 data packets.
  const size_t kNumSentCryptoPackets = 2;
  for (size_t i = 1; i <= kNumSentCryptoPackets; ++i) {
    SendCryptoPacket(i);
  }
  const size_t kNumSentDataPackets = 3;
  for (size_t i = 1; i <= kNumSentDataPackets; ++i) {
    SendDataPacket(kNumSentCryptoPackets + i);
  }
  EXPECT_TRUE(QuicSentPacketManagerPeer::HasUnackedCryptoPackets(&manager_));

  // The first retransmits 2 packets.
  manager_.OnRetransmissionTimeout();
  EXPECT_EQ(QuicTime::Delta::Zero(),
            manager_.TimeUntilSend(clock_.Now(), HAS_RETRANSMITTABLE_DATA));
  RetransmitNextPacket(6);
  RetransmitNextPacket(7);
  EXPECT_FALSE(manager_.HasPendingRetransmissions());
  EXPECT_TRUE(QuicSentPacketManagerPeer::HasUnackedCryptoPackets(&manager_));

  // The second retransmits 2 packets.
  manager_.OnRetransmissionTimeout();
  EXPECT_EQ(QuicTime::Delta::Zero(),
            manager_.TimeUntilSend(clock_.Now(), HAS_RETRANSMITTABLE_DATA));
  RetransmitNextPacket(8);
  RetransmitNextPacket(9);
  EXPECT_FALSE(manager_.HasPendingRetransmissions());
  EXPECT_TRUE(QuicSentPacketManagerPeer::HasUnackedCryptoPackets(&manager_));

  // Now ack the two crypto packets and the speculatively encrypted request,
  // and ensure the first four crypto packets get abandoned, but not lost.
  QuicPacketNumber acked[] = {3, 4, 5, 8, 9};
  ExpectAcksAndLosses(true, acked, arraysize(acked), nullptr, 0);
  QuicAckFrame ack_frame;
  ack_frame.largest_observed = 9;
  ack_frame.missing_packets.Add(1, 3);
  ack_frame.missing_packets.Add(6, 8);
  manager_.OnIncomingAck(ack_frame, clock_.ApproximateNow());

  EXPECT_FALSE(QuicSentPacketManagerPeer::HasUnackedCryptoPackets(&manager_));
}

TEST_F(QuicSentPacketManagerTest, CryptoHandshakeTimeoutVersionNegotiation) {
  // Send 2 crypto packets and 3 data packets.
  const size_t kNumSentCryptoPackets = 2;
  for (size_t i = 1; i <= kNumSentCryptoPackets; ++i) {
    SendCryptoPacket(i);
  }
  const size_t kNumSentDataPackets = 3;
  for (size_t i = 1; i <= kNumSentDataPackets; ++i) {
    SendDataPacket(kNumSentCryptoPackets + i);
  }
  EXPECT_TRUE(QuicSentPacketManagerPeer::HasUnackedCryptoPackets(&manager_));

  // The first retransmission timeout retransmits 2 crypto packets.
  manager_.OnRetransmissionTimeout();
  RetransmitNextPacket(6);
  RetransmitNextPacket(7);
  EXPECT_FALSE(manager_.HasPendingRetransmissions());
  EXPECT_TRUE(QuicSentPacketManagerPeer::HasUnackedCryptoPackets(&manager_));

  // Now act like a version negotiation packet arrived, which would cause all
  // unacked packets to be retransmitted.
  manager_.RetransmitUnackedPackets(ALL_UNACKED_RETRANSMISSION);

  // Ensure the first two pending packets are the crypto retransmits.
  ASSERT_TRUE(manager_.HasPendingRetransmissions());
  EXPECT_EQ(6u, manager_.NextPendingRetransmission().packet_number);
  RetransmitNextPacket(8);
  EXPECT_EQ(7u, manager_.NextPendingRetransmission().packet_number);
  RetransmitNextPacket(9);

  EXPECT_TRUE(manager_.HasPendingRetransmissions());
  // Send 3 more data packets and ensure the least unacked is raised.
  RetransmitNextPacket(10);
  RetransmitNextPacket(11);
  RetransmitNextPacket(12);
  EXPECT_FALSE(manager_.HasPendingRetransmissions());

  EXPECT_EQ(1u, manager_.GetLeastUnacked());
  // Least unacked isn't raised until an ack is received, so ack the
  // crypto packets.
  QuicPacketNumber acked[] = {8, 9};
  ExpectAcksAndLosses(true, acked, arraysize(acked), nullptr, 0);
  QuicAckFrame ack_frame;
  ack_frame.largest_observed = 9;
  for (QuicPacketNumber i = 1; i < 8; ++i) {
    ack_frame.missing_packets.Add(i);
  }
  manager_.OnIncomingAck(ack_frame, clock_.ApproximateNow());
  EXPECT_EQ(10u, manager_.GetLeastUnacked());
}

TEST_F(QuicSentPacketManagerTest, CryptoHandshakeSpuriousRetransmission) {
  // Send 1 crypto packet.
  SendCryptoPacket(1);
  EXPECT_TRUE(QuicSentPacketManagerPeer::HasUnackedCryptoPackets(&manager_));

  // Retransmit the crypto packet as 2.
  manager_.OnRetransmissionTimeout();
  RetransmitNextPacket(2);

  // Retransmit the crypto packet as 3.
  manager_.OnRetransmissionTimeout();
  RetransmitNextPacket(3);

  // Now ack the second crypto packet, and ensure the first gets removed, but
  // the third does not.
  ExpectUpdatedRtt(2);
  QuicAckFrame ack_frame;
  ack_frame.largest_observed = 2;
  ack_frame.missing_packets.Add(1);
  manager_.OnIncomingAck(ack_frame, clock_.ApproximateNow());

  EXPECT_FALSE(QuicSentPacketManagerPeer::HasUnackedCryptoPackets(&manager_));
  QuicPacketNumber unacked[] = {3};
  VerifyUnackedPackets(unacked, arraysize(unacked));
}

TEST_F(QuicSentPacketManagerTest, CryptoHandshakeTimeoutUnsentDataPacket) {
  // Send 2 crypto packets and 1 data packet.
  const size_t kNumSentCryptoPackets = 2;
  for (size_t i = 1; i <= kNumSentCryptoPackets; ++i) {
    SendCryptoPacket(i);
  }
  SendDataPacket(3);
  EXPECT_TRUE(QuicSentPacketManagerPeer::HasUnackedCryptoPackets(&manager_));

  // Retransmit 2 crypto packets, but not the serialized packet.
  manager_.OnRetransmissionTimeout();
  RetransmitNextPacket(4);
  RetransmitNextPacket(5);
  EXPECT_FALSE(manager_.HasPendingRetransmissions());
  EXPECT_TRUE(QuicSentPacketManagerPeer::HasUnackedCryptoPackets(&manager_));
}

TEST_F(QuicSentPacketManagerTest,
       CryptoHandshakeRetransmissionThenRetransmitAll) {
  // Send 1 crypto packet.
  SendCryptoPacket(1);
  EXPECT_TRUE(QuicSentPacketManagerPeer::HasUnackedCryptoPackets(&manager_));

  // Retransmit the crypto packet as 2.
  manager_.OnRetransmissionTimeout();
  RetransmitNextPacket(2);

  // Now retransmit all the unacked packets, which occurs when there is a
  // version negotiation.
  manager_.RetransmitUnackedPackets(ALL_UNACKED_RETRANSMISSION);
  QuicPacketNumber unacked[] = {1, 2};
  VerifyUnackedPackets(unacked, arraysize(unacked));
  EXPECT_TRUE(manager_.HasPendingRetransmissions());
  EXPECT_TRUE(QuicSentPacketManagerPeer::HasUnackedCryptoPackets(&manager_));
  EXPECT_FALSE(QuicSentPacketManagerPeer::HasPendingPackets(&manager_));
}

TEST_F(QuicSentPacketManagerTest,
       CryptoHandshakeRetransmissionThenNeuterAndAck) {
  // Send 1 crypto packet.
  SendCryptoPacket(1);
  EXPECT_TRUE(QuicSentPacketManagerPeer::HasUnackedCryptoPackets(&manager_));

  // Retransmit the crypto packet as 2.
  manager_.OnRetransmissionTimeout();
  RetransmitNextPacket(2);
  EXPECT_TRUE(QuicSentPacketManagerPeer::HasUnackedCryptoPackets(&manager_));

  // Retransmit the crypto packet as 3.
  manager_.OnRetransmissionTimeout();
  RetransmitNextPacket(3);
  EXPECT_TRUE(QuicSentPacketManagerPeer::HasUnackedCryptoPackets(&manager_));

  // Now neuter all unacked unencrypted packets, which occurs when the
  // connection goes forward secure.
  manager_.NeuterUnencryptedPackets();
  EXPECT_FALSE(QuicSentPacketManagerPeer::HasUnackedCryptoPackets(&manager_));
  QuicPacketNumber unacked[] = {1, 2, 3};
  VerifyUnackedPackets(unacked, arraysize(unacked));
  VerifyRetransmittablePackets(nullptr, 0);
  EXPECT_FALSE(manager_.HasPendingRetransmissions());
  EXPECT_FALSE(QuicSentPacketManagerPeer::HasUnackedCryptoPackets(&manager_));
  EXPECT_FALSE(QuicSentPacketManagerPeer::HasPendingPackets(&manager_));

  // Ensure both packets get discarded when packet 2 is acked.
  QuicAckFrame ack_frame;
  ack_frame.largest_observed = 3;
  ack_frame.missing_packets.Add(1, 3);
  ExpectUpdatedRtt(3);
  manager_.OnIncomingAck(ack_frame, clock_.ApproximateNow());
  VerifyUnackedPackets(nullptr, 0);
  VerifyRetransmittablePackets(nullptr, 0);
}

TEST_F(QuicSentPacketManagerTest, RetransmissionTimeout) {
  StrictMock<MockDebugDelegate> debug_delegate;
  manager_.set_debug_delegate(&debug_delegate);

  // Send 100 packets.
  const size_t kNumSentPackets = 100;
  for (size_t i = 1; i <= kNumSentPackets; ++i) {
    SendDataPacket(i);
  }

  EXPECT_FALSE(manager_.MaybeRetransmitTailLossProbe());
  manager_.OnRetransmissionTimeout();
  EXPECT_TRUE(manager_.HasPendingRetransmissions());
  EXPECT_EQ(100 * kDefaultLength,
            QuicSentPacketManagerPeer::GetBytesInFlight(&manager_));
  RetransmitNextPacket(101);
  RetransmitNextPacket(102);
  EXPECT_FALSE(manager_.HasPendingRetransmissions());

  // Ack a retransmission.
  QuicAckFrame ack_frame;
  ack_frame.ack_delay_time = QuicTime::Delta::Zero();
  ack_frame.largest_observed = 102;
  ack_frame.missing_packets.Add(0, 102);
  // Ensure no packets are lost.
  EXPECT_CALL(*send_algorithm_,
              OnCongestionEvent(true, _, ElementsAre(Pair(102, _)),
                                /*lost_packets=*/IsEmpty()));
  EXPECT_CALL(*network_change_visitor_, OnCongestionWindowChange());
  EXPECT_CALL(*network_change_visitor_, OnRttChange());
  EXPECT_CALL(*send_algorithm_, OnRetransmissionTimeout(true));
  // RTO's use loss detection instead of immediately declaring retransmitted
  // packets lost.
  for (int i = 1; i <= 99; ++i) {
    EXPECT_CALL(debug_delegate, OnPacketLoss(i, LOSS_RETRANSMISSION, _));
  }
  manager_.OnIncomingAck(ack_frame, clock_.Now());
}

TEST_F(QuicSentPacketManagerTest, NewRetransmissionTimeout) {
  QuicConfig client_config;
  QuicTagVector options;
  options.push_back(kNRTO);
  QuicSentPacketManagerPeer::SetPerspective(&manager_, Perspective::IS_CLIENT);
  client_config.SetConnectionOptionsToSend(options);
  EXPECT_CALL(*network_change_visitor_, OnCongestionWindowChange());
  EXPECT_CALL(*network_change_visitor_, OnRttChange());
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  EXPECT_CALL(*send_algorithm_, PacingRate())
      .WillRepeatedly(Return(QuicBandwidth::Zero()));
  EXPECT_CALL(*send_algorithm_, GetCongestionWindow())
      .WillOnce(Return(10 * kDefaultTCPMSS));
  manager_.SetFromConfig(client_config);
  EXPECT_TRUE(QuicSentPacketManagerPeer::GetUseNewRto(&manager_));

  // Send 100 packets.
  const size_t kNumSentPackets = 100;
  for (size_t i = 1; i <= kNumSentPackets; ++i) {
    SendDataPacket(i);
  }

  EXPECT_FALSE(manager_.MaybeRetransmitTailLossProbe());
  manager_.OnRetransmissionTimeout();
  EXPECT_TRUE(manager_.HasPendingRetransmissions());
  EXPECT_EQ(100 * kDefaultLength,
            QuicSentPacketManagerPeer::GetBytesInFlight(&manager_));
  RetransmitNextPacket(101);
  RetransmitNextPacket(102);
  EXPECT_FALSE(manager_.HasPendingRetransmissions());

  // Ack a retransmission and expect no call to OnRetransmissionTimeout.
  QuicAckFrame ack_frame;
  ack_frame.ack_delay_time = QuicTime::Delta::Zero();
  ack_frame.largest_observed = 102;
  ack_frame.missing_packets.Add(0, 102);
  // This will include packets in the lost packet map.
  EXPECT_CALL(*send_algorithm_,
              OnCongestionEvent(true, _, ElementsAre(Pair(102, _)),
                                /*lost_packets=*/Not(IsEmpty())));
  EXPECT_CALL(*network_change_visitor_, OnCongestionWindowChange());
  EXPECT_CALL(*network_change_visitor_, OnRttChange());
  manager_.OnIncomingAck(ack_frame, clock_.Now());
}

TEST_F(QuicSentPacketManagerTest, TwoRetransmissionTimeoutsAckSecond) {
  // Send 1 packet.
  SendDataPacket(1);

  manager_.OnRetransmissionTimeout();
  EXPECT_TRUE(manager_.HasPendingRetransmissions());
  EXPECT_EQ(kDefaultLength,
            QuicSentPacketManagerPeer::GetBytesInFlight(&manager_));
  RetransmitNextPacket(2);
  EXPECT_FALSE(manager_.HasPendingRetransmissions());

  // Rto a second time.
  EXPECT_CALL(*network_change_visitor_, OnPathDegrading());
  manager_.OnRetransmissionTimeout();
  EXPECT_TRUE(manager_.HasPendingRetransmissions());
  EXPECT_EQ(2 * kDefaultLength,
            QuicSentPacketManagerPeer::GetBytesInFlight(&manager_));
  RetransmitNextPacket(3);
  EXPECT_FALSE(manager_.HasPendingRetransmissions());

  // Ack a retransmission and ensure OnRetransmissionTimeout is called.
  EXPECT_CALL(*send_algorithm_, OnRetransmissionTimeout(true));
  QuicAckFrame ack_frame;
  ack_frame.ack_delay_time = QuicTime::Delta::Zero();
  ack_frame.largest_observed = 2;
  ack_frame.missing_packets.Add(1);
  ExpectAck(2);
  manager_.OnIncomingAck(ack_frame, clock_.Now());

  // The original packet and newest should be outstanding.
  EXPECT_EQ(2 * kDefaultLength,
            QuicSentPacketManagerPeer::GetBytesInFlight(&manager_));
}

TEST_F(QuicSentPacketManagerTest, TwoRetransmissionTimeoutsAckFirst) {
  // Send 1 packet.
  SendDataPacket(1);

  manager_.OnRetransmissionTimeout();
  EXPECT_TRUE(manager_.HasPendingRetransmissions());
  EXPECT_EQ(kDefaultLength,
            QuicSentPacketManagerPeer::GetBytesInFlight(&manager_));
  RetransmitNextPacket(2);
  EXPECT_FALSE(manager_.HasPendingRetransmissions());

  // Rto a second time.
  EXPECT_CALL(*network_change_visitor_, OnPathDegrading());
  manager_.OnRetransmissionTimeout();
  EXPECT_TRUE(manager_.HasPendingRetransmissions());
  EXPECT_EQ(2 * kDefaultLength,
            QuicSentPacketManagerPeer::GetBytesInFlight(&manager_));
  RetransmitNextPacket(3);
  EXPECT_FALSE(manager_.HasPendingRetransmissions());

  // Ack a retransmission and ensure OnRetransmissionTimeout is called.
  EXPECT_CALL(*send_algorithm_, OnRetransmissionTimeout(true));
  QuicAckFrame ack_frame;
  ack_frame.ack_delay_time = QuicTime::Delta::Zero();
  ack_frame.largest_observed = 3;
  ack_frame.missing_packets.Add(1, 3);
  ExpectAck(3);
  manager_.OnIncomingAck(ack_frame, clock_.Now());

  // The first two packets should still be outstanding.
  EXPECT_EQ(2 * kDefaultLength,
            QuicSentPacketManagerPeer::GetBytesInFlight(&manager_));
}

TEST_F(QuicSentPacketManagerTest, OnPathDegrading) {
  SendDataPacket(1);
  QuicTime::Delta delay = QuicTime::Delta::FromMilliseconds(500);
  EXPECT_CALL(*send_algorithm_, RetransmissionDelay())
      .WillRepeatedly(Return(delay));
  for (size_t i = 1; i < kMinTimeoutsBeforePathDegrading; ++i) {
    manager_.OnRetransmissionTimeout();
    RetransmitNextPacket(i + 2);
  }
  // Next RTO should cause network_change_visitor_'s OnPathDegrading method
  // to be called.
  EXPECT_CALL(*network_change_visitor_, OnPathDegrading());
  manager_.OnRetransmissionTimeout();
}

TEST_F(QuicSentPacketManagerTest, GetTransmissionTime) {
  EXPECT_EQ(QuicTime::Zero(), manager_.GetRetransmissionTime());
}

TEST_F(QuicSentPacketManagerTest, GetTransmissionTimeCryptoHandshake) {
  SendCryptoPacket(1);

  // Check the min.
  RttStats* rtt_stats = QuicSentPacketManagerPeer::GetRttStats(&manager_);
  rtt_stats->set_initial_rtt_us(1 * kNumMicrosPerMilli);
  EXPECT_EQ(clock_.Now().Add(QuicTime::Delta::FromMilliseconds(10)),
            manager_.GetRetransmissionTime());

  // Test with a standard smoothed RTT.
  rtt_stats->set_initial_rtt_us(100 * kNumMicrosPerMilli);

  QuicTime::Delta srtt =
      QuicTime::Delta::FromMicroseconds(rtt_stats->initial_rtt_us());
  QuicTime expected_time = clock_.Now().Add(srtt.Multiply(1.5));
  EXPECT_EQ(expected_time, manager_.GetRetransmissionTime());

  // Retransmit the packet by invoking the retransmission timeout.
  clock_.AdvanceTime(srtt.Multiply(1.5));
  manager_.OnRetransmissionTimeout();
  RetransmitNextPacket(2);

  // The retransmission time should now be twice as far in the future.
  expected_time = clock_.Now().Add(srtt.Multiply(2).Multiply(1.5));
  EXPECT_EQ(expected_time, manager_.GetRetransmissionTime());
}

TEST_F(QuicSentPacketManagerTest, GetTransmissionTimeTailLossProbe) {
  QuicSentPacketManagerPeer::SetMaxTailLossProbes(&manager_, 2);
  SendDataPacket(1);
  SendDataPacket(2);

  // Check the min.
  RttStats* rtt_stats = QuicSentPacketManagerPeer::GetRttStats(&manager_);
  rtt_stats->set_initial_rtt_us(1 * kNumMicrosPerMilli);
  EXPECT_EQ(clock_.Now().Add(QuicTime::Delta::FromMilliseconds(10)),
            manager_.GetRetransmissionTime());

  // Test with a standard smoothed RTT.
  rtt_stats->set_initial_rtt_us(100 * kNumMicrosPerMilli);
  QuicTime::Delta srtt =
      QuicTime::Delta::FromMicroseconds(rtt_stats->initial_rtt_us());
  QuicTime::Delta expected_tlp_delay = srtt.Multiply(2);
  QuicTime expected_time = clock_.Now().Add(expected_tlp_delay);
  EXPECT_EQ(expected_time, manager_.GetRetransmissionTime());

  // Retransmit the packet by invoking the retransmission timeout.
  clock_.AdvanceTime(expected_tlp_delay);
  manager_.OnRetransmissionTimeout();
  EXPECT_EQ(QuicTime::Delta::Zero(),
            manager_.TimeUntilSend(clock_.Now(), HAS_RETRANSMITTABLE_DATA));
  EXPECT_FALSE(manager_.HasPendingRetransmissions());
  EXPECT_TRUE(manager_.MaybeRetransmitTailLossProbe());
  EXPECT_TRUE(manager_.HasPendingRetransmissions());
  RetransmitNextPacket(3);
  EXPECT_CALL(*send_algorithm_, TimeUntilSend(_, _))
      .WillOnce(Return(QuicTime::Delta::Infinite()));
  EXPECT_EQ(QuicTime::Delta::Infinite(),
            manager_.TimeUntilSend(clock_.Now(), HAS_RETRANSMITTABLE_DATA));
  EXPECT_FALSE(manager_.HasPendingRetransmissions());

  expected_time = clock_.Now().Add(expected_tlp_delay);
  EXPECT_EQ(expected_time, manager_.GetRetransmissionTime());
}

TEST_F(QuicSentPacketManagerTest, GetTransmissionTimeSpuriousRTO) {
  QuicSentPacketManagerPeer::GetRttStats(&manager_)
      ->UpdateRtt(QuicTime::Delta::FromMilliseconds(100),
                  QuicTime::Delta::Zero(), QuicTime::Zero());

  SendDataPacket(1);
  SendDataPacket(2);
  SendDataPacket(3);
  SendDataPacket(4);

  QuicTime::Delta expected_rto_delay = QuicTime::Delta::FromMilliseconds(500);
  EXPECT_CALL(*send_algorithm_, RetransmissionDelay())
      .WillRepeatedly(Return(expected_rto_delay));
  QuicTime expected_time = clock_.Now().Add(expected_rto_delay);
  EXPECT_EQ(expected_time, manager_.GetRetransmissionTime());

  // Retransmit the packet by invoking the retransmission timeout.
  clock_.AdvanceTime(expected_rto_delay);
  manager_.OnRetransmissionTimeout();
  // All packets are still considered inflight.
  EXPECT_EQ(4 * kDefaultLength,
            QuicSentPacketManagerPeer::GetBytesInFlight(&manager_));
  RetransmitNextPacket(5);
  RetransmitNextPacket(6);
  // All previous packets are inflight, plus two rto retransmissions.
  EXPECT_EQ(6 * kDefaultLength,
            QuicSentPacketManagerPeer::GetBytesInFlight(&manager_));
  EXPECT_FALSE(manager_.HasPendingRetransmissions());

  // The delay should double the second time.
  expected_time = clock_.Now().Add(expected_rto_delay).Add(expected_rto_delay);
  // Once we always base the timer on the right edge, leaving the older packets
  // in flight doesn't change the timeout.
  EXPECT_EQ(expected_time, manager_.GetRetransmissionTime());

  // Ack a packet before the first RTO and ensure the RTO timeout returns to the
  // original value and OnRetransmissionTimeout is not called or reverted.
  QuicAckFrame ack_frame;
  ack_frame.largest_observed = 2;
  ack_frame.missing_packets.Add(1);
  ExpectAck(2);
  manager_.OnIncomingAck(ack_frame, clock_.ApproximateNow());
  EXPECT_FALSE(manager_.HasPendingRetransmissions());
  EXPECT_EQ(5 * kDefaultLength,
            QuicSentPacketManagerPeer::GetBytesInFlight(&manager_));

  // Wait 2RTTs from now for the RTO, since it's the max of the RTO time
  // and the TLP time.  In production, there would always be two TLP's first.
  // Since retransmission was spurious, smoothed_rtt_ is expired, and replaced
  // by the latest RTT sample of 500ms.
  expected_time = clock_.Now().Add(QuicTime::Delta::FromMilliseconds(1000));
  // Once we always base the timer on the right edge, leaving the older packets
  // in flight doesn't change the timeout.
  EXPECT_EQ(expected_time, manager_.GetRetransmissionTime());
}

TEST_F(QuicSentPacketManagerTest, GetTransmissionDelayMin) {
  SendDataPacket(1);
  EXPECT_CALL(*send_algorithm_, RetransmissionDelay())
      .WillRepeatedly(Return(QuicTime::Delta::FromMilliseconds(1)));
  QuicTime::Delta delay = QuicTime::Delta::FromMilliseconds(200);

  // If the delay is smaller than the min, ensure it exponentially backs off
  // from the min.
  EXPECT_CALL(*network_change_visitor_, OnPathDegrading());
  for (int i = 0; i < 5; ++i) {
    EXPECT_EQ(delay,
              QuicSentPacketManagerPeer::GetRetransmissionDelay(&manager_));
    delay = delay.Add(delay);
    manager_.OnRetransmissionTimeout();
    RetransmitNextPacket(i + 2);
  }
}

TEST_F(QuicSentPacketManagerTest, GetTransmissionDelayMax) {
  EXPECT_CALL(*send_algorithm_, RetransmissionDelay())
      .WillOnce(Return(QuicTime::Delta::FromSeconds(500)));

  EXPECT_EQ(QuicTime::Delta::FromSeconds(60),
            QuicSentPacketManagerPeer::GetRetransmissionDelay(&manager_));
}

TEST_F(QuicSentPacketManagerTest, GetTransmissionDelay) {
  SendDataPacket(1);
  QuicTime::Delta delay = QuicTime::Delta::FromMilliseconds(500);
  EXPECT_CALL(*send_algorithm_, RetransmissionDelay())
      .WillRepeatedly(Return(delay));

  // Delay should back off exponentially.
  EXPECT_CALL(*network_change_visitor_, OnPathDegrading());
  for (int i = 0; i < 5; ++i) {
    EXPECT_EQ(delay,
              QuicSentPacketManagerPeer::GetRetransmissionDelay(&manager_));
    delay = delay.Add(delay);
    manager_.OnRetransmissionTimeout();
    RetransmitNextPacket(i + 2);
  }
}

TEST_F(QuicSentPacketManagerTest, GetLossDelay) {
  MockLossAlgorithm* loss_algorithm = new MockLossAlgorithm();
  QuicSentPacketManagerPeer::SetLossAlgorithm(&manager_, loss_algorithm);

  EXPECT_CALL(*loss_algorithm, GetLossTimeout())
      .WillRepeatedly(Return(QuicTime::Zero()));
  SendDataPacket(1);
  SendDataPacket(2);

  // Handle an ack which causes the loss algorithm to be evaluated and
  // set the loss timeout.
  ExpectAck(2);
  EXPECT_CALL(*loss_algorithm, DetectLosses(_, _, _, _));
  QuicAckFrame ack_frame;
  ack_frame.largest_observed = 2;
  ack_frame.missing_packets.Add(1);
  manager_.OnIncomingAck(ack_frame, clock_.Now());

  QuicTime timeout(clock_.Now().Add(QuicTime::Delta::FromMilliseconds(10)));
  EXPECT_CALL(*loss_algorithm, GetLossTimeout())
      .WillRepeatedly(Return(timeout));
  EXPECT_EQ(timeout, manager_.GetRetransmissionTime());

  // Fire the retransmission timeout and ensure the loss detection algorithm
  // is invoked.
  EXPECT_CALL(*loss_algorithm, DetectLosses(_, _, _, _));
  manager_.OnRetransmissionTimeout();
}

TEST_F(QuicSentPacketManagerTest, NegotiateTimeLossDetectionFromOptions) {
  EXPECT_EQ(kNack, QuicSentPacketManagerPeer::GetLossAlgorithm(&manager_)
                       ->GetLossDetectionType());

  QuicConfig config;
  QuicTagVector options;
  options.push_back(kTIME);
  QuicConfigPeer::SetReceivedConnectionOptions(&config, options);
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  EXPECT_CALL(*network_change_visitor_, OnCongestionWindowChange());
  EXPECT_CALL(*network_change_visitor_, OnRttChange());
  manager_.SetFromConfig(config);

  EXPECT_EQ(kTime, QuicSentPacketManagerPeer::GetLossAlgorithm(&manager_)
                       ->GetLossDetectionType());
}

TEST_F(QuicSentPacketManagerTest, NegotiateCongestionControlFromOptions) {
  ValueRestore<bool> old_flag(&FLAGS_quic_allow_bbr, true);
  QuicConfig config;
  QuicTagVector options;

  options.push_back(kRENO);
  QuicConfigPeer::SetReceivedConnectionOptions(&config, options);
  EXPECT_CALL(*network_change_visitor_, OnCongestionWindowChange());
  EXPECT_CALL(*network_change_visitor_, OnRttChange());
  manager_.SetFromConfig(config);
  EXPECT_EQ(kReno, QuicSentPacketManagerPeer::GetSendAlgorithm(manager_)
                       ->GetCongestionControlType());

// TODO(rtenneti): Enable the following code after BBR code is checked in.
#if 0
  options.clear();
  options.push_back(kTBBR);
  QuicConfigPeer::SetReceivedConnectionOptions(&config, options);
  EXPECT_CALL(*network_change_visitor_, OnCongestionWindowChange());
  EXPECT_CALL(*network_change_visitor_, OnRttChange());
  manager_.SetFromConfig(config);
  EXPECT_EQ(kBBR, QuicSentPacketManagerPeer::GetSendAlgorithm(
      manager_)->GetCongestionControlType());
#endif

  options.clear();
  options.push_back(kBYTE);
  QuicConfigPeer::SetReceivedConnectionOptions(&config, options);
  EXPECT_CALL(*network_change_visitor_, OnCongestionWindowChange());
  EXPECT_CALL(*network_change_visitor_, OnRttChange());
  manager_.SetFromConfig(config);
  EXPECT_EQ(kCubicBytes, QuicSentPacketManagerPeer::GetSendAlgorithm(manager_)
                             ->GetCongestionControlType());

  options.clear();
  options.push_back(kRENO);
  options.push_back(kBYTE);
  QuicConfigPeer::SetReceivedConnectionOptions(&config, options);
  EXPECT_CALL(*network_change_visitor_, OnCongestionWindowChange());
  EXPECT_CALL(*network_change_visitor_, OnRttChange());
  manager_.SetFromConfig(config);
  EXPECT_EQ(kRenoBytes, QuicSentPacketManagerPeer::GetSendAlgorithm(manager_)
                            ->GetCongestionControlType());
}

TEST_F(QuicSentPacketManagerTest, NegotiateNumConnectionsFromOptions) {
  QuicConfig config;
  QuicTagVector options;

  options.push_back(k1CON);
  QuicConfigPeer::SetReceivedConnectionOptions(&config, options);
  EXPECT_CALL(*network_change_visitor_, OnCongestionWindowChange());
  EXPECT_CALL(*network_change_visitor_, OnRttChange());
  EXPECT_CALL(*send_algorithm_, SetNumEmulatedConnections(1));
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  manager_.SetFromConfig(config);

  QuicSentPacketManagerPeer::SetPerspective(&manager_, Perspective::IS_CLIENT);
  QuicConfig client_config;
  client_config.SetConnectionOptionsToSend(options);
  EXPECT_CALL(*network_change_visitor_, OnCongestionWindowChange());
  EXPECT_CALL(*network_change_visitor_, OnRttChange());
  EXPECT_CALL(*send_algorithm_, SetNumEmulatedConnections(1));
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  manager_.SetFromConfig(client_config);
}

TEST_F(QuicSentPacketManagerTest, NegotiateNConnectionFromOptions) {
  // By default, changing the number of open streams does nothing.
  manager_.SetNumOpenStreams(5);

  QuicConfig config;
  QuicTagVector options;

  options.push_back(kNCON);
  QuicConfigPeer::SetReceivedConnectionOptions(&config, options);
  EXPECT_CALL(*network_change_visitor_, OnCongestionWindowChange());
  EXPECT_CALL(*network_change_visitor_, OnRttChange());
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  manager_.SetFromConfig(config);

  EXPECT_CALL(*send_algorithm_, SetNumEmulatedConnections(5));
  manager_.SetNumOpenStreams(5);
}

TEST_F(QuicSentPacketManagerTest, NegotiateNoTLPFromOptionsAtServer) {
  QuicConfig config;
  QuicTagVector options;

  options.push_back(kNTLP);
  QuicConfigPeer::SetReceivedConnectionOptions(&config, options);
  EXPECT_CALL(*network_change_visitor_, OnCongestionWindowChange());
  EXPECT_CALL(*network_change_visitor_, OnRttChange());
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  manager_.SetFromConfig(config);
  EXPECT_EQ(0u, QuicSentPacketManagerPeer::GetMaxTailLossProbes(&manager_));
}

TEST_F(QuicSentPacketManagerTest, NegotiateNoTLPFromOptionsAtClient) {
  QuicConfig client_config;
  QuicTagVector options;

  options.push_back(kNTLP);
  QuicSentPacketManagerPeer::SetPerspective(&manager_, Perspective::IS_CLIENT);
  client_config.SetConnectionOptionsToSend(options);
  EXPECT_CALL(*network_change_visitor_, OnCongestionWindowChange());
  EXPECT_CALL(*network_change_visitor_, OnRttChange());
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  manager_.SetFromConfig(client_config);
  EXPECT_EQ(0u, QuicSentPacketManagerPeer::GetMaxTailLossProbes(&manager_));
}

TEST_F(QuicSentPacketManagerTest, NegotiateTLPRttFromOptionsAtServer) {
  QuicConfig config;
  QuicTagVector options;

  options.push_back(kTLPR);
  QuicConfigPeer::SetReceivedConnectionOptions(&config, options);
  EXPECT_CALL(*network_change_visitor_, OnCongestionWindowChange());
  EXPECT_CALL(*network_change_visitor_, OnRttChange());
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  manager_.SetFromConfig(config);
  EXPECT_TRUE(
      QuicSentPacketManagerPeer::GetEnableHalfRttTailLossProbe(&manager_));
}

TEST_F(QuicSentPacketManagerTest, NegotiateTLPRttFromOptionsAtClient) {
  QuicConfig client_config;
  QuicTagVector options;

  options.push_back(kTLPR);
  QuicSentPacketManagerPeer::SetPerspective(&manager_, Perspective::IS_CLIENT);
  client_config.SetConnectionOptionsToSend(options);
  EXPECT_CALL(*network_change_visitor_, OnCongestionWindowChange());
  EXPECT_CALL(*network_change_visitor_, OnRttChange());
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  manager_.SetFromConfig(client_config);
  EXPECT_TRUE(
      QuicSentPacketManagerPeer::GetEnableHalfRttTailLossProbe(&manager_));
}

TEST_F(QuicSentPacketManagerTest, NegotiateNewRTOFromOptionsAtServer) {
  EXPECT_FALSE(QuicSentPacketManagerPeer::GetUseNewRto(&manager_));
  QuicConfig config;
  QuicTagVector options;

  options.push_back(kNRTO);
  QuicConfigPeer::SetReceivedConnectionOptions(&config, options);
  EXPECT_CALL(*network_change_visitor_, OnCongestionWindowChange());
  EXPECT_CALL(*network_change_visitor_, OnRttChange());
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  manager_.SetFromConfig(config);
  EXPECT_TRUE(QuicSentPacketManagerPeer::GetUseNewRto(&manager_));
}

TEST_F(QuicSentPacketManagerTest, NegotiateNewRTOFromOptionsAtClient) {
  EXPECT_FALSE(QuicSentPacketManagerPeer::GetUseNewRto(&manager_));
  QuicConfig client_config;
  QuicTagVector options;

  options.push_back(kNRTO);
  QuicSentPacketManagerPeer::SetPerspective(&manager_, Perspective::IS_CLIENT);
  client_config.SetConnectionOptionsToSend(options);
  EXPECT_CALL(*network_change_visitor_, OnCongestionWindowChange());
  EXPECT_CALL(*network_change_visitor_, OnRttChange());
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  manager_.SetFromConfig(client_config);
  EXPECT_TRUE(QuicSentPacketManagerPeer::GetUseNewRto(&manager_));
}

TEST_F(QuicSentPacketManagerTest,
       NegotiateConservativeReceiveWindowFromOptions) {
  EXPECT_EQ(kDefaultSocketReceiveBuffer,
            QuicSentPacketManagerPeer::GetReceiveWindow(&manager_));

  // Try to set a size below the minimum and ensure it gets set to the min.
  QuicConfig client_config;
  QuicConfigPeer::SetReceivedSocketReceiveBuffer(&client_config, 1024);
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  EXPECT_CALL(*send_algorithm_,
              SetMaxCongestionWindow(kMinSocketReceiveBuffer * 0.6));
  EXPECT_CALL(*send_algorithm_, PacingRate())
      .WillRepeatedly(Return(QuicBandwidth::Zero()));
  EXPECT_CALL(*send_algorithm_, GetCongestionWindow())
      .WillOnce(Return(10 * kDefaultTCPMSS));
  EXPECT_CALL(*network_change_visitor_, OnCongestionWindowChange());
  EXPECT_CALL(*network_change_visitor_, OnRttChange());
  manager_.SetFromConfig(client_config);

  EXPECT_EQ(kMinSocketReceiveBuffer,
            QuicSentPacketManagerPeer::GetReceiveWindow(&manager_));

  // Ensure the smaller send window only allows 16 packets to be sent.
  for (QuicPacketNumber i = 1; i <= 16; ++i) {
    EXPECT_CALL(*send_algorithm_, TimeUntilSend(_, _))
        .WillOnce(Return(QuicTime::Delta::Zero()));
    EXPECT_EQ(QuicTime::Delta::Zero(),
              manager_.TimeUntilSend(clock_.Now(), HAS_RETRANSMITTABLE_DATA));
    EXPECT_CALL(*send_algorithm_,
                OnPacketSent(_, BytesInFlight(), i, kDefaultLength,
                             HAS_RETRANSMITTABLE_DATA))
        .WillOnce(Return(true));
    SerializedPacket packet(CreatePacket(i, true));
    manager_.OnPacketSent(&packet, 0, clock_.Now(), NOT_RETRANSMISSION,
                          HAS_RETRANSMITTABLE_DATA);
  }
  EXPECT_CALL(*send_algorithm_, TimeUntilSend(_, _))
      .WillOnce(Return(QuicTime::Delta::Infinite()));
  EXPECT_EQ(QuicTime::Delta::Infinite(),
            manager_.TimeUntilSend(clock_.Now(), HAS_RETRANSMITTABLE_DATA));
}

TEST_F(QuicSentPacketManagerTest, ReceiveWindowLimited) {
  EXPECT_EQ(kDefaultSocketReceiveBuffer,
            QuicSentPacketManagerPeer::GetReceiveWindow(&manager_));

  // Ensure the smaller send window only allows 256 * 0.95 packets to be sent.
  for (QuicPacketNumber i = 1; i <= 244; ++i) {
    EXPECT_CALL(*send_algorithm_, TimeUntilSend(_, _))
        .WillOnce(Return(QuicTime::Delta::Zero()));
    EXPECT_EQ(QuicTime::Delta::Zero(),
              manager_.TimeUntilSend(clock_.Now(), HAS_RETRANSMITTABLE_DATA));
    EXPECT_CALL(*send_algorithm_,
                OnPacketSent(_, BytesInFlight(), i, kDefaultLength,
                             HAS_RETRANSMITTABLE_DATA))
        .WillOnce(Return(true));
    SerializedPacket packet(CreatePacket(i, true));
    manager_.OnPacketSent(&packet, 0, clock_.Now(), NOT_RETRANSMISSION,
                          HAS_RETRANSMITTABLE_DATA);
  }
  EXPECT_CALL(*send_algorithm_, TimeUntilSend(_, _))
      .WillOnce(Return(QuicTime::Delta::Infinite()));
  EXPECT_EQ(QuicTime::Delta::Infinite(),
            manager_.TimeUntilSend(clock_.Now(), HAS_RETRANSMITTABLE_DATA));
}

TEST_F(QuicSentPacketManagerTest, UseInitialRoundTripTimeToSend) {
  uint32_t initial_rtt_us = 325000;
  EXPECT_NE(initial_rtt_us,
            manager_.GetRttStats()->smoothed_rtt().ToMicroseconds());

  QuicConfig config;
  config.SetInitialRoundTripTimeUsToSend(initial_rtt_us);
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  EXPECT_CALL(*network_change_visitor_, OnCongestionWindowChange());
  EXPECT_CALL(*network_change_visitor_, OnRttChange());
  manager_.SetFromConfig(config);

  EXPECT_EQ(0, manager_.GetRttStats()->smoothed_rtt().ToMicroseconds());
  EXPECT_EQ(initial_rtt_us, manager_.GetRttStats()->initial_rtt_us());
}

TEST_F(QuicSentPacketManagerTest, ResumeConnectionState) {
  // The sent packet manager should use the RTT from CachedNetworkParameters if
  // it is provided.
  const int kRttMs = 1234;
  CachedNetworkParameters cached_network_params;
  cached_network_params.set_min_rtt_ms(kRttMs);

  EXPECT_CALL(*send_algorithm_, ResumeConnectionState(_, false));
  manager_.ResumeConnectionState(cached_network_params, false);
  EXPECT_EQ(kRttMs * kNumMicrosPerMilli,
            static_cast<uint64_t>(manager_.GetRttStats()->initial_rtt_us()));
}

TEST_F(QuicSentPacketManagerTest, ConnectionMigrationUnspecifiedChange) {
  RttStats* rtt_stats = QuicSentPacketManagerPeer::GetRttStats(&manager_);
  int64_t default_init_rtt = rtt_stats->initial_rtt_us();
  rtt_stats->set_initial_rtt_us(default_init_rtt * 2);
  EXPECT_EQ(2 * default_init_rtt, rtt_stats->initial_rtt_us());

  QuicSentPacketManagerPeer::SetConsecutiveRtoCount(&manager_, 1);
  EXPECT_EQ(1u, manager_.consecutive_rto_count());
  QuicSentPacketManagerPeer::SetConsecutiveTlpCount(&manager_, 2);
  EXPECT_EQ(2u, manager_.consecutive_tlp_count());

  EXPECT_CALL(*send_algorithm_, OnConnectionMigration());
  manager_.OnConnectionMigration(UNSPECIFIED_CHANGE);

  EXPECT_EQ(default_init_rtt, rtt_stats->initial_rtt_us());
  EXPECT_EQ(0u, manager_.consecutive_rto_count());
  EXPECT_EQ(0u, manager_.consecutive_tlp_count());
}

TEST_F(QuicSentPacketManagerTest, ConnectionMigrationIPSubnetChange) {
  RttStats* rtt_stats = QuicSentPacketManagerPeer::GetRttStats(&manager_);
  int64_t default_init_rtt = rtt_stats->initial_rtt_us();
  rtt_stats->set_initial_rtt_us(default_init_rtt * 2);
  EXPECT_EQ(2 * default_init_rtt, rtt_stats->initial_rtt_us());

  QuicSentPacketManagerPeer::SetConsecutiveRtoCount(&manager_, 1);
  EXPECT_EQ(1u, manager_.consecutive_rto_count());
  QuicSentPacketManagerPeer::SetConsecutiveTlpCount(&manager_, 2);
  EXPECT_EQ(2u, manager_.consecutive_tlp_count());

  manager_.OnConnectionMigration(IPV4_SUBNET_CHANGE);

  EXPECT_EQ(2 * default_init_rtt, rtt_stats->initial_rtt_us());
  EXPECT_EQ(1u, manager_.consecutive_rto_count());
  EXPECT_EQ(2u, manager_.consecutive_tlp_count());
}

TEST_F(QuicSentPacketManagerTest, ConnectionMigrationPortChange) {
  RttStats* rtt_stats = QuicSentPacketManagerPeer::GetRttStats(&manager_);
  int64_t default_init_rtt = rtt_stats->initial_rtt_us();
  rtt_stats->set_initial_rtt_us(default_init_rtt * 2);
  EXPECT_EQ(2 * default_init_rtt, rtt_stats->initial_rtt_us());

  QuicSentPacketManagerPeer::SetConsecutiveRtoCount(&manager_, 1);
  EXPECT_EQ(1u, manager_.consecutive_rto_count());
  QuicSentPacketManagerPeer::SetConsecutiveTlpCount(&manager_, 2);
  EXPECT_EQ(2u, manager_.consecutive_tlp_count());

  manager_.OnConnectionMigration(PORT_CHANGE);

  EXPECT_EQ(2 * default_init_rtt, rtt_stats->initial_rtt_us());
  EXPECT_EQ(1u, manager_.consecutive_rto_count());
  EXPECT_EQ(2u, manager_.consecutive_tlp_count());
}

}  // namespace
}  // namespace test
}  // namespace net
