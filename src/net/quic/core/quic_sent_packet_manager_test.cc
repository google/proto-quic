// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/quic_sent_packet_manager.h"

#include <memory>

#include "net/quic/core/quic_pending_retransmission.h"
#include "net/quic/platform/api/quic_flags.h"
#include "net/quic/platform/api/quic_ptr_util.h"
#include "net/quic/platform/api/quic_string_piece.h"
#include "net/quic/platform/api/quic_test.h"
#include "net/quic/test_tools/quic_config_peer.h"
#include "net/quic/test_tools/quic_sent_packet_manager_peer.h"
#include "net/quic/test_tools/quic_test_utils.h"

using testing::AnyNumber;
using testing::ElementsAre;
using testing::IsEmpty;
using testing::Not;
using testing::Pair;
using testing::Pointwise;
using testing::Return;
using testing::SetArgPointee;
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

class QuicSentPacketManagerTest : public QuicTest {
 protected:
  QuicSentPacketManagerTest()
      : manager_(Perspective::IS_SERVER, &clock_, &stats_, kCubicBytes, kNack),
        send_algorithm_(new StrictMock<MockSendAlgorithm>),
        network_change_visitor_(new StrictMock<MockNetworkChangeVisitor>) {
    QuicSentPacketManagerPeer::SetSendAlgorithm(&manager_, send_algorithm_);
    // Disable tail loss probes for most tests.
    QuicSentPacketManagerPeer::SetMaxTailLossProbes(&manager_, 0);
    // Advance the time 1s so the send times are never QuicTime::Zero.
    clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(1000));
    manager_.SetNetworkChangeVisitor(network_change_visitor_.get());

    EXPECT_CALL(*send_algorithm_, HasReliableBandwidthEstimate())
        .Times(AnyNumber());
    EXPECT_CALL(*send_algorithm_, BandwidthEstimate())
        .Times(AnyNumber())
        .WillRepeatedly(Return(QuicBandwidth::Zero()));
    EXPECT_CALL(*send_algorithm_, InSlowStart()).Times(AnyNumber());
    EXPECT_CALL(*send_algorithm_, InRecovery()).Times(AnyNumber());
    EXPECT_CALL(*network_change_visitor_, OnPathMtuIncreased(1000))
        .Times(AnyNumber());
  }

  ~QuicSentPacketManagerTest() override {}

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
      EXPECT_TRUE(QuicSentPacketManagerPeer::IsUnacked(&manager_, packets[i]))
          << packets[i];
    }
  }

  void VerifyRetransmittablePackets(QuicPacketNumber* packets,
                                    size_t num_packets) {
    EXPECT_EQ(
        num_packets,
        QuicSentPacketManagerPeer::GetNumRetransmittablePackets(&manager_));
    for (size_t i = 0; i < num_packets; ++i) {
      EXPECT_TRUE(QuicSentPacketManagerPeer::HasRetransmittableFrames(
          &manager_, packets[i]))
          << " packets[" << i << "]:" << packets[i];
    }
  }

  void ExpectAck(QuicPacketNumber largest_observed) {
    EXPECT_CALL(
        *send_algorithm_,
        OnCongestionEvent(true, _, _, ElementsAre(Pair(largest_observed, _)),
                          IsEmpty()));
    EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  }

  void ExpectUpdatedRtt(QuicPacketNumber largest_observed) {
    EXPECT_CALL(*send_algorithm_,
                OnCongestionEvent(true, _, _, IsEmpty(), IsEmpty()));
    EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  }

  void ExpectAckAndLoss(bool rtt_updated,
                        QuicPacketNumber largest_observed,
                        QuicPacketNumber lost_packet) {
    EXPECT_CALL(*send_algorithm_,
                OnCongestionEvent(rtt_updated, _, _,
                                  ElementsAre(Pair(largest_observed, _)),
                                  ElementsAre(Pair(lost_packet, _))));
    EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  }

  // |packets_acked| and |packets_lost| should be in packet number order.
  void ExpectAcksAndLosses(bool rtt_updated,
                           QuicPacketNumber* packets_acked,
                           size_t num_packets_acked,
                           QuicPacketNumber* packets_lost,
                           size_t num_packets_lost) {
    std::vector<QuicPacketNumber> ack_vector;
    for (size_t i = 0; i < num_packets_acked; ++i) {
      ack_vector.push_back(packets_acked[i]);
    }
    std::vector<QuicPacketNumber> lost_vector;
    for (size_t i = 0; i < num_packets_lost; ++i) {
      lost_vector.push_back(packets_lost[i]);
    }
    EXPECT_CALL(
        *send_algorithm_,
        OnCongestionEvent(rtt_updated, _, _, Pointwise(KeyEq(), ack_vector),
                          Pointwise(KeyEq(), lost_vector)));
    EXPECT_CALL(*network_change_visitor_, OnCongestionChange())
        .Times(AnyNumber());
  }

  void RetransmitAndSendPacket(QuicPacketNumber old_packet_number,
                               QuicPacketNumber new_packet_number) {
    RetransmitAndSendPacket(old_packet_number, new_packet_number,
                            TLP_RETRANSMISSION);
  }

  void RetransmitAndSendPacket(QuicPacketNumber old_packet_number,
                               QuicPacketNumber new_packet_number,
                               TransmissionType transmission_type) {
    QuicSentPacketManagerPeer::MarkForRetransmission(
        &manager_, old_packet_number, transmission_type);
    EXPECT_TRUE(manager_.HasPendingRetransmissions());
    QuicPendingRetransmission next_retransmission =
        manager_.NextPendingRetransmission();
    EXPECT_EQ(old_packet_number, next_retransmission.packet_number);
    EXPECT_EQ(transmission_type, next_retransmission.transmission_type);

    EXPECT_CALL(*send_algorithm_,
                OnPacketSent(_, BytesInFlight(), new_packet_number,
                             kDefaultLength, HAS_RETRANSMITTABLE_DATA))
        .WillOnce(Return(true));
    SerializedPacket packet(CreatePacket(new_packet_number, false));
    manager_.OnPacketSent(&packet, old_packet_number, clock_.Now(),
                          transmission_type, HAS_RETRANSMITTABLE_DATA);
    EXPECT_TRUE(QuicSentPacketManagerPeer::IsRetransmission(&manager_,
                                                            new_packet_number));
  }

  SerializedPacket CreateDataPacket(QuicPacketNumber packet_number) {
    return CreatePacket(packet_number, true);
  }

  SerializedPacket CreatePacket(QuicPacketNumber packet_number,
                                bool retransmittable) {
    SerializedPacket packet(packet_number, PACKET_6BYTE_PACKET_NUMBER, nullptr,
                            kDefaultLength, false, false);
    if (retransmittable) {
      packet.retransmittable_frames.push_back(QuicFrame(
          new QuicStreamFrame(kStreamId, false, 0, QuicStringPiece())));
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
        QuicFrame(new QuicStreamFrame(1, false, 0, QuicStringPiece())));
    packet.has_crypto_handshake = IS_HANDSHAKE;
    manager_.OnPacketSent(&packet, 0, clock_.Now(), NOT_RETRANSMISSION,
                          HAS_RETRANSMITTABLE_DATA);
  }

  void SendAckPacket(QuicPacketNumber packet_number,
                     QuicPacketNumber largest_acked) {
    EXPECT_CALL(*send_algorithm_,
                OnPacketSent(_, BytesInFlight(), packet_number, kDefaultLength,
                             NO_RETRANSMITTABLE_DATA))
        .Times(1)
        .WillOnce(Return(false));
    SerializedPacket packet(CreatePacket(packet_number, false));
    packet.largest_acked = largest_acked;
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
    const QuicPendingRetransmission pending =
        manager_.NextPendingRetransmission();
    SerializedPacket packet(CreatePacket(retransmission_packet_number, false));
    manager_.OnPacketSent(&packet, pending.packet_number, clock_.Now(),
                          pending.transmission_type, HAS_RETRANSMITTABLE_DATA);
  }

  // Initialize a frame acknowledging all packets up to largest_observed.
  const QuicAckFrame InitAckFrame(QuicPacketNumber largest_observed) {
    QuicAckFrame frame(MakeAckFrame(largest_observed));
    if (largest_observed > 0) {
      frame.packets.Add(1, largest_observed + 1);
    }
    return frame;
  }

  // Explicitly nack packet [lower, higher).
  void NackPackets(QuicPacketNumber lower,
                   QuicPacketNumber higher,
                   QuicAckFrame* frame) {
    frame->packets.Remove(lower, higher);
  }

  QuicSentPacketManager manager_;
  MockClock clock_;
  QuicConnectionStats stats_;
  MockSendAlgorithm* send_algorithm_;
  std::unique_ptr<MockNetworkChangeVisitor> network_change_visitor_;
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
  QuicAckFrame ack_frame = InitAckFrame(2);
  NackPackets(1, 2, &ack_frame);
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
  QuicAckFrame ack_frame = InitAckFrame(1);
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
  QuicAckFrame ack_frame = InitAckFrame(1);
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
  QuicAckFrame ack_frame = InitAckFrame(1);
  manager_.OnIncomingAck(ack_frame, clock_.ApproximateNow());

  SendDataPacket(3);
  SendDataPacket(4);
  SendDataPacket(5);
  clock_.AdvanceTime(rtt);

  // Next, NACK packet 2 three times.
  ack_frame = InitAckFrame(3);
  NackPackets(2, 3, &ack_frame);
  ExpectAck(3);
  manager_.OnIncomingAck(ack_frame, clock_.ApproximateNow());

  ack_frame = InitAckFrame(4);
  NackPackets(2, 3, &ack_frame);
  ExpectAck(4);
  manager_.OnIncomingAck(ack_frame, clock_.ApproximateNow());

  ack_frame = InitAckFrame(5);
  NackPackets(2, 3, &ack_frame);
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
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  manager_.OnRetransmissionTimeout();
  EXPECT_TRUE(manager_.HasPendingRetransmissions());

  // Ack 1 but not 2, before 2 is able to be sent.
  // Since 1 has been retransmitted, it has already been lost, and so the
  // send algorithm is not informed that it has been ACK'd.
  QuicAckFrame ack_frame = InitAckFrame(1);
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
  manager_.SetDebugDelegate(&debug_delegate);

  SendDataPacket(1);
  RetransmitAndSendPacket(1, 2);
  RetransmitAndSendPacket(2, 3);
  QuicTime::Delta rtt = QuicTime::Delta::FromMilliseconds(15);
  clock_.AdvanceTime(rtt);

  // Ack 1 but not 2 or 3.
  ExpectAck(1);
  QuicAckFrame ack_frame = InitAckFrame(1);
  manager_.OnIncomingAck(ack_frame, clock_.ApproximateNow());

  // 2 and 3 remain unacked, but no packets have retransmittable data.
  QuicPacketNumber unacked[] = {2, 3};
  VerifyUnackedPackets(unacked, arraysize(unacked));
  EXPECT_TRUE(QuicSentPacketManagerPeer::HasPendingPackets(&manager_));
  VerifyRetransmittablePackets(nullptr, 0);

  // Ensure packet 2 is lost when 4 is sent and 3 and 4 are acked.
  SendDataPacket(4);
  ack_frame = InitAckFrame(4);
  NackPackets(2, 3, &ack_frame);
  QuicPacketNumber acked[] = {3, 4};
  ExpectAcksAndLosses(true, acked, arraysize(acked), nullptr, 0);
  manager_.OnIncomingAck(ack_frame, clock_.ApproximateNow());

  QuicPacketNumber unacked2[] = {2};
  VerifyUnackedPackets(unacked2, arraysize(unacked2));
  EXPECT_TRUE(QuicSentPacketManagerPeer::HasPendingPackets(&manager_));

  SendDataPacket(5);
  ack_frame = InitAckFrame(5);
  NackPackets(2, 3, &ack_frame);
  ExpectAckAndLoss(true, 5, 2);
  EXPECT_CALL(debug_delegate, OnPacketLoss(2, LOSS_RETRANSMISSION, _));
  manager_.OnIncomingAck(ack_frame, clock_.ApproximateNow());

  VerifyUnackedPackets(nullptr, 0);
  EXPECT_FALSE(QuicSentPacketManagerPeer::HasPendingPackets(&manager_));
  EXPECT_EQ(2u, stats_.packets_spuriously_retransmitted);
}

TEST_F(QuicSentPacketManagerTest, AckOriginalTransmission) {
  auto loss_algorithm = QuicMakeUnique<MockLossAlgorithm>();
  QuicSentPacketManagerPeer::SetLossAlgorithm(&manager_, loss_algorithm.get());

  SendDataPacket(1);
  RetransmitAndSendPacket(1, 2);

  // Ack original transmission, but that wasn't lost via fast retransmit,
  // so no call on OnSpuriousRetransmission is expected.
  {
    QuicAckFrame ack_frame = InitAckFrame(1);
    ExpectAck(1);
    EXPECT_CALL(*loss_algorithm, DetectLosses(_, _, _, _, _));
    manager_.OnIncomingAck(ack_frame, clock_.Now());
  }

  SendDataPacket(3);
  SendDataPacket(4);
  // Ack 4, which causes 3 to be retransmitted.
  {
    QuicAckFrame ack_frame = InitAckFrame(4);
    NackPackets(2, 4, &ack_frame);
    ExpectAck(4);
    EXPECT_CALL(*loss_algorithm, DetectLosses(_, _, _, _, _));
    manager_.OnIncomingAck(ack_frame, clock_.Now());
    RetransmitAndSendPacket(3, 5, LOSS_RETRANSMISSION);
  }

  // Ack 3, which causes SpuriousRetransmitDetected to be called.
  {
    QuicAckFrame ack_frame = InitAckFrame(4);
    NackPackets(2, 3, &ack_frame);
  }
}

TEST_F(QuicSentPacketManagerTest, GetLeastUnacked) {
  EXPECT_EQ(1u, manager_.GetLeastUnacked());
}

TEST_F(QuicSentPacketManagerTest, GetLeastUnackedUnacked) {
  SendDataPacket(1);
  EXPECT_EQ(1u, manager_.GetLeastUnacked());
}

TEST_F(QuicSentPacketManagerTest, AckAckAndUpdateRtt) {
  FLAGS_quic_reloadable_flag_quic_no_stop_waiting_frames = true;
  EXPECT_EQ(0u, manager_.largest_packet_peer_knows_is_acked());
  SendDataPacket(1);
  SendAckPacket(2, 1);

  // Now ack the ack and expect an RTT update.
  QuicAckFrame ack_frame = InitAckFrame(2);
  ack_frame.ack_delay_time = QuicTime::Delta::FromMilliseconds(5);

  ExpectAck(1);
  manager_.OnIncomingAck(ack_frame, clock_.Now());
  EXPECT_EQ(1u, manager_.largest_packet_peer_knows_is_acked());

  SendAckPacket(3, 3);

  // Now ack the ack and expect only an RTT update.
  ack_frame = InitAckFrame(3);
  ExpectUpdatedRtt(3);
  manager_.OnIncomingAck(ack_frame, clock_.Now());
  EXPECT_EQ(3u, manager_.largest_packet_peer_knows_is_acked());
}

TEST_F(QuicSentPacketManagerTest, Rtt) {
  QuicPacketNumber packet_number = 1;
  QuicTime::Delta expected_rtt = QuicTime::Delta::FromMilliseconds(15);
  SendDataPacket(packet_number);
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(20));

  ExpectAck(packet_number);
  QuicAckFrame ack_frame = InitAckFrame(packet_number);
  ack_frame.ack_delay_time = QuicTime::Delta::FromMilliseconds(5);
  manager_.OnIncomingAck(ack_frame, clock_.Now());
  EXPECT_EQ(expected_rtt, manager_.GetRttStats()->latest_rtt());
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
  QuicAckFrame ack_frame = InitAckFrame(packet_number);
  ack_frame.ack_delay_time = QuicTime::Delta::FromMilliseconds(11);
  manager_.OnIncomingAck(ack_frame, clock_.Now());
  EXPECT_EQ(expected_rtt, manager_.GetRttStats()->latest_rtt());
}

TEST_F(QuicSentPacketManagerTest, RttWithInfiniteDelta) {
  // Expect that the RTT is equal to the local time elapsed, since the
  // ack_delay_time is infinite, and is hence invalid.
  QuicPacketNumber packet_number = 1;
  QuicTime::Delta expected_rtt = QuicTime::Delta::FromMilliseconds(10);
  SendDataPacket(packet_number);
  clock_.AdvanceTime(expected_rtt);

  ExpectAck(packet_number);
  QuicAckFrame ack_frame = InitAckFrame(packet_number);
  ack_frame.ack_delay_time = QuicTime::Delta::Infinite();
  manager_.OnIncomingAck(ack_frame, clock_.Now());
  EXPECT_EQ(expected_rtt, manager_.GetRttStats()->latest_rtt());
}

TEST_F(QuicSentPacketManagerTest, RttZeroDelta) {
  // Expect that the RTT is the time between send and receive since the
  // ack_delay_time is zero.
  QuicPacketNumber packet_number = 1;
  QuicTime::Delta expected_rtt = QuicTime::Delta::FromMilliseconds(10);
  SendDataPacket(packet_number);
  clock_.AdvanceTime(expected_rtt);

  ExpectAck(packet_number);
  QuicAckFrame ack_frame = InitAckFrame(packet_number);
  ack_frame.ack_delay_time = QuicTime::Delta::Zero();
  manager_.OnIncomingAck(ack_frame, clock_.Now());
  EXPECT_EQ(expected_rtt, manager_.GetRttStats()->latest_rtt());
}

TEST_F(QuicSentPacketManagerTest, TailLossProbeTimeout) {
  QuicSentPacketManagerPeer::SetMaxTailLossProbes(&manager_, 2);

  // Send 1 packet.
  QuicPacketNumber packet_number = 1;
  SendDataPacket(packet_number);

  // The first tail loss probe retransmits 1 packet.
  manager_.OnRetransmissionTimeout();
  EXPECT_EQ(QuicTime::Delta::Zero(), manager_.TimeUntilSend(clock_.Now()));
  EXPECT_FALSE(manager_.HasPendingRetransmissions());
  manager_.MaybeRetransmitTailLossProbe();
  EXPECT_TRUE(manager_.HasPendingRetransmissions());
  RetransmitNextPacket(2);
  EXPECT_FALSE(manager_.HasPendingRetransmissions());

  // The second tail loss probe retransmits 1 packet.
  manager_.OnRetransmissionTimeout();
  EXPECT_EQ(QuicTime::Delta::Zero(), manager_.TimeUntilSend(clock_.Now()));
  EXPECT_FALSE(manager_.HasPendingRetransmissions());
  manager_.MaybeRetransmitTailLossProbe();
  EXPECT_TRUE(manager_.HasPendingRetransmissions());
  RetransmitNextPacket(3);
  EXPECT_CALL(*send_algorithm_, TimeUntilSend(_, _))
      .WillOnce(Return(QuicTime::Delta::Infinite()));
  EXPECT_EQ(QuicTime::Delta::Infinite(), manager_.TimeUntilSend(clock_.Now()));
  EXPECT_FALSE(manager_.HasPendingRetransmissions());

  // Ack the third and ensure the first two are still pending.
  ExpectAck(3);

  QuicAckFrame ack_frame = InitAckFrame(3);
  NackPackets(1, 3, &ack_frame);
  manager_.OnIncomingAck(ack_frame, clock_.ApproximateNow());

  EXPECT_TRUE(QuicSentPacketManagerPeer::HasPendingPackets(&manager_));

  // Acking two more packets will lose both of them due to nacks.
  SendDataPacket(4);
  SendDataPacket(5);
  ack_frame = InitAckFrame(5);
  NackPackets(1, 3, &ack_frame);
  QuicPacketNumber acked[] = {4, 5};
  QuicPacketNumber lost[] = {1, 2};
  ExpectAcksAndLosses(true, acked, arraysize(acked), lost, arraysize(lost));
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
  clock_.AdvanceTime(manager_.GetRetransmissionTime() - clock_.Now());

  // The first tail loss probe retransmits 1 packet.
  manager_.OnRetransmissionTimeout();
  EXPECT_EQ(QuicTime::Delta::Zero(), manager_.TimeUntilSend(clock_.Now()));
  EXPECT_FALSE(manager_.HasPendingRetransmissions());
  manager_.MaybeRetransmitTailLossProbe();
  EXPECT_TRUE(manager_.HasPendingRetransmissions());
  RetransmitNextPacket(101);
  EXPECT_CALL(*send_algorithm_, TimeUntilSend(_, _))
      .WillOnce(Return(QuicTime::Delta::Infinite()));
  EXPECT_EQ(QuicTime::Delta::Infinite(), manager_.TimeUntilSend(clock_.Now()));
  EXPECT_FALSE(manager_.HasPendingRetransmissions());
  clock_.AdvanceTime(manager_.GetRetransmissionTime() - clock_.Now());

  // The second tail loss probe retransmits 1 packet.
  manager_.OnRetransmissionTimeout();
  EXPECT_EQ(QuicTime::Delta::Zero(), manager_.TimeUntilSend(clock_.Now()));
  EXPECT_FALSE(manager_.HasPendingRetransmissions());
  EXPECT_TRUE(manager_.MaybeRetransmitTailLossProbe());
  EXPECT_TRUE(manager_.HasPendingRetransmissions());
  RetransmitNextPacket(102);
  EXPECT_CALL(*send_algorithm_, TimeUntilSend(_, _))
      .WillOnce(Return(QuicTime::Delta::Infinite()));
  EXPECT_EQ(QuicTime::Delta::Infinite(), manager_.TimeUntilSend(clock_.Now()));

  // Ensure the RTO is set based on the correct packet.
  rto_packet_time = clock_.Now();
  EXPECT_EQ(rto_packet_time + QuicTime::Delta::FromMilliseconds(500),
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
  QuicAckFrame ack_frame = InitAckFrame(103);
  NackPackets(0, 103, &ack_frame);
  EXPECT_CALL(*send_algorithm_, OnRetransmissionTimeout(true));
  EXPECT_CALL(*send_algorithm_,
              OnCongestionEvent(true, _, _, ElementsAre(Pair(103, _)), _));
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
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
  EXPECT_EQ(QuicTime::Delta::Zero(), manager_.TimeUntilSend(clock_.Now()));
  RetransmitNextPacket(6);
  RetransmitNextPacket(7);
  EXPECT_FALSE(manager_.HasPendingRetransmissions());
  EXPECT_TRUE(QuicSentPacketManagerPeer::HasUnackedCryptoPackets(&manager_));

  // The second retransmits 2 packets.
  manager_.OnRetransmissionTimeout();
  EXPECT_EQ(QuicTime::Delta::Zero(), manager_.TimeUntilSend(clock_.Now()));
  RetransmitNextPacket(8);
  RetransmitNextPacket(9);
  EXPECT_FALSE(manager_.HasPendingRetransmissions());
  EXPECT_TRUE(QuicSentPacketManagerPeer::HasUnackedCryptoPackets(&manager_));

  // Now ack the two crypto packets and the speculatively encrypted request,
  // and ensure the first four crypto packets get abandoned, but not lost.
  QuicPacketNumber acked[] = {3, 4, 5, 8, 9};
  ExpectAcksAndLosses(true, acked, arraysize(acked), nullptr, 0);
  QuicAckFrame ack_frame = InitAckFrame(9);
  NackPackets(1, 3, &ack_frame);
  NackPackets(6, 8, &ack_frame);
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
  QuicAckFrame ack_frame = InitAckFrame(9);
  for (QuicPacketNumber i = 1; i < 8; ++i) {
    NackPackets(i, i + 1, &ack_frame);
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
  QuicAckFrame ack_frame = InitAckFrame(2);
  NackPackets(1, 2, &ack_frame);
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
  QuicAckFrame ack_frame = InitAckFrame(3);
  NackPackets(1, 3, &ack_frame);
  ExpectUpdatedRtt(3);
  manager_.OnIncomingAck(ack_frame, clock_.ApproximateNow());
  VerifyUnackedPackets(nullptr, 0);
  VerifyRetransmittablePackets(nullptr, 0);
}

TEST_F(QuicSentPacketManagerTest, RetransmissionTimeout) {
  StrictMock<MockDebugDelegate> debug_delegate;
  manager_.SetDebugDelegate(&debug_delegate);

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
  QuicAckFrame ack_frame = InitAckFrame(102);
  NackPackets(0, 102, &ack_frame);
  ack_frame.ack_delay_time = QuicTime::Delta::Zero();
  // Ensure no packets are lost.
  EXPECT_CALL(*send_algorithm_,
              OnCongestionEvent(true, _, _, ElementsAre(Pair(102, _)),
                                /*lost_packets=*/IsEmpty()));
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
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
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  EXPECT_CALL(*send_algorithm_, GetCongestionControlType());
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  EXPECT_CALL(*send_algorithm_, PacingRate(_))
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
  QuicAckFrame ack_frame = InitAckFrame(102);
  NackPackets(0, 102, &ack_frame);
  ack_frame.ack_delay_time = QuicTime::Delta::Zero();
  // This will include packets in the lost packet map.
  EXPECT_CALL(*send_algorithm_,
              OnCongestionEvent(true, _, _, ElementsAre(Pair(102, _)),
                                /*lost_packets=*/Not(IsEmpty())));
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
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
  QuicAckFrame ack_frame = InitAckFrame(2);
  NackPackets(1, 2, &ack_frame);
  ack_frame.ack_delay_time = QuicTime::Delta::Zero();
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
  QuicAckFrame ack_frame = InitAckFrame(3);
  NackPackets(1, 3, &ack_frame);
  ack_frame.ack_delay_time = QuicTime::Delta::Zero();
  ExpectAck(3);
  manager_.OnIncomingAck(ack_frame, clock_.Now());

  // The first two packets should still be outstanding.
  EXPECT_EQ(2 * kDefaultLength,
            QuicSentPacketManagerPeer::GetBytesInFlight(&manager_));
}

TEST_F(QuicSentPacketManagerTest, OnPathDegrading) {
  SendDataPacket(1);
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
  RttStats* rtt_stats = const_cast<RttStats*>(manager_.GetRttStats());
  rtt_stats->set_initial_rtt_us(1 * kNumMicrosPerMilli);
  EXPECT_EQ(clock_.Now() + QuicTime::Delta::FromMilliseconds(10),
            manager_.GetRetransmissionTime());

  // Test with a standard smoothed RTT.
  rtt_stats->set_initial_rtt_us(100 * kNumMicrosPerMilli);

  QuicTime::Delta srtt =
      QuicTime::Delta::FromMicroseconds(rtt_stats->initial_rtt_us());
  QuicTime expected_time = clock_.Now() + 1.5 * srtt;
  EXPECT_EQ(expected_time, manager_.GetRetransmissionTime());

  // Retransmit the packet by invoking the retransmission timeout.
  clock_.AdvanceTime(1.5 * srtt);
  manager_.OnRetransmissionTimeout();
  RetransmitNextPacket(2);

  // The retransmission time should now be twice as far in the future.
  expected_time = clock_.Now() + srtt * 2 * 1.5;
  EXPECT_EQ(expected_time, manager_.GetRetransmissionTime());
}

TEST_F(QuicSentPacketManagerTest,
       GetConservativeTransmissionTimeCryptoHandshake) {
  QuicConfig config;
  QuicTagVector options;
  options.push_back(kCONH);
  QuicConfigPeer::SetReceivedConnectionOptions(&config, options);
  EXPECT_CALL(*send_algorithm_, GetCongestionControlType());
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  manager_.SetFromConfig(config);
  // Calling SetFromConfig requires mocking out some send algorithm methods.
  EXPECT_CALL(*send_algorithm_, PacingRate(_))
      .WillRepeatedly(Return(QuicBandwidth::Zero()));
  EXPECT_CALL(*send_algorithm_, GetCongestionWindow())
      .WillRepeatedly(Return(10 * kDefaultTCPMSS));

  SendCryptoPacket(1);

  // Check the min.
  RttStats* rtt_stats = const_cast<RttStats*>(manager_.GetRttStats());
  rtt_stats->set_initial_rtt_us(1 * kNumMicrosPerMilli);
  EXPECT_EQ(clock_.Now() + QuicTime::Delta::FromMilliseconds(25),
            manager_.GetRetransmissionTime());

  // Test with a standard smoothed RTT.
  rtt_stats->set_initial_rtt_us(100 * kNumMicrosPerMilli);

  QuicTime::Delta srtt =
      QuicTime::Delta::FromMicroseconds(rtt_stats->initial_rtt_us());
  QuicTime expected_time = clock_.Now() + 2 * srtt;
  EXPECT_EQ(expected_time, manager_.GetRetransmissionTime());

  // Retransmit the packet by invoking the retransmission timeout.
  clock_.AdvanceTime(2 * srtt);
  manager_.OnRetransmissionTimeout();
  RetransmitNextPacket(2);

  // The retransmission time should now be twice as far in the future.
  expected_time = clock_.Now() + srtt * 2 * 2;
  EXPECT_EQ(expected_time, manager_.GetRetransmissionTime());
}

TEST_F(QuicSentPacketManagerTest, GetTransmissionTimeTailLossProbe) {
  QuicSentPacketManagerPeer::SetMaxTailLossProbes(&manager_, 2);
  SendDataPacket(1);
  SendDataPacket(2);

  // Check the min.
  RttStats* rtt_stats = const_cast<RttStats*>(manager_.GetRttStats());
  rtt_stats->set_initial_rtt_us(1 * kNumMicrosPerMilli);
  EXPECT_EQ(clock_.Now() + QuicTime::Delta::FromMilliseconds(10),
            manager_.GetRetransmissionTime());

  // Test with a standard smoothed RTT.
  rtt_stats->set_initial_rtt_us(100 * kNumMicrosPerMilli);
  QuicTime::Delta srtt =
      QuicTime::Delta::FromMicroseconds(rtt_stats->initial_rtt_us());
  QuicTime::Delta expected_tlp_delay = 2 * srtt;
  QuicTime expected_time = clock_.Now() + expected_tlp_delay;
  EXPECT_EQ(expected_time, manager_.GetRetransmissionTime());

  // Retransmit the packet by invoking the retransmission timeout.
  clock_.AdvanceTime(expected_tlp_delay);
  manager_.OnRetransmissionTimeout();
  EXPECT_EQ(QuicTime::Delta::Zero(), manager_.TimeUntilSend(clock_.Now()));
  EXPECT_FALSE(manager_.HasPendingRetransmissions());
  EXPECT_TRUE(manager_.MaybeRetransmitTailLossProbe());
  EXPECT_TRUE(manager_.HasPendingRetransmissions());
  RetransmitNextPacket(3);
  EXPECT_CALL(*send_algorithm_, TimeUntilSend(_, _))
      .WillOnce(Return(QuicTime::Delta::Infinite()));
  EXPECT_EQ(QuicTime::Delta::Infinite(), manager_.TimeUntilSend(clock_.Now()));
  EXPECT_FALSE(manager_.HasPendingRetransmissions());

  expected_time = clock_.Now() + expected_tlp_delay;
  EXPECT_EQ(expected_time, manager_.GetRetransmissionTime());
}

TEST_F(QuicSentPacketManagerTest, GetTransmissionTimeSpuriousRTO) {
  RttStats* rtt_stats = const_cast<RttStats*>(manager_.GetRttStats());
  rtt_stats->UpdateRtt(QuicTime::Delta::FromMilliseconds(100),
                       QuicTime::Delta::Zero(), QuicTime::Zero());

  SendDataPacket(1);
  SendDataPacket(2);
  SendDataPacket(3);
  SendDataPacket(4);

  QuicTime::Delta expected_rto_delay =
      rtt_stats->smoothed_rtt() + 4 * rtt_stats->mean_deviation();
  QuicTime expected_time = clock_.Now() + expected_rto_delay;
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
  expected_time = clock_.Now() + expected_rto_delay + expected_rto_delay;
  // Once we always base the timer on the right edge, leaving the older packets
  // in flight doesn't change the timeout.
  EXPECT_EQ(expected_time, manager_.GetRetransmissionTime());

  // Ack a packet before the first RTO and ensure the RTO timeout returns to the
  // original value and OnRetransmissionTimeout is not called or reverted.
  QuicAckFrame ack_frame = InitAckFrame(2);
  NackPackets(1, 2, &ack_frame);
  ExpectAck(2);
  manager_.OnIncomingAck(ack_frame, clock_.ApproximateNow());
  EXPECT_FALSE(manager_.HasPendingRetransmissions());
  EXPECT_EQ(5 * kDefaultLength,
            QuicSentPacketManagerPeer::GetBytesInFlight(&manager_));

  // Wait 2RTTs from now for the RTO, since it's the max of the RTO time
  // and the TLP time.  In production, there would always be two TLP's first.
  // Since retransmission was spurious, smoothed_rtt_ is expired, and replaced
  // by the latest RTT sample of 500ms.
  expected_time = clock_.Now() + QuicTime::Delta::FromMilliseconds(1000);
  // Once we always base the timer on the right edge, leaving the older packets
  // in flight doesn't change the timeout.
  EXPECT_EQ(expected_time, manager_.GetRetransmissionTime());
}

TEST_F(QuicSentPacketManagerTest, GetTransmissionDelayMin) {
  SendDataPacket(1);
  // Provide a 1ms RTT sample.
  const_cast<RttStats*>(manager_.GetRttStats())
      ->UpdateRtt(QuicTime::Delta::FromMilliseconds(1), QuicTime::Delta::Zero(),
                  QuicTime::Zero());
  QuicTime::Delta delay = QuicTime::Delta::FromMilliseconds(200);

  // If the delay is smaller than the min, ensure it exponentially backs off
  // from the min.
  EXPECT_CALL(*network_change_visitor_, OnPathDegrading());
  for (int i = 0; i < 5; ++i) {
    EXPECT_EQ(delay,
              QuicSentPacketManagerPeer::GetRetransmissionDelay(&manager_));
    delay = delay + delay;
    manager_.OnRetransmissionTimeout();
    RetransmitNextPacket(i + 2);
  }
}

TEST_F(QuicSentPacketManagerTest, GetTransmissionDelayMax) {
  SendDataPacket(1);
  // Provide a 60s RTT sample.
  const_cast<RttStats*>(manager_.GetRttStats())
      ->UpdateRtt(QuicTime::Delta::FromSeconds(60), QuicTime::Delta::Zero(),
                  QuicTime::Zero());

  EXPECT_EQ(QuicTime::Delta::FromSeconds(60),
            QuicSentPacketManagerPeer::GetRetransmissionDelay(&manager_));
}

TEST_F(QuicSentPacketManagerTest, GetTransmissionDelayExponentialBackoff) {
  SendDataPacket(1);
  QuicTime::Delta delay = QuicTime::Delta::FromMilliseconds(500);

  // Delay should back off exponentially.
  EXPECT_CALL(*network_change_visitor_, OnPathDegrading());
  for (int i = 0; i < 5; ++i) {
    EXPECT_EQ(delay,
              QuicSentPacketManagerPeer::GetRetransmissionDelay(&manager_));
    delay = delay + delay;
    manager_.OnRetransmissionTimeout();
    RetransmitNextPacket(i + 2);
  }
}

TEST_F(QuicSentPacketManagerTest, RetransmissionDelay) {
  RttStats* rtt_stats = const_cast<RttStats*>(manager_.GetRttStats());
  const int64_t kRttMs = 250;
  const int64_t kDeviationMs = 5;

  rtt_stats->UpdateRtt(QuicTime::Delta::FromMilliseconds(kRttMs),
                       QuicTime::Delta::Zero(), clock_.Now());

  // Initial value is to set the median deviation to half of the initial rtt,
  // the median in then multiplied by a factor of 4 and finally the smoothed rtt
  // is added which is the initial rtt.
  QuicTime::Delta expected_delay =
      QuicTime::Delta::FromMilliseconds(kRttMs + kRttMs / 2 * 4);
  EXPECT_EQ(expected_delay,
            QuicSentPacketManagerPeer::GetRetransmissionDelay(&manager_));

  for (int i = 0; i < 100; ++i) {
    // Run to make sure that we converge.
    rtt_stats->UpdateRtt(
        QuicTime::Delta::FromMilliseconds(kRttMs + kDeviationMs),
        QuicTime::Delta::Zero(), clock_.Now());
    rtt_stats->UpdateRtt(
        QuicTime::Delta::FromMilliseconds(kRttMs - kDeviationMs),
        QuicTime::Delta::Zero(), clock_.Now());
  }
  expected_delay = QuicTime::Delta::FromMilliseconds(kRttMs + kDeviationMs * 4);

  EXPECT_NEAR(kRttMs, rtt_stats->smoothed_rtt().ToMilliseconds(), 1);
  EXPECT_NEAR(expected_delay.ToMilliseconds(),
              QuicSentPacketManagerPeer::GetRetransmissionDelay(&manager_)
                  .ToMilliseconds(),
              1);
}

TEST_F(QuicSentPacketManagerTest, GetLossDelay) {
  auto loss_algorithm = QuicMakeUnique<MockLossAlgorithm>();
  QuicSentPacketManagerPeer::SetLossAlgorithm(&manager_, loss_algorithm.get());

  EXPECT_CALL(*loss_algorithm, GetLossTimeout())
      .WillRepeatedly(Return(QuicTime::Zero()));
  SendDataPacket(1);
  SendDataPacket(2);

  // Handle an ack which causes the loss algorithm to be evaluated and
  // set the loss timeout.
  ExpectAck(2);
  EXPECT_CALL(*loss_algorithm, DetectLosses(_, _, _, _, _));
  QuicAckFrame ack_frame = InitAckFrame(2);
  NackPackets(1, 2, &ack_frame);
  manager_.OnIncomingAck(ack_frame, clock_.Now());

  QuicTime timeout(clock_.Now() + QuicTime::Delta::FromMilliseconds(10));
  EXPECT_CALL(*loss_algorithm, GetLossTimeout())
      .WillRepeatedly(Return(timeout));
  EXPECT_EQ(timeout, manager_.GetRetransmissionTime());

  // Fire the retransmission timeout and ensure the loss detection algorithm
  // is invoked.
  EXPECT_CALL(*loss_algorithm, DetectLosses(_, _, _, _, _));
  manager_.OnRetransmissionTimeout();
}

TEST_F(QuicSentPacketManagerTest, NegotiateTimeLossDetectionFromOptions) {
  EXPECT_EQ(kNack, QuicSentPacketManagerPeer::GetLossAlgorithm(&manager_)
                       ->GetLossDetectionType());

  QuicConfig config;
  QuicTagVector options;
  options.push_back(kTIME);
  QuicConfigPeer::SetReceivedConnectionOptions(&config, options);
  EXPECT_CALL(*send_algorithm_, GetCongestionControlType());
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  manager_.SetFromConfig(config);

  EXPECT_EQ(kTime, QuicSentPacketManagerPeer::GetLossAlgorithm(&manager_)
                       ->GetLossDetectionType());
}

TEST_F(QuicSentPacketManagerTest, NegotiateCongestionControlFromOptions) {
  FLAGS_quic_reloadable_flag_quic_allow_new_bbr = true;
  QuicConfig config;
  QuicTagVector options;

  options.push_back(kRENO);
  QuicConfigPeer::SetReceivedConnectionOptions(&config, options);
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  manager_.SetFromConfig(config);
  EXPECT_EQ(kReno, QuicSentPacketManagerPeer::GetSendAlgorithm(manager_)
                       ->GetCongestionControlType());
  EXPECT_TRUE(QuicSentPacketManagerPeer::UsingPacing(&manager_));

  options.clear();
  options.push_back(kTBBR);
  QuicConfigPeer::SetReceivedConnectionOptions(&config, options);
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  manager_.SetFromConfig(config);
  EXPECT_EQ(kBBR, QuicSentPacketManagerPeer::GetSendAlgorithm(manager_)
                      ->GetCongestionControlType());
  EXPECT_TRUE(QuicSentPacketManagerPeer::UsingPacing(&manager_));

  options.clear();
  options.push_back(kBYTE);
  QuicConfigPeer::SetReceivedConnectionOptions(&config, options);
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  manager_.SetFromConfig(config);
  EXPECT_EQ(kCubic, QuicSentPacketManagerPeer::GetSendAlgorithm(manager_)
                        ->GetCongestionControlType());
  EXPECT_TRUE(QuicSentPacketManagerPeer::UsingPacing(&manager_));

  options.clear();
  options.push_back(kRENO);
  options.push_back(kBYTE);
  QuicConfigPeer::SetReceivedConnectionOptions(&config, options);
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  manager_.SetFromConfig(config);
  EXPECT_EQ(kRenoBytes, QuicSentPacketManagerPeer::GetSendAlgorithm(manager_)
                            ->GetCongestionControlType());
  EXPECT_TRUE(QuicSentPacketManagerPeer::UsingPacing(&manager_));

  // Test with PCC enabled and disabled.
  FLAGS_quic_reloadable_flag_quic_enable_pcc = false;
  const CongestionControlType prior_cc_type =
      QuicSentPacketManagerPeer::GetSendAlgorithm(manager_)
          ->GetCongestionControlType();
  options.clear();
  options.push_back(kTPCC);
  QuicConfigPeer::SetReceivedConnectionOptions(&config, options);
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  manager_.SetFromConfig(config);
  // No change will be made to the congestion-control algorithm.
  // Defaults to current type, as set in previous test.
  EXPECT_NE(kPCC, QuicSentPacketManagerPeer::GetSendAlgorithm(manager_)
                      ->GetCongestionControlType());
  EXPECT_EQ(prior_cc_type, QuicSentPacketManagerPeer::GetSendAlgorithm(manager_)
                               ->GetCongestionControlType());
  EXPECT_TRUE(QuicSentPacketManagerPeer::UsingPacing(&manager_));

  FLAGS_quic_reloadable_flag_quic_enable_pcc = true;
  options.clear();
  options.push_back(kTPCC);
  QuicConfigPeer::SetReceivedConnectionOptions(&config, options);
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  manager_.SetFromConfig(config);
  // Don't check the tag, since the actual implementation is
  // platform-specific (i.e. it may be stubbed out).  If the
  // implementation does return PCC as the type, however, make sure
  // that the packet manager does NOT wrap it with a PacingSender.
  const bool should_pace = QuicSentPacketManagerPeer::GetSendAlgorithm(manager_)
                               ->GetCongestionControlType() != kPCC;
  EXPECT_EQ(should_pace, QuicSentPacketManagerPeer::UsingPacing(&manager_));

  // Make sure that the flag for disabling pacing actually works.
  FLAGS_quic_disable_pacing_for_perf_tests = true;
  options.clear();
  options.push_back(kBYTE);
  QuicConfigPeer::SetReceivedConnectionOptions(&config, options);
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  manager_.SetFromConfig(config);
  EXPECT_EQ(kCubic, QuicSentPacketManagerPeer::GetSendAlgorithm(manager_)
                        ->GetCongestionControlType());
  EXPECT_FALSE(QuicSentPacketManagerPeer::UsingPacing(&manager_));
}

TEST_F(QuicSentPacketManagerTest, NegotiateClientCongestionControlFromOptions) {
  FLAGS_quic_reloadable_flag_quic_allow_new_bbr = true;
  FLAGS_quic_reloadable_flag_quic_enable_pcc = true;
  QuicConfig config;
  QuicTagVector options;

  // No change if the server receives client options.
  const SendAlgorithmInterface* mock_sender =
      QuicSentPacketManagerPeer::GetSendAlgorithm(manager_);
  options.push_back(kRENO);
  config.SetClientConnectionOptions(options);
  EXPECT_CALL(*send_algorithm_, GetCongestionControlType());
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  manager_.SetFromConfig(config);
  EXPECT_EQ(mock_sender, QuicSentPacketManagerPeer::GetSendAlgorithm(manager_));

  // Change the congestion control on the client with client options.
  QuicSentPacketManagerPeer::SetPerspective(&manager_, Perspective::IS_CLIENT);
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  manager_.SetFromConfig(config);
  EXPECT_EQ(kReno, QuicSentPacketManagerPeer::GetSendAlgorithm(manager_)
                       ->GetCongestionControlType());

  options.clear();
  options.push_back(kTBBR);
  config.SetClientConnectionOptions(options);
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  manager_.SetFromConfig(config);
  EXPECT_EQ(kBBR, QuicSentPacketManagerPeer::GetSendAlgorithm(manager_)
                      ->GetCongestionControlType());

  options.clear();
  options.push_back(kBYTE);
  config.SetClientConnectionOptions(options);
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  manager_.SetFromConfig(config);
  EXPECT_EQ(kCubic, QuicSentPacketManagerPeer::GetSendAlgorithm(manager_)
                        ->GetCongestionControlType());

  options.clear();
  options.push_back(kRENO);
  options.push_back(kBYTE);
  config.SetClientConnectionOptions(options);
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  manager_.SetFromConfig(config);
  EXPECT_EQ(kRenoBytes, QuicSentPacketManagerPeer::GetSendAlgorithm(manager_)
                            ->GetCongestionControlType());
}

TEST_F(QuicSentPacketManagerTest, NegotiateNumConnectionsFromOptions) {
  QuicConfig config;
  QuicTagVector options;

  options.push_back(k1CON);
  QuicConfigPeer::SetReceivedConnectionOptions(&config, options);
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  EXPECT_CALL(*send_algorithm_, SetNumEmulatedConnections(1));
  EXPECT_CALL(*send_algorithm_, GetCongestionControlType());
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  manager_.SetFromConfig(config);

  QuicSentPacketManagerPeer::SetPerspective(&manager_, Perspective::IS_CLIENT);
  QuicConfig client_config;
  client_config.SetConnectionOptionsToSend(options);
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  EXPECT_CALL(*send_algorithm_, SetNumEmulatedConnections(1));
  EXPECT_CALL(*send_algorithm_, GetCongestionControlType());
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
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  EXPECT_CALL(*send_algorithm_, GetCongestionControlType());
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
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  EXPECT_CALL(*send_algorithm_, GetCongestionControlType());
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
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  EXPECT_CALL(*send_algorithm_, GetCongestionControlType());
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  manager_.SetFromConfig(client_config);
  EXPECT_EQ(0u, QuicSentPacketManagerPeer::GetMaxTailLossProbes(&manager_));
}

TEST_F(QuicSentPacketManagerTest, NegotiateTLPRttFromOptionsAtServer) {
  QuicConfig config;
  QuicTagVector options;

  options.push_back(kTLPR);
  QuicConfigPeer::SetReceivedConnectionOptions(&config, options);
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  EXPECT_CALL(*send_algorithm_, GetCongestionControlType());
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
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  EXPECT_CALL(*send_algorithm_, GetCongestionControlType());
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
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  EXPECT_CALL(*send_algorithm_, GetCongestionControlType());
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
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  EXPECT_CALL(*send_algorithm_, GetCongestionControlType());
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  manager_.SetFromConfig(client_config);
  EXPECT_TRUE(QuicSentPacketManagerPeer::GetUseNewRto(&manager_));
}

TEST_F(QuicSentPacketManagerTest, NegotiateUndoFromOptionsAtServer) {
  EXPECT_FALSE(QuicSentPacketManagerPeer::GetUndoRetransmits(&manager_));
  QuicConfig config;
  QuicTagVector options;

  options.push_back(kUNDO);
  QuicConfigPeer::SetReceivedConnectionOptions(&config, options);
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  EXPECT_CALL(*send_algorithm_, GetCongestionControlType());
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  manager_.SetFromConfig(config);
  EXPECT_TRUE(QuicSentPacketManagerPeer::GetUndoRetransmits(&manager_));

  // Ensure undo works as intended.
  // Send 5 packets, mark the first 4 for retransmission, and then cancel
  // them when 1 is acked.
  EXPECT_CALL(*send_algorithm_, PacingRate(_))
      .WillRepeatedly(Return(QuicBandwidth::Zero()));
  EXPECT_CALL(*send_algorithm_, GetCongestionWindow())
      .WillOnce(Return(10 * kDefaultTCPMSS));
  const size_t kNumSentPackets = 5;
  for (size_t i = 1; i <= kNumSentPackets; ++i) {
    SendDataPacket(i);
  }
  auto loss_algorithm = QuicMakeUnique<MockLossAlgorithm>();
  QuicSentPacketManagerPeer::SetLossAlgorithm(&manager_, loss_algorithm.get());
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _));
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  SendAlgorithmInterface::CongestionVector lost_packets;
  for (size_t i = 1; i < kNumSentPackets; ++i) {
    lost_packets.push_back(std::make_pair(i, kMaxPacketSize));
  }
  EXPECT_CALL(*loss_algorithm, DetectLosses(_, _, _, _, _))
      .WillOnce(SetArgPointee<4>(lost_packets));
  QuicAckFrame ack_frame = InitAckFrame(kNumSentPackets);
  NackPackets(1, kNumSentPackets, &ack_frame);
  // Congestion block the sending right before losing the packets.
  EXPECT_CALL(*send_algorithm_, TimeUntilSend(_, _))
      .WillRepeatedly(Return(QuicTime::Delta::Infinite()));
  manager_.OnIncomingAck(ack_frame, clock_.Now());
  EXPECT_TRUE(manager_.HasPendingRetransmissions());
  EXPECT_EQ(0u, BytesInFlight());

  // Ack 1 and ensure the retransmissions are cancelled and put back in flight.
  EXPECT_CALL(*loss_algorithm, DetectLosses(_, _, _, _, _));
  ack_frame = InitAckFrame(5);
  NackPackets(2, kNumSentPackets, &ack_frame);
  manager_.OnIncomingAck(ack_frame, clock_.Now());
  EXPECT_FALSE(manager_.HasPendingRetransmissions());
  EXPECT_EQ(3u * kDefaultLength, BytesInFlight());
}

TEST_F(QuicSentPacketManagerTest, NegotiateUndoFromOptionsAtClient) {
  EXPECT_FALSE(QuicSentPacketManagerPeer::GetUndoRetransmits(&manager_));
  QuicConfig client_config;
  QuicTagVector options;

  options.push_back(kUNDO);
  QuicSentPacketManagerPeer::SetPerspective(&manager_, Perspective::IS_CLIENT);
  client_config.SetConnectionOptionsToSend(options);
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  EXPECT_CALL(*send_algorithm_, GetCongestionControlType());
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  manager_.SetFromConfig(client_config);
  EXPECT_TRUE(QuicSentPacketManagerPeer::GetUndoRetransmits(&manager_));
}

TEST_F(QuicSentPacketManagerTest, UseInitialRoundTripTimeToSend) {
  uint32_t initial_rtt_us = 325000;
  EXPECT_NE(initial_rtt_us,
            manager_.GetRttStats()->smoothed_rtt().ToMicroseconds());

  QuicConfig config;
  config.SetInitialRoundTripTimeUsToSend(initial_rtt_us);
  EXPECT_CALL(*send_algorithm_, GetCongestionControlType());
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
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
  RttStats* rtt_stats = const_cast<RttStats*>(manager_.GetRttStats());
  int64_t default_init_rtt = rtt_stats->initial_rtt_us();
  rtt_stats->set_initial_rtt_us(default_init_rtt * 2);
  EXPECT_EQ(2 * default_init_rtt, rtt_stats->initial_rtt_us());

  QuicSentPacketManagerPeer::SetConsecutiveRtoCount(&manager_, 1);
  EXPECT_EQ(1u, manager_.GetConsecutiveRtoCount());
  QuicSentPacketManagerPeer::SetConsecutiveTlpCount(&manager_, 2);
  EXPECT_EQ(2u, manager_.GetConsecutiveTlpCount());

  EXPECT_CALL(*send_algorithm_, OnConnectionMigration());
  manager_.OnConnectionMigration(IPV4_TO_IPV4_CHANGE);

  EXPECT_EQ(default_init_rtt, rtt_stats->initial_rtt_us());
  EXPECT_EQ(0u, manager_.GetConsecutiveRtoCount());
  EXPECT_EQ(0u, manager_.GetConsecutiveTlpCount());
}

TEST_F(QuicSentPacketManagerTest, ConnectionMigrationIPSubnetChange) {
  RttStats* rtt_stats = const_cast<RttStats*>(manager_.GetRttStats());
  int64_t default_init_rtt = rtt_stats->initial_rtt_us();
  rtt_stats->set_initial_rtt_us(default_init_rtt * 2);
  EXPECT_EQ(2 * default_init_rtt, rtt_stats->initial_rtt_us());

  QuicSentPacketManagerPeer::SetConsecutiveRtoCount(&manager_, 1);
  EXPECT_EQ(1u, manager_.GetConsecutiveRtoCount());
  QuicSentPacketManagerPeer::SetConsecutiveTlpCount(&manager_, 2);
  EXPECT_EQ(2u, manager_.GetConsecutiveTlpCount());

  manager_.OnConnectionMigration(IPV4_SUBNET_CHANGE);

  EXPECT_EQ(2 * default_init_rtt, rtt_stats->initial_rtt_us());
  EXPECT_EQ(1u, manager_.GetConsecutiveRtoCount());
  EXPECT_EQ(2u, manager_.GetConsecutiveTlpCount());
}

TEST_F(QuicSentPacketManagerTest, ConnectionMigrationPortChange) {
  RttStats* rtt_stats = const_cast<RttStats*>(manager_.GetRttStats());
  int64_t default_init_rtt = rtt_stats->initial_rtt_us();
  rtt_stats->set_initial_rtt_us(default_init_rtt * 2);
  EXPECT_EQ(2 * default_init_rtt, rtt_stats->initial_rtt_us());

  QuicSentPacketManagerPeer::SetConsecutiveRtoCount(&manager_, 1);
  EXPECT_EQ(1u, manager_.GetConsecutiveRtoCount());
  QuicSentPacketManagerPeer::SetConsecutiveTlpCount(&manager_, 2);
  EXPECT_EQ(2u, manager_.GetConsecutiveTlpCount());

  manager_.OnConnectionMigration(PORT_CHANGE);

  EXPECT_EQ(2 * default_init_rtt, rtt_stats->initial_rtt_us());
  EXPECT_EQ(1u, manager_.GetConsecutiveRtoCount());
  EXPECT_EQ(2u, manager_.GetConsecutiveTlpCount());
}

TEST_F(QuicSentPacketManagerTest, PathMtuIncreased) {
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, BytesInFlight(), 1, _, _))
      .Times(1)
      .WillOnce(Return(true));
  SerializedPacket packet(1, PACKET_6BYTE_PACKET_NUMBER, nullptr,
                          kDefaultLength + 100, false, false);
  manager_.OnPacketSent(&packet, 0, clock_.Now(), NOT_RETRANSMISSION,
                        HAS_RETRANSMITTABLE_DATA);

  // Ack the large packet and expect the path MTU to increase.
  ExpectAck(1);
  EXPECT_CALL(*network_change_visitor_,
              OnPathMtuIncreased(kDefaultLength + 100));
  QuicAckFrame ack_frame = InitAckFrame(1);
  manager_.OnIncomingAck(ack_frame, clock_.Now());
}

}  // namespace
}  // namespace test
}  // namespace net
