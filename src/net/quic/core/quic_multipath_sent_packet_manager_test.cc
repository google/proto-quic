// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/quic_multipath_sent_packet_manager.h"

#include "net/quic/core/quic_bug_tracker.h"
#include "net/quic/test_tools/quic_multipath_sent_packet_manager_peer.h"
#include "net/quic/test_tools/quic_test_utils.h"
#include "net/test/gtest_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using testing::Return;
using testing::StrictMock;
using testing::_;

namespace net {
namespace test {

namespace {

const QuicPathId kTestPathId1 = 1;
const QuicPathId kTestPathId2 = 2;
const QuicPathId kTestPathId3 = 3;

class QuicMultipathSentPacketManagerTest : public testing::Test {
 public:
  QuicMultipathSentPacketManagerTest()
      : manager_0_(new StrictMock<MockSentPacketManager>),
        manager_1_(new StrictMock<MockSentPacketManager>),
        manager_2_(new StrictMock<MockSentPacketManager>),
        multipath_manager_(manager_0_, &delegate_) {
    // Paths 0 and 1 are active, and path 2 is closing.
    QuicMultipathSentPacketManagerPeer::AddPathWithActiveState(
        &multipath_manager_, manager_1_);
    QuicMultipathSentPacketManagerPeer::AddPathWithCloseState(
        &multipath_manager_, manager_2_);
  }

  ~QuicMultipathSentPacketManagerTest() override {}

  MockSentPacketManager* manager_0_;
  MockSentPacketManager* manager_1_;
  MockSentPacketManager* manager_2_;
  QuicMultipathSentPacketManager multipath_manager_;
  MockClock clock_;
  StrictMock<MockConnectionCloseDelegate> delegate_;
};

TEST_F(QuicMultipathSentPacketManagerTest, SetFromConfig) {
  EXPECT_CALL(*manager_0_, SetFromConfig(_)).Times(1);
  EXPECT_CALL(*manager_1_, SetFromConfig(_)).Times(1);
  EXPECT_CALL(*manager_2_, SetFromConfig(_)).Times(1);
  QuicConfig config;
  multipath_manager_.SetFromConfig(config);
}

TEST_F(QuicMultipathSentPacketManagerTest, ResumeConnectionState) {
  EXPECT_CALL(*manager_0_, ResumeConnectionState(_, true));
  multipath_manager_.ResumeConnectionState(CachedNetworkParameters(), true);
}

TEST_F(QuicMultipathSentPacketManagerTest, SetNumOpenStreams) {
  size_t kNumStreams = 10;
  EXPECT_CALL(*manager_0_, SetNumOpenStreams(kNumStreams));
  EXPECT_CALL(*manager_1_, SetNumOpenStreams(kNumStreams));
  EXPECT_CALL(*manager_2_, SetNumOpenStreams(kNumStreams));
  multipath_manager_.SetNumOpenStreams(kNumStreams);
}

TEST_F(QuicMultipathSentPacketManagerTest, SetMaxPacingRate) {
  QuicBandwidth kBandwidth = QuicBandwidth::FromBitsPerSecond(1000);
  EXPECT_CALL(*manager_0_, SetMaxPacingRate(kBandwidth));
  multipath_manager_.SetMaxPacingRate(kBandwidth);
}

TEST_F(QuicMultipathSentPacketManagerTest, SetHandshakeConfirmed) {
  EXPECT_CALL(*manager_0_, SetHandshakeConfirmed());
  multipath_manager_.SetHandshakeConfirmed();
}

TEST_F(QuicMultipathSentPacketManagerTest, OnIncomingAck) {
  QuicAckFrame frame0;
  QuicAckFrame frame1;
  frame1.path_id = kTestPathId1;
  QuicAckFrame frame2;
  frame2.path_id = kTestPathId2;
  QuicAckFrame frame3;
  frame3.path_id = kTestPathId3;
  EXPECT_CALL(*manager_0_, OnIncomingAck(_, QuicTime::Zero()));
  EXPECT_CALL(*manager_1_, OnIncomingAck(_, QuicTime::Zero()));
  EXPECT_CALL(*manager_2_, OnIncomingAck(_, QuicTime::Zero())).Times(0);
  multipath_manager_.OnIncomingAck(frame0, QuicTime::Zero());
  multipath_manager_.OnIncomingAck(frame1, QuicTime::Zero());
  multipath_manager_.OnIncomingAck(frame2, QuicTime::Zero());
  multipath_manager_.OnIncomingAck(frame3, QuicTime::Zero());
}

TEST_F(QuicMultipathSentPacketManagerTest, RetransmitUnackedPackets) {
  EXPECT_CALL(*manager_0_, RetransmitUnackedPackets(HANDSHAKE_RETRANSMISSION));
  multipath_manager_.RetransmitUnackedPackets(HANDSHAKE_RETRANSMISSION);
}

TEST_F(QuicMultipathSentPacketManagerTest, MaybeRetransmitTailLossProbe) {
  EXPECT_CALL(*manager_0_, MaybeRetransmitTailLossProbe())
      .WillOnce(Return(false));
  EXPECT_CALL(*manager_1_, MaybeRetransmitTailLossProbe())
      .WillOnce(Return(false));
  EXPECT_FALSE(multipath_manager_.MaybeRetransmitTailLossProbe());
  EXPECT_CALL(*manager_0_, MaybeRetransmitTailLossProbe())
      .WillOnce(Return(false));
  EXPECT_CALL(*manager_1_, MaybeRetransmitTailLossProbe())
      .WillOnce(Return(true));
  EXPECT_TRUE(multipath_manager_.MaybeRetransmitTailLossProbe());
}

TEST_F(QuicMultipathSentPacketManagerTest, NeuterUnencryptedPackets) {
  EXPECT_CALL(*manager_0_, NeuterUnencryptedPackets());
  multipath_manager_.NeuterUnencryptedPackets();
}

TEST_F(QuicMultipathSentPacketManagerTest, HasPendingRetransmissions) {
  EXPECT_CALL(*manager_0_, HasPendingRetransmissions()).WillOnce(Return(true));
  EXPECT_TRUE(multipath_manager_.HasPendingRetransmissions());
}

TEST_F(QuicMultipathSentPacketManagerTest, NextPendingRetransmission) {
  SerializedPacket packet(kDefaultPathId, 1, PACKET_6BYTE_PACKET_NUMBER,
                          nullptr, 1250, false, false);
  QuicPendingRetransmission retransmission(
      packet.path_id, packet.packet_number, LOSS_RETRANSMISSION,
      packet.retransmittable_frames, packet.has_crypto_handshake,
      packet.num_padding_bytes, packet.encryption_level,
      packet.packet_number_length);
  EXPECT_CALL(*manager_0_, NextPendingRetransmission())
      .WillOnce(Return(retransmission));
  multipath_manager_.NextPendingRetransmission();
}

TEST_F(QuicMultipathSentPacketManagerTest, HasUnackedPackets) {
  EXPECT_CALL(*manager_0_, HasUnackedPackets()).WillOnce(Return(false));
  EXPECT_CALL(*manager_1_, HasUnackedPackets()).WillOnce(Return(false));
  EXPECT_CALL(*manager_2_, HasUnackedPackets()).Times(0);
  EXPECT_FALSE(multipath_manager_.HasUnackedPackets());
  EXPECT_CALL(*manager_0_, HasUnackedPackets()).WillOnce(Return(false));
  EXPECT_CALL(*manager_1_, HasUnackedPackets()).WillOnce(Return(true));
  EXPECT_TRUE(multipath_manager_.HasUnackedPackets());
}

TEST_F(QuicMultipathSentPacketManagerTest, GetLeastUnacked) {
  EXPECT_CALL(*manager_0_, GetLeastUnacked(kDefaultPathId)).WillOnce(Return(2));
  EXPECT_CALL(*manager_1_, GetLeastUnacked(kTestPathId1)).WillOnce(Return(3));
  EXPECT_CALL(*manager_2_, GetLeastUnacked(kTestPathId2)).WillOnce(Return(4));
  EXPECT_EQ(2u, multipath_manager_.GetLeastUnacked(kDefaultPathId));
  EXPECT_EQ(3u, multipath_manager_.GetLeastUnacked(kTestPathId1));
  EXPECT_EQ(4u, multipath_manager_.GetLeastUnacked(kTestPathId2));
  EXPECT_QUIC_BUG(multipath_manager_.GetLeastUnacked(kTestPathId3), "");
}

TEST_F(QuicMultipathSentPacketManagerTest, OnPacketSent) {
  SerializedPacket packet0(kDefaultPathId, 1, PACKET_6BYTE_PACKET_NUMBER,
                           nullptr, 1250, false, false);
  SerializedPacket packet1(kTestPathId1, 1, PACKET_6BYTE_PACKET_NUMBER, nullptr,
                           1250, false, false);
  SerializedPacket packet2(kTestPathId2, 1, PACKET_6BYTE_PACKET_NUMBER, nullptr,
                           1250, false, false);
  SerializedPacket packet3(kTestPathId3, 1, PACKET_6BYTE_PACKET_NUMBER, nullptr,
                           1250, false, false);
  EXPECT_CALL(*manager_0_,
              OnPacketSent(&packet0, kInvalidPathId, 0, clock_.Now(),
                           NOT_RETRANSMISSION, HAS_RETRANSMITTABLE_DATA));
  multipath_manager_.OnPacketSent(&packet0, kInvalidPathId, 0, clock_.Now(),
                                  NOT_RETRANSMISSION, HAS_RETRANSMITTABLE_DATA);
  EXPECT_CALL(*manager_1_,
              OnPacketSent(&packet1, kInvalidPathId, 0, clock_.Now(),
                           NOT_RETRANSMISSION, HAS_RETRANSMITTABLE_DATA));
  multipath_manager_.OnPacketSent(&packet1, kInvalidPathId, 0, clock_.Now(),
                                  NOT_RETRANSMISSION, HAS_RETRANSMITTABLE_DATA);
  EXPECT_CALL(*manager_2_, OnPacketSent(_, _, _, _, _, _)).Times(0);
  EXPECT_CALL(delegate_,
              OnUnrecoverableError(QUIC_MULTIPATH_PATH_NOT_ACTIVE, _, _));
  EXPECT_QUIC_BUG(multipath_manager_.OnPacketSent(
                      &packet2, kInvalidPathId, 0, clock_.Now(),
                      NOT_RETRANSMISSION, HAS_RETRANSMITTABLE_DATA),
                  "");
  EXPECT_CALL(delegate_,
              OnUnrecoverableError(QUIC_MULTIPATH_PATH_DOES_NOT_EXIST, _, _));
  EXPECT_QUIC_BUG(multipath_manager_.OnPacketSent(
                      &packet3, kInvalidPathId, 0, clock_.Now(),
                      NOT_RETRANSMISSION, HAS_RETRANSMITTABLE_DATA),
                  "");
}

TEST_F(QuicMultipathSentPacketManagerTest, OnRetransmissionTimeout) {
  QuicTime time0 = clock_.Now() + QuicTime::Delta::FromMilliseconds(50);
  QuicTime time1 = clock_.Now() + QuicTime::Delta::FromMilliseconds(100);
  EXPECT_CALL(*manager_0_, GetRetransmissionTime()).WillOnce(Return(time0));
  EXPECT_CALL(*manager_1_, GetRetransmissionTime()).WillOnce(Return(time1));
  EXPECT_CALL(*manager_0_, OnRetransmissionTimeout());
  multipath_manager_.OnRetransmissionTimeout();
}

TEST_F(QuicMultipathSentPacketManagerTest, TimeUntilSend) {
  QuicPathId path_id = kInvalidPathId;
  EXPECT_CALL(*manager_0_, TimeUntilSend(clock_.Now(), &path_id))
      .WillOnce(Return(QuicTime::Delta::FromMilliseconds(200)));
  EXPECT_CALL(*manager_1_, TimeUntilSend(clock_.Now(), &path_id))
      .WillOnce(Return(QuicTime::Delta::FromMilliseconds(100)));
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(100),
            multipath_manager_.TimeUntilSend(clock_.Now(), &path_id));
  EXPECT_EQ(kTestPathId1, path_id);
}

TEST_F(QuicMultipathSentPacketManagerTest, GetRetransmissionTime) {
  QuicTime time0 = clock_.Now() + QuicTime::Delta::FromMilliseconds(200);
  QuicTime time1 = clock_.Now() + QuicTime::Delta::FromMilliseconds(100);
  EXPECT_CALL(*manager_0_, GetRetransmissionTime()).WillOnce(Return(time0));
  EXPECT_CALL(*manager_1_, GetRetransmissionTime()).WillOnce(Return(time1));
  EXPECT_EQ(time1, multipath_manager_.GetRetransmissionTime());
}

TEST_F(QuicMultipathSentPacketManagerTest, GetRttStats) {
  EXPECT_CALL(*manager_0_, GetRttStats());
  multipath_manager_.GetRttStats();
}

TEST_F(QuicMultipathSentPacketManagerTest, BandwidthEstimate) {
  QuicBandwidth bandwidth = QuicBandwidth::FromKBitsPerSecond(100);
  EXPECT_CALL(*manager_0_, BandwidthEstimate()).WillOnce(Return(bandwidth));
  EXPECT_EQ(bandwidth, multipath_manager_.BandwidthEstimate());
}

TEST_F(QuicMultipathSentPacketManagerTest, GetCongestionWindowInTcpMss) {
  EXPECT_CALL(*manager_0_, GetCongestionWindowInTcpMss()).WillOnce(Return(100));
  EXPECT_EQ(100u, multipath_manager_.GetCongestionWindowInTcpMss());
}

TEST_F(QuicMultipathSentPacketManagerTest, EstimateMaxPacketsInFlight) {
  QuicByteCount max_packet_length = 1250;
  EXPECT_CALL(*manager_0_, EstimateMaxPacketsInFlight(max_packet_length))
      .WillOnce(Return(100));
  EXPECT_CALL(*manager_1_, EstimateMaxPacketsInFlight(max_packet_length))
      .WillOnce(Return(200));
  EXPECT_CALL(*manager_2_, EstimateMaxPacketsInFlight(max_packet_length))
      .WillOnce(Return(300));
  EXPECT_EQ(300u,
            multipath_manager_.EstimateMaxPacketsInFlight(max_packet_length));
}

TEST_F(QuicMultipathSentPacketManagerTest, GetSlowStartThresholdInTcpMss) {
  EXPECT_CALL(*manager_0_, GetSlowStartThresholdInTcpMss())
      .WillOnce(Return(100));
  EXPECT_EQ(100u, multipath_manager_.GetSlowStartThresholdInTcpMss());
}

TEST_F(QuicMultipathSentPacketManagerTest, CancelRetransmissionsForStream) {
  EXPECT_CALL(*manager_0_, CancelRetransmissionsForStream(1));
  EXPECT_CALL(*manager_1_, CancelRetransmissionsForStream(1));
  EXPECT_CALL(*manager_2_, CancelRetransmissionsForStream(1));
  multipath_manager_.CancelRetransmissionsForStream(1);
}

TEST_F(QuicMultipathSentPacketManagerTest, OnConnectionMigration) {
  EXPECT_CALL(*manager_0_, OnConnectionMigration(kDefaultPathId, PORT_CHANGE));
  EXPECT_CALL(*manager_2_, OnConnectionMigration(_, _)).Times(0);
  multipath_manager_.OnConnectionMigration(kDefaultPathId, PORT_CHANGE);
  EXPECT_CALL(delegate_,
              OnUnrecoverableError(QUIC_MULTIPATH_PATH_NOT_ACTIVE, _, _));
  EXPECT_QUIC_BUG(
      multipath_manager_.OnConnectionMigration(kTestPathId2, PORT_CHANGE), "");
  EXPECT_CALL(delegate_,
              OnUnrecoverableError(QUIC_MULTIPATH_PATH_DOES_NOT_EXIST, _, _));
  EXPECT_QUIC_BUG(
      multipath_manager_.OnConnectionMigration(kTestPathId3, PORT_CHANGE), "");
}

TEST_F(QuicMultipathSentPacketManagerTest, SetDebugDelegate) {
  EXPECT_CALL(*manager_0_, SetDebugDelegate(nullptr));
  EXPECT_CALL(*manager_1_, SetDebugDelegate(nullptr));
  EXPECT_CALL(*manager_2_, SetDebugDelegate(nullptr));
  multipath_manager_.SetDebugDelegate(nullptr);
}

TEST_F(QuicMultipathSentPacketManagerTest, GetLargestObserved) {
  EXPECT_CALL(*manager_0_, GetLargestObserved(kDefaultPathId))
      .WillOnce(Return(10));
  EXPECT_CALL(*manager_1_, GetLargestObserved(kTestPathId1))
      .WillOnce(Return(11));
  EXPECT_CALL(*manager_2_, GetLargestObserved(kTestPathId2))
      .WillOnce(Return(12));
  EXPECT_EQ(10u, multipath_manager_.GetLargestObserved(kDefaultPathId));
  EXPECT_EQ(11u, multipath_manager_.GetLargestObserved(kTestPathId1));
  EXPECT_EQ(12u, multipath_manager_.GetLargestObserved(kTestPathId2));
  EXPECT_QUIC_BUG(multipath_manager_.GetLargestObserved(kTestPathId3), "");
}

TEST_F(QuicMultipathSentPacketManagerTest, GetLargestSentPacket) {
  EXPECT_CALL(*manager_0_, GetLargestSentPacket(kDefaultPathId))
      .WillOnce(Return(10));
  EXPECT_CALL(*manager_1_, GetLargestSentPacket(kTestPathId1))
      .WillOnce(Return(11));
  EXPECT_CALL(*manager_2_, GetLargestSentPacket(kTestPathId2))
      .WillOnce(Return(12));
  EXPECT_EQ(10u, multipath_manager_.GetLargestSentPacket(kDefaultPathId));
  EXPECT_EQ(11u, multipath_manager_.GetLargestSentPacket(kTestPathId1));
  EXPECT_EQ(12u, multipath_manager_.GetLargestSentPacket(kTestPathId2));
  EXPECT_QUIC_BUG(multipath_manager_.GetLargestSentPacket(kTestPathId3), "");
}

TEST_F(QuicMultipathSentPacketManagerTest, GetLeastPacketAwaitedByPeer) {
  EXPECT_CALL(*manager_0_, GetLeastPacketAwaitedByPeer(kDefaultPathId))
      .WillOnce(Return(10));
  EXPECT_CALL(*manager_1_, GetLeastPacketAwaitedByPeer(kTestPathId1))
      .WillOnce(Return(11));
  EXPECT_CALL(*manager_2_, GetLeastPacketAwaitedByPeer(kTestPathId2))
      .WillOnce(Return(12));
  EXPECT_EQ(10u,
            multipath_manager_.GetLeastPacketAwaitedByPeer(kDefaultPathId));
  EXPECT_EQ(11u, multipath_manager_.GetLeastPacketAwaitedByPeer(kTestPathId1));
  EXPECT_EQ(12u, multipath_manager_.GetLeastPacketAwaitedByPeer(kTestPathId2));
  EXPECT_QUIC_BUG(multipath_manager_.GetLeastPacketAwaitedByPeer(kTestPathId3),
                  "");
}

TEST_F(QuicMultipathSentPacketManagerTest, SetNetworkChangeVisitor) {
  EXPECT_CALL(*manager_0_, SetNetworkChangeVisitor(nullptr));
  EXPECT_CALL(*manager_1_, SetNetworkChangeVisitor(nullptr));
  multipath_manager_.SetNetworkChangeVisitor(nullptr);
}

TEST_F(QuicMultipathSentPacketManagerTest, InSlowStart) {
  EXPECT_CALL(*manager_0_, InSlowStart()).WillOnce(Return(true));
  EXPECT_TRUE(multipath_manager_.InSlowStart());
}

TEST_F(QuicMultipathSentPacketManagerTest, GetConsecutiveRtoCount) {
  EXPECT_CALL(*manager_0_, GetConsecutiveRtoCount()).WillOnce(Return(4));
  EXPECT_EQ(4u, multipath_manager_.GetConsecutiveRtoCount());
}

TEST_F(QuicMultipathSentPacketManagerTest, GetConsecutiveTlpCount) {
  EXPECT_CALL(*manager_0_, GetConsecutiveTlpCount()).WillOnce(Return(3));
  EXPECT_EQ(3u, multipath_manager_.GetConsecutiveTlpCount());
}

TEST_F(QuicMultipathSentPacketManagerTest, OnApplicationLimited) {
  EXPECT_CALL(*manager_0_, OnApplicationLimited()).Times(1);
  EXPECT_CALL(*manager_1_, OnApplicationLimited()).Times(1);
  EXPECT_CALL(*manager_2_, OnApplicationLimited()).Times(0);
  multipath_manager_.OnApplicationLimited();
}

}  // namespace
}  // namespace test
}  // namespace net
