// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/quic_multipath_received_packet_manager.h"

#include "net/quic/core/quic_connection_stats.h"
#include "net/quic/platform/api/quic_ptr_util.h"
#include "net/quic/test_tools/quic_test_utils.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using testing::Return;
using testing::_;

namespace net {
namespace test {

class QuicMultipathReceivedPacketManagerPeer {
 public:
  static bool PathReceivedPacketManagerExists(
      QuicMultipathReceivedPacketManager* multipath_manager,
      QuicPathId path_id) {
    return multipath_manager->path_managers_.count(path_id);
  }

  static void SetPathReceivedPacketManager(
      QuicMultipathReceivedPacketManager* multipath_manager,
      QuicPathId path_id,
      std::unique_ptr<QuicReceivedPacketManager> manager) {
    multipath_manager->path_managers_[path_id] = std::move(manager);
  }
};

namespace {

const QuicPathId kPathId1 = 1;
const QuicPathId kPathId2 = 2;
const QuicPathId kPathId3 = 3;

class QuicMultipathReceivedPacketManagerTest : public testing::Test {
 public:
  QuicMultipathReceivedPacketManagerTest()
      : multipath_manager_(&stats_),
        manager_0_(new MockReceivedPacketManager(&stats_)),
        manager_1_(new MockReceivedPacketManager(&stats_)) {
    QuicMultipathReceivedPacketManagerPeer::SetPathReceivedPacketManager(
        &multipath_manager_, kDefaultPathId, QuicWrapUnique(manager_0_));
    QuicMultipathReceivedPacketManagerPeer::SetPathReceivedPacketManager(
        &multipath_manager_, kPathId1, QuicWrapUnique(manager_1_));
  }

  QuicConnectionStats stats_;
  QuicMultipathReceivedPacketManager multipath_manager_;
  MockReceivedPacketManager* manager_0_;
  MockReceivedPacketManager* manager_1_;
  QuicPacketHeader header_;
};

TEST_F(QuicMultipathReceivedPacketManagerTest, OnPathCreatedAndClosed) {
  EXPECT_TRUE(
      QuicMultipathReceivedPacketManagerPeer::PathReceivedPacketManagerExists(
          &multipath_manager_, kDefaultPathId));
  EXPECT_TRUE(
      QuicMultipathReceivedPacketManagerPeer::PathReceivedPacketManagerExists(
          &multipath_manager_, kPathId1));
  EXPECT_QUIC_BUG(multipath_manager_.OnPathCreated(kDefaultPathId, &stats_),
                  "Received packet manager of path already exists");
  // Path 2 created.
  multipath_manager_.OnPathCreated(kPathId2, &stats_);
  EXPECT_TRUE(
      QuicMultipathReceivedPacketManagerPeer::PathReceivedPacketManagerExists(
          &multipath_manager_, kPathId2));
  EXPECT_FALSE(
      QuicMultipathReceivedPacketManagerPeer::PathReceivedPacketManagerExists(
          &multipath_manager_, kPathId3));
  // Path 3 created.
  multipath_manager_.OnPathCreated(kPathId3, &stats_);
  EXPECT_TRUE(
      QuicMultipathReceivedPacketManagerPeer::PathReceivedPacketManagerExists(
          &multipath_manager_, kPathId3));

  // Path 0 closed.
  multipath_manager_.OnPathClosed(kDefaultPathId);
  EXPECT_FALSE(
      QuicMultipathReceivedPacketManagerPeer::PathReceivedPacketManagerExists(
          &multipath_manager_, kDefaultPathId));
  EXPECT_QUIC_BUG(multipath_manager_.OnPathClosed(kDefaultPathId),
                  "Received packet manager of path does not exist");
}

TEST_F(QuicMultipathReceivedPacketManagerTest, RecordPacketReceived) {
  EXPECT_CALL(*manager_0_, RecordPacketReceived(_, _)).Times(1);
  multipath_manager_.RecordPacketReceived(kDefaultPathId, header_,
                                          QuicTime::Zero());
  EXPECT_QUIC_BUG(multipath_manager_.RecordPacketReceived(kPathId2, header_,
                                                          QuicTime::Zero()),
                  "Received a packet on a non-existent path");
}

TEST_F(QuicMultipathReceivedPacketManagerTest, IsMissing) {
  EXPECT_CALL(*manager_0_, IsMissing(header_.packet_number))
      .WillOnce(Return(true));
  EXPECT_CALL(*manager_1_, IsMissing(header_.packet_number))
      .WillOnce(Return(false));
  EXPECT_TRUE(
      multipath_manager_.IsMissing(kDefaultPathId, header_.packet_number));
  EXPECT_FALSE(multipath_manager_.IsMissing(kPathId1, header_.packet_number));
  EXPECT_QUIC_BUG(multipath_manager_.IsMissing(kPathId2, header_.packet_number),
                  "Check whether a packet is missing on a non-existent path");
}

TEST_F(QuicMultipathReceivedPacketManagerTest, IsAwaitingPacket) {
  EXPECT_CALL(*manager_0_, IsAwaitingPacket(header_.packet_number))
      .WillOnce(Return(true));
  EXPECT_CALL(*manager_1_, IsAwaitingPacket(header_.packet_number))
      .WillOnce(Return(false));
  EXPECT_TRUE(multipath_manager_.IsAwaitingPacket(kDefaultPathId,
                                                  header_.packet_number));
  EXPECT_FALSE(
      multipath_manager_.IsAwaitingPacket(kPathId1, header_.packet_number));
  EXPECT_QUIC_BUG(
      multipath_manager_.IsAwaitingPacket(kPathId2, header_.packet_number),
      "Check whether a packet is awaited on a non-existent path");
}

TEST_F(QuicMultipathReceivedPacketManagerTest, HasNewMissingPackets) {
  EXPECT_CALL(*manager_0_, HasNewMissingPackets()).WillOnce(Return(true));
  EXPECT_CALL(*manager_1_, HasNewMissingPackets()).WillOnce(Return(false));
  EXPECT_TRUE(multipath_manager_.HasNewMissingPackets(kDefaultPathId));
  EXPECT_FALSE(multipath_manager_.HasNewMissingPackets(kPathId1));
  EXPECT_QUIC_BUG(
      multipath_manager_.HasNewMissingPackets(kPathId2),
      "Check whether has new missing packets on a non-existent path");
}

}  // namespace
}  // namespace test
}  // namespace net
