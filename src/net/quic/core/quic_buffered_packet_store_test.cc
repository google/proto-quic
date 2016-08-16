// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/quic_buffered_packet_store.h"

#include <list>
#include <string>

#include "base/stl_util.h"
#include "net/quic/test_tools/mock_clock.h"
#include "net/quic/test_tools/quic_buffered_packet_store_peer.h"
#include "net/quic/test_tools/quic_test_utils.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using std::list;
using std::string;

namespace net {

typedef QuicBufferedPacketStore::BufferedPacket BufferedPacket;
typedef QuicBufferedPacketStore::EnqueuePacketResult EnqueuePacketResult;

static const size_t kDefaultMaxConnectionsInStore = 100;

namespace test {
namespace {

typedef QuicBufferedPacketStore::BufferedPacket BufferedPacket;
typedef QuicBufferedPacketStore::BufferedPacketList BufferedPacketList;

class QuicBufferedPacketStoreVisitor
    : public QuicBufferedPacketStore::VisitorInterface {
 public:
  QuicBufferedPacketStoreVisitor() {}

  ~QuicBufferedPacketStoreVisitor() override {}

  void OnExpiredPackets(QuicConnectionId connection_id,
                        BufferedPacketList early_arrived_packets) override {
    last_expired_packet_queue_ = std::move(early_arrived_packets);
  }

  // The packets queue for most recently expirect connection.
  BufferedPacketList last_expired_packet_queue_;
};

class QuicBufferedPacketStoreTest : public ::testing::Test {
 public:
  QuicBufferedPacketStoreTest()
      : store_(&visitor_, &clock_, &alarm_factory_),
        server_address_(Loopback6(), 65535),
        client_address_(Loopback6(), 65535),
        packet_content_("some encrypted content"),
        packet_time_(QuicTime::Zero() + QuicTime::Delta::FromMicroseconds(42)),
        data_packet_(packet_content_.data(),
                     packet_content_.size(),
                     packet_time_) {}

 protected:
  QuicBufferedPacketStoreVisitor visitor_;
  MockClock clock_;
  MockAlarmFactory alarm_factory_;
  QuicBufferedPacketStore store_;
  IPEndPoint server_address_;
  IPEndPoint client_address_;
  string packet_content_;
  QuicTime packet_time_;
  QuicReceivedPacket data_packet_;
};

TEST_F(QuicBufferedPacketStoreTest, SimpleEnqueueAndDeliverPacket) {
  QuicConnectionId connection_id = 1;
  store_.EnqueuePacket(connection_id, data_packet_, server_address_,
                       client_address_);
  EXPECT_TRUE(store_.HasBufferedPackets(connection_id));
  list<BufferedPacket> queue = store_.DeliverPackets(connection_id);
  ASSERT_EQ(1u, queue.size());
  // Check content of the only packet in the queue.
  EXPECT_EQ(packet_content_, queue.front().packet->AsStringPiece());
  EXPECT_EQ(packet_time_, queue.front().packet->receipt_time());
  EXPECT_EQ(client_address_, queue.front().client_address);
  EXPECT_EQ(server_address_, queue.front().server_address);
  // No more packets on connection 1 should remain in the store.
  EXPECT_TRUE(store_.DeliverPackets(connection_id).empty());
  EXPECT_FALSE(store_.HasBufferedPackets(connection_id));
}

TEST_F(QuicBufferedPacketStoreTest, DifferentPacketAddressOnOneConnection) {
  IPEndPoint addr_with_new_port(Loopback4(), 256);
  QuicConnectionId connection_id = 1;
  store_.EnqueuePacket(connection_id, data_packet_, server_address_,
                       client_address_);
  store_.EnqueuePacket(connection_id, data_packet_, server_address_,
                       addr_with_new_port);
  list<BufferedPacket> queue = store_.DeliverPackets(connection_id);
  ASSERT_EQ(2u, queue.size());
  // The address migration path should be preserved.
  EXPECT_EQ(client_address_, queue.front().client_address);
  EXPECT_EQ(addr_with_new_port, queue.back().client_address);
}

TEST_F(QuicBufferedPacketStoreTest,
       EnqueueAndDeliverMultiplePacketsOnMultipleConnections) {
  size_t num_connections = 10;
  for (QuicConnectionId connection_id = 1; connection_id <= num_connections;
       ++connection_id) {
    store_.EnqueuePacket(connection_id, data_packet_, server_address_,
                         client_address_);
    store_.EnqueuePacket(connection_id, data_packet_, server_address_,
                         client_address_);
  }

  // Deliver packets in reversed order.
  for (QuicConnectionId connection_id = num_connections; connection_id > 0;
       --connection_id) {
    list<BufferedPacket> queue = store_.DeliverPackets(connection_id);
    ASSERT_EQ(2u, queue.size());
  }
}

TEST_F(QuicBufferedPacketStoreTest,
       FailToBufferTooManyPacketsOnExistingConnection) {
  // Tests that for one connection, only limited number of packets can be
  // buffered.
  size_t num_packets = kDefaultMaxUndecryptablePackets + 1;
  QuicConnectionId connection_id = 1;
  for (size_t i = 1; i <= num_packets; ++i) {
    // Only first |kDefaultMaxUndecryptablePackets packets| will be buffered.
    EnqueuePacketResult result = store_.EnqueuePacket(
        connection_id, data_packet_, server_address_, client_address_);
    if (i <= kDefaultMaxUndecryptablePackets) {
      EXPECT_EQ(EnqueuePacketResult::SUCCESS, result);
    } else {
      EXPECT_EQ(EnqueuePacketResult::TOO_MANY_PACKETS, result);
    }
  }

  // Only first |kDefaultMaxUndecryptablePackets| packets are kept in the store
  // and can be delivered.
  EXPECT_EQ(kDefaultMaxUndecryptablePackets,
            store_.DeliverPackets(connection_id).size());
}

TEST_F(QuicBufferedPacketStoreTest, FailToBufferPacketsForTooManyConnections) {
  // Tests that store can only keep early arrived packets for limited number of
  // connections.
  size_t num_connections = kDefaultMaxConnectionsInStore + 1;
  for (size_t connection_id = 1; connection_id <= num_connections;
       ++connection_id) {
    EnqueuePacketResult result = store_.EnqueuePacket(
        connection_id, data_packet_, server_address_, client_address_);
    if (connection_id <= kDefaultMaxConnectionsInStore) {
      EXPECT_EQ(EnqueuePacketResult::SUCCESS, result);
    } else {
      EXPECT_EQ(EnqueuePacketResult::TOO_MANY_CONNECTIONS, result);
    }
  }
  // Store only keeps early arrived packets upto |kDefaultMaxConnectionsInStore|
  // connections.
  for (size_t connection_id = 1; connection_id <= num_connections;
       ++connection_id) {
    list<BufferedPacket> queue = store_.DeliverPackets(connection_id);
    if (connection_id <= kDefaultMaxConnectionsInStore) {
      EXPECT_EQ(1u, queue.size());
    } else {
      EXPECT_EQ(0u, queue.size());
    }
  }
}

TEST_F(QuicBufferedPacketStoreTest, PacketQueueExpiredBeforeDelivery) {
  QuicConnectionId connection_id = 1;
  store_.EnqueuePacket(connection_id, data_packet_, server_address_,
                       client_address_);
  // Packet for another connection arrive 1ms later.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(1));
  QuicConnectionId connection_id2 = 2;
  // Use different client address to differetiate packets from different
  // connections.
  IPEndPoint another_client_address(Loopback4(), 255);
  store_.EnqueuePacket(connection_id2, data_packet_, server_address_,
                       another_client_address);
  // Advance clock to the time when connection 1 expires.
  clock_.AdvanceTime(
      QuicBufferedPacketStorePeer::expiration_alarm(&store_)->deadline() -
      clock_.ApproximateNow());
  ASSERT_GE(clock_.ApproximateNow(),
            QuicBufferedPacketStorePeer::expiration_alarm(&store_)->deadline());
  // Fire alarm to remove long-staying connection 1 packets.
  alarm_factory_.FireAlarm(
      QuicBufferedPacketStorePeer::expiration_alarm(&store_));
  EXPECT_EQ(1u, visitor_.last_expired_packet_queue_.buffered_packets.size());
  // Try to deliver packets, but packet queue has been removed so no
  // packets can be returned.
  ASSERT_EQ(0u, store_.DeliverPackets(connection_id).size());

  // Deliver packets on connection 2. And the queue for connection 2 should be
  // returned.
  list<BufferedPacket> queue = store_.DeliverPackets(connection_id2);
  ASSERT_EQ(1u, queue.size());
  // Packets in connection 2 should use another client address.
  EXPECT_EQ(another_client_address, queue.front().client_address);

  // Test the alarm is reset by enqueueing 2 packets for 3rd connection and wait
  // for them to expire.
  QuicConnectionId connection_id3 = 3;
  store_.EnqueuePacket(connection_id3, data_packet_, server_address_,
                       client_address_);
  store_.EnqueuePacket(connection_id3, data_packet_, server_address_,
                       client_address_);
  clock_.AdvanceTime(
      QuicBufferedPacketStorePeer::expiration_alarm(&store_)->deadline() -
      clock_.ApproximateNow());
  alarm_factory_.FireAlarm(
      QuicBufferedPacketStorePeer::expiration_alarm(&store_));
  // |last_expired_packet_queue_| should be updated.
  EXPECT_EQ(2u, visitor_.last_expired_packet_queue_.buffered_packets.size());
}

}  // namespace
}  // namespace test
}  // namespace net
