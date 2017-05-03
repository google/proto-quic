// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/frames/quic_ack_frame.h"
#include "net/quic/core/frames/quic_blocked_frame.h"
#include "net/quic/core/frames/quic_connection_close_frame.h"
#include "net/quic/core/frames/quic_frame.h"
#include "net/quic/core/frames/quic_goaway_frame.h"
#include "net/quic/core/frames/quic_mtu_discovery_frame.h"
#include "net/quic/core/frames/quic_padding_frame.h"
#include "net/quic/core/frames/quic_ping_frame.h"
#include "net/quic/core/frames/quic_rst_stream_frame.h"
#include "net/quic/core/frames/quic_stop_waiting_frame.h"
#include "net/quic/core/frames/quic_stream_frame.h"
#include "net/quic/core/frames/quic_window_update_frame.h"
#include "net/quic/platform/api/quic_test.h"

namespace net {
namespace test {
namespace {

using testing::_;

class QuicFramesTest : public QuicTest {};

TEST_F(QuicFramesTest, AckFrameToString) {
  QuicAckFrame frame;
  frame.largest_observed = 2;
  frame.ack_delay_time = QuicTime::Delta::FromMicroseconds(3);
  frame.packets.Add(4);
  frame.packets.Add(5);
  frame.received_packet_times = {
      {6, QuicTime::Zero() + QuicTime::Delta::FromMicroseconds(7)}};
  std::ostringstream stream;
  stream << frame;
  EXPECT_EQ(
      "{ largest_observed: 2, ack_delay_time: 3, "
      "packets: [ 4 5  ], received_packets: [ 6 at 7  ] }\n",
      stream.str());
}

TEST_F(QuicFramesTest, PaddingFrameToString) {
  QuicPaddingFrame frame;
  frame.num_padding_bytes = 1;
  std::ostringstream stream;
  stream << frame;
  EXPECT_EQ("{ num_padding_bytes: 1 }\n", stream.str());
}

TEST_F(QuicFramesTest, RstStreamFrameToString) {
  QuicRstStreamFrame frame;
  frame.stream_id = 1;
  frame.error_code = QUIC_STREAM_CANCELLED;
  std::ostringstream stream;
  stream << frame;
  EXPECT_EQ("{ stream_id: 1, error_code: 6 }\n", stream.str());
}

TEST_F(QuicFramesTest, ConnectionCloseFrameToString) {
  QuicConnectionCloseFrame frame;
  frame.error_code = QUIC_NETWORK_IDLE_TIMEOUT;
  frame.error_details = "No recent network activity.";
  std::ostringstream stream;
  stream << frame;
  EXPECT_EQ(
      "{ error_code: 25, error_details: 'No recent network activity.' }\n",
      stream.str());
}

TEST_F(QuicFramesTest, GoAwayFrameToString) {
  QuicGoAwayFrame frame;
  frame.error_code = QUIC_NETWORK_IDLE_TIMEOUT;
  frame.last_good_stream_id = 2;
  frame.reason_phrase = "Reason";
  std::ostringstream stream;
  stream << frame;
  EXPECT_EQ(
      "{ error_code: 25, last_good_stream_id: 2, reason_phrase: 'Reason' }\n",
      stream.str());
}

TEST_F(QuicFramesTest, WindowUpdateFrameToString) {
  QuicWindowUpdateFrame frame;
  std::ostringstream stream;
  frame.stream_id = 1;
  frame.byte_offset = 2;
  stream << frame;
  EXPECT_EQ("{ stream_id: 1, byte_offset: 2 }\n", stream.str());
}

TEST_F(QuicFramesTest, BlockedFrameToString) {
  QuicBlockedFrame frame;
  frame.stream_id = 1;
  std::ostringstream stream;
  stream << frame;
  EXPECT_EQ("{ stream_id: 1 }\n", stream.str());
}

TEST_F(QuicFramesTest, StreamFrameToString) {
  QuicStreamFrame frame;
  frame.stream_id = 1;
  frame.fin = false;
  frame.offset = 2;
  frame.data_length = 3;
  std::ostringstream stream;
  stream << frame;
  EXPECT_EQ("{ stream_id: 1, fin: 0, offset: 2, length: 3 }\n", stream.str());
}

TEST_F(QuicFramesTest, StopWaitingFrameToString) {
  QuicStopWaitingFrame frame;
  frame.least_unacked = 2;
  std::ostringstream stream;
  stream << frame;
  EXPECT_EQ("{ least_unacked: 2 }\n", stream.str());
}

TEST_F(QuicFramesTest, IsAwaitingPacket) {
  QuicAckFrame ack_frame1;
  ack_frame1.largest_observed = 10u;
  ack_frame1.packets.Add(1, 11);
  EXPECT_TRUE(IsAwaitingPacket(ack_frame1, 11u, 0u));
  EXPECT_FALSE(IsAwaitingPacket(ack_frame1, 1u, 0u));

  ack_frame1.packets.Remove(10);
  EXPECT_TRUE(IsAwaitingPacket(ack_frame1, 10u, 0u));

  QuicAckFrame ack_frame2;
  ack_frame2.largest_observed = 100u;
  ack_frame2.packets.Add(21, 100);
  EXPECT_FALSE(IsAwaitingPacket(ack_frame2, 11u, 20u));
  EXPECT_FALSE(IsAwaitingPacket(ack_frame2, 80u, 20u));
  EXPECT_TRUE(IsAwaitingPacket(ack_frame2, 101u, 20u));

  ack_frame2.packets.Remove(50);
  EXPECT_TRUE(IsAwaitingPacket(ack_frame2, 50u, 20u));
}

TEST_F(QuicFramesTest, RemoveSmallestInterval) {
  QuicAckFrame ack_frame1;
  ack_frame1.largest_observed = 100u;
  ack_frame1.packets.Add(51, 60);
  ack_frame1.packets.Add(71, 80);
  ack_frame1.packets.Add(91, 100);
  ack_frame1.packets.RemoveSmallestInterval();
  EXPECT_EQ(2u, ack_frame1.packets.NumIntervals());
  EXPECT_EQ(71u, ack_frame1.packets.Min());
  EXPECT_EQ(99u, ack_frame1.packets.Max());

  ack_frame1.packets.RemoveSmallestInterval();
  EXPECT_EQ(1u, ack_frame1.packets.NumIntervals());
  EXPECT_EQ(91u, ack_frame1.packets.Min());
  EXPECT_EQ(99u, ack_frame1.packets.Max());
}

class PacketNumberQueueTest : public QuicTest {};

// Tests that a queue contains the expected data after calls to Add().
TEST_F(PacketNumberQueueTest, AddRange) {
  PacketNumberQueue queue;
  queue.Add(1, 51);
  queue.Add(53);

  EXPECT_FALSE(queue.Contains(0));
  for (int i = 1; i < 51; ++i) {
    EXPECT_TRUE(queue.Contains(i));
  }
  EXPECT_FALSE(queue.Contains(51));
  EXPECT_FALSE(queue.Contains(52));
  EXPECT_TRUE(queue.Contains(53));
  EXPECT_FALSE(queue.Contains(54));
  EXPECT_EQ(51u, queue.NumPacketsSlow());
  EXPECT_EQ(1u, queue.Min());
  EXPECT_EQ(53u, queue.Max());

  queue.Add(70);
  EXPECT_EQ(70u, queue.Max());
}

// Tests that a queue contains the expected data after calls to Remove().
TEST_F(PacketNumberQueueTest, Removal) {
  PacketNumberQueue queue;
  queue.Add(0, 100);

  EXPECT_TRUE(queue.RemoveUpTo(51));
  EXPECT_FALSE(queue.RemoveUpTo(51));
  queue.Remove(53);

  EXPECT_FALSE(queue.Contains(0));
  for (int i = 1; i < 51; ++i) {
    EXPECT_FALSE(queue.Contains(i));
  }
  EXPECT_TRUE(queue.Contains(51));
  EXPECT_TRUE(queue.Contains(52));
  EXPECT_FALSE(queue.Contains(53));
  EXPECT_TRUE(queue.Contains(54));
  EXPECT_EQ(48u, queue.NumPacketsSlow());
  EXPECT_EQ(51u, queue.Min());
  EXPECT_EQ(99u, queue.Max());

  queue.Remove(51);
  EXPECT_EQ(52u, queue.Min());
  queue.Remove(99);
  EXPECT_EQ(98u, queue.Max());
}

// Tests that a queue is empty when all of its elements are removed.
TEST_F(PacketNumberQueueTest, Empty) {
  PacketNumberQueue queue;
  EXPECT_TRUE(queue.Empty());
  EXPECT_EQ(0u, queue.NumPacketsSlow());

  queue.Add(1, 100);
  EXPECT_TRUE(queue.RemoveUpTo(100));
  EXPECT_TRUE(queue.Empty());
  EXPECT_EQ(0u, queue.NumPacketsSlow());
}

// Tests that logging the state of a PacketNumberQueue does not crash.
TEST_F(PacketNumberQueueTest, LogDoesNotCrash) {
  std::ostringstream oss;
  PacketNumberQueue queue;
  oss << queue;

  queue.Add(1);
  queue.Add(50, 100);
  oss << queue;
}

// Tests that the iterators returned from a packet queue iterate over the queue.
TEST_F(PacketNumberQueueTest, Iterators) {
  PacketNumberQueue queue;
  queue.Add(1, 100);

  const std::vector<Interval<QuicPacketNumber>> actual_intervals(queue.begin(),
                                                                 queue.end());

  std::vector<Interval<QuicPacketNumber>> expected_intervals;
  expected_intervals.push_back(Interval<QuicPacketNumber>(1, 100));

  EXPECT_EQ(expected_intervals, actual_intervals);
}

TEST_F(PacketNumberQueueTest, LowerBoundEquals) {
  PacketNumberQueue queue;
  queue.Add(1, 100);

  PacketNumberQueue::const_iterator it = queue.lower_bound(10);
  ASSERT_NE(queue.end(), it);
  EXPECT_TRUE(it->Contains(10u));

  it = queue.lower_bound(101);
  EXPECT_TRUE(queue.end() == it);
}

TEST_F(PacketNumberQueueTest, LowerBoundGreater) {
  PacketNumberQueue queue;
  queue.Add(15, 25);
  queue.Add(50, 100);

  PacketNumberQueue::const_iterator it = queue.lower_bound(10);
  ASSERT_NE(queue.end(), it);
  EXPECT_EQ(15u, it->min());
  EXPECT_EQ(25u, it->max());
}

TEST_F(PacketNumberQueueTest, IntervalLengthAndRemoveInterval) {
  PacketNumberQueue queue;
  queue.Add(1, 10);
  queue.Add(20, 30);
  queue.Add(40, 50);
  EXPECT_EQ(3u, queue.NumIntervals());
  EXPECT_EQ(10u, queue.LastIntervalLength());
  queue.Remove(9, 21);
  EXPECT_EQ(3u, queue.NumIntervals());
  EXPECT_FALSE(queue.Contains(9));
  EXPECT_FALSE(queue.Contains(20));
}

TEST_F(PacketNumberQueueTest, Complement) {
  PacketNumberQueue queue;
  queue.Add(1, 10);
  queue.Add(12, 20);
  queue.Add(22, 30);
  queue.Complement();
  EXPECT_EQ(2u, queue.NumIntervals());
  EXPECT_TRUE(queue.Contains(10));
  EXPECT_TRUE(queue.Contains(11));
  EXPECT_TRUE(queue.Contains(20));
  EXPECT_TRUE(queue.Contains(21));
}

}  // namespace
}  // namespace test
}  // namespace net
