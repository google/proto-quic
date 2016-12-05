// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/quic_unacked_packet_map.h"

#include "net/quic/core/quic_flags.h"
#include "net/quic/core/quic_utils.h"
#include "net/quic/test_tools/quic_test_utils.h"
#include "testing/gtest/include/gtest/gtest.h"


namespace net {
namespace test {
namespace {

// Default packet length.
const uint32_t kDefaultLength = 1000;

class QuicUnackedPacketMapTest : public ::testing::Test {
 protected:
  QuicUnackedPacketMapTest()
      : unacked_packets_(),
        now_(QuicTime::Zero() + QuicTime::Delta::FromMilliseconds(1000)) {}

  ~QuicUnackedPacketMapTest() override {}

  SerializedPacket CreateRetransmittablePacket(QuicPacketNumber packet_number) {
    return CreateRetransmittablePacketForStream(packet_number,
                                                kHeadersStreamId);
  }

  SerializedPacket CreateRetransmittablePacketForStream(
      QuicPacketNumber packet_number,
      QuicStreamId stream_id) {
    SerializedPacket packet(kDefaultPathId, packet_number,
                            PACKET_1BYTE_PACKET_NUMBER, nullptr, kDefaultLength,
                            false, false);
    QuicStreamFrame* frame = new QuicStreamFrame();
    frame->stream_id = stream_id;
    packet.retransmittable_frames.push_back(QuicFrame(frame));
    return packet;
  }

  SerializedPacket CreateNonRetransmittablePacket(
      QuicPacketNumber packet_number) {
    return SerializedPacket(kDefaultPathId, packet_number,
                            PACKET_1BYTE_PACKET_NUMBER, nullptr, kDefaultLength,
                            false, false);
  }

  void VerifyInFlightPackets(QuicPacketNumber* packets, size_t num_packets) {
    unacked_packets_.RemoveObsoletePackets();
    if (num_packets == 0) {
      EXPECT_FALSE(unacked_packets_.HasInFlightPackets());
      EXPECT_FALSE(unacked_packets_.HasMultipleInFlightPackets());
      return;
    }
    if (num_packets == 1) {
      EXPECT_TRUE(unacked_packets_.HasInFlightPackets());
      EXPECT_FALSE(unacked_packets_.HasMultipleInFlightPackets());
      ASSERT_TRUE(unacked_packets_.IsUnacked(packets[0]));
      EXPECT_TRUE(unacked_packets_.GetTransmissionInfo(packets[0]).in_flight);
    }
    for (size_t i = 0; i < num_packets; ++i) {
      ASSERT_TRUE(unacked_packets_.IsUnacked(packets[i]));
      EXPECT_TRUE(unacked_packets_.GetTransmissionInfo(packets[i]).in_flight);
    }
    size_t in_flight_count = 0;
    for (QuicUnackedPacketMap::const_iterator it = unacked_packets_.begin();
         it != unacked_packets_.end(); ++it) {
      if (it->in_flight) {
        ++in_flight_count;
      }
    }
    EXPECT_EQ(num_packets, in_flight_count);
  }

  void VerifyUnackedPackets(QuicPacketNumber* packets, size_t num_packets) {
    unacked_packets_.RemoveObsoletePackets();
    if (num_packets == 0) {
      EXPECT_FALSE(unacked_packets_.HasUnackedPackets());
      EXPECT_FALSE(unacked_packets_.HasUnackedRetransmittableFrames());
      return;
    }
    EXPECT_TRUE(unacked_packets_.HasUnackedPackets());
    for (size_t i = 0; i < num_packets; ++i) {
      EXPECT_TRUE(unacked_packets_.IsUnacked(packets[i])) << packets[i];
    }
    EXPECT_EQ(num_packets, unacked_packets_.GetNumUnackedPacketsDebugOnly());
  }

  void VerifyRetransmittablePackets(QuicPacketNumber* packets,
                                    size_t num_packets) {
    unacked_packets_.RemoveObsoletePackets();
    size_t num_retransmittable_packets = 0;
    for (QuicUnackedPacketMap::const_iterator it = unacked_packets_.begin();
         it != unacked_packets_.end(); ++it) {
      if (!it->retransmittable_frames.empty()) {
        ++num_retransmittable_packets;
      }
    }
    EXPECT_EQ(num_packets, num_retransmittable_packets);
    for (size_t i = 0; i < num_packets; ++i) {
      EXPECT_TRUE(unacked_packets_.HasRetransmittableFrames(packets[i]))
          << " packets[" << i << "]:" << packets[i];
    }
  }
  QuicUnackedPacketMap unacked_packets_;
  QuicTime now_;
};

TEST_F(QuicUnackedPacketMapTest, RttOnly) {
  // Acks are only tracked for RTT measurement purposes.
  SerializedPacket packet(CreateNonRetransmittablePacket(1));
  unacked_packets_.AddSentPacket(&packet, 0, NOT_RETRANSMISSION, now_, false);

  QuicPacketNumber unacked[] = {1};
  VerifyUnackedPackets(unacked, arraysize(unacked));
  VerifyInFlightPackets(nullptr, 0);
  VerifyRetransmittablePackets(nullptr, 0);

  unacked_packets_.IncreaseLargestObserved(1);
  VerifyUnackedPackets(nullptr, 0);
  VerifyInFlightPackets(nullptr, 0);
  VerifyRetransmittablePackets(nullptr, 0);
}

TEST_F(QuicUnackedPacketMapTest, RetransmittableInflightAndRtt) {
  // Simulate a retransmittable packet being sent and acked.
  SerializedPacket packet(CreateRetransmittablePacket(1));
  unacked_packets_.AddSentPacket(&packet, 0, NOT_RETRANSMISSION, now_, true);

  QuicPacketNumber unacked[] = {1};
  VerifyUnackedPackets(unacked, arraysize(unacked));
  VerifyInFlightPackets(unacked, arraysize(unacked));
  VerifyRetransmittablePackets(unacked, arraysize(unacked));

  unacked_packets_.RemoveRetransmittability(1);
  VerifyUnackedPackets(unacked, arraysize(unacked));
  VerifyInFlightPackets(unacked, arraysize(unacked));
  VerifyRetransmittablePackets(nullptr, 0);

  unacked_packets_.IncreaseLargestObserved(1);
  VerifyUnackedPackets(unacked, arraysize(unacked));
  VerifyInFlightPackets(unacked, arraysize(unacked));
  VerifyRetransmittablePackets(nullptr, 0);

  unacked_packets_.RemoveFromInFlight(1);
  VerifyUnackedPackets(nullptr, 0);
  VerifyInFlightPackets(nullptr, 0);
  VerifyRetransmittablePackets(nullptr, 0);
}

TEST_F(QuicUnackedPacketMapTest, StopRetransmission) {
  const QuicStreamId stream_id = 2;
  SerializedPacket packet(CreateRetransmittablePacketForStream(1, stream_id));
  unacked_packets_.AddSentPacket(&packet, 0, NOT_RETRANSMISSION, now_, true);

  QuicPacketNumber unacked[] = {1};
  VerifyUnackedPackets(unacked, arraysize(unacked));
  VerifyInFlightPackets(unacked, arraysize(unacked));
  QuicPacketNumber retransmittable[] = {1};
  VerifyRetransmittablePackets(retransmittable, arraysize(retransmittable));

  unacked_packets_.CancelRetransmissionsForStream(stream_id);
  VerifyUnackedPackets(unacked, arraysize(unacked));
  VerifyInFlightPackets(unacked, arraysize(unacked));
  VerifyRetransmittablePackets(nullptr, 0);
}

TEST_F(QuicUnackedPacketMapTest, StopRetransmissionOnOtherStream) {
  const QuicStreamId stream_id = 2;
  SerializedPacket packet(CreateRetransmittablePacketForStream(1, stream_id));
  unacked_packets_.AddSentPacket(&packet, 0, NOT_RETRANSMISSION, now_, true);

  QuicPacketNumber unacked[] = {1};
  VerifyUnackedPackets(unacked, arraysize(unacked));
  VerifyInFlightPackets(unacked, arraysize(unacked));
  QuicPacketNumber retransmittable[] = {1};
  VerifyRetransmittablePackets(retransmittable, arraysize(retransmittable));

  // Stop retransmissions on another stream and verify the packet is unchanged.
  unacked_packets_.CancelRetransmissionsForStream(stream_id + 2);
  VerifyUnackedPackets(unacked, arraysize(unacked));
  VerifyInFlightPackets(unacked, arraysize(unacked));
  VerifyRetransmittablePackets(retransmittable, arraysize(retransmittable));
}

TEST_F(QuicUnackedPacketMapTest, StopRetransmissionAfterRetransmission) {
  const QuicStreamId stream_id = 2;
  SerializedPacket packet1(CreateRetransmittablePacketForStream(1, stream_id));
  unacked_packets_.AddSentPacket(&packet1, 0, NOT_RETRANSMISSION, now_, true);
  SerializedPacket packet2(CreateNonRetransmittablePacket(2));
  unacked_packets_.AddSentPacket(&packet2, 1, LOSS_RETRANSMISSION, now_, true);

  QuicPacketNumber unacked[] = {1, 2};
  VerifyUnackedPackets(unacked, arraysize(unacked));
  VerifyInFlightPackets(unacked, arraysize(unacked));
  QuicPacketNumber retransmittable[] = {2};
  VerifyRetransmittablePackets(retransmittable, arraysize(retransmittable));

  unacked_packets_.CancelRetransmissionsForStream(stream_id);
  VerifyUnackedPackets(unacked, arraysize(unacked));
  VerifyInFlightPackets(unacked, arraysize(unacked));
  VerifyRetransmittablePackets(nullptr, 0);
}

TEST_F(QuicUnackedPacketMapTest, RetransmittedPacket) {
  // Simulate a retransmittable packet being sent, retransmitted, and the first
  // transmission being acked.
  SerializedPacket packet1(CreateRetransmittablePacket(1));
  unacked_packets_.AddSentPacket(&packet1, 0, NOT_RETRANSMISSION, now_, true);
  SerializedPacket packet2(CreateNonRetransmittablePacket(2));
  unacked_packets_.AddSentPacket(&packet2, 1, LOSS_RETRANSMISSION, now_, true);

  QuicPacketNumber unacked[] = {1, 2};
  VerifyUnackedPackets(unacked, arraysize(unacked));
  VerifyInFlightPackets(unacked, arraysize(unacked));
  QuicPacketNumber retransmittable[] = {2};
  VerifyRetransmittablePackets(retransmittable, arraysize(retransmittable));

  unacked_packets_.RemoveRetransmittability(1);
  VerifyUnackedPackets(unacked, arraysize(unacked));
  VerifyInFlightPackets(unacked, arraysize(unacked));
  VerifyRetransmittablePackets(nullptr, 0);

  unacked_packets_.IncreaseLargestObserved(2);
  VerifyUnackedPackets(unacked, arraysize(unacked));
  VerifyInFlightPackets(unacked, arraysize(unacked));
  VerifyRetransmittablePackets(nullptr, 0);

  unacked_packets_.RemoveFromInFlight(2);
  QuicPacketNumber unacked2[] = {1};
  VerifyUnackedPackets(unacked2, arraysize(unacked2));
  VerifyInFlightPackets(unacked2, arraysize(unacked2));
  VerifyRetransmittablePackets(nullptr, 0);

  unacked_packets_.RemoveFromInFlight(1);
  VerifyUnackedPackets(nullptr, 0);
  VerifyInFlightPackets(nullptr, 0);
  VerifyRetransmittablePackets(nullptr, 0);
}

TEST_F(QuicUnackedPacketMapTest, RetransmitThreeTimes) {
  // Simulate a retransmittable packet being sent and retransmitted twice.
  SerializedPacket packet1(CreateRetransmittablePacket(1));
  unacked_packets_.AddSentPacket(&packet1, 0, NOT_RETRANSMISSION, now_, true);
  SerializedPacket packet2(CreateRetransmittablePacket(2));
  unacked_packets_.AddSentPacket(&packet2, 0, NOT_RETRANSMISSION, now_, true);

  QuicPacketNumber unacked[] = {1, 2};
  VerifyUnackedPackets(unacked, arraysize(unacked));
  VerifyInFlightPackets(unacked, arraysize(unacked));
  QuicPacketNumber retransmittable[] = {1, 2};
  VerifyRetransmittablePackets(retransmittable, arraysize(retransmittable));

  // Early retransmit 1 as 3 and send new data as 4.
  unacked_packets_.IncreaseLargestObserved(2);
  unacked_packets_.RemoveFromInFlight(2);
  unacked_packets_.RemoveRetransmittability(2);
  unacked_packets_.RemoveFromInFlight(1);
  SerializedPacket packet3(CreateNonRetransmittablePacket(3));
  unacked_packets_.AddSentPacket(&packet3, 1, LOSS_RETRANSMISSION, now_, true);
  SerializedPacket packet4(CreateRetransmittablePacket(4));
  unacked_packets_.AddSentPacket(&packet4, 0, NOT_RETRANSMISSION, now_, true);

  QuicPacketNumber unacked2[] = {1, 3, 4};
  VerifyUnackedPackets(unacked2, arraysize(unacked2));
  QuicPacketNumber pending2[] = {3, 4};
  VerifyInFlightPackets(pending2, arraysize(pending2));
  QuicPacketNumber retransmittable2[] = {3, 4};
  VerifyRetransmittablePackets(retransmittable2, arraysize(retransmittable2));

  // Early retransmit 3 (formerly 1) as 5, and remove 1 from unacked.
  unacked_packets_.IncreaseLargestObserved(4);
  unacked_packets_.RemoveFromInFlight(4);
  unacked_packets_.RemoveRetransmittability(4);
  SerializedPacket packet5(CreateNonRetransmittablePacket(5));
  unacked_packets_.AddSentPacket(&packet5, 3, LOSS_RETRANSMISSION, now_, true);
  SerializedPacket packet6(CreateRetransmittablePacket(6));
  unacked_packets_.AddSentPacket(&packet6, 0, NOT_RETRANSMISSION, now_, true);

  QuicPacketNumber unacked3[] = {3, 5, 6};
  VerifyUnackedPackets(unacked3, arraysize(unacked3));
  QuicPacketNumber pending3[] = {3, 5, 6};
  VerifyInFlightPackets(pending3, arraysize(pending3));
  QuicPacketNumber retransmittable3[] = {5, 6};
  VerifyRetransmittablePackets(retransmittable3, arraysize(retransmittable3));

  // Early retransmit 5 as 7 and ensure in flight packet 3 is not removed.
  unacked_packets_.IncreaseLargestObserved(6);
  unacked_packets_.RemoveFromInFlight(6);
  unacked_packets_.RemoveRetransmittability(6);
  SerializedPacket packet7(CreateNonRetransmittablePacket(7));
  unacked_packets_.AddSentPacket(&packet7, 5, LOSS_RETRANSMISSION, now_, true);

  QuicPacketNumber unacked4[] = {3, 5, 7};
  VerifyUnackedPackets(unacked4, arraysize(unacked4));
  QuicPacketNumber pending4[] = {3, 5, 7};
  VerifyInFlightPackets(pending4, arraysize(pending4));
  QuicPacketNumber retransmittable4[] = {7};
  VerifyRetransmittablePackets(retransmittable4, arraysize(retransmittable4));

  // Remove the older two transmissions from in flight.
  unacked_packets_.RemoveFromInFlight(3);
  unacked_packets_.RemoveFromInFlight(5);
  QuicPacketNumber pending5[] = {7};
  VerifyInFlightPackets(pending5, arraysize(pending5));
}

TEST_F(QuicUnackedPacketMapTest, RetransmitFourTimes) {
  // Simulate a retransmittable packet being sent and retransmitted twice.
  SerializedPacket packet1(CreateRetransmittablePacket(1));
  unacked_packets_.AddSentPacket(&packet1, 0, NOT_RETRANSMISSION, now_, true);
  SerializedPacket packet2(CreateRetransmittablePacket(2));
  unacked_packets_.AddSentPacket(&packet2, 0, NOT_RETRANSMISSION, now_, true);

  QuicPacketNumber unacked[] = {1, 2};
  VerifyUnackedPackets(unacked, arraysize(unacked));
  VerifyInFlightPackets(unacked, arraysize(unacked));
  QuicPacketNumber retransmittable[] = {1, 2};
  VerifyRetransmittablePackets(retransmittable, arraysize(retransmittable));

  // Early retransmit 1 as 3.
  unacked_packets_.IncreaseLargestObserved(2);
  unacked_packets_.RemoveFromInFlight(2);
  unacked_packets_.RemoveRetransmittability(2);
  unacked_packets_.RemoveFromInFlight(1);
  SerializedPacket packet3(CreateNonRetransmittablePacket(3));
  unacked_packets_.AddSentPacket(&packet3, 1, LOSS_RETRANSMISSION, now_, true);

  QuicPacketNumber unacked2[] = {1, 3};
  VerifyUnackedPackets(unacked2, arraysize(unacked2));
  QuicPacketNumber pending2[] = {3};
  VerifyInFlightPackets(pending2, arraysize(pending2));
  QuicPacketNumber retransmittable2[] = {3};
  VerifyRetransmittablePackets(retransmittable2, arraysize(retransmittable2));

  // TLP 3 (formerly 1) as 4, and don't remove 1 from unacked.
  SerializedPacket packet4(CreateNonRetransmittablePacket(4));
  unacked_packets_.AddSentPacket(&packet4, 3, TLP_RETRANSMISSION, now_, true);
  SerializedPacket packet5(CreateRetransmittablePacket(5));
  unacked_packets_.AddSentPacket(&packet5, 0, NOT_RETRANSMISSION, now_, true);

  QuicPacketNumber unacked3[] = {1, 3, 4, 5};
  VerifyUnackedPackets(unacked3, arraysize(unacked3));
  QuicPacketNumber pending3[] = {3, 4, 5};
  VerifyInFlightPackets(pending3, arraysize(pending3));
  QuicPacketNumber retransmittable3[] = {4, 5};
  VerifyRetransmittablePackets(retransmittable3, arraysize(retransmittable3));

  // Early retransmit 4 as 6 and ensure in flight packet 3 is removed.
  unacked_packets_.IncreaseLargestObserved(5);
  unacked_packets_.RemoveFromInFlight(5);
  unacked_packets_.RemoveRetransmittability(5);
  unacked_packets_.RemoveFromInFlight(3);
  unacked_packets_.RemoveFromInFlight(4);
  SerializedPacket packet6(CreateNonRetransmittablePacket(6));
  unacked_packets_.AddSentPacket(&packet6, 4, LOSS_RETRANSMISSION, now_, true);

  QuicPacketNumber unacked4[] = {4, 6};
  VerifyUnackedPackets(unacked4, arraysize(unacked4));
  QuicPacketNumber pending4[] = {6};
  VerifyInFlightPackets(pending4, arraysize(pending4));
  QuicPacketNumber retransmittable4[] = {6};
  VerifyRetransmittablePackets(retransmittable4, arraysize(retransmittable4));
}

TEST_F(QuicUnackedPacketMapTest, SendWithGap) {
  // Simulate a retransmittable packet being sent, retransmitted, and the first
  // transmission being acked.
  SerializedPacket packet1(CreateRetransmittablePacket(1));
  unacked_packets_.AddSentPacket(&packet1, 0, NOT_RETRANSMISSION, now_, true);
  SerializedPacket packet3(CreateRetransmittablePacket(3));
  unacked_packets_.AddSentPacket(&packet3, 0, NOT_RETRANSMISSION, now_, true);
  SerializedPacket packet5(CreateNonRetransmittablePacket(5));
  unacked_packets_.AddSentPacket(&packet5, 3, LOSS_RETRANSMISSION, now_, true);

  EXPECT_EQ(1u, unacked_packets_.GetLeastUnacked());
  EXPECT_TRUE(unacked_packets_.IsUnacked(1));
  EXPECT_FALSE(unacked_packets_.IsUnacked(2));
  EXPECT_TRUE(unacked_packets_.IsUnacked(3));
  EXPECT_FALSE(unacked_packets_.IsUnacked(4));
  EXPECT_TRUE(unacked_packets_.IsUnacked(5));
  EXPECT_EQ(5u, unacked_packets_.largest_sent_packet());
}

}  // namespace
}  // namespace test
}  // namespace net
