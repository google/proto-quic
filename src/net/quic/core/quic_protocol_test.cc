// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/quic_protocol.h"

#include <sstream>

#include "base/stl_util.h"
#include "net/quic/core/quic_flags.h"
#include "net/quic/core/quic_utils.h"
#include "net/quic/test_tools/quic_test_utils.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {
namespace test {
namespace {

TEST(QuicProtocolTest, MakeQuicTag) {
  QuicTag tag = MakeQuicTag('A', 'B', 'C', 'D');
  char bytes[4];
  memcpy(bytes, &tag, 4);
  EXPECT_EQ('A', bytes[0]);
  EXPECT_EQ('B', bytes[1]);
  EXPECT_EQ('C', bytes[2]);
  EXPECT_EQ('D', bytes[3]);
}

TEST(QuicProtocolTest, IsAawaitingPacket) {
  QuicAckFrame ack_frame;
  ack_frame.largest_observed = 10u;
  EXPECT_TRUE(IsAwaitingPacket(ack_frame, 11u, 0u));
  EXPECT_FALSE(IsAwaitingPacket(ack_frame, 1u, 0u));

  ack_frame.packets.Add(10);
  EXPECT_TRUE(IsAwaitingPacket(ack_frame, 10u, 0u));

  QuicAckFrame ack_frame1;
  ack_frame1.missing = false;
  ack_frame1.largest_observed = 10u;
  ack_frame1.packets.Add(1, 11);
  EXPECT_TRUE(IsAwaitingPacket(ack_frame1, 11u, 0u));
  EXPECT_FALSE(IsAwaitingPacket(ack_frame1, 1u, 0u));

  ack_frame1.packets.Remove(10);
  EXPECT_TRUE(IsAwaitingPacket(ack_frame1, 10u, 0u));

  QuicAckFrame ack_frame2;
  ack_frame2.missing = false;
  ack_frame2.largest_observed = 100u;
  ack_frame2.packets.Add(21, 100);
  EXPECT_FALSE(IsAwaitingPacket(ack_frame2, 11u, 20u));
  EXPECT_FALSE(IsAwaitingPacket(ack_frame2, 80u, 20u));
  EXPECT_TRUE(IsAwaitingPacket(ack_frame2, 101u, 20u));

  ack_frame2.packets.Remove(50);
  EXPECT_TRUE(IsAwaitingPacket(ack_frame2, 50u, 20u));
}

TEST(QuicProtocolTest, QuicVersionToQuicTag) {
// If you add a new version to the QuicVersion enum you will need to add a new
// case to QuicVersionToQuicTag, otherwise this test will fail.

// TODO(rtenneti): Enable checking of Log(ERROR) messages.
#if 0
  // Any logs would indicate an unsupported version which we don't expect.
  ScopedMockLog log(kDoNotCaptureLogsYet);
  EXPECT_CALL(log, Log(_, _, _)).Times(0);
  log.StartCapturingLogs();
#endif

  // Explicitly test a specific version.
  EXPECT_EQ(MakeQuicTag('Q', '0', '3', '2'),
            QuicVersionToQuicTag(QUIC_VERSION_32));

  // Loop over all supported versions and make sure that we never hit the
  // default case (i.e. all supported versions should be successfully converted
  // to valid QuicTags).
  for (size_t i = 0; i < arraysize(kSupportedQuicVersions); ++i) {
    QuicVersion version = kSupportedQuicVersions[i];
    EXPECT_LT(0u, QuicVersionToQuicTag(version));
  }
}

TEST(QuicProtocolTest, QuicVersionToQuicTagUnsupported) {
// TODO(rtenneti): Enable checking of Log(ERROR) messages.
#if 0
  // TODO(rjshade): Change to DFATAL once we actually support multiple versions,
  // and QuicConnectionTest::SendVersionNegotiationPacket can be changed to use
  // mis-matched versions rather than relying on QUIC_VERSION_UNSUPPORTED.
  ScopedMockLog log(kDoNotCaptureLogsYet);
  EXPECT_CALL(log, Log(base_logging::ERROR, _, "Unsupported QuicVersion: 0"))
      .Times(1);
  log.StartCapturingLogs();
#endif

  EXPECT_EQ(0u, QuicVersionToQuicTag(QUIC_VERSION_UNSUPPORTED));
}

TEST(QuicProtocolTest, QuicTagToQuicVersion) {
// If you add a new version to the QuicVersion enum you will need to add a new
// case to QuicTagToQuicVersion, otherwise this test will fail.

// TODO(rtenneti): Enable checking of Log(ERROR) messages.
#if 0
  // Any logs would indicate an unsupported version which we don't expect.
  ScopedMockLog log(kDoNotCaptureLogsYet);
  EXPECT_CALL(log, Log(_, _, _)).Times(0);
  log.StartCapturingLogs();
#endif

  // Explicitly test specific versions.
  EXPECT_EQ(QUIC_VERSION_32,
            QuicTagToQuicVersion(MakeQuicTag('Q', '0', '3', '2')));

  for (size_t i = 0; i < arraysize(kSupportedQuicVersions); ++i) {
    QuicVersion version = kSupportedQuicVersions[i];

    // Get the tag from the version (we can loop over QuicVersions easily).
    QuicTag tag = QuicVersionToQuicTag(version);
    EXPECT_LT(0u, tag);

    // Now try converting back.
    QuicVersion tag_to_quic_version = QuicTagToQuicVersion(tag);
    EXPECT_EQ(version, tag_to_quic_version);
    EXPECT_NE(QUIC_VERSION_UNSUPPORTED, tag_to_quic_version);
  }
}

TEST(QuicProtocolTest, QuicTagToQuicVersionUnsupported) {
// TODO(rtenneti): Enable checking of Log(ERROR) messages.
#if 0
  ScopedMockLog log(kDoNotCaptureLogsYet);
#ifndef NDEBUG
  EXPECT_CALL(log,
              Log(base_logging::INFO, _, "Unsupported QuicTag version: FAKE"))
      .Times(1);
#endif
  log.StartCapturingLogs();
#endif

  EXPECT_EQ(QUIC_VERSION_UNSUPPORTED,
            QuicTagToQuicVersion(MakeQuicTag('F', 'A', 'K', 'E')));
}

TEST(QuicProtocolTest, QuicVersionToString) {
  EXPECT_EQ("QUIC_VERSION_32", QuicVersionToString(QUIC_VERSION_32));
  EXPECT_EQ("QUIC_VERSION_UNSUPPORTED",
            QuicVersionToString(QUIC_VERSION_UNSUPPORTED));

  QuicVersion single_version[] = {QUIC_VERSION_32};
  QuicVersionVector versions_vector;
  for (size_t i = 0; i < arraysize(single_version); ++i) {
    versions_vector.push_back(single_version[i]);
  }
  EXPECT_EQ("QUIC_VERSION_32", QuicVersionVectorToString(versions_vector));

  QuicVersion multiple_versions[] = {QUIC_VERSION_UNSUPPORTED, QUIC_VERSION_32};
  versions_vector.clear();
  for (size_t i = 0; i < arraysize(multiple_versions); ++i) {
    versions_vector.push_back(multiple_versions[i]);
  }
  EXPECT_EQ("QUIC_VERSION_UNSUPPORTED,QUIC_VERSION_32",
            QuicVersionVectorToString(versions_vector));

  // Make sure that all supported versions are present in QuicVersionToString.
  for (size_t i = 0; i < arraysize(kSupportedQuicVersions); ++i) {
    QuicVersion version = kSupportedQuicVersions[i];
    EXPECT_NE("QUIC_VERSION_UNSUPPORTED", QuicVersionToString(version));
  }
}

TEST(QuicProtocolTest, AckFrameToString) {
  QuicAckFrame frame;
  frame.entropy_hash = 1;
  frame.largest_observed = 2;
  frame.ack_delay_time = QuicTime::Delta::FromMicroseconds(3);
  frame.packets.Add(4);
  frame.packets.Add(5);
  frame.received_packet_times = {
      {6, QuicTime::Zero() + QuicTime::Delta::FromMicroseconds(7)}};
  std::ostringstream stream;
  stream << frame;
  EXPECT_EQ(
      "{ entropy_hash: 1, largest_observed: 2, ack_delay_time: 3, "
      "packets: [ 4 5  ], is_truncated: 0, received_packets: [ 6 at 7  ] }\n",
      stream.str());
}

TEST(QuicProtocolTest, PaddingFrameToString) {
  QuicPaddingFrame frame;
  frame.num_padding_bytes = 1;
  std::ostringstream stream;
  stream << frame;
  EXPECT_EQ("{ num_padding_bytes: 1 }\n", stream.str());
}

TEST(QuicProtocolTest, RstStreamFrameToString) {
  QuicRstStreamFrame frame;
  frame.stream_id = 1;
  frame.error_code = QUIC_STREAM_CANCELLED;
  std::ostringstream stream;
  stream << frame;
  EXPECT_EQ("{ stream_id: 1, error_code: 6 }\n", stream.str());
}

TEST(QuicProtocolTest, ConnectionCloseFrameToString) {
  QuicConnectionCloseFrame frame;
  frame.error_code = QUIC_NETWORK_IDLE_TIMEOUT;
  frame.error_details = "No recent network activity.";
  std::ostringstream stream;
  stream << frame;
  EXPECT_EQ(
      "{ error_code: 25, error_details: 'No recent network activity.' }\n",
      stream.str());
}

TEST(QuicProtocolTest, GoAwayFrameToString) {
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

TEST(QuicProtocolTest, WindowUpdateFrameToString) {
  QuicWindowUpdateFrame frame;
  std::ostringstream stream;
  frame.stream_id = 1;
  frame.byte_offset = 2;
  stream << frame;
  EXPECT_EQ("{ stream_id: 1, byte_offset: 2 }\n", stream.str());
}

TEST(QuicProtocolTest, BlockedFrameToString) {
  QuicBlockedFrame frame;
  frame.stream_id = 1;
  std::ostringstream stream;
  stream << frame;
  EXPECT_EQ("{ stream_id: 1 }\n", stream.str());
}

TEST(QuicProtocolTest, StreamFrameToString) {
  QuicStreamFrame frame;
  frame.stream_id = 1;
  frame.fin = false;
  frame.offset = 2;
  frame.data_length = 3;
  std::ostringstream stream;
  stream << frame;
  EXPECT_EQ("{ stream_id: 1, fin: 0, offset: 2, length: 3 }\n", stream.str());
}

TEST(QuicProtocolTest, StopWaitingFrameToString) {
  QuicStopWaitingFrame frame;
  frame.entropy_hash = 1;
  frame.least_unacked = 2;
  std::ostringstream stream;
  stream << frame;
  EXPECT_EQ("{ entropy_hash: 1, least_unacked: 2 }\n", stream.str());
}

TEST(QuicProtocolTest, PathCloseFrameToString) {
  QuicPathCloseFrame frame;
  frame.path_id = 1;
  std::ostringstream stream;
  stream << frame;
  EXPECT_EQ("{ path_id: 1 }\n", stream.str());
}

TEST(QuicProtocolTest, FilterSupportedVersions) {
  QuicFlagSaver flags;
  QuicVersionVector all_versions = {QUIC_VERSION_32, QUIC_VERSION_33,
                                    QUIC_VERSION_34, QUIC_VERSION_35,
                                    QUIC_VERSION_36};

  FLAGS_quic_disable_pre_34 = true;
  FLAGS_quic_enable_version_35 = false;
  FLAGS_quic_enable_version_36_v2 = false;

  QuicVersionVector filtered_versions = FilterSupportedVersions(all_versions);
  ASSERT_EQ(1u, filtered_versions.size());
  EXPECT_EQ(QUIC_VERSION_34, filtered_versions[0]);
}

TEST(QuicProtocolTest, FilterSupportedVersionsAllVersions) {
  QuicFlagSaver flags;
  QuicVersionVector all_versions = {QUIC_VERSION_32, QUIC_VERSION_33,
                                    QUIC_VERSION_34, QUIC_VERSION_35,
                                    QUIC_VERSION_36};

  FLAGS_quic_disable_pre_34 = false;
  FLAGS_quic_enable_version_35 = true;
  FLAGS_quic_enable_version_36_v2 = true;

  QuicVersionVector filtered_versions = FilterSupportedVersions(all_versions);
  ASSERT_EQ(all_versions, filtered_versions);
}

TEST(QuicProtocolTest, FilterSupportedVersionsNo36) {
  QuicFlagSaver flags;
  QuicVersionVector all_versions = {QUIC_VERSION_32, QUIC_VERSION_33,
                                    QUIC_VERSION_34, QUIC_VERSION_35,
                                    QUIC_VERSION_36};

  FLAGS_quic_disable_pre_34 = false;
  FLAGS_quic_enable_version_35 = true;
  FLAGS_quic_enable_version_36_v2 = false;

  all_versions.pop_back();  // Remove 36

  ASSERT_EQ(all_versions, FilterSupportedVersions(all_versions));
}

TEST(QuicProtocolTest, FilterSupportedVersionsNo35) {
  QuicFlagSaver flags;
  QuicVersionVector all_versions = {QUIC_VERSION_32, QUIC_VERSION_33,
                                    QUIC_VERSION_34, QUIC_VERSION_35,
                                    QUIC_VERSION_36};

  FLAGS_quic_disable_pre_34 = false;
  FLAGS_quic_enable_version_35 = true;
  FLAGS_quic_enable_version_36_v2 = true;

  all_versions.pop_back();  // Remove 36
  all_versions.pop_back();  // Remove 35

  ASSERT_EQ(all_versions, FilterSupportedVersions(all_versions));
}

TEST(QuicProtocolTest, FilterSupportedVersionsNoPre34) {
  QuicFlagSaver flags;
  QuicVersionVector all_versions = {QUIC_VERSION_32, QUIC_VERSION_33,
                                    QUIC_VERSION_34, QUIC_VERSION_35,
                                    QUIC_VERSION_36};

  FLAGS_quic_disable_pre_34 = true;
  FLAGS_quic_enable_version_35 = true;
  FLAGS_quic_enable_version_36_v2 = true;

  all_versions.erase(all_versions.begin());  // Remove 32
  all_versions.erase(all_versions.begin());  // Remove 33

  ASSERT_EQ(all_versions, FilterSupportedVersions(all_versions));
}

TEST(QuicProtocolTest, QuicVersionManager) {
  QuicFlagSaver flags;
  FLAGS_quic_enable_version_35 = false;
  FLAGS_quic_enable_version_36_v2 = false;
  QuicVersionManager manager(AllSupportedVersions());
  EXPECT_EQ(FilterSupportedVersions(AllSupportedVersions()),
            manager.GetSupportedVersions());
  FLAGS_quic_enable_version_35 = true;
  FLAGS_quic_enable_version_36_v2 = true;
  EXPECT_EQ(FilterSupportedVersions(AllSupportedVersions()),
            manager.GetSupportedVersions());
  EXPECT_EQ(QUIC_VERSION_36, manager.GetSupportedVersions()[0]);
  EXPECT_EQ(QUIC_VERSION_35, manager.GetSupportedVersions()[1]);
}

TEST(QuicProtocolTest, LookUpVersionByIndex) {
  QuicVersionVector all_versions = {QUIC_VERSION_32, QUIC_VERSION_33,
                                    QUIC_VERSION_34, QUIC_VERSION_35,
                                    QUIC_VERSION_36};
  int version_count = all_versions.size();
  for (int i = -5; i <= version_count + 1; ++i) {
    if (i >= 0 && i < version_count) {
      EXPECT_EQ(all_versions[i], VersionOfIndex(all_versions, i)[0]);
    } else {
      EXPECT_EQ(QUIC_VERSION_UNSUPPORTED, VersionOfIndex(all_versions, i)[0]);
    }
  }
}

// Tests that a queue contains the expected data after calls to Add().
TEST(PacketNumberQueueTest, AddRange) {
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
TEST(PacketNumberQueueTest, Removal) {
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
TEST(PacketNumberQueueTest, Empty) {
  PacketNumberQueue queue;
  EXPECT_TRUE(queue.Empty());
  EXPECT_EQ(0u, queue.NumPacketsSlow());

  queue.Add(1, 100);
  EXPECT_TRUE(queue.RemoveUpTo(100));
  EXPECT_TRUE(queue.Empty());
  EXPECT_EQ(0u, queue.NumPacketsSlow());
}

// Tests that logging the state of a PacketNumberQueue does not crash.
TEST(PacketNumberQueueTest, LogDoesNotCrash) {
  std::ostringstream oss;
  PacketNumberQueue queue;
  oss << queue;

  queue.Add(1);
  queue.Add(50, 100);
  oss << queue;
}

// Tests that the iterators returned from a packet queue iterate over the queue.
TEST(PacketNumberQueueTest, Iterators) {
  PacketNumberQueue queue;
  queue.Add(1, 100);

  const std::vector<Interval<QuicPacketNumber>> actual_intervals(queue.begin(),
                                                                 queue.end());

  std::vector<Interval<QuicPacketNumber>> expected_intervals;
  expected_intervals.push_back(Interval<QuicPacketNumber>(1, 100));

  EXPECT_EQ(expected_intervals, actual_intervals);
}

TEST(PacketNumberQueueTest, LowerBoundEquals) {
  PacketNumberQueue queue;
  queue.Add(1, 100);

  PacketNumberQueue::const_iterator it = queue.lower_bound(10);
  ASSERT_NE(queue.end(), it);
  EXPECT_TRUE(it->Contains(10u));

  it = queue.lower_bound(101);
  EXPECT_TRUE(queue.end() == it);
}

TEST(PacketNumberQueueTest, LowerBoundGreater) {
  PacketNumberQueue queue;
  queue.Add(15, 25);
  queue.Add(50, 100);

  PacketNumberQueue::const_iterator it = queue.lower_bound(10);
  ASSERT_NE(queue.end(), it);
  EXPECT_EQ(15u, it->min());
  EXPECT_EQ(25u, it->max());
}

TEST(PacketNumberQueueTest, IntervalLengthAndRemoveInterval) {
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

TEST(PacketNumberQueueTest, Complement) {
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
