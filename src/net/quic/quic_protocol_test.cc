// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_protocol.h"

#include <sstream>

#include "base/stl_util.h"
#include "net/quic/quic_utils.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {
namespace test {
namespace {

TEST(QuicProtocolTest, AdjustErrorForVersion) {
  ASSERT_EQ(14, QUIC_STREAM_LAST_ERROR)
      << "Any additions to QuicRstStreamErrorCode require an addition to "
      << "AdjustErrorForVersion and this associated test.";

  // If we ever add different RST codes, we should have a test akin to the
  // following.
  //  EXPECT_EQ(QUIC_RST_ACKNOWLEDGEMENT, AdjustErrorForVersion(
  //      QUIC_RST_ACKNOWLEDGEMENT,
  //      QUIC_VERSION_28));
}

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

TEST(QuicProtocolTest, QuicDeprecatedErrorCodeCount) {
  // If you deprecated any QuicErrorCode, you will need to update the
  // deprecated QuicErrorCode count. Otherwise this test will fail.
  int num_deprecated_errors = 0;
  std::string invalid_error_code = "INVALID_ERROR_CODE";
  for (int i = 0; i < QUIC_LAST_ERROR; ++i) {
    if (QuicUtils::ErrorToString(static_cast<QuicErrorCode>(i)) ==
        invalid_error_code) {
      ++num_deprecated_errors;
    }
  }
  EXPECT_EQ(kDeprecatedQuicErrorCount, num_deprecated_errors);
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
  EXPECT_EQ(MakeQuicTag('Q', '0', '2', '5'),
            QuicVersionToQuicTag(QUIC_VERSION_25));

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
  EXPECT_EQ(QUIC_VERSION_25,
            QuicTagToQuicVersion(MakeQuicTag('Q', '0', '2', '5')));

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
  EXPECT_EQ("QUIC_VERSION_25", QuicVersionToString(QUIC_VERSION_25));
  EXPECT_EQ("QUIC_VERSION_UNSUPPORTED",
            QuicVersionToString(QUIC_VERSION_UNSUPPORTED));

  QuicVersion single_version[] = {QUIC_VERSION_25};
  QuicVersionVector versions_vector;
  for (size_t i = 0; i < arraysize(single_version); ++i) {
    versions_vector.push_back(single_version[i]);
  }
  EXPECT_EQ("QUIC_VERSION_25", QuicVersionVectorToString(versions_vector));

  QuicVersion multiple_versions[] = {QUIC_VERSION_UNSUPPORTED, QUIC_VERSION_25};
  versions_vector.clear();
  for (size_t i = 0; i < arraysize(multiple_versions); ++i) {
    versions_vector.push_back(multiple_versions[i]);
  }
  EXPECT_EQ("QUIC_VERSION_UNSUPPORTED,QUIC_VERSION_25",
            QuicVersionVectorToString(versions_vector));

  // Make sure that all supported versions are present in QuicVersionToString.
  for (size_t i = 0; i < arraysize(kSupportedQuicVersions); ++i) {
    QuicVersion version = kSupportedQuicVersions[i];
    EXPECT_NE("QUIC_VERSION_UNSUPPORTED", QuicVersionToString(version));
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

  const std::vector<QuicPacketNumber> actual(queue.begin(), queue.end());

  std::vector<QuicPacketNumber> expected;
  for (int i = 1; i < 100; ++i) {
    expected.push_back(i);
  }

  EXPECT_EQ(expected, actual);

  PacketNumberQueue::const_iterator it_low = queue.lower_bound(10);
  EXPECT_EQ(10u, *it_low);

  it_low = queue.lower_bound(101);
  EXPECT_TRUE(queue.end() == it_low);
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

}  // namespace
}  // namespace test
}  // namespace net
