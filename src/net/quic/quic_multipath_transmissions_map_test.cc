// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_multipath_transmissions_map.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {
namespace test {
namespace {

TEST(QuicAcrossPathsTransmissionMapTest, OnPacketRetransmittedOnDifferentPath) {
  QuicMultipathTransmissionsMap transmission_map;
  // Packet0's original transmission sent on path 1 with packet number 1.
  QuicPathIdPacketNumber packet0_0(1, 1);
  // Packet0's retransmission sent on path 2 with packet number 1.
  QuicPathIdPacketNumber packet0_1(2, 1);
  // packet0's 2nd retransmission sent on path 3 with packet number 1.
  QuicPathIdPacketNumber packet0_2(3, 1);

  transmission_map.OnPacketRetransmittedOnDifferentPath(packet0_0, packet0_1);
  const QuicMultipathTransmissionsMap::MultipathTransmissionsList*
      transmission_list1 =
          transmission_map.MaybeGetTransmissionsOnOtherPaths(packet0_0);
  EXPECT_EQ(packet0_0, (*transmission_list1)[0]);
  EXPECT_EQ(packet0_1, (*transmission_list1)[1]);

  transmission_map.OnPacketRetransmittedOnDifferentPath(packet0_1, packet0_2);
  const QuicMultipathTransmissionsMap::MultipathTransmissionsList*
      transmission_list2 =
          transmission_map.MaybeGetTransmissionsOnOtherPaths(packet0_0);
  EXPECT_EQ(packet0_0, (*transmission_list2)[0]);
  EXPECT_EQ(packet0_1, (*transmission_list2)[1]);
  EXPECT_EQ(packet0_2, (*transmission_list2)[2]);
  // Make sure there is no memory leakage.
}

TEST(QuicAcrossPathsTransmissionMapTest, MaybeGetTransmissionsOnOtherPaths) {
  QuicMultipathTransmissionsMap transmission_map;
  // Packet0's original transmission sent on path 1 with packet number 1.
  QuicPathIdPacketNumber packet0_0(1, 1);
  // Packet0's retransmission sent on path 2 with packet number 1.
  QuicPathIdPacketNumber packet0_1(2, 1);
  // packet0's 2nd retransmission sent on path 3 with packet number 1.
  QuicPathIdPacketNumber packet0_2(3, 1);

  transmission_map.OnPacketRetransmittedOnDifferentPath(packet0_0, packet0_1);
  transmission_map.OnPacketRetransmittedOnDifferentPath(packet0_1, packet0_2);

  const QuicMultipathTransmissionsMap::MultipathTransmissionsList*
      transmission_list1 =
          transmission_map.MaybeGetTransmissionsOnOtherPaths(packet0_0);
  const QuicMultipathTransmissionsMap::MultipathTransmissionsList*
      transmission_list2 =
          transmission_map.MaybeGetTransmissionsOnOtherPaths(packet0_1);
  const QuicMultipathTransmissionsMap::MultipathTransmissionsList*
      transmission_list3 =
          transmission_map.MaybeGetTransmissionsOnOtherPaths(packet0_2);
  // Make sure all three pointers point to the same list.
  EXPECT_EQ(transmission_list1, transmission_list2);
  EXPECT_EQ(transmission_list2, transmission_list3);
  EXPECT_EQ(packet0_0, (*transmission_list1)[0]);
  EXPECT_EQ(packet0_1, (*transmission_list1)[1]);
  EXPECT_EQ(packet0_2, (*transmission_list1)[2]);

  // Packet1 which is not transmitted across path.
  QuicPathIdPacketNumber packet1_0(1, 2);
  EXPECT_EQ(nullptr,
            transmission_map.MaybeGetTransmissionsOnOtherPaths(packet1_0));
  // Make sure there is no memory leakage.
}

TEST(QuicAcrossPathsTransmissionMapTest, OnPacketHandled) {
  QuicMultipathTransmissionsMap transmission_map;

  // Packet's original transmission sent on path 1 with packet number 1.
  QuicPathIdPacketNumber packet0_0(1, 1);
  // Packet's retransmission sent on path 2 with packet number 1.
  QuicPathIdPacketNumber packet0_1(2, 1);
  // packet's 2nd retransmission sent on path 3 with packet number 1.
  QuicPathIdPacketNumber packet0_2(3, 1);
  transmission_map.OnPacketRetransmittedOnDifferentPath(packet0_0, packet0_1);
  transmission_map.OnPacketRetransmittedOnDifferentPath(packet0_1, packet0_2);

  // Packet1's original transmission sent on path 1 with packet number 2.
  QuicPathIdPacketNumber packet1_0(1, 2);
  // Packet1's retransmission sent on path 2 with packet number 2.
  QuicPathIdPacketNumber packet1_1(2, 2);
  transmission_map.OnPacketRetransmittedOnDifferentPath(packet1_0, packet1_1);

  transmission_map.OnPacketHandled(packet0_0);
  EXPECT_EQ(nullptr,
            transmission_map.MaybeGetTransmissionsOnOtherPaths(packet0_0));
  EXPECT_EQ(nullptr,
            transmission_map.MaybeGetTransmissionsOnOtherPaths(packet0_1));
  EXPECT_EQ(nullptr,
            transmission_map.MaybeGetTransmissionsOnOtherPaths(packet0_2));
  const QuicMultipathTransmissionsMap::MultipathTransmissionsList*
      transmission_list =
          transmission_map.MaybeGetTransmissionsOnOtherPaths(packet1_0);
  EXPECT_EQ(packet1_0, (*transmission_list)[0]);
  EXPECT_EQ(packet1_1, (*transmission_list)[1]);
  // Packet 1 is received on path 2.
  transmission_map.OnPacketHandled(packet1_1);
  EXPECT_EQ(nullptr,
            transmission_map.MaybeGetTransmissionsOnOtherPaths(packet1_0));
  EXPECT_EQ(nullptr,
            transmission_map.MaybeGetTransmissionsOnOtherPaths(packet1_1));
  // Make sure there is no memory leakage.
}

}  // namespace
}  // namespace test
}  // namespace net
