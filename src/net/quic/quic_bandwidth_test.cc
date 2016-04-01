// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_bandwidth.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {
namespace test {

class QuicBandwidthTest : public ::testing::Test {};

TEST_F(QuicBandwidthTest, FromTo) {
  EXPECT_EQ(QuicBandwidth::FromKBitsPerSecond(1),
            QuicBandwidth::FromBitsPerSecond(1000));
  EXPECT_EQ(QuicBandwidth::FromKBytesPerSecond(1),
            QuicBandwidth::FromBytesPerSecond(1000));
  EXPECT_EQ(QuicBandwidth::FromBitsPerSecond(8000),
            QuicBandwidth::FromBytesPerSecond(1000));
  EXPECT_EQ(QuicBandwidth::FromKBitsPerSecond(8),
            QuicBandwidth::FromKBytesPerSecond(1));

  EXPECT_EQ(0, QuicBandwidth::Zero().ToBitsPerSecond());
  EXPECT_EQ(0, QuicBandwidth::Zero().ToKBitsPerSecond());
  EXPECT_EQ(0, QuicBandwidth::Zero().ToBytesPerSecond());
  EXPECT_EQ(0, QuicBandwidth::Zero().ToKBytesPerSecond());

  EXPECT_EQ(1, QuicBandwidth::FromBitsPerSecond(1000).ToKBitsPerSecond());
  EXPECT_EQ(1000, QuicBandwidth::FromKBitsPerSecond(1).ToBitsPerSecond());
  EXPECT_EQ(1, QuicBandwidth::FromBytesPerSecond(1000).ToKBytesPerSecond());
  EXPECT_EQ(1000, QuicBandwidth::FromKBytesPerSecond(1).ToBytesPerSecond());
}

TEST_F(QuicBandwidthTest, Add) {
  QuicBandwidth bandwidht_1 = QuicBandwidth::FromKBitsPerSecond(1);
  QuicBandwidth bandwidht_2 = QuicBandwidth::FromKBytesPerSecond(1);

  EXPECT_EQ(9000, bandwidht_1.Add(bandwidht_2).ToBitsPerSecond());
  EXPECT_EQ(9000, bandwidht_2.Add(bandwidht_1).ToBitsPerSecond());
}

TEST_F(QuicBandwidthTest, Subtract) {
  QuicBandwidth bandwidht_1 = QuicBandwidth::FromKBitsPerSecond(1);
  QuicBandwidth bandwidht_2 = QuicBandwidth::FromKBytesPerSecond(1);

  EXPECT_EQ(7000, bandwidht_2.Subtract(bandwidht_1).ToBitsPerSecond());
}

TEST_F(QuicBandwidthTest, TimeDelta) {
  EXPECT_EQ(QuicBandwidth::FromKBytesPerSecond(1000),
            QuicBandwidth::FromBytesAndTimeDelta(
                1000, QuicTime::Delta::FromMilliseconds(1)));

  EXPECT_EQ(QuicBandwidth::FromKBytesPerSecond(10),
            QuicBandwidth::FromBytesAndTimeDelta(
                1000, QuicTime::Delta::FromMilliseconds(100)));
}

TEST_F(QuicBandwidthTest, Scale) {
  EXPECT_EQ(QuicBandwidth::FromKBytesPerSecond(500),
            QuicBandwidth::FromKBytesPerSecond(1000).Scale(0.5f));
  EXPECT_EQ(QuicBandwidth::FromKBytesPerSecond(750),
            QuicBandwidth::FromKBytesPerSecond(1000).Scale(0.75f));
  EXPECT_EQ(QuicBandwidth::FromKBytesPerSecond(1250),
            QuicBandwidth::FromKBytesPerSecond(1000).Scale(1.25f));
}

TEST_F(QuicBandwidthTest, BytesPerPeriod) {
  EXPECT_EQ(2000u, QuicBandwidth::FromKBytesPerSecond(2000)
                       .ToBytesPerPeriod(QuicTime::Delta::FromMilliseconds(1)));
  EXPECT_EQ(2u, QuicBandwidth::FromKBytesPerSecond(2000)
                    .ToKBytesPerPeriod(QuicTime::Delta::FromMilliseconds(1)));
  EXPECT_EQ(200000u, QuicBandwidth::FromKBytesPerSecond(2000).ToBytesPerPeriod(
                         QuicTime::Delta::FromMilliseconds(100)));
  EXPECT_EQ(200u, QuicBandwidth::FromKBytesPerSecond(2000).ToKBytesPerPeriod(
                      QuicTime::Delta::FromMilliseconds(100)));
}

TEST_F(QuicBandwidthTest, TransferTime) {
  EXPECT_EQ(QuicTime::Delta::FromSeconds(1),
            QuicBandwidth::FromKBytesPerSecond(1).TransferTime(1000));
  EXPECT_EQ(QuicTime::Delta::Zero(), QuicBandwidth::Zero().TransferTime(1000));
}

TEST_F(QuicBandwidthTest, RelOps) {
  const QuicBandwidth b1 = QuicBandwidth::FromKBitsPerSecond(1);
  const QuicBandwidth b2 = QuicBandwidth::FromKBytesPerSecond(2);
  EXPECT_EQ(b1, b1);
  EXPECT_NE(b1, b2);
  EXPECT_LT(b1, b2);
  EXPECT_GT(b2, b1);
  EXPECT_LE(b1, b1);
  EXPECT_LE(b1, b2);
  EXPECT_GE(b1, b1);
  EXPECT_GE(b2, b1);
}

}  // namespace test
}  // namespace net
