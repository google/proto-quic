// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/write_scheduler.h"

#include "net/spdy/spdy_test_utils.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace test {

TEST(WriteSchedulerTest, ClampSpdyPriority) {
  EXPECT_SPDY_BUG(EXPECT_EQ(7, ClampSpdyPriority(8)), "Invalid priority: 8");
  EXPECT_EQ(kV3LowestPriority, ClampSpdyPriority(kV3LowestPriority));
  EXPECT_EQ(kV3HighestPriority, ClampSpdyPriority(kV3HighestPriority));
}

TEST(WriteSchedulerTest, ClampHttp2Weight) {
  EXPECT_SPDY_BUG(EXPECT_EQ(kHttp2MinStreamWeight, ClampHttp2Weight(0)),
                  "Invalid weight: 0");
  EXPECT_SPDY_BUG(EXPECT_EQ(kHttp2MaxStreamWeight, ClampHttp2Weight(300)),
                  "Invalid weight: 300");
  EXPECT_EQ(kHttp2MinStreamWeight, ClampHttp2Weight(kHttp2MinStreamWeight));
  EXPECT_EQ(kHttp2MaxStreamWeight, ClampHttp2Weight(kHttp2MaxStreamWeight));
}

TEST(WriteSchedulerTest, SpdyPriorityToHttp2Weight) {
  EXPECT_EQ(256, SpdyPriorityToHttp2Weight(0));
  EXPECT_EQ(220, SpdyPriorityToHttp2Weight(1));
  EXPECT_EQ(183, SpdyPriorityToHttp2Weight(2));
  EXPECT_EQ(147, SpdyPriorityToHttp2Weight(3));
  EXPECT_EQ(110, SpdyPriorityToHttp2Weight(4));
  EXPECT_EQ(74, SpdyPriorityToHttp2Weight(5));
  EXPECT_EQ(37, SpdyPriorityToHttp2Weight(6));
  EXPECT_EQ(1, SpdyPriorityToHttp2Weight(7));
}

TEST(WriteSchedulerTest, Http2WeightToSpdyPriority) {
  EXPECT_EQ(0u, Http2WeightToSpdyPriority(256));
  EXPECT_EQ(0u, Http2WeightToSpdyPriority(221));
  EXPECT_EQ(1u, Http2WeightToSpdyPriority(220));
  EXPECT_EQ(1u, Http2WeightToSpdyPriority(184));
  EXPECT_EQ(2u, Http2WeightToSpdyPriority(183));
  EXPECT_EQ(2u, Http2WeightToSpdyPriority(148));
  EXPECT_EQ(3u, Http2WeightToSpdyPriority(147));
  EXPECT_EQ(3u, Http2WeightToSpdyPriority(111));
  EXPECT_EQ(4u, Http2WeightToSpdyPriority(110));
  EXPECT_EQ(4u, Http2WeightToSpdyPriority(75));
  EXPECT_EQ(5u, Http2WeightToSpdyPriority(74));
  EXPECT_EQ(5u, Http2WeightToSpdyPriority(38));
  EXPECT_EQ(6u, Http2WeightToSpdyPriority(37));
  EXPECT_EQ(6u, Http2WeightToSpdyPriority(2));
  EXPECT_EQ(7u, Http2WeightToSpdyPriority(1));
}

}  // namespace test
}  // namespace net
