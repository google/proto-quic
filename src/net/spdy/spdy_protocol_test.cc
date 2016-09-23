// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/spdy_protocol.h"

#include <iostream>
#include <limits>
#include <memory>

#include "net/spdy/spdy_bitmasks.h"
#include "net/spdy/spdy_framer.h"
#include "net/spdy/spdy_test_utils.h"
#include "net/test/gtest_util.h"
#include "testing/gtest/include/gtest/gtest.h"

using std::ostream;

namespace net {

ostream& operator<<(ostream& os, const SpdyStreamPrecedence precedence) {
  if (precedence.is_spdy3_priority()) {
    os << "SpdyStreamPrecedence[spdy3_priority=" << precedence.spdy3_priority()
       << "]";
  } else {
    os << "SpdyStreamPrecedence[parent_id=" << precedence.parent_id()
       << ", weight=" << precedence.weight()
       << ", is_exclusive=" << precedence.is_exclusive() << "]";
  }
  return os;
}

namespace test {

TEST(SpdyProtocolDeathTest, TestSpdySettingsAndIdOutOfBounds) {
  std::unique_ptr<SettingsFlagsAndId> flags_and_id;

  EXPECT_SPDY_BUG(flags_and_id.reset(new SettingsFlagsAndId(1, 0xffffffff)),
                  "SPDY setting ID too large.");
  // Make sure that we get expected values in opt mode.
  if (flags_and_id.get() != nullptr) {
    EXPECT_EQ(1, flags_and_id->flags());
    EXPECT_EQ(0xffffffu, flags_and_id->id());
  }
}

TEST(SpdyProtocolTest, IsValidHTTP2FrameStreamId) {
  // Stream-specific frames must have non-zero stream ids
  EXPECT_TRUE(SpdyConstants::IsValidHTTP2FrameStreamId(1, DATA));
  EXPECT_FALSE(SpdyConstants::IsValidHTTP2FrameStreamId(0, DATA));
  EXPECT_TRUE(SpdyConstants::IsValidHTTP2FrameStreamId(1, HEADERS));
  EXPECT_FALSE(SpdyConstants::IsValidHTTP2FrameStreamId(0, HEADERS));
  EXPECT_TRUE(SpdyConstants::IsValidHTTP2FrameStreamId(1, PRIORITY));
  EXPECT_FALSE(SpdyConstants::IsValidHTTP2FrameStreamId(0, PRIORITY));
  EXPECT_TRUE(SpdyConstants::IsValidHTTP2FrameStreamId(1, RST_STREAM));
  EXPECT_FALSE(SpdyConstants::IsValidHTTP2FrameStreamId(0, RST_STREAM));
  EXPECT_TRUE(SpdyConstants::IsValidHTTP2FrameStreamId(1, CONTINUATION));
  EXPECT_FALSE(SpdyConstants::IsValidHTTP2FrameStreamId(0, CONTINUATION));
  EXPECT_TRUE(SpdyConstants::IsValidHTTP2FrameStreamId(1, PUSH_PROMISE));
  EXPECT_FALSE(SpdyConstants::IsValidHTTP2FrameStreamId(0, PUSH_PROMISE));

  // Connection-level frames must have zero stream ids
  EXPECT_FALSE(SpdyConstants::IsValidHTTP2FrameStreamId(1, GOAWAY));
  EXPECT_TRUE(SpdyConstants::IsValidHTTP2FrameStreamId(0, GOAWAY));
  EXPECT_FALSE(SpdyConstants::IsValidHTTP2FrameStreamId(1, SETTINGS));
  EXPECT_TRUE(SpdyConstants::IsValidHTTP2FrameStreamId(0, SETTINGS));
  EXPECT_FALSE(SpdyConstants::IsValidHTTP2FrameStreamId(1, PING));
  EXPECT_TRUE(SpdyConstants::IsValidHTTP2FrameStreamId(0, PING));

  // Frames that are neither stream-specific nor connection-level
  // should not have their stream id declared invalid
  EXPECT_TRUE(SpdyConstants::IsValidHTTP2FrameStreamId(1, WINDOW_UPDATE));
  EXPECT_TRUE(SpdyConstants::IsValidHTTP2FrameStreamId(0, WINDOW_UPDATE));
}

TEST(SpdyDataIRTest, Construct) {
  // Confirm that it makes a string of zero length from a StringPiece(nullptr).
  base::StringPiece s1(nullptr);
  SpdyDataIR d1(1, s1);
  EXPECT_EQ(d1.data().size(), (uint64_t)0);
  EXPECT_NE(d1.data().data(), nullptr);

  // Confirms makes a copy of char array.
  const char s2[] = "something";
  SpdyDataIR d2(2, s2);
  EXPECT_EQ(d2.data(), s2);
  EXPECT_NE(d1.data().data(), s2);

  // Confirm copies a const string.
  const std::string foo = "foo";
  SpdyDataIR d3(3, foo);
  EXPECT_EQ(foo, d3.data());

  // Confirm copies a non-const string.
  std::string bar = "bar";
  SpdyDataIR d4(4, bar);
  bar[0] = 'B';
  EXPECT_EQ("bar", d4.data());

  // Confirm moves an rvalue reference. Note that the test string "baz" is too
  // short to trigger the move optimization, and instead a copy occurs.
  std::string baz = "The quick brown fox jumps over the lazy dog.";
  const char* baz_data = baz.data();
  SpdyDataIR d5(5, std::move(baz));
  EXPECT_EQ("", baz);
  EXPECT_EQ(d5.data(), "The quick brown fox jumps over the lazy dog.");
  EXPECT_EQ(d5.data().data(), baz_data);

  // Confirm that it makes a string of zero length from a nullptr.
  SpdyDataIR d6(6, nullptr);
  EXPECT_EQ(d6.data().size(), (uint64_t)0);
  EXPECT_NE(d6.data().data(), nullptr);

  // Confirms makes a copy of string literal.
  SpdyDataIR d7(7, "something else");
  EXPECT_EQ(d7.data(), "something else");
}

TEST(SpdyProtocolTest, ClampSpdy3Priority) {
  EXPECT_SPDY_BUG(EXPECT_EQ(7, ClampSpdy3Priority(8)), "Invalid priority: 8");
  EXPECT_EQ(kV3LowestPriority, ClampSpdy3Priority(kV3LowestPriority));
  EXPECT_EQ(kV3HighestPriority, ClampSpdy3Priority(kV3HighestPriority));
}

TEST(SpdyProtocolTest, ClampHttp2Weight) {
  EXPECT_SPDY_BUG(EXPECT_EQ(kHttp2MinStreamWeight, ClampHttp2Weight(0)),
                  "Invalid weight: 0");
  EXPECT_SPDY_BUG(EXPECT_EQ(kHttp2MaxStreamWeight, ClampHttp2Weight(300)),
                  "Invalid weight: 300");
  EXPECT_EQ(kHttp2MinStreamWeight, ClampHttp2Weight(kHttp2MinStreamWeight));
  EXPECT_EQ(kHttp2MaxStreamWeight, ClampHttp2Weight(kHttp2MaxStreamWeight));
}

TEST(SpdyProtocolTest, Spdy3PriorityToHttp2Weight) {
  EXPECT_EQ(256, Spdy3PriorityToHttp2Weight(0));
  EXPECT_EQ(220, Spdy3PriorityToHttp2Weight(1));
  EXPECT_EQ(183, Spdy3PriorityToHttp2Weight(2));
  EXPECT_EQ(147, Spdy3PriorityToHttp2Weight(3));
  EXPECT_EQ(110, Spdy3PriorityToHttp2Weight(4));
  EXPECT_EQ(74, Spdy3PriorityToHttp2Weight(5));
  EXPECT_EQ(37, Spdy3PriorityToHttp2Weight(6));
  EXPECT_EQ(1, Spdy3PriorityToHttp2Weight(7));
}

TEST(SpdyProtocolTest, Http2WeightToSpdy3Priority) {
  EXPECT_EQ(0u, Http2WeightToSpdy3Priority(256));
  EXPECT_EQ(0u, Http2WeightToSpdy3Priority(221));
  EXPECT_EQ(1u, Http2WeightToSpdy3Priority(220));
  EXPECT_EQ(1u, Http2WeightToSpdy3Priority(184));
  EXPECT_EQ(2u, Http2WeightToSpdy3Priority(183));
  EXPECT_EQ(2u, Http2WeightToSpdy3Priority(148));
  EXPECT_EQ(3u, Http2WeightToSpdy3Priority(147));
  EXPECT_EQ(3u, Http2WeightToSpdy3Priority(111));
  EXPECT_EQ(4u, Http2WeightToSpdy3Priority(110));
  EXPECT_EQ(4u, Http2WeightToSpdy3Priority(75));
  EXPECT_EQ(5u, Http2WeightToSpdy3Priority(74));
  EXPECT_EQ(5u, Http2WeightToSpdy3Priority(38));
  EXPECT_EQ(6u, Http2WeightToSpdy3Priority(37));
  EXPECT_EQ(6u, Http2WeightToSpdy3Priority(2));
  EXPECT_EQ(7u, Http2WeightToSpdy3Priority(1));
}

TEST(SpdyStreamPrecedenceTest, Basic) {
  SpdyStreamPrecedence spdy3_prec(2);
  EXPECT_TRUE(spdy3_prec.is_spdy3_priority());
  EXPECT_EQ(2, spdy3_prec.spdy3_priority());
  EXPECT_EQ(kHttp2RootStreamId, spdy3_prec.parent_id());
  EXPECT_EQ(Spdy3PriorityToHttp2Weight(2), spdy3_prec.weight());
  EXPECT_FALSE(spdy3_prec.is_exclusive());

  for (bool is_exclusive : {true, false}) {
    SpdyStreamPrecedence h2_prec(7, 123, is_exclusive);
    EXPECT_FALSE(h2_prec.is_spdy3_priority());
    EXPECT_EQ(Http2WeightToSpdy3Priority(123), h2_prec.spdy3_priority());
    EXPECT_EQ(7u, h2_prec.parent_id());
    EXPECT_EQ(123, h2_prec.weight());
    EXPECT_EQ(is_exclusive, h2_prec.is_exclusive());
  }
}

TEST(SpdyStreamPrecedenceTest, Clamping) {
  EXPECT_SPDY_BUG(EXPECT_EQ(7, SpdyStreamPrecedence(8).spdy3_priority()),
                  "Invalid priority: 8");
  EXPECT_SPDY_BUG(EXPECT_EQ(kHttp2MinStreamWeight,
                            SpdyStreamPrecedence(3, 0, false).weight()),
                  "Invalid weight: 0");
  EXPECT_SPDY_BUG(EXPECT_EQ(kHttp2MaxStreamWeight,
                            SpdyStreamPrecedence(3, 300, false).weight()),
                  "Invalid weight: 300");
}

TEST(SpdyStreamPrecedenceTest, Copying) {
  SpdyStreamPrecedence prec1(3);
  SpdyStreamPrecedence copy1(prec1);
  EXPECT_TRUE(copy1.is_spdy3_priority());
  EXPECT_EQ(3, copy1.spdy3_priority());

  SpdyStreamPrecedence prec2(4, 5, true);
  SpdyStreamPrecedence copy2(prec2);
  EXPECT_FALSE(copy2.is_spdy3_priority());
  EXPECT_EQ(4u, copy2.parent_id());
  EXPECT_EQ(5, copy2.weight());
  EXPECT_TRUE(copy2.is_exclusive());

  copy1 = prec2;
  EXPECT_FALSE(copy1.is_spdy3_priority());
  EXPECT_EQ(4u, copy1.parent_id());
  EXPECT_EQ(5, copy1.weight());
  EXPECT_TRUE(copy1.is_exclusive());

  copy2 = prec1;
  EXPECT_TRUE(copy2.is_spdy3_priority());
  EXPECT_EQ(3, copy2.spdy3_priority());
}

TEST(SpdyStreamPrecedenceTest, Equals) {
  EXPECT_EQ(SpdyStreamPrecedence(3), SpdyStreamPrecedence(3));
  EXPECT_NE(SpdyStreamPrecedence(3), SpdyStreamPrecedence(4));

  EXPECT_EQ(SpdyStreamPrecedence(1, 2, false),
            SpdyStreamPrecedence(1, 2, false));
  EXPECT_NE(SpdyStreamPrecedence(1, 2, false),
            SpdyStreamPrecedence(2, 2, false));
  EXPECT_NE(SpdyStreamPrecedence(1, 2, false),
            SpdyStreamPrecedence(1, 3, false));
  EXPECT_NE(SpdyStreamPrecedence(1, 2, false),
            SpdyStreamPrecedence(1, 2, true));

  SpdyStreamPrecedence spdy3_prec(3);
  SpdyStreamPrecedence h2_prec(spdy3_prec.parent_id(), spdy3_prec.weight(),
                               spdy3_prec.is_exclusive());
  EXPECT_NE(spdy3_prec, h2_prec);
}

}  // namespace test
}  // namespace net
