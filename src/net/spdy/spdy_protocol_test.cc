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

using std::string;

namespace net {

std::ostream& operator<<(std::ostream& os,
                         const SpdyStreamPrecedence precedence) {
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

TEST(SpdyProtocolTest, IsValidHTTP2FrameStreamId) {
  // Stream-specific frames must have non-zero stream ids
  EXPECT_TRUE(IsValidHTTP2FrameStreamId(1, DATA));
  EXPECT_FALSE(IsValidHTTP2FrameStreamId(0, DATA));
  EXPECT_TRUE(IsValidHTTP2FrameStreamId(1, HEADERS));
  EXPECT_FALSE(IsValidHTTP2FrameStreamId(0, HEADERS));
  EXPECT_TRUE(IsValidHTTP2FrameStreamId(1, PRIORITY));
  EXPECT_FALSE(IsValidHTTP2FrameStreamId(0, PRIORITY));
  EXPECT_TRUE(IsValidHTTP2FrameStreamId(1, RST_STREAM));
  EXPECT_FALSE(IsValidHTTP2FrameStreamId(0, RST_STREAM));
  EXPECT_TRUE(IsValidHTTP2FrameStreamId(1, CONTINUATION));
  EXPECT_FALSE(IsValidHTTP2FrameStreamId(0, CONTINUATION));
  EXPECT_TRUE(IsValidHTTP2FrameStreamId(1, PUSH_PROMISE));
  EXPECT_FALSE(IsValidHTTP2FrameStreamId(0, PUSH_PROMISE));

  // Connection-level frames must have zero stream ids
  EXPECT_FALSE(IsValidHTTP2FrameStreamId(1, GOAWAY));
  EXPECT_TRUE(IsValidHTTP2FrameStreamId(0, GOAWAY));
  EXPECT_FALSE(IsValidHTTP2FrameStreamId(1, SETTINGS));
  EXPECT_TRUE(IsValidHTTP2FrameStreamId(0, SETTINGS));
  EXPECT_FALSE(IsValidHTTP2FrameStreamId(1, PING));
  EXPECT_TRUE(IsValidHTTP2FrameStreamId(0, PING));

  // Frames that are neither stream-specific nor connection-level
  // should not have their stream id declared invalid
  EXPECT_TRUE(IsValidHTTP2FrameStreamId(1, WINDOW_UPDATE));
  EXPECT_TRUE(IsValidHTTP2FrameStreamId(0, WINDOW_UPDATE));
}

TEST(SpdyProtocolTest, ParseSettingsId) {
  SpdySettingsIds setting_id;
  EXPECT_FALSE(ParseSettingsId(0, &setting_id));
  EXPECT_TRUE(ParseSettingsId(1, &setting_id));
  EXPECT_EQ(SETTINGS_HEADER_TABLE_SIZE, setting_id);
  EXPECT_TRUE(ParseSettingsId(2, &setting_id));
  EXPECT_EQ(SETTINGS_ENABLE_PUSH, setting_id);
  EXPECT_TRUE(ParseSettingsId(3, &setting_id));
  EXPECT_EQ(SETTINGS_MAX_CONCURRENT_STREAMS, setting_id);
  EXPECT_TRUE(ParseSettingsId(4, &setting_id));
  EXPECT_EQ(SETTINGS_INITIAL_WINDOW_SIZE, setting_id);
  EXPECT_TRUE(ParseSettingsId(5, &setting_id));
  EXPECT_EQ(SETTINGS_MAX_FRAME_SIZE, setting_id);
  EXPECT_TRUE(ParseSettingsId(6, &setting_id));
  EXPECT_EQ(SETTINGS_MAX_HEADER_LIST_SIZE, setting_id);
  EXPECT_FALSE(ParseSettingsId(7, &setting_id));
}

TEST(SpdyProtocolTest, SettingsIdToString) {
  struct {
    SpdySettingsIds setting_id;
    bool expected_bool;
    const string expected_string;
  } test_cases[] = {
      {static_cast<SpdySettingsIds>(0), false, "SETTINGS_UNKNOWN"},
      {SETTINGS_HEADER_TABLE_SIZE, true, "SETTINGS_HEADER_TABLE_SIZE"},
      {SETTINGS_ENABLE_PUSH, true, "SETTINGS_ENABLE_PUSH"},
      {SETTINGS_MAX_CONCURRENT_STREAMS, true,
       "SETTINGS_MAX_CONCURRENT_STREAMS"},
      {SETTINGS_INITIAL_WINDOW_SIZE, true, "SETTINGS_INITIAL_WINDOW_SIZE"},
      {SETTINGS_MAX_FRAME_SIZE, true, "SETTINGS_MAX_FRAME_SIZE"},
      {SETTINGS_MAX_HEADER_LIST_SIZE, true, "SETTINGS_MAX_HEADER_LIST_SIZE"},
      {static_cast<SpdySettingsIds>(7), false, "SETTINGS_UNKNOWN"}};
  for (auto test_case : test_cases) {
    const char* settings_id_string;
    EXPECT_EQ(test_case.expected_bool,
              SettingsIdToString(test_case.setting_id, &settings_id_string));
    EXPECT_EQ(test_case.expected_string, settings_id_string);
  }
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

TEST(SpdyDataIRTest, Construct) {
  // Confirm that it makes a string of zero length from a StringPiece(nullptr).
  base::StringPiece s1;
  SpdyDataIR d1(1, s1);
  EXPECT_EQ(d1.data_len(), 0ul);
  EXPECT_NE(d1.data(), nullptr);

  // Confirms makes a copy of char array.
  const char s2[] = "something";
  SpdyDataIR d2(2, s2);
  EXPECT_EQ(base::StringPiece(d2.data(), d2.data_len()), s2);
  EXPECT_NE(base::StringPiece(d1.data(), d1.data_len()), s2);

  // Confirm copies a const string.
  const string foo = "foo";
  SpdyDataIR d3(3, foo);
  EXPECT_EQ(foo, d3.data());

  // Confirm copies a non-const string.
  string bar = "bar";
  SpdyDataIR d4(4, bar);
  EXPECT_EQ("bar", bar);
  EXPECT_EQ("bar", base::StringPiece(d4.data(), d4.data_len()));

  // Confirm moves an rvalue reference. Note that the test string "baz" is too
  // short to trigger the move optimization, and instead a copy occurs.
  string baz = "the quick brown fox";
  SpdyDataIR d5(5, std::move(baz));
  EXPECT_EQ("", baz);
  EXPECT_EQ(base::StringPiece(d5.data(), d5.data_len()), "the quick brown fox");

  // Confirms makes a copy of string literal.
  SpdyDataIR d7(7, "something else");
  EXPECT_EQ(base::StringPiece(d7.data(), d7.data_len()), "something else");
}

}  // namespace test
}  // namespace net
