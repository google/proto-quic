// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/chromium/header_coalescer.h"

#include <vector>

#include "net/log/test_net_log.h"
#include "net/spdy/chromium/spdy_test_util_common.h"
#include "net/spdy/platform/api/spdy_string.h"
#include "net/spdy/platform/api/spdy_string_utils.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using ::testing::ElementsAre;
using ::testing::Pair;

namespace net {
namespace test {

class HeaderCoalescerTest : public ::testing::Test {
 public:
  HeaderCoalescerTest()
      : header_coalescer_(kMaxHeaderListSizeForTest, net_log_.bound()) {}

  void ExpectEntry(SpdyStringPiece expected_header_name,
                   SpdyStringPiece expected_header_value,
                   SpdyStringPiece expected_error_message) {
    TestNetLogEntry::List entry_list;
    net_log_.GetEntries(&entry_list);
    ASSERT_EQ(1u, entry_list.size());
    EXPECT_EQ(entry_list[0].type,
              NetLogEventType::HTTP2_SESSION_RECV_INVALID_HEADER);
    EXPECT_EQ(entry_list[0].source.id, net_log_.bound().source().id);
    std::string value;
    EXPECT_TRUE(entry_list[0].GetStringValue("header_name", &value));
    EXPECT_EQ(expected_header_name, value);
    EXPECT_TRUE(entry_list[0].GetStringValue("header_value", &value));
    EXPECT_EQ(expected_header_value, value);
    EXPECT_TRUE(entry_list[0].GetStringValue("error", &value));
    EXPECT_EQ(expected_error_message, value);
  }

 protected:
  BoundTestNetLog net_log_;
  HeaderCoalescer header_coalescer_;
};

TEST_F(HeaderCoalescerTest, CorrectHeaders) {
  header_coalescer_.OnHeader(":foo", "bar");
  header_coalescer_.OnHeader("baz", "qux");
  EXPECT_FALSE(header_coalescer_.error_seen());

  SpdyHeaderBlock header_block = header_coalescer_.release_headers();
  EXPECT_THAT(header_block,
              ElementsAre(Pair(":foo", "bar"), Pair("baz", "qux")));
}

TEST_F(HeaderCoalescerTest, EmptyHeaderKey) {
  header_coalescer_.OnHeader("", "foo");
  EXPECT_TRUE(header_coalescer_.error_seen());
  ExpectEntry("", "foo", "Header name must not be empty.");
}

TEST_F(HeaderCoalescerTest, HeaderBlockTooLarge) {
  // key + value + overhead = 3 + kMaxHeaderListSizeForTest - 40 + 32
  // = kMaxHeaderListSizeForTest - 5
  SpdyString data(kMaxHeaderListSizeForTest - 40, 'a');
  header_coalescer_.OnHeader("foo", data);
  EXPECT_FALSE(header_coalescer_.error_seen());

  // Another 3 + 4 + 32 bytes: too large.
  SpdyStringPiece header_value("\x1\x7F\x80\xFF");
  header_coalescer_.OnHeader("bar", header_value);
  EXPECT_TRUE(header_coalescer_.error_seen());
  ExpectEntry("bar", "%01%7F%80%FF", "Header list too large.");
}

TEST_F(HeaderCoalescerTest, PseudoHeadersMustNotFollowRegularHeaders) {
  header_coalescer_.OnHeader("foo", "bar");
  EXPECT_FALSE(header_coalescer_.error_seen());
  header_coalescer_.OnHeader(":baz", "qux");
  EXPECT_TRUE(header_coalescer_.error_seen());
  ExpectEntry(":baz", "qux", "Pseudo header must not follow regular headers.");
}

TEST_F(HeaderCoalescerTest, Append) {
  header_coalescer_.OnHeader("foo", "bar");
  header_coalescer_.OnHeader("cookie", "baz");
  header_coalescer_.OnHeader("foo", "quux");
  header_coalescer_.OnHeader("cookie", "qux");
  EXPECT_FALSE(header_coalescer_.error_seen());

  SpdyHeaderBlock header_block = header_coalescer_.release_headers();
  EXPECT_THAT(header_block,
              ElementsAre(Pair("foo", SpdyStringPiece("bar\0quux", 8)),
                          Pair("cookie", "baz; qux")));
}

TEST_F(HeaderCoalescerTest, CRLFInHeaderValue) {
  header_coalescer_.OnHeader("foo", "bar\r\nbaz");
  EXPECT_TRUE(header_coalescer_.error_seen());
  ExpectEntry("foo", "bar%0D%0Abaz", "Header value must not contain CR+LF.");
}

TEST_F(HeaderCoalescerTest, HeaderNameNotValid) {
  SpdyStringPiece header_name("\x1\x7F\x80\xFF");
  header_coalescer_.OnHeader(header_name, "foo");
  EXPECT_TRUE(header_coalescer_.error_seen());
  ExpectEntry("%01%7F%80%FF", "foo", "Invalid character in header name.");
}

// RFC 7230 Section 3.2. Valid header name is defined as:
// field-name     = token
// token          = 1*tchar
// tchar          = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." /
//                  "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
TEST_F(HeaderCoalescerTest, HeaderNameValid) {
  SpdyStringPiece header_name(
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&'*+-."
      "^_`|~");
  header_coalescer_.OnHeader(header_name, "foo");
  EXPECT_FALSE(header_coalescer_.error_seen());
  SpdyHeaderBlock header_block = header_coalescer_.release_headers();
  EXPECT_THAT(header_block, ElementsAre(Pair(header_name, "foo")));
}

// RFC 7230 Section 3.2. Valid header value is defined as:
// field-value    = *( field-content / obs-fold )
// field-content  = field-vchar [ 1*( SP / HTAB ) field-vchar ]
// field-vchar    = VCHAR / obs-text
//
// obs-fold       = CRLF 1*( SP / HTAB )
//                ; obsolete line folding
//                ; see Section 3.2.4
TEST_F(HeaderCoalescerTest, HeaderValueValid) {
  // Add two headers, one with an HTAB and one with a SP.
  std::vector<char> header_values[2];
  char prefixes[] = {'\t', ' '};
  for (int i = 0; i < 2; ++i) {
    header_values[i] = std::vector<char>();
    header_values[i].push_back(prefixes[i]);
    // obs-text. From 0x80 to 0xff.
    for (int j = 0x80; j <= 0xff; ++j) {
      header_values[i].push_back(j);
    }
    // vchar
    for (int j = 0x21; j <= 0x7E; ++j) {
      header_values[i].push_back(j);
    }
    header_coalescer_.OnHeader(
        SpdyStringPrintf("%s_%d", "foo", i),
        SpdyStringPiece(header_values[i].data(), header_values[i].size()));
    EXPECT_FALSE(header_coalescer_.error_seen());
  }
  SpdyHeaderBlock header_block = header_coalescer_.release_headers();
  EXPECT_THAT(
      header_block,
      ElementsAre(Pair("foo_0", SpdyStringPiece(header_values[0].data(),
                                                header_values[0].size())),
                  Pair("foo_1", SpdyStringPiece(header_values[1].data(),
                                                header_values[1].size()))));
}

}  // namespace test

}  // namespace net
