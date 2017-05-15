// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/chromium/header_coalescer.h"

#include <vector>

#include "net/log/net_log_with_source.h"
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
  HeaderCoalescerTest() : header_coalescer_(NetLogWithSource()) {}

 protected:
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
  EXPECT_FALSE(header_coalescer_.error_seen());
  header_coalescer_.OnHeader("", "foo");
  EXPECT_TRUE(header_coalescer_.error_seen());
}

TEST_F(HeaderCoalescerTest, HeaderBlockTooLarge) {
  // 3 byte key, 256 * 1024 - 40 byte value, 32 byte overhead:
  // less than 256 * 1024 bytes in total.
  SpdyString data(256 * 1024 - 40, 'a');
  header_coalescer_.OnHeader("foo", data);
  EXPECT_FALSE(header_coalescer_.error_seen());

  // Another 3 + 3 + 32 bytes: too large.
  header_coalescer_.OnHeader("bar", "baz");
  EXPECT_TRUE(header_coalescer_.error_seen());
}

TEST_F(HeaderCoalescerTest, PseudoHeadersMustNotFollowRegularHeaders) {
  header_coalescer_.OnHeader("foo", "bar");
  EXPECT_FALSE(header_coalescer_.error_seen());
  header_coalescer_.OnHeader(":baz", "qux");
  EXPECT_TRUE(header_coalescer_.error_seen());
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
  EXPECT_FALSE(header_coalescer_.error_seen());
  header_coalescer_.OnHeader("foo", "bar\r\nbaz");
  EXPECT_TRUE(header_coalescer_.error_seen());
}

TEST_F(HeaderCoalescerTest, HeaderNameNotValid) {
  SpdyStringPiece header_name("\x01\x7F\x80\xff");
  header_coalescer_.OnHeader(header_name, "foo");
  EXPECT_TRUE(header_coalescer_.error_seen());
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
