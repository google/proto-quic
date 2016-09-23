// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "header_coalescer.h"

#include <string>

#include "base/strings/string_piece.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using ::testing::ElementsAre;
using ::testing::Pair;

namespace net {
namespace test {

class HeaderCoalescerTest : public ::testing::Test {
 public:
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
  std::string data(256 * 1024 - 40, 'a');
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
              ElementsAre(Pair("foo", base::StringPiece("bar\0quux", 8)),
                          Pair("cookie", "baz; qux")));
}

TEST_F(HeaderCoalescerTest, CRLFInHeaderValue) {
  EXPECT_FALSE(header_coalescer_.error_seen());
  header_coalescer_.OnHeader("foo", "bar\r\nbaz");
  EXPECT_TRUE(header_coalescer_.error_seen());
}

}  // namespace test
}  // namespace net
