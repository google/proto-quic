// Copyright (c) 2009 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/dns/dns_util.h"

#include "testing/gtest/include/gtest/gtest.h"

namespace net {

class DNSUtilTest : public testing::Test {
};

// IncludeNUL converts a char* to a std::string and includes the terminating
// NUL in the result.
static std::string IncludeNUL(const char* in) {
  return std::string(in, strlen(in) + 1);
}

TEST_F(DNSUtilTest, DNSDomainFromDot) {
  std::string out;

  EXPECT_FALSE(DNSDomainFromDot("", &out));
  EXPECT_FALSE(DNSDomainFromDot(".", &out));
  EXPECT_FALSE(DNSDomainFromDot("..", &out));

  EXPECT_TRUE(DNSDomainFromDot("com", &out));
  EXPECT_EQ(out, IncludeNUL("\003com"));
  EXPECT_TRUE(DNSDomainFromDot("google.com", &out));
  EXPECT_EQ(out, IncludeNUL("\x006google\003com"));
  EXPECT_TRUE(DNSDomainFromDot("www.google.com", &out));
  EXPECT_EQ(out, IncludeNUL("\003www\006google\003com"));

  // Label is 63 chars: still valid
  EXPECT_TRUE(DNSDomainFromDot("z23456789a123456789a123456789a123456789a123456789a123456789a123", &out));
  EXPECT_EQ(out, IncludeNUL("\077z23456789a123456789a123456789a123456789a123456789a123456789a123"));

  // Label is too long: invalid
  EXPECT_FALSE(DNSDomainFromDot("123456789a123456789a123456789a123456789a123456789a123456789a1234", &out));

  // 253 characters in the name: still valid
  EXPECT_TRUE(DNSDomainFromDot("abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abcdefghi.abc", &out));
  EXPECT_EQ(out, IncludeNUL("\011abcdefghi\011abcdefghi\011abcdefghi\011abcdefghi\011abcdefghi\011abcdefghi\011abcdefghi\011abcdefghi\011abcdefghi\011abcdefghi\011abcdefghi\011abcdefghi\011abcdefghi\011abcdefghi\011abcdefghi\011abcdefghi\011abcdefghi\011abcdefghi\011abcdefghi\011abcdefghi\011abcdefghi\011abcdefghi\011abcdefghi\011abcdefghi\011abcdefghi\003abc"));

  // 254 characters in the name: invalid
  EXPECT_FALSE(DNSDomainFromDot("123456789.123456789.123456789.123456789.123456789.123456789.123456789.123456789.123456789.123456789.123456789.123456789.123456789.123456789.123456789.123456789.123456789.123456789.123456789.123456789.123456789.123456789.123456789.123456789.123456789.1234", &out));

  // Zero length labels should fail, except that one trailing dot is allowed
  // (to disable suffix search):
  EXPECT_FALSE(DNSDomainFromDot(".google.com", &out));
  EXPECT_FALSE(DNSDomainFromDot("www..google.com", &out));

  EXPECT_TRUE(DNSDomainFromDot("www.google.com.", &out));
  EXPECT_EQ(out, IncludeNUL("\003www\006google\003com"));
}

TEST_F(DNSUtilTest, DNSDomainToString) {
  EXPECT_EQ("", DNSDomainToString(IncludeNUL("")));
  EXPECT_EQ("foo", DNSDomainToString(IncludeNUL("\003foo")));
  EXPECT_EQ("foo.bar", DNSDomainToString(IncludeNUL("\003foo\003bar")));
  EXPECT_EQ("foo.bar.uk",
            DNSDomainToString(IncludeNUL("\003foo\003bar\002uk")));

  // It should cope with a lack of root label.
  EXPECT_EQ("foo.bar", DNSDomainToString("\003foo\003bar"));

  // Invalid inputs should return an empty string.
  EXPECT_EQ("", DNSDomainToString(IncludeNUL("\x80")));
  EXPECT_EQ("", DNSDomainToString("\x06"));
}

}  // namespace net
