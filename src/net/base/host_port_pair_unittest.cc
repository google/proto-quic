// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/base/host_port_pair.h"

#include "base/logging.h"
#include "net/test/gtest_util.h"
#include "testing/gtest/include/gtest/gtest.h"

using std::string;

namespace net {

namespace {

struct TestData {
  string host;
  uint16_t port;
  string to_string;
  string host_for_url;
} tests[] = {
  { "www.google.com", 80, "www.google.com:80", "www.google.com" },
  { "www.google.com", 443, "www.google.com:443", "www.google.com" },
  { "127.0.0.1", 80, "127.0.0.1:80", "127.0.0.1" },
  { "192.168.1.1", 80, "192.168.1.1:80", "192.168.1.1" },
  { "::1", 80, "[::1]:80", "[::1]" },
  { "2001:db8::42", 80, "[2001:db8::42]:80", "[2001:db8::42]" },
};

TEST(HostPortPairTest, Parsing) {
  HostPortPair foo("foo.com", 10);
  string foo_str = foo.ToString();
  EXPECT_EQ("foo.com:10", foo_str);
  HostPortPair bar = HostPortPair::FromString(foo_str);
  EXPECT_TRUE(foo.Equals(bar));
}

TEST(HostPortPairTest, BadString) {
  const char* kBadStrings[] = {
      "foo.com:2:3",       "bar.com:two",     "www.google.com:-1",
      "www.google.com:+1", "127.0.0.1:65536", "[2001:db8::42]:65536",
  };

  for (size_t index = 0; index < arraysize(kBadStrings); ++index) {
    HostPortPair foo = HostPortPair::FromString(kBadStrings[index]);
    EXPECT_TRUE(foo.host().empty());
    EXPECT_EQ(0, foo.port());
  }
}

TEST(HostPortPairTest, Emptiness) {
  HostPortPair foo;
  EXPECT_TRUE(foo.IsEmpty());
  foo = HostPortPair::FromString("foo.com:8080");
  EXPECT_FALSE(foo.IsEmpty());
}

TEST(HostPortPairTest, ToString) {
  for (size_t index = 0; index < arraysize(tests); ++index) {
    HostPortPair foo(tests[index].host, tests[index].port);
    EXPECT_EQ(tests[index].to_string, foo.ToString());
  }

  // Test empty hostname.
  HostPortPair foo(string(), 10);
}

TEST(HostPortPairTest, HostForURL) {
  for (size_t index = 0; index < arraysize(tests); ++index) {
    HostPortPair foo(tests[index].host, tests[index].port);
    EXPECT_EQ(tests[index].host_for_url, foo.HostForURL());
  }

  // Test hostname with null character.
  string bar_hostname("a\0.\0com", 7);
  HostPortPair bar(bar_hostname, 80);
  string expected_error("Host has a null char: a%00.%00com");
  EXPECT_DFATAL(bar.HostForURL(), expected_error);
}

TEST(HostPortPairTest, LessThan) {
  HostPortPair a_10("a.com", 10);
  HostPortPair a_11("a.com", 11);
  HostPortPair b_10("b.com", 10);
  HostPortPair b_11("b.com", 11);

  EXPECT_FALSE(a_10 < a_10);
  EXPECT_TRUE(a_10  < a_11);
  EXPECT_TRUE(a_10  < b_10);
  EXPECT_TRUE(a_10  < b_11);

  EXPECT_FALSE(a_11 < a_10);
  EXPECT_FALSE(a_11 < b_10);

  EXPECT_FALSE(b_10 < a_10);
  EXPECT_TRUE(b_10  < a_11);

  EXPECT_FALSE(b_11 < a_10);
}

TEST(HostPortPairTest, Equals) {
  HostPortPair a_10("a.com", 10);
  HostPortPair a_11("a.com", 11);
  HostPortPair b_10("b.com", 10);
  HostPortPair b_11("b.com", 11);

  HostPortPair new_a_10("a.com", 10);

  EXPECT_TRUE(new_a_10.Equals(a_10));
  EXPECT_FALSE(new_a_10.Equals(a_11));
  EXPECT_FALSE(new_a_10.Equals(b_10));
  EXPECT_FALSE(new_a_10.Equals(b_11));
}

}  // namespace

}  // namespace net
