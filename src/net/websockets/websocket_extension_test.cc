// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/websockets/websocket_extension.h"

#include <string>
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

TEST(WebSocketExtensionTest, EqualityTest1) {
  WebSocketExtension e1("hello");
  WebSocketExtension e2("world");
  EXPECT_FALSE(e1.Equals(e2));
  EXPECT_FALSE(e2.Equals(e1));
}

TEST(WebSocketExtensionTest, EqualityTest2) {
  WebSocketExtension e1("world");
  WebSocketExtension e2("world");
  e1.Add(WebSocketExtension::Parameter("foo", "bar"));
  e2.Add(WebSocketExtension::Parameter("foo"));
  EXPECT_FALSE(e1.Equals(e2));
  EXPECT_FALSE(e2.Equals(e1));
}

TEST(WebSocketExtensionTest, EqualityTest3) {
  WebSocketExtension e1("world");
  WebSocketExtension e2("world");
  e1.Add(WebSocketExtension::Parameter("foo", "bar"));
  e1.Add(WebSocketExtension::Parameter("bar", "baz"));
  e2.Add(WebSocketExtension::Parameter("bar", "baz"));
  e2.Add(WebSocketExtension::Parameter("foo", "bar"));
  EXPECT_TRUE(e1.Equals(e2));
  EXPECT_TRUE(e2.Equals(e1));
}

TEST(WebSocketExtensionTest, EmptyToString) {
  EXPECT_EQ("", WebSocketExtension().ToString());
}

TEST(WebSocketExtensionTest, SimpleToString) {
  EXPECT_EQ("foo", WebSocketExtension("foo").ToString());
}

TEST(WebSocketExtensionTest, ToString) {
  const std::string expected = "foo; bar; baz=hoge";

  WebSocketExtension e("foo");
  e.Add(WebSocketExtension::Parameter("bar"));
  e.Add(WebSocketExtension::Parameter("baz", "hoge"));
  EXPECT_EQ(expected, e.ToString());
}

}  // namespace

}  // namespace net
