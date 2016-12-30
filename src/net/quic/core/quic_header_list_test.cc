// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/quic_header_list.h"

#include "net/quic/core/quic_flags.h"
#include "net/quic/test_tools/quic_test_utils.h"
#include "testing/gtest/include/gtest/gtest.h"

using std::string;

namespace net {

// This test verifies that QuicHeaderList accumulates header pairs in order.
TEST(QuicHeaderListTest, OnHeader) {
  QuicHeaderList headers;
  headers.OnHeader("foo", "bar");
  headers.OnHeader("april", "fools");
  headers.OnHeader("beep", "");

  EXPECT_EQ("{ foo=bar, april=fools, beep=, }", headers.DebugString());
}

TEST(QuicHeaderListTest, TooLarge) {
  test::QuicFlagSaver flags;
  FLAGS_quic_reloadable_flag_quic_limit_uncompressed_headers = true;
  QuicHeaderList headers;
  string key = "key";
  string value(1 << 18, '1');
  headers.OnHeader(key, value);
  headers.OnHeaderBlockEnd(key.size() + value.size());
  EXPECT_TRUE(headers.empty());

  EXPECT_EQ("{ }", headers.DebugString());
}

TEST(QuicHeaderListTest, NotTooLarge) {
  QuicHeaderList headers;
  headers.set_max_uncompressed_header_bytes(1 << 20);
  string key = "key";
  string value(1 << 18, '1');
  headers.OnHeader(key, value);
  headers.OnHeaderBlockEnd(key.size() + value.size());
  EXPECT_FALSE(headers.empty());
}

// This test verifies that QuicHeaderList is copyable and assignable.
TEST(QuicHeaderListTest, IsCopyableAndAssignable) {
  QuicHeaderList headers;
  headers.OnHeader("foo", "bar");
  headers.OnHeader("april", "fools");
  headers.OnHeader("beep", "");

  QuicHeaderList headers2(headers);
  QuicHeaderList headers3 = headers;

  EXPECT_EQ("{ foo=bar, april=fools, beep=, }", headers2.DebugString());
  EXPECT_EQ("{ foo=bar, april=fools, beep=, }", headers3.DebugString());
}

}  // namespace net
