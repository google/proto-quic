// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/quic_header_list.h"

#include "net/test/gtest_util.h"
#include "testing/gmock/include/gmock/gmock.h"

namespace net {

// This test verifies that QuicHeaderList accumulates header pairs in order.
TEST(QuicHeaderListTest, OnHeader) {
  QuicHeaderList headers;
  headers.OnHeader("foo", "bar");
  headers.OnHeader("april", "fools");
  headers.OnHeader("beep", "");

  EXPECT_EQ("{ foo=bar, april=fools, beep=, }", headers.DebugString());
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
