// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/quic_error_codes.h"

#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {
namespace test {
namespace {

TEST(QuicUtilsTest, QuicRstStreamErrorCodeToString) {
  EXPECT_STREQ("QUIC_BAD_APPLICATION_PAYLOAD",
               QuicRstStreamErrorCodeToString(QUIC_BAD_APPLICATION_PAYLOAD));
}

TEST(QuicUtilsTest, QuicErrorCodeToString) {
  EXPECT_STREQ("QUIC_NO_ERROR", QuicErrorCodeToString(QUIC_NO_ERROR));
}

}  // namespace
}  // namespace test
}  // namespace net
