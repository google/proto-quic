// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/test_tools/quic_test_utils.h"

#include "testing/gtest/include/gtest/gtest-spi.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {
namespace test {

TEST(QuicTestUtilsTest, BasicApproxEq) {
  ExpectApproxEq(10, 10, 1e-6f);
  ExpectApproxEq(1000, 1001, 0.01f);
  EXPECT_NONFATAL_FAILURE(ExpectApproxEq(1000, 1100, 0.01f), "");

  ExpectApproxEq(64, 31, 0.55f);
  EXPECT_NONFATAL_FAILURE(ExpectApproxEq(31, 64, 0.55f), "");
}

TEST(QuicTestUtilsTest, QuicTimeDelta) {
  ExpectApproxEq(QuicTime::Delta::FromMicroseconds(1000),
                 QuicTime::Delta::FromMicroseconds(1003), 0.01f);
  EXPECT_NONFATAL_FAILURE(
      ExpectApproxEq(QuicTime::Delta::FromMicroseconds(1000),
                     QuicTime::Delta::FromMicroseconds(1200), 0.01f),
      "");
}

TEST(QuicTestUtilsTest, QuicBandwidth) {
  ExpectApproxEq(QuicBandwidth::FromBytesPerSecond(1000),
                 QuicBandwidth::FromBitsPerSecond(8005), 0.01f);
  EXPECT_NONFATAL_FAILURE(
      ExpectApproxEq(QuicBandwidth::FromBytesPerSecond(1000),
                     QuicBandwidth::FromBitsPerSecond(9005), 0.01f),
      "");
}

// Ensure that SimpleRandom does not change its output for a fixed seed.
TEST(QuicTestUtilsTest, SimpleRandomStability) {
  SimpleRandom rng;
  rng.set_seed(UINT64_C(0x1234567800010001));
  EXPECT_EQ(UINT64_C(14865409841904857791), rng.RandUint64());
  EXPECT_EQ(UINT64_C(12139094019410129741), rng.RandUint64());
}

}  // namespace test
}  // namespace net
