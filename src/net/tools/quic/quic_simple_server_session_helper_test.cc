// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/test_tools/mock_random.h"
#include "net/tools/quic/quic_simple_crypto_server_stream_helper.h"

#include "testing/gtest/include/gtest/gtest.h"

namespace net {

TEST(QuicSimpleCryptoServerStreamHelperTest, GenerateConnectionIdForReject) {
  test::MockRandom random;
  QuicSimpleCryptoServerStreamHelper helper(&random);

  EXPECT_EQ(random.RandUint64(), helper.GenerateConnectionIdForReject(42));
}

}  // namespace net
