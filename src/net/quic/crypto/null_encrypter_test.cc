// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/crypto/null_encrypter.h"
#include "net/quic/test_tools/quic_test_utils.h"

using base::StringPiece;

namespace net {
namespace test {

class NullEncrypterTest : public ::testing::TestWithParam<bool> {};

TEST_F(NullEncrypterTest, Encrypt) {
  unsigned char expected[] = {
      // fnv hash
      0xa0, 0x6f, 0x44, 0x8a, 0x44, 0xf8, 0x18, 0x3b, 0x47, 0x91, 0xb2, 0x13,
      // payload
      'g', 'o', 'o', 'd', 'b', 'y', 'e', '!',
  };
  NullEncrypter encrypter;
  char encrypted[256];
  size_t encrypted_len = 0;
  ASSERT_TRUE(encrypter.EncryptPacket(kDefaultPathId, 0, "hello world!",
                                      "goodbye!", encrypted, &encrypted_len,
                                      256));
  test::CompareCharArraysWithHexError(
      "encrypted data", encrypted, encrypted_len,
      reinterpret_cast<const char*>(expected), arraysize(expected));
}

TEST_F(NullEncrypterTest, GetMaxPlaintextSize) {
  NullEncrypter encrypter;
  EXPECT_EQ(1000u, encrypter.GetMaxPlaintextSize(1012));
  EXPECT_EQ(100u, encrypter.GetMaxPlaintextSize(112));
  EXPECT_EQ(10u, encrypter.GetMaxPlaintextSize(22));
}

TEST_F(NullEncrypterTest, GetCiphertextSize) {
  NullEncrypter encrypter;
  EXPECT_EQ(1012u, encrypter.GetCiphertextSize(1000));
  EXPECT_EQ(112u, encrypter.GetCiphertextSize(100));
  EXPECT_EQ(22u, encrypter.GetCiphertextSize(10));
}

}  // namespace test
}  // namespace net
