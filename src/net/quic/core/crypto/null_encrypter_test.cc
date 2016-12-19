// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/crypto/null_encrypter.h"
#include "net/quic/test_tools/quic_test_utils.h"

using base::StringPiece;

namespace net {
namespace test {

class NullEncrypterTest : public ::testing::TestWithParam<bool> {};

TEST_F(NullEncrypterTest, EncryptClient) {
  unsigned char expected[] = {
      // fnv hash
      0x97, 0xdc, 0x27, 0x2f, 0x18, 0xa8, 0x56, 0x73, 0xdf, 0x8d, 0x1d, 0xd0,
      // payload
      'g', 'o', 'o', 'd', 'b', 'y', 'e', '!',
  };
  char encrypted[256];
  size_t encrypted_len = 0;
  NullEncrypter encrypter(Perspective::IS_CLIENT);
  ASSERT_TRUE(encrypter.EncryptPacket(QUIC_VERSION_37, kDefaultPathId, 0,
                                      "hello world!", "goodbye!", encrypted,
                                      &encrypted_len, 256));
  test::CompareCharArraysWithHexError(
      "encrypted data", encrypted, encrypted_len,
      reinterpret_cast<const char*>(expected), arraysize(expected));
}

TEST_F(NullEncrypterTest, EncryptServer) {
  unsigned char expected[] = {
      // fnv hash
      0x63, 0x5e, 0x08, 0x03, 0x32, 0x80, 0x8f, 0x73, 0xdf, 0x8d, 0x1d, 0x1a,
      // payload
      'g', 'o', 'o', 'd', 'b', 'y', 'e', '!',
  };
  char encrypted[256];
  size_t encrypted_len = 0;
  NullEncrypter encrypter(Perspective::IS_SERVER);
  ASSERT_TRUE(encrypter.EncryptPacket(QUIC_VERSION_37, kDefaultPathId, 0,
                                      "hello world!", "goodbye!", encrypted,
                                      &encrypted_len, 256));
  test::CompareCharArraysWithHexError(
      "encrypted data", encrypted, encrypted_len,
      reinterpret_cast<const char*>(expected), arraysize(expected));
}

TEST_F(NullEncrypterTest, EncryptClientPre37) {
  unsigned char expected[] = {
      // fnv hash
      0xa0, 0x6f, 0x44, 0x8a, 0x44, 0xf8, 0x18, 0x3b, 0x47, 0x91, 0xb2, 0x13,
      // payload
      'g', 'o', 'o', 'd', 'b', 'y', 'e', '!',
  };
  char encrypted[256];
  size_t encrypted_len = 0;
  NullEncrypter encrypter(Perspective::IS_CLIENT);
  ASSERT_TRUE(encrypter.EncryptPacket(QUIC_VERSION_36, kDefaultPathId, 0,
                                      "hello world!", "goodbye!", encrypted,
                                      &encrypted_len, 256));
  test::CompareCharArraysWithHexError(
      "encrypted data", encrypted, encrypted_len,
      reinterpret_cast<const char*>(expected), arraysize(expected));
}

TEST_F(NullEncrypterTest, EncryptServerPre37) {
  unsigned char expected[] = {
      // fnv hash
      0xa0, 0x6f, 0x44, 0x8a, 0x44, 0xf8, 0x18, 0x3b, 0x47, 0x91, 0xb2, 0x13,
      // payload
      'g', 'o', 'o', 'd', 'b', 'y', 'e', '!',
  };
  char encrypted[256];
  size_t encrypted_len = 0;
  NullEncrypter encrypter(Perspective::IS_SERVER);
  ASSERT_TRUE(encrypter.EncryptPacket(QUIC_VERSION_36, kDefaultPathId, 0,
                                      "hello world!", "goodbye!", encrypted,
                                      &encrypted_len, 256));
  test::CompareCharArraysWithHexError(
      "encrypted data", encrypted, encrypted_len,
      reinterpret_cast<const char*>(expected), arraysize(expected));
}

TEST_F(NullEncrypterTest, GetMaxPlaintextSize) {
  NullEncrypter encrypter(Perspective::IS_CLIENT);
  EXPECT_EQ(1000u, encrypter.GetMaxPlaintextSize(1012));
  EXPECT_EQ(100u, encrypter.GetMaxPlaintextSize(112));
  EXPECT_EQ(10u, encrypter.GetMaxPlaintextSize(22));
}

TEST_F(NullEncrypterTest, GetCiphertextSize) {
  NullEncrypter encrypter(Perspective::IS_CLIENT);
  EXPECT_EQ(1012u, encrypter.GetCiphertextSize(1000));
  EXPECT_EQ(112u, encrypter.GetCiphertextSize(100));
  EXPECT_EQ(22u, encrypter.GetCiphertextSize(10));
}

}  // namespace test
}  // namespace net
