// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Test cases are from RFC 1320. https://tools.ietf.org/html/rfc1320

#include "net/ntlm/md4.h"

#include <string>

#include "testing/gtest/include/gtest/gtest.h"

namespace net {
namespace {

void Md4String(const std::string& input, uint8_t* hash) {
  weak_crypto::MD4Sum(reinterpret_cast<const uint8_t*>(input.data()),
                      input.length(), hash);
}

}  // namespace

TEST(Md4Test, RfcTest1_EmptyString) {
  uint8_t actual_hash[16];
  const uint8_t expected_hash[16] = {0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a,
                                     0xe9, 0x31, 0xb7, 0x3c, 0x59, 0xd7,
                                     0xe0, 0xc0, 0x89, 0xc0};
  Md4String("", actual_hash);
  ASSERT_EQ(0, memcmp(expected_hash, actual_hash, 16));
}

TEST(Md4Test, RfcTest2_OneChar) {
  uint8_t actual_hash[16];
  const uint8_t expected_hash[16] = {0xbd, 0xe5, 0x2c, 0xb3, 0x1d, 0xe3,
                                     0x3e, 0x46, 0x24, 0x5e, 0x05, 0xfb,
                                     0xdb, 0xd6, 0xfb, 0x24};
  Md4String("a", actual_hash);
  ASSERT_EQ(0, memcmp(expected_hash, actual_hash, 16));
}

TEST(Md4Test, RfcTest3_Abc) {
  uint8_t actual_hash[16];
  const uint8_t expected_hash[16] = {0xa4, 0x48, 0x01, 0x7a, 0xaf, 0x21,
                                     0xd8, 0x52, 0x5f, 0xc1, 0x0a, 0xe8,
                                     0x7a, 0xa6, 0x72, 0x9d};
  Md4String("abc", actual_hash);
  ASSERT_EQ(0, memcmp(expected_hash, actual_hash, 16));
}

TEST(Md4Test, RfcTest4_MessageDigest) {
  uint8_t actual_hash[16];
  const uint8_t expected_hash[16] = {0xd9, 0x13, 0x0a, 0x81, 0x64, 0x54,
                                     0x9f, 0xe8, 0x18, 0x87, 0x48, 0x06,
                                     0xe1, 0xc7, 0x01, 0x4b};
  Md4String("message digest", actual_hash);
  ASSERT_EQ(0, memcmp(expected_hash, actual_hash, 16));
}

TEST(Md4Test, RfcTest5_Alphabet) {
  uint8_t actual_hash[16];
  const uint8_t expected_hash[16] = {0xd7, 0x9e, 0x1c, 0x30, 0x8a, 0xa5,
                                     0xbb, 0xcd, 0xee, 0xa8, 0xed, 0x63,
                                     0xdf, 0x41, 0x2d, 0xa9};
  Md4String("abcdefghijklmnopqrstuvwxyz", actual_hash);
  ASSERT_EQ(0, memcmp(expected_hash, actual_hash, 16));
}

TEST(Md4Test, RfcTest6_Mod56CornerCase) {
  uint8_t actual_hash[16];
  const uint8_t expected_hash[16] = {0x04, 0x3f, 0x85, 0x82, 0xf2, 0x41,
                                     0xdb, 0x35, 0x1c, 0xe6, 0x27, 0xe1,
                                     0x53, 0xe7, 0xf0, 0xe4};
  // The string is 62 bytes long. Inputs where (len % 64 >= 56) == true
  // hit a special case in the implementation.
  Md4String("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            actual_hash);
  ASSERT_EQ(0, memcmp(expected_hash, actual_hash, 16));
}

TEST(Md4Test, RfcTest7_LongerThanOneBlock) {
  uint8_t actual_hash[16];
  const uint8_t expected_hash[16] = {0xe3, 0x3b, 0x4d, 0xdc, 0x9c, 0x38,
                                     0xf2, 0x19, 0x9c, 0x3e, 0x7b, 0x16,
                                     0x4f, 0xcc, 0x05, 0x36};
  // The string is 70 bytes long. MD4 processes data in 64 byte chunks.
  Md4String(
      "123456789012345678901234567890123456789012345678901234567890123456789012"
      "34567890",
      actual_hash);
  ASSERT_EQ(0, memcmp(expected_hash, actual_hash, 16));
}

}  // namespace net