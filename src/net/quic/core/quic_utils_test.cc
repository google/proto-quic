// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/quic_utils.h"

#include "net/quic/core/crypto/crypto_protocol.h"
#include "net/quic/platform/api/quic_test.h"

using std::string;

namespace net {
namespace test {
namespace {

class QuicUtilsTest : public QuicTest {};

TEST_F(QuicUtilsTest, DetermineAddressChangeType) {
  const string kIPv4String1 = "1.2.3.4";
  const string kIPv4String2 = "1.2.3.5";
  const string kIPv4String3 = "1.1.3.5";
  const string kIPv6String1 = "2001:700:300:1800::f";
  const string kIPv6String2 = "2001:700:300:1800:1:1:1:f";
  QuicSocketAddress old_address;
  QuicSocketAddress new_address;
  QuicIpAddress address;

  EXPECT_EQ(NO_CHANGE,
            QuicUtils::DetermineAddressChangeType(old_address, new_address));
  ASSERT_TRUE(address.FromString(kIPv4String1));
  old_address = QuicSocketAddress(address, 1234);
  EXPECT_EQ(NO_CHANGE,
            QuicUtils::DetermineAddressChangeType(old_address, new_address));
  new_address = QuicSocketAddress(address, 1234);
  EXPECT_EQ(NO_CHANGE,
            QuicUtils::DetermineAddressChangeType(old_address, new_address));

  new_address = QuicSocketAddress(address, 5678);
  EXPECT_EQ(PORT_CHANGE,
            QuicUtils::DetermineAddressChangeType(old_address, new_address));
  ASSERT_TRUE(address.FromString(kIPv6String1));
  old_address = QuicSocketAddress(address, 1234);
  new_address = QuicSocketAddress(address, 5678);
  EXPECT_EQ(PORT_CHANGE,
            QuicUtils::DetermineAddressChangeType(old_address, new_address));

  ASSERT_TRUE(address.FromString(kIPv4String1));
  old_address = QuicSocketAddress(address, 1234);
  ASSERT_TRUE(address.FromString(kIPv6String1));
  new_address = QuicSocketAddress(address, 1234);
  EXPECT_EQ(IPV4_TO_IPV6_CHANGE,
            QuicUtils::DetermineAddressChangeType(old_address, new_address));

  old_address = QuicSocketAddress(address, 1234);
  ASSERT_TRUE(address.FromString(kIPv4String1));
  new_address = QuicSocketAddress(address, 1234);
  EXPECT_EQ(IPV6_TO_IPV4_CHANGE,
            QuicUtils::DetermineAddressChangeType(old_address, new_address));

  ASSERT_TRUE(address.FromString(kIPv6String2));
  new_address = QuicSocketAddress(address, 1234);
  EXPECT_EQ(IPV6_TO_IPV6_CHANGE,
            QuicUtils::DetermineAddressChangeType(old_address, new_address));

  ASSERT_TRUE(address.FromString(kIPv4String1));
  old_address = QuicSocketAddress(address, 1234);
  ASSERT_TRUE(address.FromString(kIPv4String2));
  new_address = QuicSocketAddress(address, 1234);
  EXPECT_EQ(IPV4_SUBNET_CHANGE,
            QuicUtils::DetermineAddressChangeType(old_address, new_address));
  ASSERT_TRUE(address.FromString(kIPv4String3));
  new_address = QuicSocketAddress(address, 1234);
  EXPECT_EQ(IPV4_TO_IPV4_CHANGE,
            QuicUtils::DetermineAddressChangeType(old_address, new_address));
}

uint128 IncrementalHashReference(const void* data, size_t len) {
  // The two constants are defined as part of the hash algorithm.
  // see http://www.isthe.com/chongo/tech/comp/fnv/
  // hash = 144066263297769815596495629667062367629
  uint128 hash =
      MakeUint128(UINT64_C(7809847782465536322), UINT64_C(7113472399480571277));
  // kPrime = 309485009821345068724781371
  const uint128 kPrime = MakeUint128(16777216, 315);
  const uint8_t* octets = reinterpret_cast<const uint8_t*>(data);
  for (size_t i = 0; i < len; ++i) {
    hash = hash ^ MakeUint128(0, octets[i]);
    hash = hash * kPrime;
  }
  return hash;
}

TEST_F(QuicUtilsTest, ReferenceTest) {
  std::vector<uint8_t> data(32);
  for (size_t i = 0; i < data.size(); ++i) {
    data[i] = i % 255;
  }
  EXPECT_EQ(IncrementalHashReference(data.data(), data.size()),
            QuicUtils::FNV1a_128_Hash(QuicStringPiece(
                reinterpret_cast<const char*>(data.data()), data.size())));
}

}  // namespace
}  // namespace test
}  // namespace net
