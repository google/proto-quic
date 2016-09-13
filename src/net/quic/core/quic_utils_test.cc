// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/quic_utils.h"

#include "net/quic/core/crypto/crypto_protocol.h"
#include "net/quic/core/quic_flags.h"
#include "testing/gtest/include/gtest/gtest.h"

using base::StringPiece;
using std::string;

namespace net {
namespace test {
namespace {

TEST(QuicUtilsTest, StreamErrorToString) {
  EXPECT_STREQ("QUIC_BAD_APPLICATION_PAYLOAD",
               QuicUtils::StreamErrorToString(QUIC_BAD_APPLICATION_PAYLOAD));
}

TEST(QuicUtilsTest, ErrorToString) {
  EXPECT_STREQ("QUIC_NO_ERROR", QuicUtils::ErrorToString(QUIC_NO_ERROR));
}

TEST(QuicUtilsTest, TagToString) {
  EXPECT_EQ("SCFG", QuicUtils::TagToString(kSCFG));
  EXPECT_EQ("SNO ", QuicUtils::TagToString(kServerNonceTag));
  EXPECT_EQ("CRT ", QuicUtils::TagToString(kCertificateTag));
  EXPECT_EQ("CHLO", QuicUtils::TagToString(MakeQuicTag('C', 'H', 'L', 'O')));
  // A tag that contains a non-printing character will be printed as a decimal
  // number.
  EXPECT_EQ("525092931",
            QuicUtils::TagToString(MakeQuicTag('C', 'H', 'L', '\x1f')));
}

TEST(QuicUtilsTest, ParseQuicConnectionOptions) {
  QuicTagVector empty_options = QuicUtils::ParseQuicConnectionOptions("");
  EXPECT_EQ(0ul, empty_options.size());

  QuicTagVector parsed_options =
      QuicUtils::ParseQuicConnectionOptions("TIMER,TBBR,REJ");
  QuicTagVector expected_options;
  expected_options.push_back(kTIME);
  expected_options.push_back(kTBBR);
  expected_options.push_back(kREJ);
  EXPECT_EQ(expected_options, parsed_options);
}

TEST(QuicUtilsTest, DetermineAddressChangeType) {
  const string kIPv4String1 = "1.2.3.4";
  const string kIPv4String2 = "1.2.3.5";
  const string kIPv4String3 = "1.1.3.5";
  const string kIPv6String1 = "2001:700:300:1800::f";
  const string kIPv6String2 = "2001:700:300:1800:1:1:1:f";
  IPEndPoint old_address;
  IPEndPoint new_address;
  IPAddress address;

  EXPECT_EQ(NO_CHANGE,
            QuicUtils::DetermineAddressChangeType(old_address, new_address));
  ASSERT_TRUE(address.AssignFromIPLiteral(kIPv4String1));
  old_address = IPEndPoint(address, 1234);
  EXPECT_EQ(NO_CHANGE,
            QuicUtils::DetermineAddressChangeType(old_address, new_address));
  new_address = IPEndPoint(address, 1234);
  EXPECT_EQ(NO_CHANGE,
            QuicUtils::DetermineAddressChangeType(old_address, new_address));

  new_address = IPEndPoint(address, 5678);
  EXPECT_EQ(PORT_CHANGE,
            QuicUtils::DetermineAddressChangeType(old_address, new_address));
  ASSERT_TRUE(address.AssignFromIPLiteral(kIPv6String1));
  old_address = IPEndPoint(address, 1234);
  new_address = IPEndPoint(address, 5678);
  EXPECT_EQ(PORT_CHANGE,
            QuicUtils::DetermineAddressChangeType(old_address, new_address));

  ASSERT_TRUE(address.AssignFromIPLiteral(kIPv4String1));
  old_address = IPEndPoint(address, 1234);
  ASSERT_TRUE(address.AssignFromIPLiteral(kIPv6String1));
  new_address = IPEndPoint(address, 1234);
  EXPECT_EQ(IPV4_TO_IPV6_CHANGE,
            QuicUtils::DetermineAddressChangeType(old_address, new_address));

  old_address = IPEndPoint(address, 1234);
  ASSERT_TRUE(address.AssignFromIPLiteral(kIPv4String1));
  new_address = IPEndPoint(address, 1234);
  EXPECT_EQ(IPV6_TO_IPV4_CHANGE,
            QuicUtils::DetermineAddressChangeType(old_address, new_address));

  ASSERT_TRUE(address.AssignFromIPLiteral(kIPv6String2));
  new_address = IPEndPoint(address, 1234);
  EXPECT_EQ(IPV6_TO_IPV6_CHANGE,
            QuicUtils::DetermineAddressChangeType(old_address, new_address));

  ASSERT_TRUE(address.AssignFromIPLiteral(kIPv4String1));
  old_address = IPEndPoint(address, 1234);
  ASSERT_TRUE(address.AssignFromIPLiteral(kIPv4String2));
  new_address = IPEndPoint(address, 1234);
  EXPECT_EQ(IPV4_SUBNET_CHANGE,
            QuicUtils::DetermineAddressChangeType(old_address, new_address));
  ASSERT_TRUE(address.AssignFromIPLiteral(kIPv4String3));
  new_address = IPEndPoint(address, 1234);
  EXPECT_EQ(IPV4_TO_IPV4_CHANGE,
            QuicUtils::DetermineAddressChangeType(old_address, new_address));
}

uint128 IncrementalHashReference(const void* data, size_t len) {
  // The two constants are defined as part of the hash algorithm.
  // see http://www.isthe.com/chongo/tech/comp/fnv/
  // hash = 144066263297769815596495629667062367629
  uint128 hash =
      uint128(UINT64_C(7809847782465536322), UINT64_C(7113472399480571277));
  // kPrime = 309485009821345068724781371
  const uint128 kPrime(16777216, 315);
  const uint8_t* octets = reinterpret_cast<const uint8_t*>(data);
  for (size_t i = 0; i < len; ++i) {
    hash = hash ^ uint128(0, octets[i]);
    hash = hash * kPrime;
  }
  return hash;
}

TEST(QuicUtilsHashTest, ReferenceTest) {
  std::vector<uint8_t> data(32);
  for (size_t i = 0; i < data.size(); ++i) {
    data[i] = i % 255;
  }
  EXPECT_EQ(IncrementalHashReference(data.data(), data.size()),
            QuicUtils::FNV1a_128_Hash(
                reinterpret_cast<const char*>(data.data()), data.size()));
}

TEST(QuicUtilsTest, HexDump) {
  // Verify output of the HexDump method is as expected.
  char packet[] = {
      0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x51, 0x55, 0x49, 0x43, 0x21,
      0x20, 0x54, 0x68, 0x69, 0x73, 0x20, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67,
      0x20, 0x73, 0x68, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x6c,
      0x6f, 0x6e, 0x67, 0x20, 0x65, 0x6e, 0x6f, 0x75, 0x67, 0x68, 0x20, 0x74,
      0x6f, 0x20, 0x73, 0x70, 0x61, 0x6e, 0x20, 0x6d, 0x75, 0x6c, 0x74, 0x69,
      0x70, 0x6c, 0x65, 0x20, 0x6c, 0x69, 0x6e, 0x65, 0x73, 0x20, 0x6f, 0x66,
      0x20, 0x6f, 0x75, 0x74, 0x70, 0x75, 0x74, 0x2e, 0x01, 0x02, 0x03, 0x00,
  };
  EXPECT_EQ(
      QuicUtils::HexDump(packet),
      "0x0000:  4865 6c6c 6f2c 2051 5549 4321 2054 6869  Hello,.QUIC!.Thi\n"
      "0x0010:  7320 7374 7269 6e67 2073 686f 756c 6420  s.string.should.\n"
      "0x0020:  6265 206c 6f6e 6720 656e 6f75 6768 2074  be.long.enough.t\n"
      "0x0030:  6f20 7370 616e 206d 756c 7469 706c 6520  o.span.multiple.\n"
      "0x0040:  6c69 6e65 7320 6f66 206f 7574 7075 742e  lines.of.output.\n"
      "0x0050:  0102 03                                  ...\n");
}

}  // namespace
}  // namespace test
}  // namespace net
