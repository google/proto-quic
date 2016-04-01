// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_utils.h"

#include "net/quic/crypto/crypto_protocol.h"
#include "net/quic/quic_flags.h"
#include "testing/gtest/include/gtest/gtest.h"

using base::StringPiece;
using std::string;

namespace net {
namespace test {
namespace {

// A test string and a hex+ASCII dump of the same string.
const unsigned char kString[] = {
    0x00, 0x90, 0x69, 0xbd, 0x54, 0x00, 0x00, 0x0d, 0x61, 0x0f, 0x01,
    0x89, 0x08, 0x00, 0x45, 0x00, 0x00, 0x1c, 0xfb, 0x98, 0x40, 0x00,
    0x40, 0x01, 0x7e, 0x18, 0xd8, 0xef, 0x23, 0x01, 0x45, 0x5d, 0x7f,
    0xe2, 0x08, 0x00, 0x6b, 0xcb, 0x0b, 0xc6, 0x80, 0x6e};

const unsigned char kHexDump[] =
    "0x0000:  0090 69bd 5400 000d 610f 0189 0800 4500  ..i.T...a.....E.\n"
    "0x0010:  001c fb98 4000 4001 7e18 d8ef 2301 455d  ....@.@.~...#.E]\n"
    "0x0020:  7fe2 0800 6bcb 0bc6 806e                 ....k....n\n";

TEST(QuicUtilsTest, StreamErrorToString) {
  EXPECT_STREQ("QUIC_BAD_APPLICATION_PAYLOAD",
               QuicUtils::StreamErrorToString(QUIC_BAD_APPLICATION_PAYLOAD));
}

TEST(QuicUtilsTest, ErrorToString) {
  EXPECT_STREQ("QUIC_NO_ERROR", QuicUtils::ErrorToString(QUIC_NO_ERROR));
}

TEST(QuicUtilsTest, StringToHexASCIIDumpArgTypes) {
  // Verify that char*, string and StringPiece are all valid argument types.
  struct {
    const string input;
    const string expected;
  } tests[] = {
      {
          "", "",
      },
      {
          "A", "0x0000:  41                                       A\n",
      },
      {
          "AB", "0x0000:  4142                                     AB\n",
      },
      {
          "ABC", "0x0000:  4142 43                                  ABC\n",
      },
      {
          "original",
          "0x0000:  6f72 6967 696e 616c                      original\n",
      },
  };

  for (size_t i = 0; i < arraysize(tests); ++i) {
    EXPECT_EQ(tests[i].expected,
              QuicUtils::StringToHexASCIIDump(tests[i].input.c_str()));
    EXPECT_EQ(tests[i].expected,
              QuicUtils::StringToHexASCIIDump(tests[i].input));
    EXPECT_EQ(tests[i].expected,
              QuicUtils::StringToHexASCIIDump(StringPiece(tests[i].input)));
  }
}

TEST(QuicUtilsTest, StringToHexASCIIDumpSuccess) {
  EXPECT_EQ(string(reinterpret_cast<const char*>(kHexDump)),
            QuicUtils::StringToHexASCIIDump(string(
                reinterpret_cast<const char*>(kString), sizeof(kString))));
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
  EXPECT_EQ(UNSPECIFIED_CHANGE,
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

}  // namespace
}  // namespace test
}  // namespace net
