// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/crypto/crypto_handshake_message.h"

#include "net/quic/crypto/crypto_handshake.h"
#include "net/quic/crypto/crypto_protocol.h"
#include "net/test/gtest_util.h"

namespace net {
namespace test {
namespace {

TEST(CryptoHandshakeMessageTest, DebugString) {
  CryptoHandshakeMessage message;
  message.set_tag(kSHLO);
  EXPECT_EQ("SHLO<\n>", message.DebugString());
}

TEST(CryptoHandshakeMessageTest, DebugStringWithUintVector) {
  CryptoHandshakeMessage message;
  message.set_tag(kREJ);
  std::vector<uint32_t> reasons = {
      SOURCE_ADDRESS_TOKEN_DIFFERENT_IP_ADDRESS_FAILURE,
      CLIENT_NONCE_NOT_UNIQUE_FAILURE};
  message.SetVector(kRREJ, reasons);
  EXPECT_EQ(
      "REJ <\n  RREJ: "
      "SOURCE_ADDRESS_TOKEN_DIFFERENT_IP_ADDRESS_FAILURE,"
      "CLIENT_NONCE_NOT_UNIQUE_FAILURE\n>",
      message.DebugString());
}

TEST(CryptoHandshakeMessageTest, DebugStringWithTagVector) {
  CryptoHandshakeMessage message;
  message.set_tag(kCHLO);
  message.SetTaglist(kCOPT, kTBBR, kPAD, kBYTE, 0);
  EXPECT_EQ("CHLO<\n  COPT: 'TBBR','PAD ','BYTE'\n>", message.DebugString());
}

TEST(CryptoHandshakeMessageTest, ServerDesignatedConnectionId) {
  CryptoHandshakeMessage message;
  message.set_tag(kSREJ);
  message.SetValue(kRCID, UINT64_C(18364758544493064720));
  EXPECT_EQ("SREJ<\n  RCID: 18364758544493064720\n>", message.DebugString());
}

}  // namespace
}  // namespace test
}  // namespace net
