// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/quic/quic_simple_server.h"

#include "net/quic/crypto/quic_random.h"
#include "net/quic/quic_utils.h"
#include "net/quic/test_tools/crypto_test_utils.h"
#include "net/quic/test_tools/mock_quic_dispatcher.h"
#include "net/quic/test_tools/quic_test_utils.h"
#include "net/tools/quic/quic_simple_server_session_helper.h"
#include "testing/gtest/include/gtest/gtest.h"

using ::testing::_;
using net::test::CryptoTestUtils;

namespace net {
namespace test {

// TODO(dmz) Remove "Chrome" part of name once net/tools/quic is deleted.
class QuicChromeServerDispatchPacketTest : public ::testing::Test {
 public:
  QuicChromeServerDispatchPacketTest()
      : crypto_config_("blah",
                       QuicRandom::GetInstance(),
                       CryptoTestUtils::ProofSourceForTesting()),
        dispatcher_(
            config_,
            &crypto_config_,
            std::unique_ptr<MockQuicConnectionHelper>(
                new net::test::MockQuicConnectionHelper),
            std::unique_ptr<QuicServerSessionBase::Helper>(
                new QuicSimpleServerSessionHelper(QuicRandom::GetInstance())),
            std::unique_ptr<MockAlarmFactory>(
                new net::test::MockAlarmFactory)) {
    dispatcher_.InitializeWithWriter(nullptr);
  }

  void DispatchPacket(const QuicReceivedPacket& packet) {
    IPEndPoint client_addr, server_addr;
    dispatcher_.ProcessPacket(server_addr, client_addr, packet);
  }

 protected:
  QuicConfig config_;
  QuicCryptoServerConfig crypto_config_;
  net::test::MockQuicDispatcher dispatcher_;
};

TEST_F(QuicChromeServerDispatchPacketTest, DispatchPacket) {
  unsigned char valid_packet[] = {// public flags (8 byte connection_id)
                                  0x3C,
                                  // connection_id
                                  0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC,
                                  0xFE,
                                  // packet sequence number
                                  0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12,
                                  // private flags
                                  0x00};
  QuicReceivedPacket encrypted_valid_packet(QuicUtils::AsChars(valid_packet),
                                            arraysize(valid_packet),
                                            QuicTime::Zero(), false);

  EXPECT_CALL(dispatcher_, ProcessPacket(_, _, _)).Times(1);
  DispatchPacket(encrypted_valid_packet);
}

}  // namespace test
}  // namespace net
