// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_config.h"

#include "net/quic/crypto/crypto_handshake_message.h"
#include "net/quic/crypto/crypto_protocol.h"
#include "net/quic/quic_flags.h"
#include "net/quic/quic_protocol.h"
#include "net/quic/quic_time.h"
#include "net/quic/quic_utils.h"
#include "net/quic/test_tools/quic_config_peer.h"
#include "net/quic/test_tools/quic_test_utils.h"
#include "net/test/gtest_util.h"
#include "testing/gtest/include/gtest/gtest.h"

using std::string;

namespace net {
namespace test {
namespace {

class QuicConfigTest : public ::testing::Test {
 protected:
  QuicConfig config_;
};

TEST_F(QuicConfigTest, ToHandshakeMessage) {
  config_.SetInitialStreamFlowControlWindowToSend(
      kInitialStreamFlowControlWindowForTest);
  config_.SetInitialSessionFlowControlWindowToSend(
      kInitialSessionFlowControlWindowForTest);
  config_.SetIdleConnectionStateLifetime(QuicTime::Delta::FromSeconds(5),
                                         QuicTime::Delta::FromSeconds(2));
  config_.SetMaxStreamsPerConnection(4, 2);
  config_.SetSocketReceiveBufferToSend(kDefaultSocketReceiveBuffer);
  CryptoHandshakeMessage msg;
  config_.ToHandshakeMessage(&msg);

  uint32_t value;
  QuicErrorCode error = msg.GetUint32(kICSL, &value);
  EXPECT_EQ(QUIC_NO_ERROR, error);
  EXPECT_EQ(5u, value);

  error = msg.GetUint32(kMSPC, &value);
  EXPECT_EQ(QUIC_NO_ERROR, error);
  EXPECT_EQ(4u, value);

  error = msg.GetUint32(kSFCW, &value);
  EXPECT_EQ(QUIC_NO_ERROR, error);
  EXPECT_EQ(kInitialStreamFlowControlWindowForTest, value);

  error = msg.GetUint32(kCFCW, &value);
  EXPECT_EQ(QUIC_NO_ERROR, error);
  EXPECT_EQ(kInitialSessionFlowControlWindowForTest, value);

  error = msg.GetUint32(kSRBF, &value);
  EXPECT_EQ(QUIC_NO_ERROR, error);
  EXPECT_EQ(kDefaultSocketReceiveBuffer, value);
}

TEST_F(QuicConfigTest, ProcessClientHello) {
  QuicConfig client_config;
  QuicTagVector cgst;
  cgst.push_back(kQBIC);
  client_config.SetIdleConnectionStateLifetime(
      QuicTime::Delta::FromSeconds(2 * kMaximumIdleTimeoutSecs),
      QuicTime::Delta::FromSeconds(kMaximumIdleTimeoutSecs));
  client_config.SetMaxStreamsPerConnection(2 * kDefaultMaxStreamsPerConnection,
                                           kDefaultMaxStreamsPerConnection);
  client_config.SetInitialRoundTripTimeUsToSend(10 * kNumMicrosPerMilli);
  client_config.SetInitialStreamFlowControlWindowToSend(
      2 * kInitialStreamFlowControlWindowForTest);
  client_config.SetInitialSessionFlowControlWindowToSend(
      2 * kInitialSessionFlowControlWindowForTest);
  client_config.SetSocketReceiveBufferToSend(kDefaultSocketReceiveBuffer);
  QuicTagVector copt;
  copt.push_back(kTBBR);
  client_config.SetConnectionOptionsToSend(copt);
  CryptoHandshakeMessage msg;
  client_config.ToHandshakeMessage(&msg);

  string error_details;
  QuicTagVector initial_received_options;
  initial_received_options.push_back(kIW50);
  EXPECT_TRUE(
      config_.SetInitialReceivedConnectionOptions(initial_received_options));
  EXPECT_FALSE(
      config_.SetInitialReceivedConnectionOptions(initial_received_options))
      << "You can only set initial options once.";
  const QuicErrorCode error =
      config_.ProcessPeerHello(msg, CLIENT, &error_details);
  EXPECT_FALSE(
      config_.SetInitialReceivedConnectionOptions(initial_received_options))
      << "You cannot set initial options after the hello.";
  EXPECT_EQ(QUIC_NO_ERROR, error);
  EXPECT_TRUE(config_.negotiated());
  EXPECT_EQ(QuicTime::Delta::FromSeconds(kMaximumIdleTimeoutSecs),
            config_.IdleConnectionStateLifetime());
  EXPECT_EQ(kDefaultMaxStreamsPerConnection, config_.MaxStreamsPerConnection());
  EXPECT_EQ(10 * kNumMicrosPerMilli, config_.ReceivedInitialRoundTripTimeUs());
  EXPECT_TRUE(config_.HasReceivedConnectionOptions());
  EXPECT_EQ(2u, config_.ReceivedConnectionOptions().size());
  EXPECT_EQ(config_.ReceivedConnectionOptions()[0], kIW50);
  EXPECT_EQ(config_.ReceivedConnectionOptions()[1], kTBBR);
  EXPECT_EQ(config_.ReceivedInitialStreamFlowControlWindowBytes(),
            2 * kInitialStreamFlowControlWindowForTest);
  EXPECT_EQ(config_.ReceivedInitialSessionFlowControlWindowBytes(),
            2 * kInitialSessionFlowControlWindowForTest);
  EXPECT_EQ(config_.ReceivedSocketReceiveBuffer(), kDefaultSocketReceiveBuffer);
}

TEST_F(QuicConfigTest, ProcessServerHello) {
  const IPEndPoint kTestServerAddress(IPAddress(127, 0, 3, 1), 1234);
  QuicConfig server_config;
  QuicTagVector cgst;
  cgst.push_back(kQBIC);
  server_config.SetIdleConnectionStateLifetime(
      QuicTime::Delta::FromSeconds(kMaximumIdleTimeoutSecs / 2),
      QuicTime::Delta::FromSeconds(kMaximumIdleTimeoutSecs / 2));
  server_config.SetMaxStreamsPerConnection(kDefaultMaxStreamsPerConnection / 2,
                                           kDefaultMaxStreamsPerConnection / 2);
  server_config.SetInitialRoundTripTimeUsToSend(10 * kNumMicrosPerMilli);
  server_config.SetInitialStreamFlowControlWindowToSend(
      2 * kInitialStreamFlowControlWindowForTest);
  server_config.SetInitialSessionFlowControlWindowToSend(
      2 * kInitialSessionFlowControlWindowForTest);
  server_config.SetSocketReceiveBufferToSend(kDefaultSocketReceiveBuffer);
  server_config.SetAlternateServerAddressToSend(kTestServerAddress);
  CryptoHandshakeMessage msg;
  server_config.ToHandshakeMessage(&msg);
  string error_details;
  const QuicErrorCode error =
      config_.ProcessPeerHello(msg, SERVER, &error_details);
  EXPECT_EQ(QUIC_NO_ERROR, error);
  EXPECT_TRUE(config_.negotiated());
  EXPECT_EQ(QuicTime::Delta::FromSeconds(kMaximumIdleTimeoutSecs / 2),
            config_.IdleConnectionStateLifetime());
  EXPECT_EQ(kDefaultMaxStreamsPerConnection / 2,
            config_.MaxStreamsPerConnection());
  EXPECT_EQ(10 * kNumMicrosPerMilli, config_.ReceivedInitialRoundTripTimeUs());
  EXPECT_EQ(config_.ReceivedInitialStreamFlowControlWindowBytes(),
            2 * kInitialStreamFlowControlWindowForTest);
  EXPECT_EQ(config_.ReceivedInitialSessionFlowControlWindowBytes(),
            2 * kInitialSessionFlowControlWindowForTest);
  EXPECT_EQ(config_.ReceivedSocketReceiveBuffer(), kDefaultSocketReceiveBuffer);
  EXPECT_TRUE(config_.HasReceivedAlternateServerAddress());
  EXPECT_EQ(kTestServerAddress, config_.ReceivedAlternateServerAddress());
}

TEST_F(QuicConfigTest, MissingOptionalValuesInCHLO) {
  CryptoHandshakeMessage msg;
  msg.SetValue(kICSL, 1);

  // Set all REQUIRED tags.
  msg.SetValue(kICSL, 1);
  msg.SetValue(kMSPC, 1);

  // No error, as rest are optional.
  string error_details;
  const QuicErrorCode error =
      config_.ProcessPeerHello(msg, CLIENT, &error_details);
  EXPECT_EQ(QUIC_NO_ERROR, error);
  EXPECT_TRUE(config_.negotiated());
}

TEST_F(QuicConfigTest, MissingOptionalValuesInSHLO) {
  CryptoHandshakeMessage msg;

  // Set all REQUIRED tags.
  msg.SetValue(kICSL, 1);
  msg.SetValue(kMSPC, 1);

  // No error, as rest are optional.
  string error_details;
  const QuicErrorCode error =
      config_.ProcessPeerHello(msg, SERVER, &error_details);
  EXPECT_EQ(QUIC_NO_ERROR, error);
  EXPECT_TRUE(config_.negotiated());
}

TEST_F(QuicConfigTest, MissingValueInCHLO) {
  // Server receives CHLO with missing kICSL.
  CryptoHandshakeMessage msg;
  string error_details;
  const QuicErrorCode error =
      config_.ProcessPeerHello(msg, CLIENT, &error_details);
  EXPECT_EQ(QUIC_CRYPTO_MESSAGE_PARAMETER_NOT_FOUND, error);
}

TEST_F(QuicConfigTest, MissingValueInSHLO) {
  // Client receives SHLO with missing kICSL.
  CryptoHandshakeMessage msg;
  string error_details;
  const QuicErrorCode error =
      config_.ProcessPeerHello(msg, SERVER, &error_details);
  EXPECT_EQ(QUIC_CRYPTO_MESSAGE_PARAMETER_NOT_FOUND, error);
}

TEST_F(QuicConfigTest, OutOfBoundSHLO) {
  QuicConfig server_config;
  server_config.SetIdleConnectionStateLifetime(
      QuicTime::Delta::FromSeconds(2 * kMaximumIdleTimeoutSecs),
      QuicTime::Delta::FromSeconds(2 * kMaximumIdleTimeoutSecs));

  CryptoHandshakeMessage msg;
  server_config.ToHandshakeMessage(&msg);
  string error_details;
  const QuicErrorCode error =
      config_.ProcessPeerHello(msg, SERVER, &error_details);
  EXPECT_EQ(QUIC_INVALID_NEGOTIATED_VALUE, error);
}

TEST_F(QuicConfigTest, InvalidFlowControlWindow) {
  // QuicConfig should not accept an invalid flow control window to send to the
  // peer: the receive window must be at least the default of 16 Kb.
  QuicConfig config;
  const uint64_t kInvalidWindow = kMinimumFlowControlSendWindow - 1;
  EXPECT_DFATAL(config.SetInitialStreamFlowControlWindowToSend(kInvalidWindow),
                "Initial stream flow control receive window");

  EXPECT_EQ(kMinimumFlowControlSendWindow,
            config.GetInitialStreamFlowControlWindowToSend());
}

TEST_F(QuicConfigTest, HasClientSentConnectionOption) {
  QuicConfig client_config;
  QuicTagVector copt;
  copt.push_back(kTBBR);
  client_config.SetConnectionOptionsToSend(copt);
  EXPECT_TRUE(client_config.HasClientSentConnectionOption(
      kTBBR, Perspective::IS_CLIENT));

  CryptoHandshakeMessage msg;
  client_config.ToHandshakeMessage(&msg);

  string error_details;
  const QuicErrorCode error =
      config_.ProcessPeerHello(msg, CLIENT, &error_details);
  EXPECT_EQ(QUIC_NO_ERROR, error);
  EXPECT_TRUE(config_.negotiated());

  EXPECT_TRUE(config_.HasReceivedConnectionOptions());
  EXPECT_EQ(1u, config_.ReceivedConnectionOptions().size());
  EXPECT_TRUE(
      config_.HasClientSentConnectionOption(kTBBR, Perspective::IS_SERVER));
}

}  // namespace
}  // namespace test
}  // namespace net
