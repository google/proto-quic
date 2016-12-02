// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/quic_crypto_server_stream.h"

#include <map>
#include <memory>
#include <vector>

#include "base/memory/ptr_util.h"
#include "net/quic/core/crypto/aes_128_gcm_12_encrypter.h"
#include "net/quic/core/crypto/crypto_framer.h"
#include "net/quic/core/crypto/crypto_handshake.h"
#include "net/quic/core/crypto/crypto_protocol.h"
#include "net/quic/core/crypto/crypto_utils.h"
#include "net/quic/core/crypto/quic_crypto_server_config.h"
#include "net/quic/core/crypto/quic_decrypter.h"
#include "net/quic/core/crypto/quic_encrypter.h"
#include "net/quic/core/crypto/quic_random.h"
#include "net/quic/core/quic_crypto_client_stream.h"
#include "net/quic/core/quic_flags.h"
#include "net/quic/core/quic_packets.h"
#include "net/quic/core/quic_session.h"
#include "net/quic/platform/api/quic_socket_address.h"
#include "net/quic/test_tools/crypto_test_utils.h"
#include "net/quic/test_tools/quic_crypto_server_config_peer.h"
#include "net/quic/test_tools/quic_test_utils.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {
class QuicConnection;
class QuicStream;
}  // namespace net

using std::string;
using testing::_;

namespace net {
namespace test {

class QuicCryptoServerStreamPeer {
 public:
  static bool DoesPeerSupportStatelessRejects(
      const CryptoHandshakeMessage& message) {
    return net::QuicCryptoServerStream::DoesPeerSupportStatelessRejects(
        message);
  }
};

namespace {

const char kServerHostname[] = "test.example.com";
const uint16_t kServerPort = 443;

class QuicCryptoServerStreamTest : public ::testing::TestWithParam<bool> {
 public:
  QuicCryptoServerStreamTest()
      : QuicCryptoServerStreamTest(CryptoTestUtils::ProofSourceForTesting()) {}

  explicit QuicCryptoServerStreamTest(std::unique_ptr<ProofSource> proof_source)
      : server_crypto_config_(QuicCryptoServerConfig::TESTING,
                              QuicRandom::GetInstance(),
                              std::move(proof_source)),
        server_compressed_certs_cache_(
            QuicCompressedCertsCache::kQuicCompressedCertsCacheSize),
        server_id_(kServerHostname, kServerPort, PRIVACY_MODE_DISABLED),
        client_crypto_config_(CryptoTestUtils::ProofVerifierForTesting()) {
    FLAGS_enable_quic_stateless_reject_support = false;
  }

  void Initialize() { InitializeServer(); }

  ~QuicCryptoServerStreamTest() override {
    // Ensure that anything that might reference |helpers_| is destroyed before
    // |helpers_| is destroyed.
    server_session_.reset();
    client_session_.reset();
    helpers_.clear();
    alarm_factories_.clear();
  }

  // Initializes the crypto server stream state for testing.  May be
  // called multiple times.
  void InitializeServer() {
    TestQuicSpdyServerSession* server_session = nullptr;
    helpers_.push_back(base::MakeUnique<MockQuicConnectionHelper>());
    alarm_factories_.push_back(base::MakeUnique<MockAlarmFactory>());
    CreateServerSessionForTest(
        server_id_, QuicTime::Delta::FromSeconds(100000), supported_versions_,
        helpers_.back().get(), alarm_factories_.back().get(),
        &server_crypto_config_, &server_compressed_certs_cache_,
        &server_connection_, &server_session);
    CHECK(server_session);
    server_session_.reset(server_session);
    CryptoTestUtils::FakeServerOptions options;
    options.token_binding_params = QuicTagVector{kTB10};
    CryptoTestUtils::SetupCryptoServerConfigForTest(
        server_connection_->clock(), server_connection_->random_generator(),
        &server_crypto_config_, options);
  }

  QuicCryptoServerStream* server_stream() {
    return server_session_->GetCryptoStream();
  }

  QuicCryptoClientStream* client_stream() {
    return client_session_->GetCryptoStream();
  }

  // Initializes a fake client, and all its associated state, for
  // testing.  May be called multiple times.
  void InitializeFakeClient(bool supports_stateless_rejects) {
    TestQuicSpdyClientSession* client_session = nullptr;
    helpers_.push_back(base::MakeUnique<MockQuicConnectionHelper>());
    alarm_factories_.push_back(base::MakeUnique<MockAlarmFactory>());
    CreateClientSessionForTest(
        server_id_, supports_stateless_rejects,
        QuicTime::Delta::FromSeconds(100000), supported_versions_,
        helpers_.back().get(), alarm_factories_.back().get(),
        &client_crypto_config_, &client_connection_, &client_session);
    CHECK(client_session);
    client_session_.reset(client_session);
  }

  void ConstructHandshakeMessage() {
    CryptoFramer framer;
    message_data_.reset(framer.ConstructHandshakeMessage(message_));
  }

  int CompleteCryptoHandshake() {
    CHECK(server_connection_);
    CHECK(server_session_ != nullptr);
    return CryptoTestUtils::HandshakeWithFakeClient(
        helpers_.back().get(), alarm_factories_.back().get(),
        server_connection_, server_stream(), server_id_, client_options_);
  }

  // Performs a single round of handshake message-exchange between the
  // client and server.
  void AdvanceHandshakeWithFakeClient() {
    CHECK(server_connection_);
    CHECK(client_session_ != nullptr);

    EXPECT_CALL(*client_session_, OnProofValid(_)).Times(testing::AnyNumber());
    client_stream()->CryptoConnect();
    CryptoTestUtils::AdvanceHandshake(client_connection_, client_stream(), 0,
                                      server_connection_, server_stream(), 0);
  }

 protected:
  QuicFlagSaver flags_;  // Save/restore all QUIC flag values.

  // Every connection gets its own MockQuicConnectionHelper and
  // MockAlarmFactory, tracked separately from the server and client state so
  // their lifetimes persist through the whole test.
  std::vector<std::unique_ptr<MockQuicConnectionHelper>> helpers_;
  std::vector<std::unique_ptr<MockAlarmFactory>> alarm_factories_;

  // Server state.
  PacketSavingConnection* server_connection_;
  std::unique_ptr<TestQuicSpdyServerSession> server_session_;
  QuicCryptoServerConfig server_crypto_config_;
  QuicCompressedCertsCache server_compressed_certs_cache_;
  QuicServerId server_id_;

  // Client state.
  PacketSavingConnection* client_connection_;
  QuicCryptoClientConfig client_crypto_config_;
  std::unique_ptr<TestQuicSpdyClientSession> client_session_;

  CryptoHandshakeMessage message_;
  std::unique_ptr<QuicData> message_data_;
  CryptoTestUtils::FakeClientOptions client_options_;

  // Which QUIC versions the client and server support.
  QuicVersionVector supported_versions_ = AllSupportedVersions();
};

INSTANTIATE_TEST_CASE_P(Tests, QuicCryptoServerStreamTest, testing::Bool());

TEST_P(QuicCryptoServerStreamTest, NotInitiallyConected) {
  Initialize();
  EXPECT_FALSE(server_stream()->encryption_established());
  EXPECT_FALSE(server_stream()->handshake_confirmed());
}

TEST_P(QuicCryptoServerStreamTest, NotInitiallySendingStatelessRejects) {
  Initialize();
  EXPECT_FALSE(server_stream()->UseStatelessRejectsIfPeerSupported());
  EXPECT_FALSE(server_stream()->PeerSupportsStatelessRejects());
}

TEST_P(QuicCryptoServerStreamTest, ConnectedAfterCHLO) {
  // CompleteCryptoHandshake returns the number of client hellos sent. This
  // test should send:
  //   * One to get a source-address token and certificates.
  //   * One to complete the handshake.
  Initialize();
  EXPECT_EQ(2, CompleteCryptoHandshake());
  EXPECT_TRUE(server_stream()->encryption_established());
  EXPECT_TRUE(server_stream()->handshake_confirmed());
}

TEST_P(QuicCryptoServerStreamTest, ForwardSecureAfterCHLO) {
  Initialize();
  InitializeFakeClient(/* supports_stateless_rejects= */ false);

  // Do a first handshake in order to prime the client config with the server's
  // information.
  AdvanceHandshakeWithFakeClient();
  EXPECT_FALSE(server_stream()->encryption_established());
  EXPECT_FALSE(server_stream()->handshake_confirmed());

  // Now do another handshake, with the blocking SHLO connection option.
  InitializeServer();
  InitializeFakeClient(/* supports_stateless_rejects= */ false);

  AdvanceHandshakeWithFakeClient();
  EXPECT_TRUE(server_stream()->encryption_established());
  EXPECT_TRUE(server_stream()->handshake_confirmed());
  EXPECT_EQ(ENCRYPTION_FORWARD_SECURE,
            server_session_->connection()->encryption_level());
}

TEST_P(QuicCryptoServerStreamTest, StatelessRejectAfterCHLO) {
  FLAGS_enable_quic_stateless_reject_support = true;

  Initialize();

  EXPECT_CALL(*server_connection_,
              CloseConnection(QUIC_CRYPTO_HANDSHAKE_STATELESS_REJECT, _, _));

  InitializeFakeClient(/* supports_stateless_rejects= */ true);
  AdvanceHandshakeWithFakeClient();

  // Check the server to make the sure the handshake did not succeed.
  EXPECT_FALSE(server_stream()->encryption_established());
  EXPECT_FALSE(server_stream()->handshake_confirmed());

  // Check the client state to make sure that it received a server-designated
  // connection id.
  QuicCryptoClientConfig::CachedState* client_state =
      client_crypto_config_.LookupOrCreate(server_id_);

  ASSERT_TRUE(client_state->has_server_nonce());
  ASSERT_FALSE(client_state->GetNextServerNonce().empty());
  ASSERT_FALSE(client_state->has_server_nonce());

  ASSERT_TRUE(client_state->has_server_designated_connection_id());
  const QuicConnectionId server_designated_connection_id =
      client_state->GetNextServerDesignatedConnectionId();
  const QuicConnectionId expected_id =
      server_connection_->random_generator()->RandUint64();
  EXPECT_EQ(expected_id, server_designated_connection_id);
  EXPECT_FALSE(client_state->has_server_designated_connection_id());
  ASSERT_TRUE(client_state->IsComplete(QuicWallTime::FromUNIXSeconds(0)));
}

TEST_P(QuicCryptoServerStreamTest, ConnectedAfterStatelessHandshake) {
  FLAGS_enable_quic_stateless_reject_support = true;

  Initialize();

  InitializeFakeClient(/* supports_stateless_rejects= */ true);
  AdvanceHandshakeWithFakeClient();

  // On the first round, encryption will not be established.
  EXPECT_FALSE(server_stream()->encryption_established());
  EXPECT_FALSE(server_stream()->handshake_confirmed());
  EXPECT_EQ(1, server_stream()->NumHandshakeMessages());
  EXPECT_EQ(0, server_stream()->NumHandshakeMessagesWithServerNonces());

  // Now check the client state.
  QuicCryptoClientConfig::CachedState* client_state =
      client_crypto_config_.LookupOrCreate(server_id_);

  ASSERT_TRUE(client_state->has_server_designated_connection_id());
  const QuicConnectionId server_designated_connection_id =
      client_state->GetNextServerDesignatedConnectionId();
  const QuicConnectionId expected_id =
      server_connection_->random_generator()->RandUint64();
  EXPECT_EQ(expected_id, server_designated_connection_id);
  EXPECT_FALSE(client_state->has_server_designated_connection_id());
  ASSERT_TRUE(client_state->IsComplete(QuicWallTime::FromUNIXSeconds(0)));

  // Now create new client and server streams with the existing config
  // and try the handshake again (0-RTT handshake).
  InitializeServer();

  InitializeFakeClient(/* supports_stateless_rejects= */ true);
  // In the stateless case, the second handshake contains a server-nonce, so the
  // AsyncStrikeRegisterVerification() case will still succeed (unlike a 0-RTT
  // handshake).
  AdvanceHandshakeWithFakeClient();

  // On the second round, encryption will be established.
  EXPECT_TRUE(server_stream()->encryption_established());
  EXPECT_TRUE(server_stream()->handshake_confirmed());
  EXPECT_EQ(1, server_stream()->NumHandshakeMessages());
  EXPECT_EQ(1, server_stream()->NumHandshakeMessagesWithServerNonces());
}

TEST_P(QuicCryptoServerStreamTest, NoStatelessRejectIfNoClientSupport) {
  FLAGS_enable_quic_stateless_reject_support = true;

  Initialize();

  // The server is configured to use stateless rejects, but the client does not
  // support it.
  InitializeFakeClient(/* supports_stateless_rejects= */ false);
  AdvanceHandshakeWithFakeClient();

  // Check the server to make the sure the handshake did not succeed.
  EXPECT_FALSE(server_stream()->encryption_established());
  EXPECT_FALSE(server_stream()->handshake_confirmed());

  // Check the client state to make sure that it did not receive a
  // server-designated connection id.
  QuicCryptoClientConfig::CachedState* client_state =
      client_crypto_config_.LookupOrCreate(server_id_);

  ASSERT_FALSE(client_state->has_server_designated_connection_id());
  ASSERT_TRUE(client_state->IsComplete(QuicWallTime::FromUNIXSeconds(0)));
}

TEST_P(QuicCryptoServerStreamTest, ZeroRTT) {
  Initialize();
  InitializeFakeClient(/* supports_stateless_rejects= */ false);

  // Do a first handshake in order to prime the client config with the server's
  // information.
  AdvanceHandshakeWithFakeClient();

  // Now do another handshake, hopefully in 0-RTT.
  DVLOG(1) << "Resetting for 0-RTT handshake attempt";
  InitializeFakeClient(/* supports_stateless_rejects= */ false);
  InitializeServer();

  client_stream()->CryptoConnect();

  CryptoTestUtils::CommunicateHandshakeMessages(
      client_connection_, client_stream(), server_connection_, server_stream());

  EXPECT_EQ(1, client_stream()->num_sent_client_hellos());
}

TEST_P(QuicCryptoServerStreamTest, FailByPolicy) {
  Initialize();
  InitializeFakeClient(/* supports_stateless_rejects= */ false);

  EXPECT_CALL(*server_session_->helper(), CanAcceptClientHello(_, _, _))
      .WillOnce(testing::Return(false));
  EXPECT_CALL(*server_connection_,
              CloseConnection(QUIC_HANDSHAKE_FAILED, _, _));

  AdvanceHandshakeWithFakeClient();
}

TEST_P(QuicCryptoServerStreamTest, MessageAfterHandshake) {
  Initialize();
  CompleteCryptoHandshake();
  EXPECT_CALL(
      *server_connection_,
      CloseConnection(QUIC_CRYPTO_MESSAGE_AFTER_HANDSHAKE_COMPLETE, _, _));
  message_.set_tag(kCHLO);
  ConstructHandshakeMessage();
  server_stream()->OnStreamFrame(
      QuicStreamFrame(kCryptoStreamId, /*fin=*/false, /*offset=*/0,
                      message_data_->AsStringPiece()));
}

TEST_P(QuicCryptoServerStreamTest, BadMessageType) {
  Initialize();

  message_.set_tag(kSHLO);
  ConstructHandshakeMessage();
  EXPECT_CALL(*server_connection_,
              CloseConnection(QUIC_INVALID_CRYPTO_MESSAGE_TYPE, _, _));
  server_stream()->OnStreamFrame(
      QuicStreamFrame(kCryptoStreamId, /*fin=*/false, /*offset=*/0,
                      message_data_->AsStringPiece()));
}

TEST_P(QuicCryptoServerStreamTest, ChannelID) {
  Initialize();

  client_options_.channel_id_enabled = true;
  client_options_.channel_id_source_async = false;
  // CompleteCryptoHandshake verifies
  // server_stream()->crypto_negotiated_params().channel_id is correct.
  EXPECT_EQ(2, CompleteCryptoHandshake());
  EXPECT_TRUE(server_stream()->encryption_established());
  EXPECT_TRUE(server_stream()->handshake_confirmed());
}

TEST_P(QuicCryptoServerStreamTest, ChannelIDAsync) {
  Initialize();

  client_options_.channel_id_enabled = true;
  client_options_.channel_id_source_async = true;
  // CompleteCryptoHandshake verifies
  // server_stream()->crypto_negotiated_params().channel_id is correct.
  EXPECT_EQ(2, CompleteCryptoHandshake());
  EXPECT_TRUE(server_stream()->encryption_established());
  EXPECT_TRUE(server_stream()->handshake_confirmed());
}

TEST_P(QuicCryptoServerStreamTest, OnlySendSCUPAfterHandshakeComplete) {
  // An attempt to send a SCUP before completing handshake should fail.
  Initialize();

  server_stream()->SendServerConfigUpdate(nullptr);
  EXPECT_EQ(0, server_stream()->NumServerConfigUpdateMessagesSent());
}

TEST_P(QuicCryptoServerStreamTest, SendSCUPAfterHandshakeComplete) {
  Initialize();

  InitializeFakeClient(/* supports_stateless_rejects= */ false);

  // Do a first handshake in order to prime the client config with the server's
  // information.
  AdvanceHandshakeWithFakeClient();

  // Now do another handshake, with the blocking SHLO connection option.
  InitializeServer();
  InitializeFakeClient(/* supports_stateless_rejects= */ false);
  AdvanceHandshakeWithFakeClient();

  // Send a SCUP message and ensure that the client was able to verify it.
  EXPECT_CALL(*client_connection_, CloseConnection(_, _, _)).Times(0);
  server_stream()->SendServerConfigUpdate(nullptr);
  CryptoTestUtils::AdvanceHandshake(client_connection_, client_stream(), 1,
                                    server_connection_, server_stream(), 1);

  EXPECT_EQ(1, server_stream()->NumServerConfigUpdateMessagesSent());
  EXPECT_EQ(1, client_stream()->num_scup_messages_received());
}

TEST_P(QuicCryptoServerStreamTest, DoesPeerSupportStatelessRejects) {
  Initialize();

  ConstructHandshakeMessage();
  QuicConfig stateless_reject_config = DefaultQuicConfigStatelessRejects();
  stateless_reject_config.ToHandshakeMessage(&message_);
  EXPECT_TRUE(
      QuicCryptoServerStreamPeer::DoesPeerSupportStatelessRejects(message_));

  message_.Clear();
  QuicConfig stateful_reject_config = DefaultQuicConfig();
  stateful_reject_config.ToHandshakeMessage(&message_);
  EXPECT_FALSE(
      QuicCryptoServerStreamPeer::DoesPeerSupportStatelessRejects(message_));
}

TEST_P(QuicCryptoServerStreamTest, TokenBindingNegotiated) {
  Initialize();

  client_options_.token_binding_params = QuicTagVector{kTB10, kP256};
  CompleteCryptoHandshake();
  EXPECT_EQ(
      kTB10,
      server_stream()->crypto_negotiated_params().token_binding_key_param);
  EXPECT_TRUE(server_stream()->encryption_established());
  EXPECT_TRUE(server_stream()->handshake_confirmed());
}

TEST_P(QuicCryptoServerStreamTest, NoTokenBindingWithoutClientSupport) {
  Initialize();

  CompleteCryptoHandshake();
  EXPECT_EQ(
      0u, server_stream()->crypto_negotiated_params().token_binding_key_param);
  EXPECT_TRUE(server_stream()->encryption_established());
  EXPECT_TRUE(server_stream()->handshake_confirmed());
}

class FailingProofSource : public ProofSource {
 public:
  bool GetProof(const QuicIpAddress& server_ip,
                const string& hostname,
                const string& server_config,
                QuicVersion quic_version,
                StringPiece chlo_hash,
                const QuicTagVector& connection_options,
                scoped_refptr<ProofSource::Chain>* out_chain,
                QuicCryptoProof* out_proof) override {
    return false;
  }

  void GetProof(const QuicIpAddress& server_ip,
                const string& hostname,
                const string& server_config,
                QuicVersion quic_version,
                StringPiece chlo_hash,
                const QuicTagVector& connection_options,
                std::unique_ptr<Callback> callback) override {
    callback->Run(false, nullptr, QuicCryptoProof(), nullptr);
  }
};

class QuicCryptoServerStreamTestWithFailingProofSource
    : public QuicCryptoServerStreamTest {
 public:
  QuicCryptoServerStreamTestWithFailingProofSource()
      : QuicCryptoServerStreamTest(
            std::unique_ptr<FailingProofSource>(new FailingProofSource)) {}
};

INSTANTIATE_TEST_CASE_P(MoreTests,
                        QuicCryptoServerStreamTestWithFailingProofSource,
                        testing::Bool());

TEST_P(QuicCryptoServerStreamTestWithFailingProofSource, Test) {
  Initialize();
  InitializeFakeClient(/* supports_stateless_rejects= */ false);

  // Regression test for b/31521252, in which a crash would happen here.
  AdvanceHandshakeWithFakeClient();
  EXPECT_FALSE(server_stream()->encryption_established());
  EXPECT_FALSE(server_stream()->handshake_confirmed());
}

}  // namespace

}  // namespace test
}  // namespace net
