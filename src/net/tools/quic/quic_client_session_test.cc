// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/quic/quic_client_session.h"

#include <vector>

#include "net/quic/core/crypto/aes_128_gcm_12_encrypter.h"
#include "net/quic/core/quic_flags.h"
#include "net/quic/core/spdy_utils.h"
#include "net/quic/platform/api/quic_ptr_util.h"
#include "net/quic/platform/api/quic_socket_address.h"
#include "net/quic/platform/api/quic_str_cat.h"
#include "net/quic/test_tools/crypto_test_utils.h"
#include "net/quic/test_tools/mock_quic_spdy_client_stream.h"
#include "net/quic/test_tools/quic_config_peer.h"
#include "net/quic/test_tools/quic_connection_peer.h"
#include "net/quic/test_tools/quic_packet_creator_peer.h"
#include "net/quic/test_tools/quic_spdy_session_peer.h"
#include "net/quic/test_tools/quic_test_utils.h"
#include "net/tools/quic/quic_spdy_client_stream.h"
#include "testing/gtest/include/gtest/gtest.h"

using google::protobuf::implicit_cast;
using std::string;
using testing::AnyNumber;
using testing::Invoke;
using testing::Truly;
using testing::_;

namespace net {
namespace test {
namespace {

const char kServerHostname[] = "test.example.com";
const uint16_t kPort = 443;

class TestQuicClientSession : public QuicClientSession {
 public:
  explicit TestQuicClientSession(const QuicConfig& config,
                                 QuicConnection* connection,
                                 const QuicServerId& server_id,
                                 QuicCryptoClientConfig* crypto_config,
                                 QuicClientPushPromiseIndex* push_promise_index)
      : QuicClientSession(config,
                          connection,
                          server_id,
                          crypto_config,
                          push_promise_index) {}

  std::unique_ptr<QuicSpdyClientStream> CreateClientStream() override {
    return QuicMakeUnique<MockQuicSpdyClientStream>(GetNextOutgoingStreamId(),
                                                    this);
  }

  MockQuicSpdyClientStream* CreateIncomingDynamicStream(
      QuicStreamId id) override {
    MockQuicSpdyClientStream* stream = new MockQuicSpdyClientStream(id, this);
    ActivateStream(QuicWrapUnique(stream));
    return stream;
  }
};

class QuicClientSessionTest : public ::testing::TestWithParam<QuicVersion> {
 protected:
  QuicClientSessionTest()
      : crypto_config_(crypto_test_utils::ProofVerifierForTesting()),
        promised_stream_id_(kServerDataStreamId1),
        associated_stream_id_(kClientDataStreamId1) {
    Initialize();
    // Advance the time, because timers do not like uninitialized times.
    connection_->AdvanceTime(QuicTime::Delta::FromSeconds(1));
  }

  ~QuicClientSessionTest() override {
    // Session must be destroyed before promised_by_url_
    session_.reset(nullptr);
  }

  void Initialize() {
    session_.reset();
    connection_ = new PacketSavingConnection(&helper_, &alarm_factory_,
                                             Perspective::IS_CLIENT,
                                             SupportedVersions(GetParam()));
    session_.reset(new TestQuicClientSession(
        DefaultQuicConfig(), connection_,
        QuicServerId(kServerHostname, kPort, PRIVACY_MODE_DISABLED),
        &crypto_config_, &push_promise_index_));
    session_->Initialize();
    push_promise_[":path"] = "/bar";
    push_promise_[":authority"] = "www.google.com";
    push_promise_[":version"] = "HTTP/1.1";
    push_promise_[":method"] = "GET";
    push_promise_[":scheme"] = "https";
    promise_url_ = SpdyUtils::GetUrlFromHeaderBlock(push_promise_);
  }

  void CompleteCryptoHandshake() {
    CompleteCryptoHandshake(kDefaultMaxStreamsPerConnection);
  }

  void CompleteCryptoHandshake(uint32_t server_max_incoming_streams) {
    session_->CryptoConnect();
    QuicCryptoClientStream* stream =
        static_cast<QuicCryptoClientStream*>(session_->GetCryptoStream());
    crypto_test_utils::FakeServerOptions options;
    QuicConfig config = DefaultQuicConfig();
    config.SetMaxIncomingDynamicStreamsToSend(server_max_incoming_streams);
    crypto_test_utils::HandshakeWithFakeServer(
        &config, &helper_, &alarm_factory_, connection_, stream, options);
  }

  QuicCryptoClientConfig crypto_config_;
  MockQuicConnectionHelper helper_;
  MockAlarmFactory alarm_factory_;
  PacketSavingConnection* connection_;
  std::unique_ptr<TestQuicClientSession> session_;
  QuicClientPushPromiseIndex push_promise_index_;
  SpdyHeaderBlock push_promise_;
  string promise_url_;
  QuicStreamId promised_stream_id_;
  QuicStreamId associated_stream_id_;
};

INSTANTIATE_TEST_CASE_P(Tests,
                        QuicClientSessionTest,
                        ::testing::ValuesIn(AllSupportedVersions()));

TEST_P(QuicClientSessionTest, CryptoConnect) {
  CompleteCryptoHandshake();
}

TEST_P(QuicClientSessionTest, NoEncryptionAfterInitialEncryption) {
  // Complete a handshake in order to prime the crypto config for 0-RTT.
  CompleteCryptoHandshake();

  // Now create a second session using the same crypto config.
  Initialize();

  // Starting the handshake should move immediately to encryption
  // established and will allow streams to be created.
  session_->CryptoConnect();
  EXPECT_TRUE(session_->IsEncryptionEstablished());
  QuicSpdyClientStream* stream =
      session_->CreateOutgoingDynamicStream(kDefaultPriority);
  ASSERT_TRUE(stream != nullptr);
  EXPECT_NE(kCryptoStreamId, stream->id());

  // Process an "inchoate" REJ from the server which will cause
  // an inchoate CHLO to be sent and will leave the encryption level
  // at NONE.
  CryptoHandshakeMessage rej;
  crypto_test_utils::FillInDummyReject(&rej, /* stateless */ false);
  EXPECT_TRUE(session_->IsEncryptionEstablished());
  session_->GetCryptoStream()->OnHandshakeMessage(rej);
  EXPECT_FALSE(session_->IsEncryptionEstablished());
  EXPECT_EQ(ENCRYPTION_NONE,
            QuicPacketCreatorPeer::GetEncryptionLevel(
                QuicConnectionPeer::GetPacketCreator(connection_)));
  // Verify that no new streams may be created.
  EXPECT_TRUE(session_->CreateOutgoingDynamicStream(kDefaultPriority) ==
              nullptr);
  // Verify that no data may be send on existing streams.
  char data[] = "hello world";
  struct iovec iov = {data, arraysize(data)};
  QuicIOVector iovector(&iov, 1, iov.iov_len);
  QuicConsumedData consumed =
      session_->WritevData(stream, stream->id(), iovector, 0, false, nullptr);
  EXPECT_FALSE(consumed.fin_consumed);
  EXPECT_EQ(0u, consumed.bytes_consumed);
}

TEST_P(QuicClientSessionTest, MaxNumStreamsWithNoFinOrRst) {
  EXPECT_CALL(*connection_, SendRstStream(_, _, _)).Times(AnyNumber());

  if (GetParam() <= QUIC_VERSION_34) {
    session_->config()->SetMaxStreamsPerConnection(1, 1);

    // Initialize crypto before the client session will create a stream.
    CompleteCryptoHandshake();
  } else {
    const uint32_t kServerMaxIncomingStreams = 1;
    CompleteCryptoHandshake(kServerMaxIncomingStreams);
  }

  QuicSpdyClientStream* stream =
      session_->CreateOutgoingDynamicStream(kDefaultPriority);
  ASSERT_TRUE(stream);
  EXPECT_FALSE(session_->CreateOutgoingDynamicStream(kDefaultPriority));

  // Close the stream, but without having received a FIN or a RST_STREAM
  // and check that a new one can not be created.
  session_->CloseStream(stream->id());
  EXPECT_EQ(1u, session_->GetNumOpenOutgoingStreams());

  stream = session_->CreateOutgoingDynamicStream(kDefaultPriority);
  EXPECT_FALSE(stream);
}

TEST_P(QuicClientSessionTest, MaxNumStreamsWithRst) {
  EXPECT_CALL(*connection_, SendRstStream(_, _, _)).Times(AnyNumber());

  if (GetParam() <= QUIC_VERSION_34) {
    session_->config()->SetMaxStreamsPerConnection(1, 1);

    // Initialize crypto before the client session will create a stream.
    CompleteCryptoHandshake();
  } else {
    const uint32_t kServerMaxIncomingStreams = 1;
    CompleteCryptoHandshake(kServerMaxIncomingStreams);
  }

  QuicSpdyClientStream* stream =
      session_->CreateOutgoingDynamicStream(kDefaultPriority);
  ASSERT_TRUE(stream);
  EXPECT_FALSE(session_->CreateOutgoingDynamicStream(kDefaultPriority));

  // Close the stream and receive an RST frame to remove the unfinished stream
  session_->CloseStream(stream->id());
  session_->OnRstStream(
      QuicRstStreamFrame(stream->id(), QUIC_RST_ACKNOWLEDGEMENT, 0));
  // Check that a new one can be created.
  EXPECT_EQ(0u, session_->GetNumOpenOutgoingStreams());
  stream = session_->CreateOutgoingDynamicStream(kDefaultPriority);
  EXPECT_TRUE(stream);
}

TEST_P(QuicClientSessionTest, GoAwayReceived) {
  CompleteCryptoHandshake();

  // After receiving a GoAway, I should no longer be able to create outgoing
  // streams.
  session_->connection()->OnGoAwayFrame(
      QuicGoAwayFrame(QUIC_PEER_GOING_AWAY, 1u, "Going away."));
  EXPECT_EQ(nullptr, session_->CreateOutgoingDynamicStream(kDefaultPriority));
}

static bool CheckForDecryptionError(QuicFramer* framer) {
  return framer->error() == QUIC_DECRYPTION_FAILURE;
}

// Regression test for b/17206611.
TEST_P(QuicClientSessionTest, InvalidPacketReceived) {
  QuicSocketAddress server_address(TestPeerIPAddress(), kTestPort);
  QuicSocketAddress client_address(TestPeerIPAddress(), kTestPort);

  EXPECT_CALL(*connection_, ProcessUdpPacket(server_address, client_address, _))
      .WillRepeatedly(Invoke(implicit_cast<MockQuicConnection*>(connection_),
                             &MockQuicConnection::ReallyProcessUdpPacket));
  EXPECT_CALL(*connection_, OnCanWrite()).Times(AnyNumber());
  EXPECT_CALL(*connection_, OnError(_)).Times(1);

  // Verify that empty packets don't close the connection.
  QuicReceivedPacket zero_length_packet(nullptr, 0, QuicTime::Zero(), false);
  EXPECT_CALL(*connection_, CloseConnection(_, _, _)).Times(0);
  session_->ProcessUdpPacket(client_address, server_address,
                             zero_length_packet);

  // Verifiy that small, invalid packets don't close the connection.
  char buf[2] = {0x00, 0x01};
  QuicReceivedPacket valid_packet(buf, 2, QuicTime::Zero(), false);
  // Close connection shouldn't be called.
  EXPECT_CALL(*connection_, CloseConnection(_, _, _)).Times(0);
  session_->ProcessUdpPacket(client_address, server_address, valid_packet);

  // Verify that a non-decryptable packet doesn't close the connection.
  QuicConnectionId connection_id = session_->connection()->connection_id();
  std::unique_ptr<QuicEncryptedPacket> packet(ConstructEncryptedPacket(
      connection_id, false, false, false, kDefaultPathId, 100, "data",
      PACKET_8BYTE_CONNECTION_ID, PACKET_6BYTE_PACKET_NUMBER, nullptr,
      Perspective::IS_SERVER));
  std::unique_ptr<QuicReceivedPacket> received(
      ConstructReceivedPacket(*packet, QuicTime::Zero()));
  // Change the last byte of the encrypted data.
  *(const_cast<char*>(received->data() + received->length() - 1)) += 1;
  EXPECT_CALL(*connection_, CloseConnection(_, _, _)).Times(0);
  EXPECT_CALL(*connection_, OnError(Truly(CheckForDecryptionError))).Times(1);
  session_->ProcessUdpPacket(client_address, server_address, *received);
}

// A packet with invalid framing should cause a connection to be closed.
TEST_P(QuicClientSessionTest, InvalidFramedPacketReceived) {
  QuicSocketAddress server_address(TestPeerIPAddress(), kTestPort);
  QuicSocketAddress client_address(TestPeerIPAddress(), kTestPort);

  EXPECT_CALL(*connection_, ProcessUdpPacket(server_address, client_address, _))
      .WillRepeatedly(Invoke(implicit_cast<MockQuicConnection*>(connection_),
                             &MockQuicConnection::ReallyProcessUdpPacket));
  EXPECT_CALL(*connection_, OnError(_)).Times(1);

  // Verify that a decryptable packet with bad frames does close the connection.
  QuicConnectionId connection_id = session_->connection()->connection_id();
  QuicVersionVector versions = {GetParam()};
  std::unique_ptr<QuicEncryptedPacket> packet(ConstructMisFramedEncryptedPacket(
      connection_id, false, false, kDefaultPathId, 100, "data",
      PACKET_8BYTE_CONNECTION_ID, PACKET_6BYTE_PACKET_NUMBER, &versions,
      Perspective::IS_SERVER));
  std::unique_ptr<QuicReceivedPacket> received(
      ConstructReceivedPacket(*packet, QuicTime::Zero()));
  EXPECT_CALL(*connection_, CloseConnection(_, _, _)).Times(1);
  session_->ProcessUdpPacket(client_address, server_address, *received);
}

TEST_P(QuicClientSessionTest, PushPromiseOnPromiseHeaders) {
  // Initialize crypto before the client session will create a stream.
  CompleteCryptoHandshake();

  MockQuicSpdyClientStream* stream = static_cast<MockQuicSpdyClientStream*>(
      session_->CreateOutgoingDynamicStream(kDefaultPriority));

  EXPECT_CALL(*stream, OnPromiseHeaderList(_, _, _));
  session_->OnPromiseHeaderList(associated_stream_id_, promised_stream_id_, 0,
                                QuicHeaderList());
}

TEST_P(QuicClientSessionTest, PushPromiseOnPromiseHeadersAlreadyClosed) {
  // Initialize crypto before the client session will create a stream.
  CompleteCryptoHandshake();

  session_->CreateOutgoingDynamicStream(kDefaultPriority);

  EXPECT_CALL(*connection_,
              SendRstStream(associated_stream_id_, QUIC_REFUSED_STREAM, 0));
  session_->ResetPromised(associated_stream_id_, QUIC_REFUSED_STREAM);

  session_->OnPromiseHeaderList(associated_stream_id_, promised_stream_id_, 0,
                                QuicHeaderList());
}

TEST_P(QuicClientSessionTest, PushPromiseOutOfOrder) {
  // Initialize crypto before the client session will create a stream.
  CompleteCryptoHandshake();

  MockQuicSpdyClientStream* stream = static_cast<MockQuicSpdyClientStream*>(
      session_->CreateOutgoingDynamicStream(kDefaultPriority));

  EXPECT_CALL(*stream, OnPromiseHeaderList(promised_stream_id_, _, _));
  session_->OnPromiseHeaderList(associated_stream_id_, promised_stream_id_, 0,
                                QuicHeaderList());
  associated_stream_id_ += 2;
  EXPECT_CALL(*connection_,
              CloseConnection(QUIC_INVALID_STREAM_ID,
                              "Received push stream id lesser or equal to the"
                              " last accepted before",
                              _));
  session_->OnPromiseHeaderList(associated_stream_id_, promised_stream_id_, 0,
                                QuicHeaderList());
}

TEST_P(QuicClientSessionTest, PushPromiseHandlePromise) {
  // Initialize crypto before the client session will create a stream.
  CompleteCryptoHandshake();

  session_->CreateOutgoingDynamicStream(kDefaultPriority);

  session_->HandlePromised(associated_stream_id_, promised_stream_id_,
                           push_promise_);

  EXPECT_NE(session_->GetPromisedById(promised_stream_id_), nullptr);
  EXPECT_NE(session_->GetPromisedByUrl(promise_url_), nullptr);
}

TEST_P(QuicClientSessionTest, PushPromiseAlreadyClosed) {
  // Initialize crypto before the client session will create a stream.
  CompleteCryptoHandshake();

  session_->CreateOutgoingDynamicStream(kDefaultPriority);
  session_->GetOrCreateStream(promised_stream_id_);

  EXPECT_CALL(*connection_,
              SendRstStream(promised_stream_id_, QUIC_REFUSED_STREAM, 0));

  session_->ResetPromised(promised_stream_id_, QUIC_REFUSED_STREAM);
  SpdyHeaderBlock promise_headers;
  session_->HandlePromised(associated_stream_id_, promised_stream_id_,
                           promise_headers);

  // Verify that the promise was not created.
  EXPECT_EQ(session_->GetPromisedById(promised_stream_id_), nullptr);
  EXPECT_EQ(session_->GetPromisedByUrl(promise_url_), nullptr);
}

TEST_P(QuicClientSessionTest, PushPromiseDuplicateUrl) {
  // Initialize crypto before the client session will create a stream.
  CompleteCryptoHandshake();

  session_->CreateOutgoingDynamicStream(kDefaultPriority);

  session_->HandlePromised(associated_stream_id_, promised_stream_id_,
                           push_promise_);

  EXPECT_NE(session_->GetPromisedById(promised_stream_id_), nullptr);
  EXPECT_NE(session_->GetPromisedByUrl(promise_url_), nullptr);

  promised_stream_id_ += 2;
  EXPECT_CALL(*connection_, SendRstStream(promised_stream_id_,
                                          QUIC_DUPLICATE_PROMISE_URL, 0));

  session_->HandlePromised(associated_stream_id_, promised_stream_id_,
                           push_promise_);

  // Verify that the promise was not created.
  EXPECT_EQ(session_->GetPromisedById(promised_stream_id_), nullptr);
}

TEST_P(QuicClientSessionTest, ReceivingPromiseEnhanceYourCalm) {
  for (size_t i = 0u; i < session_->get_max_promises(); i++) {
    push_promise_[":path"] = QuicStringPrintf("/bar%zu", i);

    QuicStreamId id = promised_stream_id_ + i * 2;

    session_->HandlePromised(associated_stream_id_, id, push_promise_);

    // Verify that the promise is in the unclaimed streams map.
    string promise_url(SpdyUtils::GetUrlFromHeaderBlock(push_promise_));
    EXPECT_NE(session_->GetPromisedByUrl(promise_url), nullptr);
    EXPECT_NE(session_->GetPromisedById(id), nullptr);
  }

  // One more promise, this should be refused.
  int i = session_->get_max_promises();
  push_promise_[":path"] = QuicStringPrintf("/bar%d", i);

  QuicStreamId id = promised_stream_id_ + i * 2;
  EXPECT_CALL(*connection_, SendRstStream(id, QUIC_REFUSED_STREAM, 0));
  session_->HandlePromised(associated_stream_id_, id, push_promise_);

  // Verify that the promise was not created.
  string promise_url(SpdyUtils::GetUrlFromHeaderBlock(push_promise_));
  EXPECT_EQ(session_->GetPromisedById(id), nullptr);
  EXPECT_EQ(session_->GetPromisedByUrl(promise_url), nullptr);
}

TEST_P(QuicClientSessionTest, IsClosedTrueAfterResetPromisedAlreadyOpen) {
  // Initialize crypto before the client session will create a stream.
  CompleteCryptoHandshake();

  session_->GetOrCreateStream(promised_stream_id_);
  session_->ResetPromised(promised_stream_id_, QUIC_REFUSED_STREAM);
  EXPECT_TRUE(session_->IsClosedStream(promised_stream_id_));
}

TEST_P(QuicClientSessionTest, IsClosedTrueAfterResetPromisedNonexistant) {
  // Initialize crypto before the client session will create a stream.
  CompleteCryptoHandshake();

  session_->ResetPromised(promised_stream_id_, QUIC_REFUSED_STREAM);
  EXPECT_TRUE(session_->IsClosedStream(promised_stream_id_));
}

TEST_P(QuicClientSessionTest, OnInitialHeadersCompleteIsPush) {
  // Initialize crypto before the client session will create a stream.
  CompleteCryptoHandshake();
  session_->GetOrCreateStream(promised_stream_id_);
  session_->HandlePromised(associated_stream_id_, promised_stream_id_,
                           push_promise_);
  EXPECT_NE(session_->GetPromisedById(promised_stream_id_), nullptr);
  EXPECT_NE(session_->GetPromisedStream(promised_stream_id_), nullptr);
  EXPECT_NE(session_->GetPromisedByUrl(promise_url_), nullptr);

  session_->OnInitialHeadersComplete(promised_stream_id_, SpdyHeaderBlock());
}

TEST_P(QuicClientSessionTest, OnInitialHeadersCompleteIsNotPush) {
  // Initialize crypto before the client session will create a stream.
  CompleteCryptoHandshake();
  session_->CreateOutgoingDynamicStream(kDefaultPriority);
  session_->OnInitialHeadersComplete(promised_stream_id_, SpdyHeaderBlock());
}

TEST_P(QuicClientSessionTest, DeletePromised) {
  // Initialize crypto before the client session will create a stream.
  CompleteCryptoHandshake();
  session_->GetOrCreateStream(promised_stream_id_);
  session_->HandlePromised(associated_stream_id_, promised_stream_id_,
                           push_promise_);
  QuicClientPromisedInfo* promised =
      session_->GetPromisedById(promised_stream_id_);
  EXPECT_NE(promised, nullptr);
  EXPECT_NE(session_->GetPromisedStream(promised_stream_id_), nullptr);
  EXPECT_NE(session_->GetPromisedByUrl(promise_url_), nullptr);

  session_->DeletePromised(promised);
  EXPECT_EQ(session_->GetPromisedById(promised_stream_id_), nullptr);
  EXPECT_EQ(session_->GetPromisedByUrl(promise_url_), nullptr);
}

TEST_P(QuicClientSessionTest, ResetPromised) {
  // Initialize crypto before the client session will create a stream.
  CompleteCryptoHandshake();
  session_->GetOrCreateStream(promised_stream_id_);
  session_->HandlePromised(associated_stream_id_, promised_stream_id_,
                           push_promise_);
  EXPECT_CALL(*connection_, SendRstStream(promised_stream_id_,
                                          QUIC_STREAM_PEER_GOING_AWAY, 0));
  session_->SendRstStream(promised_stream_id_, QUIC_STREAM_PEER_GOING_AWAY, 0);
  QuicClientPromisedInfo* promised =
      session_->GetPromisedById(promised_stream_id_);
  EXPECT_NE(promised, nullptr);
  EXPECT_NE(session_->GetPromisedByUrl(promise_url_), nullptr);
  EXPECT_EQ(session_->GetPromisedStream(promised_stream_id_), nullptr);
}

}  // namespace
}  // namespace test
}  // namespace net
