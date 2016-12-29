// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/chromium/quic_chromium_client_session.h"

#include "base/base64.h"
#include "base/files/file_path.h"
#include "base/memory/ptr_util.h"
#include "base/rand_util.h"
#include "base/run_loop.h"
#include "base/test/histogram_tester.h"
#include "base/threading/thread_task_runner_handle.h"
#include "net/base/test_completion_callback.h"
#include "net/cert/cert_verify_result.h"
#include "net/http/transport_security_state.h"
#include "net/log/net_log_source.h"
#include "net/log/test_net_log.h"
#include "net/quic/chromium/crypto/proof_verifier_chromium.h"
#include "net/quic/chromium/mock_crypto_client_stream_factory.h"
#include "net/quic/chromium/quic_chromium_alarm_factory.h"
#include "net/quic/chromium/quic_chromium_client_session_peer.h"
#include "net/quic/chromium/quic_chromium_connection_helper.h"
#include "net/quic/chromium/quic_chromium_packet_reader.h"
#include "net/quic/chromium/quic_chromium_packet_writer.h"
#include "net/quic/chromium/quic_crypto_client_stream_factory.h"
#include "net/quic/chromium/quic_http_utils.h"
#include "net/quic/chromium/quic_server_info.h"
#include "net/quic/chromium/quic_test_packet_maker.h"
#include "net/quic/core/crypto/aes_128_gcm_12_encrypter.h"
#include "net/quic/core/crypto/crypto_protocol.h"
#include "net/quic/core/crypto/quic_decrypter.h"
#include "net/quic/core/crypto/quic_encrypter.h"
#include "net/quic/core/quic_client_promised_info.h"
#include "net/quic/core/quic_flags.h"
#include "net/quic/core/quic_packet_writer.h"
#include "net/quic/test_tools/crypto_test_utils.h"
#include "net/quic/test_tools/quic_client_promised_info_peer.h"
#include "net/quic/test_tools/quic_spdy_session_peer.h"
#include "net/quic/test_tools/quic_test_utils.h"
#include "net/quic/test_tools/simple_quic_framer.h"
#include "net/socket/datagram_client_socket.h"
#include "net/socket/socket_test_util.h"
#include "net/spdy/spdy_test_utils.h"
#include "net/test/cert_test_util.h"
#include "net/test/gtest_util.h"
#include "net/test/test_data_directory.h"
#include "testing/gmock/include/gmock/gmock.h"

using testing::_;

namespace net {
namespace test {
namespace {

const IPEndPoint kIpEndPoint = IPEndPoint(IPAddress::IPv4AllZeros(), 0);
const char kServerHostname[] = "test.example.com";
const uint16_t kServerPort = 443;
const size_t kMaxReadersPerQuicSession = 5;

class MockStreamDelegate : public QuicChromiumClientStream::Delegate {
 public:
  MockStreamDelegate() {}

  MOCK_METHOD0(OnSendData, int());
  MOCK_METHOD2(OnSendDataComplete, int(int, bool*));
  MOCK_METHOD2(OnHeadersAvailable,
               void(const SpdyHeaderBlock& headers, size_t frame_len));
  MOCK_METHOD2(OnHeadersAvailableMock,
               void(const SpdyHeaderBlock& headers, size_t frame_len));
  MOCK_METHOD2(OnDataReceived, int(const char*, int));
  MOCK_METHOD0(OnDataAvailable, void());
  MOCK_METHOD0(OnClose, void());
  MOCK_METHOD1(OnError, void(int));
  MOCK_METHOD0(HasSendHeadersComplete, bool());

 private:
  DISALLOW_COPY_AND_ASSIGN(MockStreamDelegate);
};

class QuicChromiumClientSessionTest
    : public ::testing::TestWithParam<QuicVersion> {
 protected:
  QuicChromiumClientSessionTest()
      : crypto_config_(CryptoTestUtils::ProofVerifierForTesting()),
        default_read_(new MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)),
        socket_data_(
            new SequencedSocketData(default_read_.get(), 1, nullptr, 0)),
        random_(0),
        helper_(&clock_, &random_),
        client_maker_(GetParam(),
                      0,
                      &clock_,
                      kServerHostname,
                      Perspective::IS_CLIENT),
        server_maker_(GetParam(),
                      0,
                      &clock_,
                      kServerHostname,
                      Perspective::IS_SERVER) {
    // Advance the time, because timers do not like uninitialized times.
    clock_.AdvanceTime(QuicTime::Delta::FromSeconds(1));
  }

  void Initialize() {
    socket_factory_.AddSocketDataProvider(socket_data_.get());
    std::unique_ptr<DatagramClientSocket> socket =
        socket_factory_.CreateDatagramClientSocket(DatagramSocket::DEFAULT_BIND,
                                                   base::Bind(&base::RandInt),
                                                   &net_log_, NetLogSource());
    socket->Connect(kIpEndPoint);
    QuicChromiumPacketWriter* writer =
        new net::QuicChromiumPacketWriter(socket.get());
    QuicConnection* connection = new QuicConnection(
        0, QuicSocketAddress(QuicSocketAddressImpl(kIpEndPoint)), &helper_,
        &alarm_factory_, writer, true, Perspective::IS_CLIENT,
        SupportedVersions(GetParam()));
    session_.reset(new QuicChromiumClientSession(
        connection, std::move(socket),
        /*stream_factory=*/nullptr, &crypto_client_stream_factory_, &clock_,
        &transport_security_state_,
        base::WrapUnique(static_cast<QuicServerInfo*>(nullptr)),
        QuicServerId(kServerHostname, kServerPort, PRIVACY_MODE_DISABLED),
        kQuicYieldAfterPacketsRead,
        QuicTime::Delta::FromMilliseconds(kQuicYieldAfterDurationMilliseconds),
        /*cert_verify_flags=*/0, DefaultQuicConfig(), &crypto_config_,
        "CONNECTION_UNKNOWN", base::TimeTicks::Now(), base::TimeTicks::Now(),
        &push_promise_index_, &test_push_delegate_,
        base::ThreadTaskRunnerHandle::Get().get(),
        /*socket_performance_watcher=*/nullptr, &net_log_));

    scoped_refptr<X509Certificate> cert(
        ImportCertFromFile(GetTestCertsDirectory(), "spdy_pooling.pem"));
    verify_details_.cert_verify_result.verified_cert = cert;
    verify_details_.cert_verify_result.is_issued_by_known_root = true;
    session_->Initialize();
    session_->StartReading();
    writer->set_delegate(session_.get());
  }

  void TearDown() override {
    session_->CloseSessionOnError(ERR_ABORTED, QUIC_INTERNAL_ERROR);
  }

  void CompleteCryptoHandshake() {
    ASSERT_THAT(session_->CryptoConnect(false, callback_.callback()), IsOk());
  }

  QuicChromiumPacketWriter* CreateQuicChromiumPacketWriter(
      DatagramClientSocket* socket,
      QuicChromiumClientSession* session) const {
    std::unique_ptr<QuicChromiumPacketWriter> writer(
        new QuicChromiumPacketWriter(socket));
    writer->set_delegate(session);
    return writer.release();
  }

  QuicCryptoClientConfig crypto_config_;
  TestNetLog net_log_;
  BoundTestNetLog bound_test_net_log_;
  MockClientSocketFactory socket_factory_;
  std::unique_ptr<MockRead> default_read_;
  std::unique_ptr<SequencedSocketData> socket_data_;
  MockClock clock_;
  MockRandom random_;
  QuicChromiumConnectionHelper helper_;
  MockAlarmFactory alarm_factory_;
  TransportSecurityState transport_security_state_;
  MockCryptoClientStreamFactory crypto_client_stream_factory_;
  QuicClientPushPromiseIndex push_promise_index_;
  std::unique_ptr<QuicChromiumClientSession> session_;
  TestServerPushDelegate test_push_delegate_;
  QuicConnectionVisitorInterface* visitor_;
  TestCompletionCallback callback_;
  QuicTestPacketMaker client_maker_;
  QuicTestPacketMaker server_maker_;
  ProofVerifyDetailsChromium verify_details_;
};

INSTANTIATE_TEST_CASE_P(Tests,
                        QuicChromiumClientSessionTest,
                        ::testing::ValuesIn(AllSupportedVersions()));

TEST_P(QuicChromiumClientSessionTest, CryptoConnect) {
  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  std::unique_ptr<QuicEncryptedPacket> settings_packet(
      client_maker_.MakeSettingsPacket(1, SETTINGS_MAX_HEADER_LIST_SIZE,
                                       kDefaultMaxUncompressedHeaderSize, true,
                                       nullptr));
  MockWrite writes[] = {
      MockWrite(ASYNC, settings_packet->data(), settings_packet->length(), 1)};
  socket_data_.reset(new SequencedSocketData(reads, arraysize(reads), writes,
                                             arraysize(writes)));
  Initialize();
  CompleteCryptoHandshake();
}

TEST_P(QuicChromiumClientSessionTest, MaxNumStreams) {
  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  std::unique_ptr<QuicEncryptedPacket> settings_packet(
      client_maker_.MakeSettingsPacket(1, SETTINGS_MAX_HEADER_LIST_SIZE,
                                       kDefaultMaxUncompressedHeaderSize, true,
                                       nullptr));
  std::unique_ptr<QuicEncryptedPacket> client_rst(client_maker_.MakeRstPacket(
      2, true, kClientDataStreamId1, QUIC_RST_ACKNOWLEDGEMENT));
  MockWrite writes[] = {
      MockWrite(ASYNC, settings_packet->data(), settings_packet->length(), 1),
      MockWrite(ASYNC, client_rst->data(), client_rst->length(), 2)};
  socket_data_.reset(new SequencedSocketData(reads, arraysize(reads), writes,
                                             arraysize(writes)));

  Initialize();
  CompleteCryptoHandshake();
  const size_t kMaxOpenStreams = session_->max_open_outgoing_streams();

  std::vector<QuicChromiumClientStream*> streams;
  for (size_t i = 0; i < kMaxOpenStreams; i++) {
    QuicChromiumClientStream* stream =
        session_->CreateOutgoingDynamicStream(kDefaultPriority);
    EXPECT_TRUE(stream);
    streams.push_back(stream);
  }
  EXPECT_FALSE(session_->CreateOutgoingDynamicStream(kDefaultPriority));

  EXPECT_EQ(kMaxOpenStreams, session_->GetNumOpenOutgoingStreams());

  // Close a stream and ensure I can now open a new one.
  QuicStreamId stream_id = streams[0]->id();
  session_->CloseStream(stream_id);

  EXPECT_FALSE(session_->CreateOutgoingDynamicStream(kDefaultPriority));
  QuicRstStreamFrame rst1(stream_id, QUIC_STREAM_NO_ERROR, 0);
  session_->OnRstStream(rst1);
  EXPECT_EQ(kMaxOpenStreams - 1, session_->GetNumOpenOutgoingStreams());
  EXPECT_TRUE(session_->CreateOutgoingDynamicStream(kDefaultPriority));
}

TEST_P(QuicChromiumClientSessionTest, PushStreamTimedOutNoResponse) {
  base::HistogramTester histogram_tester;
  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  std::unique_ptr<QuicEncryptedPacket> settings_packet(
      client_maker_.MakeSettingsPacket(1, SETTINGS_MAX_HEADER_LIST_SIZE,
                                       kDefaultMaxUncompressedHeaderSize, true,
                                       nullptr));
  std::unique_ptr<QuicEncryptedPacket> client_rst(client_maker_.MakeRstPacket(
      2, true, kServerDataStreamId1, QUIC_PUSH_STREAM_TIMED_OUT));
  MockWrite writes[] = {
      MockWrite(ASYNC, settings_packet->data(), settings_packet->length(), 1),
      MockWrite(ASYNC, client_rst->data(), client_rst->length(), 2)};
  socket_data_.reset(new SequencedSocketData(reads, arraysize(reads), writes,
                                             arraysize(writes)));
  Initialize();

  ProofVerifyDetailsChromium details;
  details.cert_verify_result.verified_cert =
      ImportCertFromFile(GetTestCertsDirectory(), "spdy_pooling.pem");
  ASSERT_TRUE(details.cert_verify_result.verified_cert.get());

  CompleteCryptoHandshake();
  session_->OnProofVerifyDetailsAvailable(details);

  QuicChromiumClientStream* stream =
      session_->CreateOutgoingDynamicStream(kDefaultPriority);
  EXPECT_TRUE(stream);

  SpdyHeaderBlock promise_headers;
  promise_headers[":method"] = "GET";
  promise_headers[":authority"] = "www.example.org";
  promise_headers[":scheme"] = "https";
  promise_headers[":path"] = "/pushed.jpg";

  // Receive a PUSH PROMISE from the server.
  EXPECT_TRUE(session_->HandlePromised(stream->id(), kServerDataStreamId1,
                                       promise_headers));

  QuicClientPromisedInfo* promised =
      session_->GetPromisedById(kServerDataStreamId1);
  EXPECT_TRUE(promised);
  // Fire alarm to time out the push stream.
  alarm_factory_.FireAlarm(QuicClientPromisedInfoPeer::GetAlarm(promised));
  EXPECT_FALSE(
      session_->GetPromisedByUrl("https://www.example.org/pushed.jpg"));
  EXPECT_EQ(0u,
            QuicChromiumClientSessionPeer::GetPushedBytesCount(session_.get()));
  EXPECT_EQ(0u, QuicChromiumClientSessionPeer::GetPushedAndUnclaimedBytesCount(
                    session_.get()));
}

TEST_P(QuicChromiumClientSessionTest, PushStreamTimedOutWithResponse) {
  base::HistogramTester histogram_tester;
  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  std::unique_ptr<QuicEncryptedPacket> settings_packet(
      client_maker_.MakeSettingsPacket(1, SETTINGS_MAX_HEADER_LIST_SIZE,
                                       kDefaultMaxUncompressedHeaderSize, true,
                                       nullptr));
  std::unique_ptr<QuicEncryptedPacket> client_rst(client_maker_.MakeRstPacket(
      2, true, kServerDataStreamId1, QUIC_PUSH_STREAM_TIMED_OUT));
  MockWrite writes[] = {
      MockWrite(ASYNC, settings_packet->data(), settings_packet->length(), 1),
      MockWrite(ASYNC, client_rst->data(), client_rst->length(), 2)};
  socket_data_.reset(new SequencedSocketData(reads, arraysize(reads), writes,
                                             arraysize(writes)));
  Initialize();

  ProofVerifyDetailsChromium details;
  details.cert_verify_result.verified_cert =
      ImportCertFromFile(GetTestCertsDirectory(), "spdy_pooling.pem");
  ASSERT_TRUE(details.cert_verify_result.verified_cert.get());

  CompleteCryptoHandshake();
  session_->OnProofVerifyDetailsAvailable(details);

  QuicChromiumClientStream* stream =
      session_->CreateOutgoingDynamicStream(kDefaultPriority);
  EXPECT_TRUE(stream);

  SpdyHeaderBlock promise_headers;
  promise_headers[":method"] = "GET";
  promise_headers[":authority"] = "www.example.org";
  promise_headers[":scheme"] = "https";
  promise_headers[":path"] = "/pushed.jpg";

  session_->GetOrCreateStream(kServerDataStreamId1);
  // Receive a PUSH PROMISE from the server.
  EXPECT_TRUE(session_->HandlePromised(stream->id(), kServerDataStreamId1,
                                       promise_headers));
  session_->OnInitialHeadersComplete(kServerDataStreamId1, SpdyHeaderBlock());
  // Read data on the pushed stream.
  QuicStreamFrame data(kServerDataStreamId1, false, 0, StringPiece("SP"));
  session_->OnStreamFrame(data);

  QuicClientPromisedInfo* promised =
      session_->GetPromisedById(kServerDataStreamId1);
  EXPECT_TRUE(promised);
  // Fire alarm to time out the push stream.
  alarm_factory_.FireAlarm(QuicClientPromisedInfoPeer::GetAlarm(promised));
  EXPECT_EQ(2u,
            QuicChromiumClientSessionPeer::GetPushedBytesCount(session_.get()));
  EXPECT_EQ(2u, QuicChromiumClientSessionPeer::GetPushedAndUnclaimedBytesCount(
                    session_.get()));
}

TEST_P(QuicChromiumClientSessionTest, CancelPushWhenPendingValidation) {
  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  std::unique_ptr<QuicEncryptedPacket> settings_packet(
      client_maker_.MakeSettingsPacket(1, SETTINGS_MAX_HEADER_LIST_SIZE,
                                       kDefaultMaxUncompressedHeaderSize, true,
                                       nullptr));
  std::unique_ptr<QuicEncryptedPacket> client_rst(client_maker_.MakeRstPacket(
      2, true, kClientDataStreamId1, QUIC_RST_ACKNOWLEDGEMENT));

  MockWrite writes[] = {
      MockWrite(ASYNC, settings_packet->data(), settings_packet->length(), 1),
      MockWrite(ASYNC, client_rst->data(), client_rst->length(), 2)};
  socket_data_.reset(new SequencedSocketData(reads, arraysize(reads), writes,
                                             arraysize(writes)));
  Initialize();

  ProofVerifyDetailsChromium details;
  details.cert_verify_result.verified_cert =
      ImportCertFromFile(GetTestCertsDirectory(), "spdy_pooling.pem");
  ASSERT_TRUE(details.cert_verify_result.verified_cert.get());

  CompleteCryptoHandshake();
  session_->OnProofVerifyDetailsAvailable(details);

  QuicChromiumClientStream* stream =
      session_->CreateOutgoingDynamicStream(kDefaultPriority);
  EXPECT_TRUE(stream);

  SpdyHeaderBlock promise_headers;
  promise_headers[":method"] = "GET";
  promise_headers[":authority"] = "www.example.org";
  promise_headers[":scheme"] = "https";
  promise_headers[":path"] = "/pushed.jpg";

  // Receive a PUSH PROMISE from the server.
  EXPECT_TRUE(session_->HandlePromised(stream->id(), kServerDataStreamId1,
                                       promise_headers));

  QuicClientPromisedInfo* promised =
      session_->GetPromisedById(kServerDataStreamId1);
  EXPECT_TRUE(promised);

  // Initiate rendezvous.
  SpdyHeaderBlock client_request = promise_headers.Clone();
  TestPushPromiseDelegate delegate(/*match=*/true);
  promised->HandleClientRequest(client_request, &delegate);

  // Cancel the push before receiving the response to the pushed request.
  GURL pushed_url("https://www.example.org/pushed.jpg");
  test_push_delegate_.CancelPush(pushed_url);
  EXPECT_TRUE(session_->GetPromisedByUrl(pushed_url.spec()));

  // Reset the stream now before tear down.
  session_->CloseStream(kClientDataStreamId1);
}

TEST_P(QuicChromiumClientSessionTest, CancelPushBeforeReceivingResponse) {
  base::HistogramTester histogram_tester;
  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  std::unique_ptr<QuicEncryptedPacket> settings_packet(
      client_maker_.MakeSettingsPacket(1, SETTINGS_MAX_HEADER_LIST_SIZE,
                                       kDefaultMaxUncompressedHeaderSize, true,
                                       nullptr));
  std::unique_ptr<QuicEncryptedPacket> client_rst(client_maker_.MakeRstPacket(
      2, true, kServerDataStreamId1, QUIC_STREAM_CANCELLED));
  MockWrite writes[] = {
      MockWrite(ASYNC, settings_packet->data(), settings_packet->length(), 1),
      MockWrite(ASYNC, client_rst->data(), client_rst->length(), 2)};
  socket_data_.reset(new SequencedSocketData(reads, arraysize(reads), writes,
                                             arraysize(writes)));
  Initialize();

  ProofVerifyDetailsChromium details;
  details.cert_verify_result.verified_cert =
      ImportCertFromFile(GetTestCertsDirectory(), "spdy_pooling.pem");
  ASSERT_TRUE(details.cert_verify_result.verified_cert.get());

  CompleteCryptoHandshake();
  session_->OnProofVerifyDetailsAvailable(details);

  QuicChromiumClientStream* stream =
      session_->CreateOutgoingDynamicStream(kDefaultPriority);
  EXPECT_TRUE(stream);

  SpdyHeaderBlock promise_headers;
  promise_headers[":method"] = "GET";
  promise_headers[":authority"] = "www.example.org";
  promise_headers[":scheme"] = "https";
  promise_headers[":path"] = "/pushed.jpg";

  // Receive a PUSH PROMISE from the server.
  EXPECT_TRUE(session_->HandlePromised(stream->id(), kServerDataStreamId1,
                                       promise_headers));

  QuicClientPromisedInfo* promised =
      session_->GetPromisedById(kServerDataStreamId1);
  EXPECT_TRUE(promised);
  // Cancel the push before receiving the response to the pushed request.
  GURL pushed_url("https://www.example.org/pushed.jpg");
  test_push_delegate_.CancelPush(pushed_url);

  EXPECT_FALSE(session_->GetPromisedByUrl(pushed_url.spec()));
  EXPECT_EQ(0u,
            QuicChromiumClientSessionPeer::GetPushedBytesCount(session_.get()));
  EXPECT_EQ(0u, QuicChromiumClientSessionPeer::GetPushedAndUnclaimedBytesCount(
                    session_.get()));
}

TEST_P(QuicChromiumClientSessionTest, CancelPushAfterReceivingResponse) {
  base::HistogramTester histogram_tester;
  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  std::unique_ptr<QuicEncryptedPacket> settings_packet(
      client_maker_.MakeSettingsPacket(1, SETTINGS_MAX_HEADER_LIST_SIZE,
                                       kDefaultMaxUncompressedHeaderSize, true,
                                       nullptr));
  std::unique_ptr<QuicEncryptedPacket> client_rst(client_maker_.MakeRstPacket(
      2, true, kServerDataStreamId1, QUIC_STREAM_CANCELLED));
  MockWrite writes[] = {
      MockWrite(ASYNC, settings_packet->data(), settings_packet->length(), 1),
      MockWrite(ASYNC, client_rst->data(), client_rst->length(), 2)};
  socket_data_.reset(new SequencedSocketData(reads, arraysize(reads), writes,
                                             arraysize(writes)));
  Initialize();

  ProofVerifyDetailsChromium details;
  details.cert_verify_result.verified_cert =
      ImportCertFromFile(GetTestCertsDirectory(), "spdy_pooling.pem");
  ASSERT_TRUE(details.cert_verify_result.verified_cert.get());

  CompleteCryptoHandshake();
  session_->OnProofVerifyDetailsAvailable(details);

  QuicChromiumClientStream* stream =
      session_->CreateOutgoingDynamicStream(kDefaultPriority);
  EXPECT_TRUE(stream);

  SpdyHeaderBlock promise_headers;
  promise_headers[":method"] = "GET";
  promise_headers[":authority"] = "www.example.org";
  promise_headers[":scheme"] = "https";
  promise_headers[":path"] = "/pushed.jpg";

  session_->GetOrCreateStream(kServerDataStreamId1);
  // Receive a PUSH PROMISE from the server.
  EXPECT_TRUE(session_->HandlePromised(stream->id(), kServerDataStreamId1,
                                       promise_headers));
  session_->OnInitialHeadersComplete(kServerDataStreamId1, SpdyHeaderBlock());
  // Read data on the pushed stream.
  QuicStreamFrame data(kServerDataStreamId1, false, 0, StringPiece("SP"));
  session_->OnStreamFrame(data);

  QuicClientPromisedInfo* promised =
      session_->GetPromisedById(kServerDataStreamId1);
  EXPECT_TRUE(promised);
  // Cancel the push after receiving data on the push stream.
  GURL pushed_url("https://www.example.org/pushed.jpg");
  test_push_delegate_.CancelPush(pushed_url);

  EXPECT_FALSE(session_->GetPromisedByUrl(pushed_url.spec()));
  EXPECT_EQ(2u,
            QuicChromiumClientSessionPeer::GetPushedBytesCount(session_.get()));
  EXPECT_EQ(2u, QuicChromiumClientSessionPeer::GetPushedAndUnclaimedBytesCount(
                    session_.get()));
}

TEST_P(QuicChromiumClientSessionTest, Priority) {
  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  std::unique_ptr<QuicEncryptedPacket> settings_packet(
      client_maker_.MakeSettingsPacket(1, SETTINGS_MAX_HEADER_LIST_SIZE,
                                       kDefaultMaxUncompressedHeaderSize, true,
                                       nullptr));
  std::unique_ptr<QuicEncryptedPacket> client_rst(client_maker_.MakeRstPacket(
      2, true, kClientDataStreamId1, QUIC_RST_ACKNOWLEDGEMENT));
  MockWrite writes[] = {
      MockWrite(ASYNC, settings_packet->data(), settings_packet->length(), 1),
      MockWrite(ASYNC, client_rst->data(), client_rst->length(), 2)};
  socket_data_.reset(new SequencedSocketData(reads, arraysize(reads), writes,
                                             arraysize(writes)));

  Initialize();
  CompleteCryptoHandshake();
  for (SpdyPriority priority : {kV3HighestPriority, kV3LowestPriority}) {
    QuicChromiumClientStream* stream =
        session_->CreateOutgoingDynamicStream(priority);
    EXPECT_EQ(kV3HighestPriority, stream->priority());

    MockStreamDelegate delegate;
    EXPECT_CALL(delegate, HasSendHeadersComplete())
        .WillOnce(testing::Return(true));
    stream->SetDelegate(&delegate);
    EXPECT_EQ(priority, stream->priority());
    stream->SetDelegate(nullptr);
    session_->CloseStream(stream->id());
  }
}

TEST_P(QuicChromiumClientSessionTest, MaxNumStreamsViaRequest) {
  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  std::unique_ptr<QuicEncryptedPacket> settings_packet(
      client_maker_.MakeSettingsPacket(1, SETTINGS_MAX_HEADER_LIST_SIZE,
                                       kDefaultMaxUncompressedHeaderSize, true,
                                       nullptr));
  std::unique_ptr<QuicEncryptedPacket> client_rst(client_maker_.MakeRstPacket(
      2, true, kClientDataStreamId1, QUIC_RST_ACKNOWLEDGEMENT));
  MockWrite writes[] = {
      MockWrite(ASYNC, settings_packet->data(), settings_packet->length(), 1),
      MockWrite(ASYNC, client_rst->data(), client_rst->length(), 2)};
  socket_data_.reset(new SequencedSocketData(reads, arraysize(reads), writes,
                                             arraysize(writes)));

  Initialize();
  CompleteCryptoHandshake();
  const size_t kMaxOpenStreams = session_->max_open_outgoing_streams();

  std::vector<QuicChromiumClientStream*> streams;
  for (size_t i = 0; i < kMaxOpenStreams; i++) {
    QuicChromiumClientStream* stream =
        session_->CreateOutgoingDynamicStream(kDefaultPriority);
    EXPECT_TRUE(stream);
    streams.push_back(stream);
  }

  QuicChromiumClientStream* stream;
  QuicChromiumClientSession::StreamRequest stream_request;
  TestCompletionCallback callback;
  ASSERT_EQ(ERR_IO_PENDING,
            stream_request.StartRequest(session_->GetWeakPtr(), &stream,
                                        callback.callback()));

  // Close a stream and ensure I can now open a new one.
  QuicStreamId stream_id = streams[0]->id();
  session_->CloseStream(stream_id);
  QuicRstStreamFrame rst1(stream_id, QUIC_STREAM_NO_ERROR, 0);
  session_->OnRstStream(rst1);
  ASSERT_TRUE(callback.have_result());
  EXPECT_THAT(callback.WaitForResult(), IsOk());
  EXPECT_TRUE(stream != nullptr);
}

TEST_P(QuicChromiumClientSessionTest, GoAwayReceived) {
  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  std::unique_ptr<QuicEncryptedPacket> settings_packet(
      client_maker_.MakeSettingsPacket(1, SETTINGS_MAX_HEADER_LIST_SIZE,
                                       kDefaultMaxUncompressedHeaderSize, true,
                                       nullptr));
  MockWrite writes[] = {
      MockWrite(ASYNC, settings_packet->data(), settings_packet->length(), 1)};
  socket_data_.reset(new SequencedSocketData(reads, arraysize(reads), writes,
                                             arraysize(writes)));
  Initialize();
  CompleteCryptoHandshake();

  // After receiving a GoAway, I should no longer be able to create outgoing
  // streams.
  session_->connection()->OnGoAwayFrame(
      QuicGoAwayFrame(QUIC_PEER_GOING_AWAY, 1u, "Going away."));
  EXPECT_EQ(nullptr, session_->CreateOutgoingDynamicStream(kDefaultPriority));
}

TEST_P(QuicChromiumClientSessionTest, CanPool) {
  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  std::unique_ptr<QuicEncryptedPacket> settings_packet(
      client_maker_.MakeSettingsPacket(1, SETTINGS_MAX_HEADER_LIST_SIZE,
                                       kDefaultMaxUncompressedHeaderSize, true,
                                       nullptr));
  MockWrite writes[] = {
      MockWrite(ASYNC, settings_packet->data(), settings_packet->length(), 1)};
  socket_data_.reset(new SequencedSocketData(reads, arraysize(reads), writes,
                                             arraysize(writes)));
  Initialize();
  // Load a cert that is valid for:
  //   www.example.org
  //   mail.example.org
  //   www.example.com

  ProofVerifyDetailsChromium details;
  details.cert_verify_result.verified_cert =
      ImportCertFromFile(GetTestCertsDirectory(), "spdy_pooling.pem");
  ASSERT_TRUE(details.cert_verify_result.verified_cert.get());

  CompleteCryptoHandshake();
  session_->OnProofVerifyDetailsAvailable(details);

  EXPECT_TRUE(session_->CanPool("www.example.org", PRIVACY_MODE_DISABLED));
  EXPECT_FALSE(session_->CanPool("www.example.org", PRIVACY_MODE_ENABLED));
  EXPECT_TRUE(session_->CanPool("mail.example.org", PRIVACY_MODE_DISABLED));
  EXPECT_TRUE(session_->CanPool("mail.example.com", PRIVACY_MODE_DISABLED));
  EXPECT_FALSE(session_->CanPool("mail.google.com", PRIVACY_MODE_DISABLED));
}

TEST_P(QuicChromiumClientSessionTest, ConnectionPooledWithTlsChannelId) {
  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  std::unique_ptr<QuicEncryptedPacket> settings_packet(
      client_maker_.MakeSettingsPacket(1, SETTINGS_MAX_HEADER_LIST_SIZE,
                                       kDefaultMaxUncompressedHeaderSize, true,
                                       nullptr));
  MockWrite writes[] = {
      MockWrite(ASYNC, settings_packet->data(), settings_packet->length(), 1)};
  socket_data_.reset(new SequencedSocketData(reads, arraysize(reads), writes,
                                             arraysize(writes)));
  Initialize();
  // Load a cert that is valid for:
  //   www.example.org
  //   mail.example.org
  //   www.example.com

  ProofVerifyDetailsChromium details;
  details.cert_verify_result.verified_cert =
      ImportCertFromFile(GetTestCertsDirectory(), "spdy_pooling.pem");
  ASSERT_TRUE(details.cert_verify_result.verified_cert.get());

  CompleteCryptoHandshake();
  session_->OnProofVerifyDetailsAvailable(details);
  QuicChromiumClientSessionPeer::SetHostname(session_.get(), "www.example.org");
  QuicChromiumClientSessionPeer::SetChannelIDSent(session_.get(), true);

  EXPECT_TRUE(session_->CanPool("www.example.org", PRIVACY_MODE_DISABLED));
  EXPECT_TRUE(session_->CanPool("mail.example.org", PRIVACY_MODE_DISABLED));
  EXPECT_FALSE(session_->CanPool("mail.example.com", PRIVACY_MODE_DISABLED));
  EXPECT_FALSE(session_->CanPool("mail.google.com", PRIVACY_MODE_DISABLED));
}

TEST_P(QuicChromiumClientSessionTest, ConnectionNotPooledWithDifferentPin) {
  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  std::unique_ptr<QuicEncryptedPacket> settings_packet(
      client_maker_.MakeSettingsPacket(1, SETTINGS_MAX_HEADER_LIST_SIZE,
                                       kDefaultMaxUncompressedHeaderSize, true,
                                       nullptr));
  MockWrite writes[] = {
      MockWrite(ASYNC, settings_packet->data(), settings_packet->length(), 1)};
  socket_data_.reset(new SequencedSocketData(reads, arraysize(reads), writes,
                                             arraysize(writes)));
  Initialize();

  uint8_t primary_pin = 1;
  uint8_t backup_pin = 2;
  uint8_t bad_pin = 3;
  AddPin(&transport_security_state_, "mail.example.org", primary_pin,
         backup_pin);

  ProofVerifyDetailsChromium details;
  details.cert_verify_result.verified_cert =
      ImportCertFromFile(GetTestCertsDirectory(), "spdy_pooling.pem");
  details.cert_verify_result.is_issued_by_known_root = true;
  details.cert_verify_result.public_key_hashes.push_back(
      GetTestHashValue(bad_pin));

  ASSERT_TRUE(details.cert_verify_result.verified_cert.get());

  CompleteCryptoHandshake();
  session_->OnProofVerifyDetailsAvailable(details);
  QuicChromiumClientSessionPeer::SetHostname(session_.get(), "www.example.org");
  QuicChromiumClientSessionPeer::SetChannelIDSent(session_.get(), true);

  EXPECT_FALSE(session_->CanPool("mail.example.org", PRIVACY_MODE_DISABLED));
}

TEST_P(QuicChromiumClientSessionTest, ConnectionPooledWithMatchingPin) {
  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  std::unique_ptr<QuicEncryptedPacket> settings_packet(
      client_maker_.MakeSettingsPacket(1, SETTINGS_MAX_HEADER_LIST_SIZE,
                                       kDefaultMaxUncompressedHeaderSize, true,
                                       nullptr));
  MockWrite writes[] = {
      MockWrite(ASYNC, settings_packet->data(), settings_packet->length(), 1)};
  socket_data_.reset(new SequencedSocketData(reads, arraysize(reads), writes,
                                             arraysize(writes)));
  Initialize();

  uint8_t primary_pin = 1;
  uint8_t backup_pin = 2;
  AddPin(&transport_security_state_, "mail.example.org", primary_pin,
         backup_pin);

  ProofVerifyDetailsChromium details;
  details.cert_verify_result.verified_cert =
      ImportCertFromFile(GetTestCertsDirectory(), "spdy_pooling.pem");
  details.cert_verify_result.is_issued_by_known_root = true;
  details.cert_verify_result.public_key_hashes.push_back(
      GetTestHashValue(primary_pin));

  ASSERT_TRUE(details.cert_verify_result.verified_cert.get());

  CompleteCryptoHandshake();
  session_->OnProofVerifyDetailsAvailable(details);
  QuicChromiumClientSessionPeer::SetHostname(session_.get(), "www.example.org");
  QuicChromiumClientSessionPeer::SetChannelIDSent(session_.get(), true);

  EXPECT_TRUE(session_->CanPool("mail.example.org", PRIVACY_MODE_DISABLED));
}

TEST_P(QuicChromiumClientSessionTest, MigrateToSocket) {
  MockRead old_reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  std::unique_ptr<QuicEncryptedPacket> settings_packet(
      client_maker_.MakeSettingsPacket(1, SETTINGS_MAX_HEADER_LIST_SIZE,
                                       kDefaultMaxUncompressedHeaderSize, true,
                                       nullptr));
  MockWrite old_writes[] = {
      MockWrite(ASYNC, settings_packet->data(), settings_packet->length(), 1)};
  socket_data_.reset(new SequencedSocketData(
      old_reads, arraysize(old_reads), old_writes, arraysize(old_writes)));
  Initialize();
  CompleteCryptoHandshake();

  char data[] = "ABCD";
  std::unique_ptr<QuicEncryptedPacket> client_ping(
      client_maker_.MakePingPacket(2, /*include_version=*/false));
  std::unique_ptr<QuicEncryptedPacket> server_ping(
      server_maker_.MakePingPacket(1, /*include_version=*/false));
  std::unique_ptr<QuicEncryptedPacket> ack_and_data_out(
      client_maker_.MakeAckAndDataPacket(3, false, 5, 1, 1, false, 0,
                                         StringPiece(data)));
  MockRead reads[] = {
      MockRead(SYNCHRONOUS, server_ping->data(), server_ping->length(), 0),
      MockRead(SYNCHRONOUS, ERR_IO_PENDING, 1)};
  MockWrite writes[] = {
      MockWrite(SYNCHRONOUS, client_ping->data(), client_ping->length(), 2),
      MockWrite(SYNCHRONOUS, ack_and_data_out->data(),
                ack_and_data_out->length(), 3)};
  StaticSocketDataProvider socket_data(reads, arraysize(reads), writes,
                                       arraysize(writes));
  socket_factory_.AddSocketDataProvider(&socket_data);
  // Create connected socket.
  std::unique_ptr<DatagramClientSocket> new_socket =
      socket_factory_.CreateDatagramClientSocket(DatagramSocket::DEFAULT_BIND,
                                                 base::Bind(&base::RandInt),
                                                 &net_log_, NetLogSource());
  EXPECT_THAT(new_socket->Connect(kIpEndPoint), IsOk());

  // Create reader and writer.
  std::unique_ptr<QuicChromiumPacketReader> new_reader(
      new QuicChromiumPacketReader(new_socket.get(), &clock_, session_.get(),
                                   kQuicYieldAfterPacketsRead,
                                   QuicTime::Delta::FromMilliseconds(
                                       kQuicYieldAfterDurationMilliseconds),
                                   bound_test_net_log_.bound()));
  std::unique_ptr<QuicChromiumPacketWriter> new_writer(
      CreateQuicChromiumPacketWriter(new_socket.get(), session_.get()));

  // Migrate session.
  EXPECT_TRUE(session_->MigrateToSocket(
      std::move(new_socket), std::move(new_reader), std::move(new_writer)));
  // Spin message loop to complete migration.
  base::RunLoop().RunUntilIdle();

  // Write data to session.
  QuicChromiumClientStream* stream =
      session_->CreateOutgoingDynamicStream(kDefaultPriority);
  struct iovec iov[1];
  iov[0].iov_base = data;
  iov[0].iov_len = 4;
  session_->WritevData(stream, stream->id(),
                       QuicIOVector(iov, arraysize(iov), 4), 0, false, nullptr);

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
}

TEST_P(QuicChromiumClientSessionTest, MigrateToSocketMaxReaders) {
  MockRead old_reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  std::unique_ptr<QuicEncryptedPacket> settings_packet(
      client_maker_.MakeSettingsPacket(1, SETTINGS_MAX_HEADER_LIST_SIZE,
                                       kDefaultMaxUncompressedHeaderSize, true,
                                       nullptr));
  MockWrite old_writes[] = {
      MockWrite(ASYNC, settings_packet->data(), settings_packet->length(), 1)};
  socket_data_.reset(new SequencedSocketData(
      old_reads, arraysize(old_reads), old_writes, arraysize(old_writes)));
  Initialize();
  CompleteCryptoHandshake();

  for (size_t i = 0; i < kMaxReadersPerQuicSession; ++i) {
    MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 1)};
    std::unique_ptr<QuicEncryptedPacket> ping_out(
        client_maker_.MakePingPacket(i + 2, /*include_version=*/true));
    MockWrite writes[] = {
        MockWrite(SYNCHRONOUS, ping_out->data(), ping_out->length(), i + 2)};
    StaticSocketDataProvider socket_data(reads, arraysize(reads), writes,
                                         arraysize(writes));
    socket_factory_.AddSocketDataProvider(&socket_data);

    // Create connected socket.
    std::unique_ptr<DatagramClientSocket> new_socket =
        socket_factory_.CreateDatagramClientSocket(DatagramSocket::DEFAULT_BIND,
                                                   base::Bind(&base::RandInt),
                                                   &net_log_, NetLogSource());
    EXPECT_THAT(new_socket->Connect(kIpEndPoint), IsOk());

    // Create reader and writer.
    std::unique_ptr<QuicChromiumPacketReader> new_reader(
        new QuicChromiumPacketReader(new_socket.get(), &clock_, session_.get(),
                                     kQuicYieldAfterPacketsRead,
                                     QuicTime::Delta::FromMilliseconds(
                                         kQuicYieldAfterDurationMilliseconds),
                                     bound_test_net_log_.bound()));
    std::unique_ptr<QuicChromiumPacketWriter> new_writer(
        CreateQuicChromiumPacketWriter(new_socket.get(), session_.get()));

    // Migrate session.
    if (i < kMaxReadersPerQuicSession - 1) {
      EXPECT_TRUE(session_->MigrateToSocket(
          std::move(new_socket), std::move(new_reader), std::move(new_writer)));
      // Spin message loop to complete migration.
      base::RunLoop().RunUntilIdle();
      EXPECT_TRUE(socket_data.AllReadDataConsumed());
      EXPECT_TRUE(socket_data.AllWriteDataConsumed());
    } else {
      // Max readers exceeded.
      EXPECT_FALSE(session_->MigrateToSocket(
          std::move(new_socket), std::move(new_reader), std::move(new_writer)));
      EXPECT_FALSE(socket_data.AllReadDataConsumed());
      EXPECT_FALSE(socket_data.AllWriteDataConsumed());
    }
  }
}

TEST_P(QuicChromiumClientSessionTest, MigrateToSocketReadError) {
  std::unique_ptr<QuicEncryptedPacket> settings_packet(
      client_maker_.MakeSettingsPacket(1, SETTINGS_MAX_HEADER_LIST_SIZE,
                                       kDefaultMaxUncompressedHeaderSize, true,
                                       nullptr));
  std::unique_ptr<QuicEncryptedPacket> client_ping(
      client_maker_.MakePingPacket(2, /*include_version=*/false));
  std::unique_ptr<QuicEncryptedPacket> server_ping(
      server_maker_.MakePingPacket(1, /*include_version=*/false));
  MockWrite old_writes[] = {
      MockWrite(ASYNC, settings_packet->data(), settings_packet->length(), 0)};
  MockRead old_reads[] = {
      MockRead(ASYNC, ERR_IO_PENDING, 1),  // causes reading to pause.
      MockRead(ASYNC, ERR_NETWORK_CHANGED, 2)};
  socket_data_.reset(new SequencedSocketData(
      old_reads, arraysize(old_reads), old_writes, arraysize(old_writes)));
  Initialize();
  CompleteCryptoHandshake();
  MockWrite writes[] = {
      MockWrite(SYNCHRONOUS, client_ping->data(), client_ping->length(), 1)};
  MockRead new_reads[] = {
      MockRead(SYNCHRONOUS, server_ping->data(), server_ping->length(), 0),
      MockRead(ASYNC, ERR_IO_PENDING, 2),  // pause reading.
      MockRead(ASYNC, server_ping->data(), server_ping->length(), 3),
      MockRead(ASYNC, ERR_IO_PENDING, 4),  // pause reading
      MockRead(ASYNC, ERR_NETWORK_CHANGED, 5)};
  SequencedSocketData new_socket_data(new_reads, arraysize(new_reads), writes,
                                      arraysize(writes));
  socket_factory_.AddSocketDataProvider(&new_socket_data);

  // Create connected socket.
  std::unique_ptr<DatagramClientSocket> new_socket =
      socket_factory_.CreateDatagramClientSocket(DatagramSocket::DEFAULT_BIND,
                                                 base::Bind(&base::RandInt),
                                                 &net_log_, NetLogSource());
  EXPECT_THAT(new_socket->Connect(kIpEndPoint), IsOk());

  // Create reader and writer.
  std::unique_ptr<QuicChromiumPacketReader> new_reader(
      new QuicChromiumPacketReader(new_socket.get(), &clock_, session_.get(),
                                   kQuicYieldAfterPacketsRead,
                                   QuicTime::Delta::FromMilliseconds(
                                       kQuicYieldAfterDurationMilliseconds),
                                   bound_test_net_log_.bound()));
  std::unique_ptr<QuicChromiumPacketWriter> new_writer(
      CreateQuicChromiumPacketWriter(new_socket.get(), session_.get()));

  // Store old socket and migrate session.
  EXPECT_TRUE(session_->MigrateToSocket(
      std::move(new_socket), std::move(new_reader), std::move(new_writer)));
  // Spin message loop to complete migration.
  base::RunLoop().RunUntilIdle();

  // Read error on old socket does not impact session.
  EXPECT_TRUE(socket_data_->IsPaused());
  socket_data_->Resume();
  EXPECT_TRUE(session_->connection()->connected());
  EXPECT_TRUE(new_socket_data.IsPaused());
  new_socket_data.Resume();

  // Read error on new socket causes session close.
  EXPECT_TRUE(new_socket_data.IsPaused());
  EXPECT_TRUE(session_->connection()->connected());
  new_socket_data.Resume();
  EXPECT_FALSE(session_->connection()->connected());

  EXPECT_TRUE(socket_data_->AllReadDataConsumed());
  EXPECT_TRUE(socket_data_->AllWriteDataConsumed());
  EXPECT_TRUE(new_socket_data.AllReadDataConsumed());
  EXPECT_TRUE(new_socket_data.AllWriteDataConsumed());
}

}  // namespace
}  // namespace test
}  // namespace net
