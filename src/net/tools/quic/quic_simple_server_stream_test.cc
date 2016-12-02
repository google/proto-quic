// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/quic/quic_simple_server_stream.h"

#include <list>
#include <memory>
#include <utility>

#include "base/memory/ptr_util.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_piece.h"
#include "net/quic/core/quic_connection.h"
#include "net/quic/core/quic_flags.h"
#include "net/quic/core/quic_packets.h"
#include "net/quic/core/quic_utils.h"
#include "net/quic/core/spdy_utils.h"
#include "net/quic/platform/api/quic_socket_address.h"
#include "net/quic/test_tools/crypto_test_utils.h"
#include "net/quic/test_tools/quic_stream_peer.h"
#include "net/quic/test_tools/quic_test_utils.h"
#include "net/test/gtest_util.h"
#include "net/tools/epoll_server/epoll_server.h"
#include "net/tools/quic/quic_http_response_cache.h"
#include "net/tools/quic/quic_simple_server_session.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"

using base::StringPiece;
using net::test::MockQuicConnection;
using net::test::MockQuicConnectionHelper;
using net::test::MockQuicSpdySession;
using net::test::QuicStreamPeer;
using net::test::SupportedVersions;
using net::test::kInitialSessionFlowControlWindowForTest;
using net::test::kInitialStreamFlowControlWindowForTest;
using std::string;
using testing::_;
using testing::AnyNumber;
using testing::Invoke;
using testing::InvokeArgument;
using testing::InSequence;
using testing::Return;
using testing::StrictMock;
using testing::WithArgs;

namespace net {
namespace test {

size_t kFakeFrameLen = 60;

class QuicSimpleServerStreamPeer : public QuicSimpleServerStream {
 public:
  QuicSimpleServerStreamPeer(QuicStreamId stream_id,
                             QuicSpdySession* session,
                             QuicHttpResponseCache* response_cache)
      : QuicSimpleServerStream(stream_id, session, response_cache) {}

  ~QuicSimpleServerStreamPeer() override{};

  using QuicSimpleServerStream::SendResponse;
  using QuicSimpleServerStream::SendErrorResponse;

  SpdyHeaderBlock* mutable_headers() { return &request_headers_; }

  static void SendResponse(QuicSimpleServerStream* stream) {
    stream->SendResponse();
  }

  static void SendErrorResponse(QuicSimpleServerStream* stream) {
    stream->SendErrorResponse();
  }

  static const string& body(QuicSimpleServerStream* stream) {
    return stream->body_;
  }

  static int content_length(QuicSimpleServerStream* stream) {
    return stream->content_length_;
  }

  static SpdyHeaderBlock& headers(QuicSimpleServerStream* stream) {
    return stream->request_headers_;
  }
};

class MockQuicSimpleServerSession : public QuicSimpleServerSession {
 public:
  const size_t kMaxStreamsForTest = 100;

  explicit MockQuicSimpleServerSession(
      QuicConnection* connection,
      MockQuicSessionVisitor* owner,
      MockQuicCryptoServerStreamHelper* helper,
      QuicCryptoServerConfig* crypto_config,
      QuicCompressedCertsCache* compressed_certs_cache,
      QuicHttpResponseCache* response_cache)
      : QuicSimpleServerSession(DefaultQuicConfig(),
                                connection,
                                owner,
                                helper,
                                crypto_config,
                                compressed_certs_cache,
                                response_cache) {
    set_max_open_incoming_streams(kMaxStreamsForTest);
    set_max_open_outgoing_streams(kMaxStreamsForTest);
    ON_CALL(*this, WritevData(_, _, _, _, _, _))
        .WillByDefault(testing::Return(QuicConsumedData(0, false)));
  }

  ~MockQuicSimpleServerSession() override {}

  MOCK_METHOD3(OnConnectionClosed,
               void(QuicErrorCode error,
                    const string& error_details,
                    ConnectionCloseSource source));
  MOCK_METHOD1(CreateIncomingDynamicStream, QuicSpdyStream*(QuicStreamId id));
  MOCK_METHOD6(WritevData,
               QuicConsumedData(QuicStream* stream,
                                QuicStreamId id,
                                QuicIOVector data,
                                QuicStreamOffset offset,
                                bool fin,
                                QuicAckListenerInterface*));
  MOCK_METHOD4(OnStreamHeaderList,
               void(QuicStreamId stream_id,
                    bool fin,
                    size_t frame_len,
                    const QuicHeaderList& header_list));
  MOCK_METHOD2(OnStreamHeadersPriority,
               void(QuicStreamId stream_id, SpdyPriority priority));
  // Methods taking non-copyable types like SpdyHeaderBlock by value cannot be
  // mocked directly.
  size_t WriteHeaders(
      QuicStreamId id,
      SpdyHeaderBlock headers,
      bool fin,
      SpdyPriority priority,
      QuicAckListenerInterface* ack_notifier_delegate) override {
    return WriteHeadersMock(id, headers, fin, priority, ack_notifier_delegate);
  }
  MOCK_METHOD5(WriteHeadersMock,
               size_t(QuicStreamId id,
                      const SpdyHeaderBlock& headers,
                      bool fin,
                      SpdyPriority priority,
                      QuicAckListenerInterface* ack_notifier_delegate));
  MOCK_METHOD3(SendRstStream,
               void(QuicStreamId stream_id,
                    QuicRstStreamErrorCode error,
                    QuicStreamOffset bytes_written));
  MOCK_METHOD1(OnHeadersHeadOfLineBlocking, void(QuicTime::Delta delta));
  // Matchers cannot be used on non-copyable types like SpdyHeaderBlock.
  void PromisePushResources(
      const string& request_url,
      const std::list<QuicHttpResponseCache::ServerPushInfo>& resources,
      QuicStreamId original_stream_id,
      const SpdyHeaderBlock& original_request_headers) override {
    original_request_headers_ = original_request_headers.Clone();
    PromisePushResourcesMock(request_url, resources, original_stream_id,
                             original_request_headers);
  }
  MOCK_METHOD4(PromisePushResourcesMock,
               void(const string&,
                    const std::list<QuicHttpResponseCache::ServerPushInfo>&,
                    QuicStreamId,
                    const SpdyHeaderBlock&));

  using QuicSession::ActivateStream;

  SpdyHeaderBlock original_request_headers_;

 private:
  DISALLOW_COPY_AND_ASSIGN(MockQuicSimpleServerSession);
};

namespace {

class QuicSimpleServerStreamTest
    : public ::testing::TestWithParam<QuicVersion> {
 public:
  QuicSimpleServerStreamTest()
      : connection_(
            new StrictMock<MockQuicConnection>(&helper_,
                                               &alarm_factory_,
                                               Perspective::IS_SERVER,
                                               SupportedVersions(GetParam()))),
        crypto_config_(new QuicCryptoServerConfig(
            QuicCryptoServerConfig::TESTING,
            QuicRandom::GetInstance(),
            ::net::test::CryptoTestUtils::ProofSourceForTesting())),
        compressed_certs_cache_(
            QuicCompressedCertsCache::kQuicCompressedCertsCacheSize),
        session_(connection_,
                 &session_owner_,
                 &session_helper_,
                 crypto_config_.get(),
                 &compressed_certs_cache_,
                 &response_cache_),
        body_("hello world") {
    header_list_.OnHeaderBlockStart();
    header_list_.OnHeader(":authority", "www.google.com");
    header_list_.OnHeader(":path", "/");
    header_list_.OnHeader(":method", "POST");
    header_list_.OnHeader(":version", "HTTP/1.1");
    header_list_.OnHeader("content-length", "11");
    header_list_.OnHeaderBlockEnd(128);

    // New streams rely on having the peer's flow control receive window
    // negotiated in the config.
    session_.config()->SetInitialStreamFlowControlWindowToSend(
        kInitialStreamFlowControlWindowForTest);
    session_.config()->SetInitialSessionFlowControlWindowToSend(
        kInitialSessionFlowControlWindowForTest);
    stream_ = new QuicSimpleServerStreamPeer(::net::test::kClientDataStreamId1,
                                             &session_, &response_cache_);
    // Register stream_ in dynamic_stream_map_ and pass ownership to session_.
    session_.ActivateStream(base::WrapUnique(stream_));
  }

  const string& StreamBody() {
    return QuicSimpleServerStreamPeer::body(stream_);
  }

  string StreamHeadersValue(const string& key) {
    return (*stream_->mutable_headers())[key].as_string();
  }

  SpdyHeaderBlock response_headers_;
  MockQuicConnectionHelper helper_;
  MockAlarmFactory alarm_factory_;
  StrictMock<MockQuicConnection>* connection_;
  StrictMock<MockQuicSessionVisitor> session_owner_;
  StrictMock<MockQuicCryptoServerStreamHelper> session_helper_;
  std::unique_ptr<QuicCryptoServerConfig> crypto_config_;
  QuicCompressedCertsCache compressed_certs_cache_;
  QuicHttpResponseCache response_cache_;
  StrictMock<MockQuicSimpleServerSession> session_;
  QuicSimpleServerStreamPeer* stream_;  // Owned by session_.
  string headers_string_;
  string body_;
  QuicHeaderList header_list_;
};

INSTANTIATE_TEST_CASE_P(Tests,
                        QuicSimpleServerStreamTest,
                        ::testing::ValuesIn(AllSupportedVersions()));

TEST_P(QuicSimpleServerStreamTest, TestFraming) {
  EXPECT_CALL(session_, WritevData(_, _, _, _, _, _))
      .Times(AnyNumber())
      .WillRepeatedly(Invoke(MockQuicSession::ConsumeAllData));
  stream_->OnStreamHeaderList(false, kFakeFrameLen, header_list_);
  stream_->OnStreamFrame(
      QuicStreamFrame(stream_->id(), /*fin=*/false, /*offset=*/0, body_));
  EXPECT_EQ("11", StreamHeadersValue("content-length"));
  EXPECT_EQ("/", StreamHeadersValue(":path"));
  EXPECT_EQ("POST", StreamHeadersValue(":method"));
  EXPECT_EQ(body_, StreamBody());
}

TEST_P(QuicSimpleServerStreamTest, TestFramingOnePacket) {
  EXPECT_CALL(session_, WritevData(_, _, _, _, _, _))
      .Times(AnyNumber())
      .WillRepeatedly(Invoke(MockQuicSession::ConsumeAllData));

  stream_->OnStreamHeaderList(false, kFakeFrameLen, header_list_);
  stream_->OnStreamFrame(
      QuicStreamFrame(stream_->id(), /*fin=*/false, /*offset=*/0, body_));
  EXPECT_EQ("11", StreamHeadersValue("content-length"));
  EXPECT_EQ("/", StreamHeadersValue(":path"));
  EXPECT_EQ("POST", StreamHeadersValue(":method"));
  EXPECT_EQ(body_, StreamBody());
}

TEST_P(QuicSimpleServerStreamTest, SendQuicRstStreamNoErrorInStopReading) {
  EXPECT_CALL(session_, WritevData(_, _, _, _, _, _))
      .Times(AnyNumber())
      .WillRepeatedly(Invoke(MockQuicSession::ConsumeAllData));

  EXPECT_FALSE(stream_->fin_received());
  EXPECT_FALSE(stream_->rst_received());

  stream_->set_fin_sent(true);
  stream_->CloseWriteSide();

  EXPECT_CALL(session_, SendRstStream(_, QUIC_STREAM_NO_ERROR, _)).Times(1);
  stream_->StopReading();
}

TEST_P(QuicSimpleServerStreamTest, TestFramingExtraData) {
  string large_body = "hello world!!!!!!";

  // We'll automatically write out an error (headers + body)
  EXPECT_CALL(session_, WriteHeadersMock(_, _, _, _, _));
  EXPECT_CALL(session_, WritevData(_, _, _, _, _, _))
      .WillOnce(Invoke(MockQuicSession::ConsumeAllData));
  EXPECT_CALL(session_, SendRstStream(_, QUIC_STREAM_NO_ERROR, _)).Times(0);

  stream_->OnStreamHeaderList(false, kFakeFrameLen, header_list_);
  stream_->OnStreamFrame(
      QuicStreamFrame(stream_->id(), /*fin=*/false, /*offset=*/0, body_));
  // Content length is still 11.  This will register as an error and we won't
  // accept the bytes.
  stream_->OnStreamFrame(
      QuicStreamFrame(stream_->id(), /*fin=*/true, body_.size(), large_body));
  EXPECT_EQ("11", StreamHeadersValue("content-length"));
  EXPECT_EQ("/", StreamHeadersValue(":path"));
  EXPECT_EQ("POST", StreamHeadersValue(":method"));
}

TEST_P(QuicSimpleServerStreamTest, SendResponseWithIllegalResponseStatus) {
  // Send an illegal response with response status not supported by HTTP/2.
  SpdyHeaderBlock* request_headers = stream_->mutable_headers();
  (*request_headers)[":path"] = "/bar";
  (*request_headers)[":authority"] = "www.google.com";
  (*request_headers)[":version"] = "HTTP/1.1";
  (*request_headers)[":method"] = "GET";

  response_headers_[":version"] = "HTTP/1.1";
  // HTTP/2 only supports integer responsecode, so "200 OK" is illegal.
  response_headers_[":status"] = "200 OK";
  response_headers_["content-length"] = "5";
  string body = "Yummm";
  response_cache_.AddResponse("www.google.com", "/bar",
                              std::move(response_headers_), body);

  stream_->set_fin_received(true);

  InSequence s;
  EXPECT_CALL(session_, WriteHeadersMock(stream_->id(), _, false, _, nullptr));
  EXPECT_CALL(session_, WritevData(_, _, _, _, _, _))
      .Times(1)
      .WillOnce(Return(QuicConsumedData(
          strlen(QuicSimpleServerStream::kErrorResponseBody), true)));

  QuicSimpleServerStreamPeer::SendResponse(stream_);
  EXPECT_FALSE(QuicStreamPeer::read_side_closed(stream_));
  EXPECT_TRUE(stream_->reading_stopped());
  EXPECT_TRUE(stream_->write_side_closed());
}

TEST_P(QuicSimpleServerStreamTest, SendResponseWithIllegalResponseStatus2) {
  // Send an illegal response with response status not supported by HTTP/2.
  SpdyHeaderBlock* request_headers = stream_->mutable_headers();
  (*request_headers)[":path"] = "/bar";
  (*request_headers)[":authority"] = "www.google.com";
  (*request_headers)[":version"] = "HTTP/1.1";
  (*request_headers)[":method"] = "GET";

  response_headers_[":version"] = "HTTP/1.1";
  // HTTP/2 only supports 3-digit-integer, so "+200" is illegal.
  response_headers_[":status"] = "+200";
  response_headers_["content-length"] = "5";
  string body = "Yummm";
  response_cache_.AddResponse("www.google.com", "/bar",
                              std::move(response_headers_), body);

  stream_->set_fin_received(true);

  InSequence s;
  EXPECT_CALL(session_, WriteHeadersMock(stream_->id(), _, false, _, nullptr));
  EXPECT_CALL(session_, WritevData(_, _, _, _, _, _))
      .Times(1)
      .WillOnce(Return(QuicConsumedData(
          strlen(QuicSimpleServerStream::kErrorResponseBody), true)));

  QuicSimpleServerStreamPeer::SendResponse(stream_);
  EXPECT_FALSE(QuicStreamPeer::read_side_closed(stream_));
  EXPECT_TRUE(stream_->reading_stopped());
  EXPECT_TRUE(stream_->write_side_closed());
}

TEST_P(QuicSimpleServerStreamTest, SendPushResponseWith404Response) {
  // Create a new promised stream with even id().
  QuicSimpleServerStreamPeer* promised_stream =
      new QuicSimpleServerStreamPeer(2, &session_, &response_cache_);
  session_.ActivateStream(base::WrapUnique(promised_stream));

  // Send a push response with response status 404, which will be regarded as
  // invalid server push response.
  SpdyHeaderBlock* request_headers = promised_stream->mutable_headers();
  (*request_headers)[":path"] = "/bar";
  (*request_headers)[":authority"] = "www.google.com";
  (*request_headers)[":version"] = "HTTP/1.1";
  (*request_headers)[":method"] = "GET";

  response_headers_[":version"] = "HTTP/1.1";
  response_headers_[":status"] = "404";
  response_headers_["content-length"] = "8";
  string body = "NotFound";
  response_cache_.AddResponse("www.google.com", "/bar",
                              std::move(response_headers_), body);

  InSequence s;
  EXPECT_CALL(session_,
              SendRstStream(promised_stream->id(), QUIC_STREAM_CANCELLED, 0));

  QuicSimpleServerStreamPeer::SendResponse(promised_stream);
}

TEST_P(QuicSimpleServerStreamTest, SendResponseWithValidHeaders) {
  // Add a request and response with valid headers.
  SpdyHeaderBlock* request_headers = stream_->mutable_headers();
  (*request_headers)[":path"] = "/bar";
  (*request_headers)[":authority"] = "www.google.com";
  (*request_headers)[":version"] = "HTTP/1.1";
  (*request_headers)[":method"] = "GET";

  response_headers_[":version"] = "HTTP/1.1";
  response_headers_[":status"] = "200";
  response_headers_["content-length"] = "5";
  string body = "Yummm";
  response_cache_.AddResponse("www.google.com", "/bar",
                              std::move(response_headers_), body);
  stream_->set_fin_received(true);

  InSequence s;
  EXPECT_CALL(session_, WriteHeadersMock(stream_->id(), _, false, _, nullptr));
  EXPECT_CALL(session_, WritevData(_, _, _, _, _, _))
      .Times(1)
      .WillOnce(Return(QuicConsumedData(body.length(), true)));

  QuicSimpleServerStreamPeer::SendResponse(stream_);
  EXPECT_FALSE(QuicStreamPeer::read_side_closed(stream_));
  EXPECT_TRUE(stream_->reading_stopped());
  EXPECT_TRUE(stream_->write_side_closed());
}

TEST_P(QuicSimpleServerStreamTest, SendReponseWithPushResources) {
  // Tests that if a reponse has push resources to be send, SendResponse() will
  // call PromisePushResources() to handle these resources.

  // Add a request and response with valid headers into cache.
  string host = "www.google.com";
  string request_path = "/foo";
  string body = "Yummm";
  string url = host + "/bar";
  QuicHttpResponseCache::ServerPushInfo push_info(
      GURL(url), SpdyHeaderBlock(), kDefaultPriority, "Push body");
  std::list<QuicHttpResponseCache::ServerPushInfo> push_resources;
  push_resources.push_back(push_info);
  response_cache_.AddSimpleResponseWithServerPushResources(
      host, request_path, 200, body, push_resources);

  SpdyHeaderBlock* request_headers = stream_->mutable_headers();
  (*request_headers)[":path"] = request_path;
  (*request_headers)[":authority"] = host;
  (*request_headers)[":version"] = "HTTP/1.1";
  (*request_headers)[":method"] = "GET";

  stream_->set_fin_received(true);
  InSequence s;
  EXPECT_CALL(session_,
              PromisePushResourcesMock(host + request_path, _,
                                       ::net::test::kClientDataStreamId1, _));
  EXPECT_CALL(session_, WriteHeadersMock(stream_->id(), _, false, _, nullptr));
  EXPECT_CALL(session_, WritevData(_, _, _, _, _, _))
      .Times(1)
      .WillOnce(Return(QuicConsumedData(body.length(), true)));
  QuicSimpleServerStreamPeer::SendResponse(stream_);
  EXPECT_EQ(*request_headers, session_.original_request_headers_);
}

TEST_P(QuicSimpleServerStreamTest, PushResponseOnClientInitiatedStream) {
  // Calling PushResponse() on a client initialted stream is never supposed to
  // happen.
  EXPECT_QUIC_BUG(stream_->PushResponse(SpdyHeaderBlock()),
                  "Client initiated stream"
                  " shouldn't be used as promised stream.");
}

TEST_P(QuicSimpleServerStreamTest, PushResponseOnServerInitiatedStream) {
  // Tests that PushResponse() should take the given headers as request headers
  // and fetch response from cache, and send it out.

  // Create a stream with even stream id and test against this stream.
  const QuicStreamId kServerInitiatedStreamId = 2;
  // Create a server initiated stream and pass it to session_.
  QuicSimpleServerStreamPeer* server_initiated_stream =
      new QuicSimpleServerStreamPeer(kServerInitiatedStreamId, &session_,
                                     &response_cache_);
  session_.ActivateStream(base::WrapUnique(server_initiated_stream));

  const string kHost = "www.foo.com";
  const string kPath = "/bar";
  SpdyHeaderBlock headers;
  headers[":path"] = kPath;
  headers[":authority"] = kHost;
  headers[":version"] = "HTTP/1.1";
  headers[":method"] = "GET";

  response_headers_[":version"] = "HTTP/1.1";
  response_headers_[":status"] = "200";
  response_headers_["content-length"] = "5";
  const string kBody = "Hello";
  response_cache_.AddResponse(kHost, kPath, std::move(response_headers_),
                              kBody);

  // Call PushResponse() should trigger stream to fetch response from cache
  // and send it back.
  EXPECT_CALL(session_,
              WriteHeadersMock(kServerInitiatedStreamId, _, false,
                               server_initiated_stream->priority(), nullptr));
  EXPECT_CALL(session_, WritevData(_, kServerInitiatedStreamId, _, _, _, _))
      .Times(1)
      .WillOnce(Return(QuicConsumedData(kBody.size(), true)));
  server_initiated_stream->PushResponse(std::move(headers));
  EXPECT_EQ(kPath, QuicSimpleServerStreamPeer::headers(
                       server_initiated_stream)[":path"]
                       .as_string());
  EXPECT_EQ("GET", QuicSimpleServerStreamPeer::headers(
                       server_initiated_stream)[":method"]
                       .as_string());
}

TEST_P(QuicSimpleServerStreamTest, TestSendErrorResponse) {
  EXPECT_CALL(session_, SendRstStream(_, QUIC_STREAM_NO_ERROR, _)).Times(0);

  stream_->set_fin_received(true);

  InSequence s;
  EXPECT_CALL(session_, WriteHeadersMock(_, _, _, _, _));
  EXPECT_CALL(session_, WritevData(_, _, _, _, _, _))
      .Times(1)
      .WillOnce(Return(QuicConsumedData(3, true)));

  QuicSimpleServerStreamPeer::SendErrorResponse(stream_);
  EXPECT_FALSE(QuicStreamPeer::read_side_closed(stream_));
  EXPECT_TRUE(stream_->reading_stopped());
  EXPECT_TRUE(stream_->write_side_closed());
}

TEST_P(QuicSimpleServerStreamTest, InvalidMultipleContentLength) {
  EXPECT_CALL(session_, SendRstStream(_, QUIC_STREAM_NO_ERROR, _)).Times(0);

  SpdyHeaderBlock request_headers;
  // \000 is a way to write the null byte when followed by a literal digit.
  header_list_.OnHeader("content-length", StringPiece("11\00012", 5));

  headers_string_ = SpdyUtils::SerializeUncompressedHeaders(request_headers);

  EXPECT_CALL(session_, WriteHeadersMock(_, _, _, _, _));
  EXPECT_CALL(session_, WritevData(_, _, _, _, _, _))
      .Times(AnyNumber())
      .WillRepeatedly(Invoke(MockQuicSession::ConsumeAllData));
  stream_->OnStreamHeaderList(true, kFakeFrameLen, header_list_);

  EXPECT_TRUE(QuicStreamPeer::read_side_closed(stream_));
  EXPECT_TRUE(stream_->reading_stopped());
  EXPECT_TRUE(stream_->write_side_closed());
}

TEST_P(QuicSimpleServerStreamTest, InvalidLeadingNullContentLength) {
  EXPECT_CALL(session_, SendRstStream(_, QUIC_STREAM_NO_ERROR, _)).Times(0);

  SpdyHeaderBlock request_headers;
  // \000 is a way to write the null byte when followed by a literal digit.
  header_list_.OnHeader("content-length", StringPiece("\00012", 3));

  headers_string_ = SpdyUtils::SerializeUncompressedHeaders(request_headers);

  EXPECT_CALL(session_, WriteHeadersMock(_, _, _, _, _));
  EXPECT_CALL(session_, WritevData(_, _, _, _, _, _))
      .Times(AnyNumber())
      .WillRepeatedly(Invoke(MockQuicSession::ConsumeAllData));
  stream_->OnStreamHeaderList(true, kFakeFrameLen, header_list_);

  EXPECT_TRUE(QuicStreamPeer::read_side_closed(stream_));
  EXPECT_TRUE(stream_->reading_stopped());
  EXPECT_TRUE(stream_->write_side_closed());
}

TEST_P(QuicSimpleServerStreamTest, ValidMultipleContentLength) {
  SpdyHeaderBlock request_headers;
  // \000 is a way to write the null byte when followed by a literal digit.
  header_list_.OnHeader("content-length", StringPiece("11\00011", 5));

  headers_string_ = SpdyUtils::SerializeUncompressedHeaders(request_headers);

  stream_->OnStreamHeaderList(false, kFakeFrameLen, header_list_);

  EXPECT_EQ(11, QuicSimpleServerStreamPeer::content_length(stream_));
  EXPECT_FALSE(QuicStreamPeer::read_side_closed(stream_));
  EXPECT_FALSE(stream_->reading_stopped());
  EXPECT_FALSE(stream_->write_side_closed());
}

TEST_P(QuicSimpleServerStreamTest, SendQuicRstStreamNoErrorWithEarlyResponse) {
  InSequence s;
  EXPECT_CALL(session_, WriteHeadersMock(stream_->id(), _, false, _, nullptr));
  EXPECT_CALL(session_, WritevData(_, _, _, _, _, _))
      .Times(1)
      .WillOnce(Return(QuicConsumedData(3, true)));
  EXPECT_CALL(session_, SendRstStream(_, QUIC_STREAM_NO_ERROR, _)).Times(1);
  EXPECT_FALSE(stream_->fin_received());
  QuicSimpleServerStreamPeer::SendErrorResponse(stream_);
  EXPECT_TRUE(stream_->reading_stopped());
  EXPECT_TRUE(stream_->write_side_closed());
}

TEST_P(QuicSimpleServerStreamTest,
       DoNotSendQuicRstStreamNoErrorWithRstReceived) {
  InSequence s;
  EXPECT_FALSE(stream_->reading_stopped());

  EXPECT_CALL(session_, SendRstStream(_, QUIC_STREAM_NO_ERROR, _)).Times(0);
  EXPECT_CALL(session_, SendRstStream(_, QUIC_RST_ACKNOWLEDGEMENT, _)).Times(1);
  QuicRstStreamFrame rst_frame(stream_->id(), QUIC_STREAM_CANCELLED, 1234);
  stream_->OnStreamReset(rst_frame);

  EXPECT_TRUE(stream_->reading_stopped());
  EXPECT_TRUE(stream_->write_side_closed());
}

TEST_P(QuicSimpleServerStreamTest, InvalidHeadersWithFin) {
  char arr[] = {
      0x3a,   0x68, 0x6f, 0x73,  // :hos
      0x74,   0x00, 0x00, 0x00,  // t...
      0x00,   0x00, 0x00, 0x00,  // ....
      0x07,   0x3a, 0x6d, 0x65,  // .:me
      0x74,   0x68, 0x6f, 0x64,  // thod
      0x00,   0x00, 0x00, 0x03,  // ....
      0x47,   0x45, 0x54, 0x00,  // GET.
      0x00,   0x00, 0x05, 0x3a,  // ...:
      0x70,   0x61, 0x74, 0x68,  // path
      0x00,   0x00, 0x00, 0x04,  // ....
      0x2f,   0x66, 0x6f, 0x6f,  // /foo
      0x00,   0x00, 0x00, 0x07,  // ....
      0x3a,   0x73, 0x63, 0x68,  // :sch
      0x65,   0x6d, 0x65, 0x00,  // eme.
      0x00,   0x00, 0x00, 0x00,  // ....
      0x00,   0x00, 0x08, 0x3a,  // ...:
      0x76,   0x65, 0x72, 0x73,  // vers
      '\x96', 0x6f, 0x6e, 0x00,  // <i(69)>on.
      0x00,   0x00, 0x08, 0x48,  // ...H
      0x54,   0x54, 0x50, 0x2f,  // TTP/
      0x31,   0x2e, 0x31,        // 1.1
  };
  StringPiece data(arr, arraysize(arr));
  QuicStreamFrame frame(stream_->id(), true, 0, data);
  // Verify that we don't crash when we get a invalid headers in stream frame.
  stream_->OnStreamFrame(frame);
}

}  // namespace
}  // namespace test
}  // namespace net
