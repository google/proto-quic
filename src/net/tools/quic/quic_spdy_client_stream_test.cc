// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/quic/quic_spdy_client_stream.h"

#include <memory>

#include "base/macros.h"
#include "base/strings/string_number_conversions.h"
#include "net/quic/quic_utils.h"
#include "net/quic/spdy_utils.h"
#include "net/quic/test_tools/crypto_test_utils.h"
#include "net/quic/test_tools/quic_test_utils.h"
#include "net/tools/quic/quic_client_session.h"
#include "net/tools/quic/spdy_balsa_utils.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using net::test::CryptoTestUtils;
using net::test::DefaultQuicConfig;
using net::test::MockConnection;
using net::test::MockConnectionHelper;
using net::test::SupportedVersions;
using net::test::kClientDataStreamId1;
using net::test::kServerDataStreamId1;
using net::test::kInitialSessionFlowControlWindowForTest;
using net::test::kInitialStreamFlowControlWindowForTest;
using net::test::ValueRestore;

using std::string;
using testing::StrictMock;
using testing::TestWithParam;

namespace net {
namespace test {

namespace {

class MockQuicClientSession : public QuicClientSession {
 public:
  explicit MockQuicClientSession(QuicConnection* connection,
                                 QuicClientPushPromiseIndex* push_promise_index)
      : QuicClientSession(
            DefaultQuicConfig(),
            connection,
            QuicServerId("example.com", 443, PRIVACY_MODE_DISABLED),
            &crypto_config_,
            push_promise_index),
        crypto_config_(CryptoTestUtils::ProofVerifierForTesting()) {}
  ~MockQuicClientSession() override {}

  MOCK_METHOD1(CloseStream, void(QuicStreamId stream_id));

 private:
  QuicCryptoClientConfig crypto_config_;

  DISALLOW_COPY_AND_ASSIGN(MockQuicClientSession);
};

class QuicSpdyClientStreamTest : public ::testing::Test {
 public:
  class StreamVisitor;

  QuicSpdyClientStreamTest()
      : connection_(new StrictMock<MockConnection>(&helper_,
                                                   &alarm_factory_,
                                                   Perspective::IS_CLIENT)),
        session_(connection_, &push_promise_index_),
        body_("hello world") {
    session_.Initialize();

    headers_.SetResponseFirstlineFromStringPieces("HTTP/1.1", "200", "Ok");
    headers_.ReplaceOrAppendHeader("content-length", "11");

    headers_string_ = net::SpdyBalsaUtils::SerializeResponseHeaders(headers_);

    stream_.reset(new QuicSpdyClientStream(kClientDataStreamId1, &session_));
    stream_visitor_.reset(new StreamVisitor());
    stream_->set_visitor(stream_visitor_.get());
  }

  class StreamVisitor : public QuicSpdyClientStream::Visitor {
    void OnClose(QuicSpdyStream* stream) override {
      DVLOG(1) << "stream " << stream->id();
    }
  };

  MockConnectionHelper helper_;
  MockAlarmFactory alarm_factory_;
  StrictMock<MockConnection>* connection_;
  QuicClientPushPromiseIndex push_promise_index_;

  MockQuicClientSession session_;
  std::unique_ptr<QuicSpdyClientStream> stream_;
  std::unique_ptr<StreamVisitor> stream_visitor_;
  BalsaHeaders headers_;
  string headers_string_;
  string body_;
};

TEST_F(QuicSpdyClientStreamTest, TestReceivingIllegalResponseStatusCode) {
  headers_.ReplaceOrAppendHeader(":status", "200 ok");
  headers_string_ = SpdyBalsaUtils::SerializeResponseHeaders(headers_);

  stream_->OnStreamHeaders(headers_string_);
  EXPECT_CALL(*connection_,
              SendRstStream(stream_->id(), QUIC_BAD_APPLICATION_PAYLOAD, 0));
  stream_->OnStreamHeadersComplete(false, headers_string_.size());
  EXPECT_EQ(QUIC_BAD_APPLICATION_PAYLOAD, stream_->stream_error());
}

TEST_F(QuicSpdyClientStreamTest, TestFraming) {
  stream_->OnStreamHeaders(headers_string_);
  stream_->OnStreamHeadersComplete(false, headers_string_.size());
  stream_->OnStreamFrame(
      QuicStreamFrame(stream_->id(), /*fin=*/false, /*offset=*/0, body_));
  EXPECT_EQ("200", stream_->response_headers().find(":status")->second);
  EXPECT_EQ(200, stream_->response_code());
  EXPECT_EQ(body_, stream_->data());
}

TEST_F(QuicSpdyClientStreamTest, TestFramingOnePacket) {
  stream_->OnStreamHeaders(headers_string_);
  stream_->OnStreamHeadersComplete(false, headers_string_.size());
  stream_->OnStreamFrame(
      QuicStreamFrame(stream_->id(), /*fin=*/false, /*offset=*/0, body_));
  EXPECT_EQ("200", stream_->response_headers().find(":status")->second);
  EXPECT_EQ(200, stream_->response_code());
  EXPECT_EQ(body_, stream_->data());
}

TEST_F(QuicSpdyClientStreamTest, DISABLED_TestFramingExtraData) {
  string large_body = "hello world!!!!!!";

  stream_->OnStreamHeaders(headers_string_);
  stream_->OnStreamHeadersComplete(false, headers_string_.size());
  // The headers should parse successfully.
  EXPECT_EQ(QUIC_STREAM_NO_ERROR, stream_->stream_error());
  EXPECT_EQ("200", stream_->response_headers().find(":status")->second);
  EXPECT_EQ(200, stream_->response_code());

  EXPECT_CALL(*connection_,
              SendRstStream(stream_->id(), QUIC_BAD_APPLICATION_PAYLOAD, 0));
  stream_->OnStreamFrame(
      QuicStreamFrame(stream_->id(), /*fin=*/false, /*offset=*/0, large_body));

  EXPECT_NE(QUIC_STREAM_NO_ERROR, stream_->stream_error());
}

TEST_F(QuicSpdyClientStreamTest, TestNoBidirectionalStreaming) {
  QuicStreamFrame frame(kClientDataStreamId1, false, 3, StringPiece("asd"));

  EXPECT_FALSE(stream_->write_side_closed());
  stream_->OnStreamFrame(frame);
  EXPECT_TRUE(stream_->write_side_closed());
}

TEST_F(QuicSpdyClientStreamTest, ReceivingTrailers) {
  // Test that receiving trailing headers, containing a final offset, results in
  // the stream being closed at that byte offset.
  // Send headers as usual.
  stream_->OnStreamHeaders(headers_string_);
  stream_->OnStreamHeadersComplete(false, headers_string_.size());

  // Send trailers before sending the body. Even though a FIN has been received
  // the stream should not be closed, as it does not yet have all the data bytes
  // promised by the final offset field.
  SpdyHeaderBlock trailers;
  trailers["trailer key"] = "trailer value";
  trailers[kFinalOffsetHeaderKey] = base::IntToString(body_.size());
  string trailers_string = SpdyUtils::SerializeUncompressedHeaders(trailers);
  stream_->OnStreamHeaders(trailers_string);
  stream_->OnStreamHeadersComplete(true, trailers_string.size());

  // Now send the body, which should close the stream as the FIN has been
  // received, as well as all data.
  EXPECT_CALL(session_, CloseStream(stream_->id()));
  stream_->OnStreamFrame(
      QuicStreamFrame(stream_->id(), /*fin=*/false, /*offset=*/0, body_));
}

}  // namespace
}  // namespace test
}  // namespace net
