// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/quic_client_push_promise_index.h"

#include <string>

#include "net/quic/core/spdy_utils.h"
#include "net/quic/test_tools/crypto_test_utils.h"
#include "net/quic/test_tools/mock_quic_client_promised_info.h"
#include "net/quic/test_tools/quic_test_utils.h"
#include "net/tools/quic/quic_client_session.h"

using testing::_;
using testing::Return;
using testing::StrictMock;
using std::string;

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
        crypto_config_(crypto_test_utils::ProofVerifierForTesting()) {}
  ~MockQuicClientSession() override {}

  MOCK_METHOD1(CloseStream, void(QuicStreamId stream_id));

 private:
  QuicCryptoClientConfig crypto_config_;

  DISALLOW_COPY_AND_ASSIGN(MockQuicClientSession);
};

class QuicClientPushPromiseIndexTest : public ::testing::Test {
 public:
  QuicClientPushPromiseIndexTest()
      : connection_(new StrictMock<MockQuicConnection>(&helper_,
                                                       &alarm_factory_,
                                                       Perspective::IS_CLIENT)),
        session_(connection_, &index_),
        promised_(&session_, kServerDataStreamId1, url_) {
    request_[":path"] = "/bar";
    request_[":authority"] = "www.google.com";
    request_[":version"] = "HTTP/1.1";
    request_[":method"] = "GET";
    request_[":scheme"] = "https";
    url_ = SpdyUtils::GetUrlFromHeaderBlock(request_);
  }

  MockQuicConnectionHelper helper_;
  MockAlarmFactory alarm_factory_;
  StrictMock<MockQuicConnection>* connection_;
  MockQuicClientSession session_;
  QuicClientPushPromiseIndex index_;
  SpdyHeaderBlock request_;
  string url_;
  MockQuicClientPromisedInfo promised_;
  QuicClientPushPromiseIndex::TryHandle* handle_;
};

TEST_F(QuicClientPushPromiseIndexTest, TryRequestSuccess) {
  (*index_.promised_by_url())[url_] = &promised_;
  EXPECT_CALL(promised_, HandleClientRequest(_, _))
      .WillOnce(Return(QUIC_SUCCESS));
  EXPECT_EQ(index_.Try(request_, nullptr, &handle_), QUIC_SUCCESS);
}

TEST_F(QuicClientPushPromiseIndexTest, TryRequestPending) {
  (*index_.promised_by_url())[url_] = &promised_;
  EXPECT_CALL(promised_, HandleClientRequest(_, _))
      .WillOnce(Return(QUIC_PENDING));
  EXPECT_EQ(index_.Try(request_, nullptr, &handle_), QUIC_PENDING);
}

TEST_F(QuicClientPushPromiseIndexTest, TryRequestFailure) {
  (*index_.promised_by_url())[url_] = &promised_;
  EXPECT_CALL(promised_, HandleClientRequest(_, _))
      .WillOnce(Return(QUIC_FAILURE));
  EXPECT_EQ(index_.Try(request_, nullptr, &handle_), QUIC_FAILURE);
}

TEST_F(QuicClientPushPromiseIndexTest, TryNoPromise) {
  EXPECT_EQ(index_.Try(request_, nullptr, &handle_), QUIC_FAILURE);
}

TEST_F(QuicClientPushPromiseIndexTest, GetNoPromise) {
  EXPECT_EQ(index_.GetPromised(url_), nullptr);
}

TEST_F(QuicClientPushPromiseIndexTest, GetPromise) {
  (*index_.promised_by_url())[url_] = &promised_;
  EXPECT_EQ(index_.GetPromised(url_), &promised_);
}

}  // namespace
}  // namespace test
}  // namespace net
