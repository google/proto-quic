// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_crypto_stream.h"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "base/macros.h"
#include "net/quic/crypto/crypto_handshake.h"
#include "net/quic/crypto/crypto_protocol.h"
#include "net/quic/test_tools/crypto_test_utils.h"
#include "net/quic/test_tools/quic_test_utils.h"
#include "net/quic/test_tools/reliable_quic_stream_peer.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using std::string;
using std::vector;

namespace net {
namespace test {
namespace {

class MockQuicCryptoStream : public QuicCryptoStream {
 public:
  explicit MockQuicCryptoStream(QuicSession* session)
      : QuicCryptoStream(session) {}

  void OnHandshakeMessage(const CryptoHandshakeMessage& message) override {
    messages_.push_back(message);
  }

  vector<CryptoHandshakeMessage>* messages() { return &messages_; }

 private:
  vector<CryptoHandshakeMessage> messages_;

  DISALLOW_COPY_AND_ASSIGN(MockQuicCryptoStream);
};

class QuicCryptoStreamTest : public ::testing::Test {
 public:
  QuicCryptoStreamTest()
      : connection_(new MockQuicConnection(&helper_,
                                           &alarm_factory_,
                                           Perspective::IS_CLIENT)),
        session_(connection_),
        stream_(&session_) {
    message_.set_tag(kSHLO);
    message_.SetStringPiece(1, "abc");
    message_.SetStringPiece(2, "def");
    ConstructHandshakeMessage();
  }

  void ConstructHandshakeMessage() {
    CryptoFramer framer;
    message_data_.reset(framer.ConstructHandshakeMessage(message_));
  }

 protected:
  MockQuicConnectionHelper helper_;
  MockAlarmFactory alarm_factory_;
  MockQuicConnection* connection_;
  MockQuicSpdySession session_;
  MockQuicCryptoStream stream_;
  CryptoHandshakeMessage message_;
  std::unique_ptr<QuicData> message_data_;

 private:
  DISALLOW_COPY_AND_ASSIGN(QuicCryptoStreamTest);
};

TEST_F(QuicCryptoStreamTest, NotInitiallyConected) {
  EXPECT_FALSE(stream_.encryption_established());
  EXPECT_FALSE(stream_.handshake_confirmed());
}

TEST_F(QuicCryptoStreamTest, ProcessRawData) {
  stream_.OnStreamFrame(QuicStreamFrame(kCryptoStreamId, /*fin=*/false,
                                        /*offset=*/0,
                                        message_data_->AsStringPiece()));
  ASSERT_EQ(1u, stream_.messages()->size());
  const CryptoHandshakeMessage& message = (*stream_.messages())[0];
  EXPECT_EQ(kSHLO, message.tag());
  EXPECT_EQ(2u, message.tag_value_map().size());
  EXPECT_EQ("abc", CryptoTestUtils::GetValueForTag(message, 1));
  EXPECT_EQ("def", CryptoTestUtils::GetValueForTag(message, 2));
}

TEST_F(QuicCryptoStreamTest, ProcessBadData) {
  string bad(message_data_->data(), message_data_->length());
  const int kFirstTagIndex = sizeof(uint32_t) +  // message tag
                             sizeof(uint16_t) +  // number of tag-value pairs
                             sizeof(uint16_t);   // padding
  EXPECT_EQ(1, bad[kFirstTagIndex]);
  bad[kFirstTagIndex] = 0x7F;  // out of order tag

  EXPECT_CALL(*connection_, CloseConnection(QUIC_CRYPTO_TAGS_OUT_OF_ORDER,
                                            testing::_, testing::_));
  stream_.OnStreamFrame(
      QuicStreamFrame(kCryptoStreamId, /*fin=*/false, /*offset=*/0, bad));
}

TEST_F(QuicCryptoStreamTest, NoConnectionLevelFlowControl) {
  EXPECT_FALSE(ReliableQuicStreamPeer::StreamContributesToConnectionFlowControl(
      &stream_));
}

}  // namespace
}  // namespace test
}  // namespace net
