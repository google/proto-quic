// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/quic/chlo_extractor.h"

#include "net/quic/core/quic_framer.h"
#include "net/quic/platform/api/quic_test.h"
#include "net/quic/test_tools/crypto_test_utils.h"
#include "net/quic/test_tools/quic_test_utils.h"

using std::string;
using testing::Return;
using testing::_;

namespace net {
namespace test {
namespace {

class TestDelegate : public ChloExtractor::Delegate {
 public:
  TestDelegate() {}
  ~TestDelegate() override {}

  // ChloExtractor::Delegate implementation
  void OnChlo(QuicVersion version,
              QuicConnectionId connection_id,
              const CryptoHandshakeMessage& chlo) override {
    version_ = version;
    connection_id_ = connection_id;
    chlo_ = chlo.DebugString(Perspective::IS_SERVER);
  }

  QuicConnectionId connection_id() const { return connection_id_; }
  QuicVersion version() const { return version_; }
  const string& chlo() const { return chlo_; }

 private:
  QuicConnectionId connection_id_;
  QuicVersion version_;
  string chlo_;
};

class ChloExtractorTest : public QuicTest {
 public:
  ChloExtractorTest() {
    header_.public_header.connection_id = 42;
    header_.public_header.connection_id_length = PACKET_8BYTE_CONNECTION_ID;
    header_.public_header.version_flag = true;
    header_.public_header.versions =
        SupportedVersions(AllSupportedVersions().front());
    header_.public_header.reset_flag = false;
    header_.public_header.packet_number_length = PACKET_6BYTE_PACKET_NUMBER;
    header_.packet_number = 1;
  }

  void MakePacket(QuicStreamFrame* stream_frame) {
    QuicFrame frame(stream_frame);
    QuicFrames frames;
    frames.push_back(frame);
    QuicFramer framer(SupportedVersions(header_.public_header.versions.front()),
                      QuicTime::Zero(), Perspective::IS_CLIENT);
    std::unique_ptr<QuicPacket> packet(
        BuildUnsizedDataPacket(&framer, header_, frames));
    EXPECT_TRUE(packet != nullptr);
    size_t encrypted_length =
        framer.EncryptPayload(ENCRYPTION_NONE, header_.packet_number, *packet,
                              buffer_, arraysize(buffer_));
    ASSERT_NE(0u, encrypted_length);
    packet_.reset(new QuicEncryptedPacket(buffer_, encrypted_length));
    EXPECT_TRUE(packet_ != nullptr);
    delete stream_frame;
  }

 protected:
  TestDelegate delegate_;
  QuicPacketHeader header_;
  std::unique_ptr<QuicEncryptedPacket> packet_;
  char buffer_[kMaxPacketSize];
};

TEST_F(ChloExtractorTest, FindsValidChlo) {
  CryptoHandshakeMessage client_hello;
  client_hello.set_tag(kCHLO);

  string client_hello_str(client_hello.GetSerialized(Perspective::IS_CLIENT)
                              .AsStringPiece()
                              .as_string());
  // Construct a CHLO with each supported version
  for (QuicVersion version : AllSupportedVersions()) {
    QuicVersionVector versions(SupportedVersions(version));
    header_.public_header.versions = versions;
    MakePacket(
        new QuicStreamFrame(kCryptoStreamId, false, 0, client_hello_str));
    EXPECT_TRUE(ChloExtractor::Extract(*packet_, versions, &delegate_))
        << QuicVersionToString(version);
    EXPECT_EQ(version, delegate_.version());
    EXPECT_EQ(GetPeerInMemoryConnectionId(header_.public_header.connection_id),
              delegate_.connection_id());
    EXPECT_EQ(client_hello.DebugString(Perspective::IS_SERVER),
              delegate_.chlo())
        << QuicVersionToString(version);
  }
}

TEST_F(ChloExtractorTest, DoesNotFindValidChloOnWrongStream) {
  CryptoHandshakeMessage client_hello;
  client_hello.set_tag(kCHLO);

  string client_hello_str(client_hello.GetSerialized(Perspective::IS_CLIENT)
                              .AsStringPiece()
                              .as_string());
  MakePacket(
      new QuicStreamFrame(kCryptoStreamId + 1, false, 0, client_hello_str));
  EXPECT_FALSE(
      ChloExtractor::Extract(*packet_, AllSupportedVersions(), &delegate_));
}

TEST_F(ChloExtractorTest, DoesNotFindValidChloOnWrongOffset) {
  CryptoHandshakeMessage client_hello;
  client_hello.set_tag(kCHLO);

  string client_hello_str(client_hello.GetSerialized(Perspective::IS_CLIENT)
                              .AsStringPiece()
                              .as_string());
  MakePacket(new QuicStreamFrame(kCryptoStreamId, false, 1, client_hello_str));
  EXPECT_FALSE(
      ChloExtractor::Extract(*packet_, AllSupportedVersions(), &delegate_));
}

TEST_F(ChloExtractorTest, DoesNotFindInvalidChlo) {
  MakePacket(new QuicStreamFrame(kCryptoStreamId, false, 0, "foo"));
  EXPECT_FALSE(
      ChloExtractor::Extract(*packet_, AllSupportedVersions(), &delegate_));
}

}  // namespace
}  // namespace test
}  // namespace net
