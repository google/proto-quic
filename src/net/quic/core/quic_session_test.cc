// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/quic_session.h"

#include <set>
#include <utility>

#include "base/memory/ptr_util.h"
#include "base/rand_util.h"
#include "base/stl_util.h"
#include "base/strings/string_number_conversions.h"
#include "build/build_config.h"
#include "net/quic/core/crypto/crypto_protocol.h"
#include "net/quic/core/crypto/null_encrypter.h"
#include "net/quic/core/quic_crypto_stream.h"
#include "net/quic/core/quic_flags.h"
#include "net/quic/core/quic_packets.h"
#include "net/quic/core/quic_stream.h"
#include "net/quic/core/quic_utils.h"
#include "net/quic/test_tools/quic_config_peer.h"
#include "net/quic/test_tools/quic_connection_peer.h"
#include "net/quic/test_tools/quic_flow_controller_peer.h"
#include "net/quic/test_tools/quic_headers_stream_peer.h"
#include "net/quic/test_tools/quic_session_peer.h"
#include "net/quic/test_tools/quic_spdy_session_peer.h"
#include "net/quic/test_tools/quic_spdy_stream_peer.h"
#include "net/quic/test_tools/quic_stream_peer.h"
#include "net/quic/test_tools/quic_test_utils.h"
#include "net/spdy/spdy_framer.h"
#include "net/test/gtest_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gmock_mutant.h"
#include "testing/gtest/include/gtest/gtest.h"

using net::SpdyHeaderBlock;
using net::SpdyPriority;
using std::string;
using testing::CreateFunctor;
using testing::AtLeast;
using testing::InSequence;
using testing::Invoke;
using testing::Return;
using testing::StrictMock;
using testing::_;

namespace net {
namespace test {
namespace {

const SpdyPriority kHighestPriority = kV3HighestPriority;

class TestCryptoStream : public QuicCryptoStream {
 public:
  explicit TestCryptoStream(QuicSession* session) : QuicCryptoStream(session) {}

  void OnHandshakeMessage(const CryptoHandshakeMessage& /*message*/) override {
    encryption_established_ = true;
    handshake_confirmed_ = true;
    CryptoHandshakeMessage msg;
    string error_details;
    session()->config()->SetInitialStreamFlowControlWindowToSend(
        kInitialStreamFlowControlWindowForTest);
    session()->config()->SetInitialSessionFlowControlWindowToSend(
        kInitialSessionFlowControlWindowForTest);
    session()->config()->ToHandshakeMessage(&msg);
    const QuicErrorCode error =
        session()->config()->ProcessPeerHello(msg, CLIENT, &error_details);
    EXPECT_EQ(QUIC_NO_ERROR, error);
    session()->OnConfigNegotiated();
    session()->OnCryptoHandshakeEvent(QuicSession::HANDSHAKE_CONFIRMED);
  }

  MOCK_METHOD0(OnCanWrite, void());
};

class TestHeadersStream : public QuicHeadersStream {
 public:
  explicit TestHeadersStream(QuicSpdySession* session)
      : QuicHeadersStream(session) {}

  MOCK_METHOD0(OnCanWrite, void());
};

class TestStream : public QuicSpdyStream {
 public:
  TestStream(QuicStreamId id, QuicSpdySession* session)
      : QuicSpdyStream(id, session) {}

  using QuicStream::CloseWriteSide;

  void OnDataAvailable() override {}

  MOCK_METHOD0(OnCanWrite, void());
};

// Poor man's functor for use as callback in a mock.
class StreamBlocker {
 public:
  StreamBlocker(QuicSession* session, QuicStreamId stream_id)
      : session_(session), stream_id_(stream_id) {}

  void MarkConnectionLevelWriteBlocked() {
    session_->MarkConnectionLevelWriteBlocked(stream_id_);
  }

 private:
  QuicSession* const session_;
  const QuicStreamId stream_id_;
};

class TestSession : public QuicSpdySession {
 public:
  explicit TestSession(QuicConnection* connection)
      : QuicSpdySession(connection, nullptr, DefaultQuicConfig()),
        crypto_stream_(this),
        writev_consumes_all_data_(false) {
    Initialize();
    this->connection()->SetEncrypter(ENCRYPTION_FORWARD_SECURE,
                                     new NullEncrypter());
  }

  ~TestSession() override { delete connection(); }

  TestCryptoStream* GetCryptoStream() override { return &crypto_stream_; }

  TestStream* CreateOutgoingDynamicStream(SpdyPriority priority) override {
    TestStream* stream = new TestStream(GetNextOutgoingStreamId(), this);
    stream->SetPriority(priority);
    ActivateStream(base::WrapUnique(stream));
    return stream;
  }

  TestStream* CreateIncomingDynamicStream(QuicStreamId id) override {
    // Enforce the limit on the number of open streams.
    if (GetNumOpenIncomingStreams() + 1 > max_open_incoming_streams()) {
      connection()->CloseConnection(
          QUIC_TOO_MANY_OPEN_STREAMS, "Too many streams!",
          ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
      return nullptr;
    } else {
      TestStream* stream = new TestStream(id, this);
      ActivateStream(base::WrapUnique(stream));
      return stream;
    }
  }

  bool ShouldCreateIncomingDynamicStream(QuicStreamId /*id*/) override {
    return true;
  }

  bool ShouldCreateOutgoingDynamicStream() override { return true; }

  bool IsClosedStream(QuicStreamId id) {
    return QuicSession::IsClosedStream(id);
  }

  QuicStream* GetOrCreateDynamicStream(QuicStreamId stream_id) {
    return QuicSpdySession::GetOrCreateDynamicStream(stream_id);
  }

  QuicConsumedData WritevData(
      QuicStream* stream,
      QuicStreamId id,
      QuicIOVector data,
      QuicStreamOffset offset,
      bool fin,
      QuicAckListenerInterface* ack_notifier_delegate) override {
    QuicConsumedData consumed(data.total_length, fin);
    if (!writev_consumes_all_data_) {
      consumed = QuicSession::WritevData(stream, id, data, offset, fin,
                                         ack_notifier_delegate);
    }
    stream->set_stream_bytes_written(stream->stream_bytes_written() +
                                     consumed.bytes_consumed);
    if (fin && consumed.fin_consumed) {
      stream->set_fin_sent(true);
    }
    QuicSessionPeer::GetWriteBlockedStreams(this)->UpdateBytesForStream(
        id, consumed.bytes_consumed);
    return consumed;
  }

  void set_writev_consumes_all_data(bool val) {
    writev_consumes_all_data_ = val;
  }

  QuicConsumedData SendStreamData(QuicStream* stream) {
    struct iovec iov;
    if (stream->id() != kCryptoStreamId) {
      this->connection()->SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
    }
    QuicConsumedData consumed =
        WritevData(stream, stream->id(), MakeIOVector("not empty", &iov), 0,
                   true, nullptr);
    return consumed;
  }

  QuicConsumedData SendLargeFakeData(QuicStream* stream, int bytes) {
    DCHECK(writev_consumes_all_data_);
    struct iovec iov;
    iov.iov_base = nullptr;  // should not be read.
    iov.iov_len = static_cast<size_t>(bytes);
    return WritevData(stream, stream->id(), QuicIOVector(&iov, 1, bytes), 0,
                      true, nullptr);
  }

  using QuicSession::PostProcessAfterData;

 private:
  StrictMock<TestCryptoStream> crypto_stream_;

  bool writev_consumes_all_data_;
};

class QuicSessionTestBase : public ::testing::TestWithParam<QuicVersion> {
 protected:
  explicit QuicSessionTestBase(Perspective perspective)
      : connection_(
            new StrictMock<MockQuicConnection>(&helper_,
                                               &alarm_factory_,
                                               perspective,
                                               SupportedVersions(GetParam()))),
        session_(connection_) {
    session_.config()->SetInitialStreamFlowControlWindowToSend(
        kInitialStreamFlowControlWindowForTest);
    session_.config()->SetInitialSessionFlowControlWindowToSend(
        kInitialSessionFlowControlWindowForTest);
    headers_[":host"] = "www.google.com";
    headers_[":path"] = "/index.hml";
    headers_[":scheme"] = "http";
    headers_["cookie"] =
        "__utma=208381060.1228362404.1372200928.1372200928.1372200928.1; "
        "__utmc=160408618; "
        "GX=DQAAAOEAAACWJYdewdE9rIrW6qw3PtVi2-d729qaa-74KqOsM1NVQblK4VhX"
        "hoALMsy6HOdDad2Sz0flUByv7etmo3mLMidGrBoljqO9hSVA40SLqpG_iuKKSHX"
        "RW3Np4bq0F0SDGDNsW0DSmTS9ufMRrlpARJDS7qAI6M3bghqJp4eABKZiRqebHT"
        "pMU-RXvTI5D5oCF1vYxYofH_l1Kviuiy3oQ1kS1enqWgbhJ2t61_SNdv-1XJIS0"
        "O3YeHLmVCs62O6zp89QwakfAWK9d3IDQvVSJzCQsvxvNIvaZFa567MawWlXg0Rh"
        "1zFMi5vzcns38-8_Sns; "
        "GA=v*2%2Fmem*57968640*47239936%2Fmem*57968640*47114716%2Fno-nm-"
        "yj*15%2Fno-cc-yj*5%2Fpc-ch*133685%2Fpc-s-cr*133947%2Fpc-s-t*1339"
        "47%2Fno-nm-yj*4%2Fno-cc-yj*1%2Fceft-as*1%2Fceft-nqas*0%2Fad-ra-c"
        "v_p%2Fad-nr-cv_p-f*1%2Fad-v-cv_p*859%2Fad-ns-cv_p-f*1%2Ffn-v-ad%"
        "2Fpc-t*250%2Fpc-cm*461%2Fpc-s-cr*722%2Fpc-s-t*722%2Fau_p*4"
        "SICAID=AJKiYcHdKgxum7KMXG0ei2t1-W4OD1uW-ecNsCqC0wDuAXiDGIcT_HA2o1"
        "3Rs1UKCuBAF9g8rWNOFbxt8PSNSHFuIhOo2t6bJAVpCsMU5Laa6lewuTMYI8MzdQP"
        "ARHKyW-koxuhMZHUnGBJAM1gJODe0cATO_KGoX4pbbFxxJ5IicRxOrWK_5rU3cdy6"
        "edlR9FsEdH6iujMcHkbE5l18ehJDwTWmBKBzVD87naobhMMrF6VvnDGxQVGp9Ir_b"
        "Rgj3RWUoPumQVCxtSOBdX0GlJOEcDTNCzQIm9BSfetog_eP_TfYubKudt5eMsXmN6"
        "QnyXHeGeK2UINUzJ-D30AFcpqYgH9_1BvYSpi7fc7_ydBU8TaD8ZRxvtnzXqj0RfG"
        "tuHghmv3aD-uzSYJ75XDdzKdizZ86IG6Fbn1XFhYZM-fbHhm3mVEXnyRW4ZuNOLFk"
        "Fas6LMcVC6Q8QLlHYbXBpdNFuGbuZGUnav5C-2I_-46lL0NGg3GewxGKGHvHEfoyn"
        "EFFlEYHsBQ98rXImL8ySDycdLEFvBPdtctPmWCfTxwmoSMLHU2SCVDhbqMWU5b0yr"
        "JBCScs_ejbKaqBDoB7ZGxTvqlrB__2ZmnHHjCr8RgMRtKNtIeuZAo ";
    connection_->AdvanceTime(QuicTime::Delta::FromSeconds(1));
  }

  void CheckClosedStreams() {
    for (QuicStreamId i = kCryptoStreamId; i < 100; i++) {
      if (!base::ContainsKey(closed_streams_, i)) {
        EXPECT_FALSE(session_.IsClosedStream(i)) << " stream id: " << i;
      } else {
        EXPECT_TRUE(session_.IsClosedStream(i)) << " stream id: " << i;
      }
    }
  }

  void CloseStream(QuicStreamId id) {
    EXPECT_CALL(*connection_, SendRstStream(id, _, _));
    session_.CloseStream(id);
    closed_streams_.insert(id);
  }

  QuicVersion version() const { return connection_->version(); }

  QuicFlagSaver flags_;  // Save/restore all QUIC flag values.
  MockQuicConnectionHelper helper_;
  MockAlarmFactory alarm_factory_;
  StrictMock<MockQuicConnection>* connection_;
  TestSession session_;
  std::set<QuicStreamId> closed_streams_;
  SpdyHeaderBlock headers_;
};

class QuicSessionTestServer : public QuicSessionTestBase {
 protected:
  QuicSessionTestServer() : QuicSessionTestBase(Perspective::IS_SERVER) {}
};

INSTANTIATE_TEST_CASE_P(Tests,
                        QuicSessionTestServer,
                        ::testing::ValuesIn(AllSupportedVersions()));

TEST_P(QuicSessionTestServer, PeerAddress) {
  EXPECT_EQ(QuicSocketAddress(QuicIpAddress::Loopback4(), kTestPort),
            session_.peer_address());
}

TEST_P(QuicSessionTestServer, IsCryptoHandshakeConfirmed) {
  EXPECT_FALSE(session_.IsCryptoHandshakeConfirmed());
  CryptoHandshakeMessage message;
  session_.GetCryptoStream()->OnHandshakeMessage(message);
  EXPECT_TRUE(session_.IsCryptoHandshakeConfirmed());
}

TEST_P(QuicSessionTestServer, IsClosedStreamDefault) {
  // Ensure that no streams are initially closed.
  for (QuicStreamId i = kCryptoStreamId; i < 100; i++) {
    EXPECT_FALSE(session_.IsClosedStream(i)) << "stream id: " << i;
  }
}

TEST_P(QuicSessionTestServer, AvailableStreams) {
  ASSERT_TRUE(session_.GetOrCreateDynamicStream(9) != nullptr);
  // Both 5 and 7 should be available.
  EXPECT_TRUE(QuicSessionPeer::IsStreamAvailable(&session_, 5));
  EXPECT_TRUE(QuicSessionPeer::IsStreamAvailable(&session_, 7));
  ASSERT_TRUE(session_.GetOrCreateDynamicStream(7) != nullptr);
  ASSERT_TRUE(session_.GetOrCreateDynamicStream(5) != nullptr);
}

TEST_P(QuicSessionTestServer, IsClosedStreamLocallyCreated) {
  TestStream* stream2 = session_.CreateOutgoingDynamicStream(kDefaultPriority);
  EXPECT_EQ(2u, stream2->id());
  TestStream* stream4 = session_.CreateOutgoingDynamicStream(kDefaultPriority);
  EXPECT_EQ(4u, stream4->id());

  CheckClosedStreams();
  CloseStream(4);
  CheckClosedStreams();
  CloseStream(2);
  CheckClosedStreams();
}

TEST_P(QuicSessionTestServer, IsClosedStreamPeerCreated) {
  QuicStreamId stream_id1 = kClientDataStreamId1;
  QuicStreamId stream_id2 = kClientDataStreamId2;
  session_.GetOrCreateDynamicStream(stream_id1);
  session_.GetOrCreateDynamicStream(stream_id2);

  CheckClosedStreams();
  CloseStream(stream_id1);
  CheckClosedStreams();
  CloseStream(stream_id2);
  // Create a stream, and make another available.
  QuicStream* stream3 = session_.GetOrCreateDynamicStream(stream_id2 + 4);
  CheckClosedStreams();
  // Close one, but make sure the other is still not closed
  CloseStream(stream3->id());
  CheckClosedStreams();
}

TEST_P(QuicSessionTestServer, MaximumAvailableOpenedStreams) {
  QuicStreamId stream_id = kClientDataStreamId1;
  session_.GetOrCreateDynamicStream(stream_id);
  EXPECT_CALL(*connection_, CloseConnection(_, _, _)).Times(0);
  EXPECT_NE(nullptr,
            session_.GetOrCreateDynamicStream(
                stream_id + 2 * (session_.max_open_incoming_streams() - 1)));
}

TEST_P(QuicSessionTestServer, TooManyAvailableStreams) {
  QuicStreamId stream_id1 = kClientDataStreamId1;
  QuicStreamId stream_id2;
  EXPECT_NE(nullptr, session_.GetOrCreateDynamicStream(stream_id1));
  // A stream ID which is too large to create.
  stream_id2 = stream_id1 + 2 * session_.MaxAvailableStreams() + 4;
  EXPECT_CALL(*connection_,
              CloseConnection(QUIC_TOO_MANY_AVAILABLE_STREAMS, _, _));
  EXPECT_EQ(nullptr, session_.GetOrCreateDynamicStream(stream_id2));
}

TEST_P(QuicSessionTestServer, ManyAvailableStreams) {
  // When max_open_streams_ is 200, should be able to create 200 streams
  // out-of-order, that is, creating the one with the largest stream ID first.
  QuicSessionPeer::SetMaxOpenIncomingStreams(&session_, 200);
  QuicStreamId stream_id = kClientDataStreamId1;
  // Create one stream.
  session_.GetOrCreateDynamicStream(stream_id);
  EXPECT_CALL(*connection_, CloseConnection(_, _, _)).Times(0);
  // Create the largest stream ID of a threatened total of 200 streams.
  session_.GetOrCreateDynamicStream(stream_id + 2 * (200 - 1));
}

TEST_P(QuicSessionTestServer, DebugDFatalIfMarkingClosedStreamWriteBlocked) {
  TestStream* stream2 = session_.CreateOutgoingDynamicStream(kDefaultPriority);
  QuicStreamId closed_stream_id = stream2->id();
  // Close the stream.
  EXPECT_CALL(*connection_, SendRstStream(closed_stream_id, _, _));
  stream2->Reset(QUIC_BAD_APPLICATION_PAYLOAD);
  EXPECT_QUIC_BUG(session_.MarkConnectionLevelWriteBlocked(closed_stream_id),
                  "Marking unknown stream 2 blocked.");
}

TEST_P(QuicSessionTestServer, OnCanWrite) {
  session_.set_writev_consumes_all_data(true);
  TestStream* stream2 = session_.CreateOutgoingDynamicStream(kDefaultPriority);
  TestStream* stream4 = session_.CreateOutgoingDynamicStream(kDefaultPriority);
  TestStream* stream6 = session_.CreateOutgoingDynamicStream(kDefaultPriority);

  session_.MarkConnectionLevelWriteBlocked(stream2->id());
  session_.MarkConnectionLevelWriteBlocked(stream6->id());
  session_.MarkConnectionLevelWriteBlocked(stream4->id());

  InSequence s;
  StreamBlocker stream2_blocker(&session_, stream2->id());

  // Reregister, to test the loop limit.
  EXPECT_CALL(*stream2, OnCanWrite())
      .WillOnce(DoAll(testing::IgnoreResult(Invoke(
                          CreateFunctor(&TestSession::SendStreamData,
                                        base::Unretained(&session_), stream2))),
                      Invoke(&stream2_blocker,
                             &StreamBlocker::MarkConnectionLevelWriteBlocked)));
  // 2 will get called a second time as it didn't finish its block
  EXPECT_CALL(*stream2, OnCanWrite())
      .WillOnce(testing::IgnoreResult(
          Invoke(CreateFunctor(&TestSession::SendStreamData,
                               base::Unretained(&session_), stream2))));
  EXPECT_CALL(*stream6, OnCanWrite())
      .WillOnce(testing::IgnoreResult(
          Invoke(CreateFunctor(&TestSession::SendStreamData,
                               base::Unretained(&session_), stream6))));
  // 4 will not get called, as we exceeded the loop limit.
  session_.OnCanWrite();
  EXPECT_TRUE(session_.WillingAndAbleToWrite());
}

TEST_P(QuicSessionTestServer, TestBatchedWrites) {
  session_.set_writev_consumes_all_data(true);
  TestStream* stream2 = session_.CreateOutgoingDynamicStream(kDefaultPriority);
  TestStream* stream4 = session_.CreateOutgoingDynamicStream(kDefaultPriority);
  TestStream* stream6 = session_.CreateOutgoingDynamicStream(kDefaultPriority);

  session_.set_writev_consumes_all_data(true);
  session_.MarkConnectionLevelWriteBlocked(stream2->id());
  session_.MarkConnectionLevelWriteBlocked(stream4->id());

  StreamBlocker stream2_blocker(&session_, stream2->id());
  StreamBlocker stream4_blocker(&session_, stream4->id());
  StreamBlocker stream6_blocker(&session_, stream6->id());
  // With two sessions blocked, we should get two write calls.  They should both
  // go to the first stream as it will only write 6k and mark itself blocked
  // again.
  InSequence s;
  EXPECT_CALL(*stream2, OnCanWrite())
      .WillOnce(DoAll(testing::IgnoreResult(Invoke(CreateFunctor(
                          &TestSession::SendLargeFakeData,
                          base::Unretained(&session_), stream2, 6000))),
                      Invoke(&stream2_blocker,
                             &StreamBlocker::MarkConnectionLevelWriteBlocked)));
  EXPECT_CALL(*stream2, OnCanWrite())
      .WillOnce(DoAll(testing::IgnoreResult(Invoke(CreateFunctor(
                          &TestSession::SendLargeFakeData,
                          base::Unretained(&session_), stream2, 6000))),
                      Invoke(&stream2_blocker,
                             &StreamBlocker::MarkConnectionLevelWriteBlocked)));
  session_.OnCanWrite();

  // We should get one more call for stream2, at which point it has used its
  // write quota and we move over to stream 4.
  EXPECT_CALL(*stream2, OnCanWrite())
      .WillOnce(DoAll(testing::IgnoreResult(Invoke(CreateFunctor(
                          &TestSession::SendLargeFakeData,
                          base::Unretained(&session_), stream2, 6000))),
                      Invoke(&stream2_blocker,
                             &StreamBlocker::MarkConnectionLevelWriteBlocked)));
  EXPECT_CALL(*stream4, OnCanWrite())
      .WillOnce(DoAll(testing::IgnoreResult(Invoke(CreateFunctor(
                          &TestSession::SendLargeFakeData,
                          base::Unretained(&session_), stream4, 6000))),
                      Invoke(&stream4_blocker,
                             &StreamBlocker::MarkConnectionLevelWriteBlocked)));
  session_.OnCanWrite();

  // Now let stream 4 do the 2nd of its 3 writes, but add a block for a high
  // priority stream 6.  4 should be preempted.  6 will write but *not* block so
  // will cede back to 4.
  stream6->SetPriority(kHighestPriority);
  EXPECT_CALL(*stream4, OnCanWrite())
      .WillOnce(DoAll(testing::IgnoreResult(Invoke(CreateFunctor(
                          &TestSession::SendLargeFakeData,
                          base::Unretained(&session_), stream4, 6000))),
                      Invoke(&stream4_blocker,
                             &StreamBlocker::MarkConnectionLevelWriteBlocked),
                      Invoke(&stream6_blocker,
                             &StreamBlocker::MarkConnectionLevelWriteBlocked)));
  EXPECT_CALL(*stream6, OnCanWrite())
      .WillOnce(DoAll(testing::IgnoreResult(Invoke(
                          CreateFunctor(&TestSession::SendStreamData,
                                        base::Unretained(&session_), stream6))),
                      testing::IgnoreResult(Invoke(CreateFunctor(
                          &TestSession::SendLargeFakeData,
                          base::Unretained(&session_), stream4, 6000)))));
  session_.OnCanWrite();

  // Stream4 alread did 6k worth of writes, so after doing another 12k it should
  // cede and 2 should resume.
  EXPECT_CALL(*stream4, OnCanWrite())
      .WillOnce(DoAll(testing::IgnoreResult(Invoke(CreateFunctor(
                          &TestSession::SendLargeFakeData,
                          base::Unretained(&session_), stream4, 12000))),
                      Invoke(&stream4_blocker,
                             &StreamBlocker::MarkConnectionLevelWriteBlocked)));
  EXPECT_CALL(*stream2, OnCanWrite())
      .WillOnce(DoAll(testing::IgnoreResult(Invoke(CreateFunctor(
                          &TestSession::SendLargeFakeData,
                          base::Unretained(&session_), stream2, 6000))),
                      Invoke(&stream2_blocker,
                             &StreamBlocker::MarkConnectionLevelWriteBlocked)));
  session_.OnCanWrite();
}

TEST_P(QuicSessionTestServer, OnCanWriteBundlesStreams) {
  // Encryption needs to be established before data can be sent.
  CryptoHandshakeMessage msg;
  session_.GetCryptoStream()->OnHandshakeMessage(msg);

  // Drive congestion control manually.
  MockSendAlgorithm* send_algorithm = new StrictMock<MockSendAlgorithm>;
  QuicConnectionPeer::SetSendAlgorithm(session_.connection(), kDefaultPathId,
                                       send_algorithm);

  TestStream* stream2 = session_.CreateOutgoingDynamicStream(kDefaultPriority);
  TestStream* stream4 = session_.CreateOutgoingDynamicStream(kDefaultPriority);
  TestStream* stream6 = session_.CreateOutgoingDynamicStream(kDefaultPriority);

  session_.MarkConnectionLevelWriteBlocked(stream2->id());
  session_.MarkConnectionLevelWriteBlocked(stream6->id());
  session_.MarkConnectionLevelWriteBlocked(stream4->id());

  EXPECT_CALL(*send_algorithm, TimeUntilSend(_, _))
      .WillRepeatedly(Return(QuicTime::Delta::Zero()));
  EXPECT_CALL(*send_algorithm, GetCongestionWindow())
      .WillRepeatedly(Return(kMaxPacketSize * 10));
  EXPECT_CALL(*send_algorithm, InRecovery()).WillRepeatedly(Return(false));
  EXPECT_CALL(*stream2, OnCanWrite())
      .WillOnce(testing::IgnoreResult(
          Invoke(CreateFunctor(&TestSession::SendStreamData,
                               base::Unretained(&session_), stream2))));
  EXPECT_CALL(*stream4, OnCanWrite())
      .WillOnce(testing::IgnoreResult(
          Invoke(CreateFunctor(&TestSession::SendStreamData,
                               base::Unretained(&session_), stream4))));
  EXPECT_CALL(*stream6, OnCanWrite())
      .WillOnce(testing::IgnoreResult(
          Invoke(CreateFunctor(&TestSession::SendStreamData,
                               base::Unretained(&session_), stream6))));

  // Expect that we only send one packet, the writes from different streams
  // should be bundled together.
  MockPacketWriter* writer = static_cast<MockPacketWriter*>(
      QuicConnectionPeer::GetWriter(session_.connection()));
  EXPECT_CALL(*writer, WritePacket(_, _, _, _, _))
      .WillOnce(Return(WriteResult(WRITE_STATUS_OK, 0)));
  EXPECT_CALL(*send_algorithm, OnPacketSent(_, _, _, _, _));
  EXPECT_CALL(*send_algorithm, OnApplicationLimited(_));
  session_.OnCanWrite();
  EXPECT_FALSE(session_.WillingAndAbleToWrite());
}

TEST_P(QuicSessionTestServer, OnCanWriteCongestionControlBlocks) {
  session_.set_writev_consumes_all_data(true);
  InSequence s;

  // Drive congestion control manually.
  MockSendAlgorithm* send_algorithm = new StrictMock<MockSendAlgorithm>;
  QuicConnectionPeer::SetSendAlgorithm(session_.connection(), kDefaultPathId,
                                       send_algorithm);

  TestStream* stream2 = session_.CreateOutgoingDynamicStream(kDefaultPriority);
  TestStream* stream4 = session_.CreateOutgoingDynamicStream(kDefaultPriority);
  TestStream* stream6 = session_.CreateOutgoingDynamicStream(kDefaultPriority);

  session_.MarkConnectionLevelWriteBlocked(stream2->id());
  session_.MarkConnectionLevelWriteBlocked(stream6->id());
  session_.MarkConnectionLevelWriteBlocked(stream4->id());

  StreamBlocker stream2_blocker(&session_, stream2->id());
  EXPECT_CALL(*send_algorithm, TimeUntilSend(_, _))
      .WillOnce(Return(QuicTime::Delta::Zero()));
  EXPECT_CALL(*stream2, OnCanWrite())
      .WillOnce(testing::IgnoreResult(
          Invoke(CreateFunctor(&TestSession::SendStreamData,
                               base::Unretained(&session_), stream2))));
  EXPECT_CALL(*send_algorithm, TimeUntilSend(_, _))
      .WillOnce(Return(QuicTime::Delta::Zero()));
  EXPECT_CALL(*stream6, OnCanWrite())
      .WillOnce(testing::IgnoreResult(
          Invoke(CreateFunctor(&TestSession::SendStreamData,
                               base::Unretained(&session_), stream6))));
  EXPECT_CALL(*send_algorithm, TimeUntilSend(_, _))
      .WillOnce(Return(QuicTime::Delta::Infinite()));
  // stream4->OnCanWrite is not called.

  session_.OnCanWrite();
  EXPECT_TRUE(session_.WillingAndAbleToWrite());

  // Still congestion-control blocked.
  EXPECT_CALL(*send_algorithm, TimeUntilSend(_, _))
      .WillOnce(Return(QuicTime::Delta::Infinite()));
  session_.OnCanWrite();
  EXPECT_TRUE(session_.WillingAndAbleToWrite());

  // stream4->OnCanWrite is called once the connection stops being
  // congestion-control blocked.
  EXPECT_CALL(*send_algorithm, TimeUntilSend(_, _))
      .WillOnce(Return(QuicTime::Delta::Zero()));
  EXPECT_CALL(*stream4, OnCanWrite())
      .WillOnce(testing::IgnoreResult(
          Invoke(CreateFunctor(&TestSession::SendStreamData,
                               base::Unretained(&session_), stream4))));
  EXPECT_CALL(*send_algorithm, OnApplicationLimited(_));
  session_.OnCanWrite();
  EXPECT_FALSE(session_.WillingAndAbleToWrite());
}

TEST_P(QuicSessionTestServer, OnCanWriteWriterBlocks) {
  // Drive congestion control manually in order to ensure that
  // application-limited signaling is handled correctly.
  MockSendAlgorithm* send_algorithm = new StrictMock<MockSendAlgorithm>;
  QuicConnectionPeer::SetSendAlgorithm(session_.connection(), kDefaultPathId,
                                       send_algorithm);
  EXPECT_CALL(*send_algorithm, TimeUntilSend(_, _))
      .WillRepeatedly(Return(QuicTime::Delta::Zero()));

  // Drive packet writer manually.
  MockPacketWriter* writer = static_cast<MockPacketWriter*>(
      QuicConnectionPeer::GetWriter(session_.connection()));
  EXPECT_CALL(*writer, IsWriteBlocked()).WillRepeatedly(Return(true));
  EXPECT_CALL(*writer, IsWriteBlockedDataBuffered())
      .WillRepeatedly(Return(true));
  EXPECT_CALL(*writer, WritePacket(_, _, _, _, _)).Times(0);

  TestStream* stream2 = session_.CreateOutgoingDynamicStream(kDefaultPriority);

  session_.MarkConnectionLevelWriteBlocked(stream2->id());

  EXPECT_CALL(*stream2, OnCanWrite()).Times(0);
  EXPECT_CALL(*send_algorithm, OnApplicationLimited(_)).Times(0);

  session_.OnCanWrite();
  EXPECT_TRUE(session_.WillingAndAbleToWrite());
}

TEST_P(QuicSessionTestServer, BufferedHandshake) {
  session_.set_writev_consumes_all_data(true);
  EXPECT_FALSE(session_.HasPendingHandshake());  // Default value.

  // Test that blocking other streams does not change our status.
  TestStream* stream2 = session_.CreateOutgoingDynamicStream(kDefaultPriority);
  StreamBlocker stream2_blocker(&session_, stream2->id());
  stream2_blocker.MarkConnectionLevelWriteBlocked();
  EXPECT_FALSE(session_.HasPendingHandshake());

  TestStream* stream3 = session_.CreateOutgoingDynamicStream(kDefaultPriority);
  StreamBlocker stream3_blocker(&session_, stream3->id());
  stream3_blocker.MarkConnectionLevelWriteBlocked();
  EXPECT_FALSE(session_.HasPendingHandshake());

  // Blocking (due to buffering of) the Crypto stream is detected.
  session_.MarkConnectionLevelWriteBlocked(kCryptoStreamId);
  EXPECT_TRUE(session_.HasPendingHandshake());

  TestStream* stream4 = session_.CreateOutgoingDynamicStream(kDefaultPriority);
  StreamBlocker stream4_blocker(&session_, stream4->id());
  stream4_blocker.MarkConnectionLevelWriteBlocked();
  EXPECT_TRUE(session_.HasPendingHandshake());

  InSequence s;
  // Force most streams to re-register, which is common scenario when we block
  // the Crypto stream, and only the crypto stream can "really" write.

  // Due to prioritization, we *should* be asked to write the crypto stream
  // first.
  // Don't re-register the crypto stream (which signals complete writing).
  TestCryptoStream* crypto_stream = session_.GetCryptoStream();
  EXPECT_CALL(*crypto_stream, OnCanWrite());

  EXPECT_CALL(*stream2, OnCanWrite())
      .WillOnce(testing::IgnoreResult(
          Invoke(CreateFunctor(&TestSession::SendStreamData,
                               base::Unretained(&session_), stream2))));
  EXPECT_CALL(*stream3, OnCanWrite())
      .WillOnce(testing::IgnoreResult(
          Invoke(CreateFunctor(&TestSession::SendStreamData,
                               base::Unretained(&session_), stream3))));
  EXPECT_CALL(*stream4, OnCanWrite())
      .WillOnce(DoAll(testing::IgnoreResult(Invoke(
                          CreateFunctor(&TestSession::SendStreamData,
                                        base::Unretained(&session_), stream4))),
                      Invoke(&stream4_blocker,
                             &StreamBlocker::MarkConnectionLevelWriteBlocked)));

  session_.OnCanWrite();
  EXPECT_TRUE(session_.WillingAndAbleToWrite());
  EXPECT_FALSE(session_.HasPendingHandshake());  // Crypto stream wrote.
}

TEST_P(QuicSessionTestServer, OnCanWriteWithClosedStream) {
  session_.set_writev_consumes_all_data(true);
  TestStream* stream2 = session_.CreateOutgoingDynamicStream(kDefaultPriority);
  TestStream* stream4 = session_.CreateOutgoingDynamicStream(kDefaultPriority);
  TestStream* stream6 = session_.CreateOutgoingDynamicStream(kDefaultPriority);

  session_.MarkConnectionLevelWriteBlocked(stream2->id());
  session_.MarkConnectionLevelWriteBlocked(stream6->id());
  session_.MarkConnectionLevelWriteBlocked(stream4->id());
  CloseStream(stream6->id());

  InSequence s;
  EXPECT_CALL(*stream2, OnCanWrite())
      .WillOnce(testing::IgnoreResult(
          Invoke(CreateFunctor(&TestSession::SendStreamData,
                               base::Unretained(&session_), stream2))));
  EXPECT_CALL(*stream4, OnCanWrite())
      .WillOnce(testing::IgnoreResult(
          Invoke(CreateFunctor(&TestSession::SendStreamData,
                               base::Unretained(&session_), stream4))));
  session_.OnCanWrite();
  EXPECT_FALSE(session_.WillingAndAbleToWrite());
}

TEST_P(QuicSessionTestServer, OnCanWriteLimitsNumWritesIfFlowControlBlocked) {
  // Drive congestion control manually in order to ensure that
  // application-limited signaling is handled correctly.
  MockSendAlgorithm* send_algorithm = new StrictMock<MockSendAlgorithm>;
  QuicConnectionPeer::SetSendAlgorithm(session_.connection(), kDefaultPathId,
                                       send_algorithm);
  EXPECT_CALL(*send_algorithm, TimeUntilSend(_, _))
      .WillRepeatedly(Return(QuicTime::Delta::Zero()));

  // Ensure connection level flow control blockage.
  QuicFlowControllerPeer::SetSendWindowOffset(session_.flow_controller(), 0);
  EXPECT_TRUE(session_.flow_controller()->IsBlocked());
  EXPECT_TRUE(session_.IsConnectionFlowControlBlocked());
  EXPECT_FALSE(session_.IsStreamFlowControlBlocked());

  // Mark the crypto and headers streams as write blocked, we expect them to be
  // allowed to write later.
  session_.MarkConnectionLevelWriteBlocked(kCryptoStreamId);
  session_.MarkConnectionLevelWriteBlocked(kHeadersStreamId);

  // Create a data stream, and although it is write blocked we never expect it
  // to be allowed to write as we are connection level flow control blocked.
  TestStream* stream = session_.CreateOutgoingDynamicStream(kDefaultPriority);
  session_.MarkConnectionLevelWriteBlocked(stream->id());
  EXPECT_CALL(*stream, OnCanWrite()).Times(0);

  // The crypto and headers streams should be called even though we are
  // connection flow control blocked.
  TestCryptoStream* crypto_stream = session_.GetCryptoStream();
  EXPECT_CALL(*crypto_stream, OnCanWrite());
  TestHeadersStream* headers_stream = new TestHeadersStream(&session_);
  QuicSpdySessionPeer::SetHeadersStream(&session_, headers_stream);
  EXPECT_CALL(*headers_stream, OnCanWrite());

  // After the crypto and header streams perform a write, the connection will be
  // blocked by the flow control, hence it should become application-limited.
  EXPECT_CALL(*send_algorithm, OnApplicationLimited(_));

  session_.OnCanWrite();
  EXPECT_FALSE(session_.WillingAndAbleToWrite());
}

TEST_P(QuicSessionTestServer, SendGoAway) {
  MockPacketWriter* writer = static_cast<MockPacketWriter*>(
      QuicConnectionPeer::GetWriter(session_.connection()));
  EXPECT_CALL(*writer, WritePacket(_, _, _, _, _))
      .WillOnce(Return(WriteResult(WRITE_STATUS_OK, 0)));
  EXPECT_CALL(*connection_, SendGoAway(_, _, _))
      .WillOnce(Invoke(connection_, &MockQuicConnection::ReallySendGoAway));
  session_.SendGoAway(QUIC_PEER_GOING_AWAY, "Going Away.");
  EXPECT_TRUE(session_.goaway_sent());

  const QuicStreamId kTestStreamId = 5u;
  EXPECT_CALL(*connection_,
              SendRstStream(kTestStreamId, QUIC_STREAM_PEER_GOING_AWAY, 0))
      .Times(0);
  EXPECT_TRUE(session_.GetOrCreateDynamicStream(kTestStreamId));
}

TEST_P(QuicSessionTestServer, IncreasedTimeoutAfterCryptoHandshake) {
  EXPECT_EQ(kInitialIdleTimeoutSecs + 3,
            QuicConnectionPeer::GetNetworkTimeout(connection_).ToSeconds());
  CryptoHandshakeMessage msg;
  session_.GetCryptoStream()->OnHandshakeMessage(msg);
  EXPECT_EQ(kMaximumIdleTimeoutSecs + 3,
            QuicConnectionPeer::GetNetworkTimeout(connection_).ToSeconds());
}

TEST_P(QuicSessionTestServer, RstStreamBeforeHeadersDecompressed) {
  // Send two bytes of payload.
  QuicStreamFrame data1(kClientDataStreamId1, false, 0, StringPiece("HT"));
  session_.OnStreamFrame(data1);
  EXPECT_EQ(1u, session_.GetNumOpenIncomingStreams());

  EXPECT_CALL(*connection_, SendRstStream(kClientDataStreamId1, _, _));
  QuicRstStreamFrame rst1(kClientDataStreamId1, QUIC_ERROR_PROCESSING_STREAM,
                          0);
  session_.OnRstStream(rst1);
  EXPECT_EQ(0u, session_.GetNumOpenIncomingStreams());
  // Connection should remain alive.
  EXPECT_TRUE(connection_->connected());
}

TEST_P(QuicSessionTestServer, HandshakeUnblocksFlowControlBlockedStream) {
  // Test that if a stream is flow control blocked, then on receipt of the SHLO
  // containing a suitable send window offset, the stream becomes unblocked.

  // Ensure that Writev consumes all the data it is given (simulate no socket
  // blocking).
  session_.set_writev_consumes_all_data(true);

  // Create a stream, and send enough data to make it flow control blocked.
  TestStream* stream2 = session_.CreateOutgoingDynamicStream(kDefaultPriority);
  string body(kMinimumFlowControlSendWindow, '.');
  EXPECT_FALSE(stream2->flow_controller()->IsBlocked());
  EXPECT_FALSE(session_.IsConnectionFlowControlBlocked());
  EXPECT_FALSE(session_.IsStreamFlowControlBlocked());
  EXPECT_CALL(*connection_, SendBlocked(_)).Times(AtLeast(1));
  EXPECT_CALL(*connection_, SendBlocked(0));
  stream2->WriteOrBufferBody(body, false, nullptr);
  EXPECT_TRUE(stream2->flow_controller()->IsBlocked());
  EXPECT_TRUE(session_.IsConnectionFlowControlBlocked());
  EXPECT_TRUE(session_.IsStreamFlowControlBlocked());

  // The handshake message will call OnCanWrite, so the stream can resume
  // writing.
  EXPECT_CALL(*stream2, OnCanWrite());
  // Now complete the crypto handshake, resulting in an increased flow control
  // send window.
  CryptoHandshakeMessage msg;
  session_.GetCryptoStream()->OnHandshakeMessage(msg);

  // Stream is now unblocked.
  EXPECT_FALSE(stream2->flow_controller()->IsBlocked());
  EXPECT_FALSE(session_.IsConnectionFlowControlBlocked());
  EXPECT_FALSE(session_.IsStreamFlowControlBlocked());
}

TEST_P(QuicSessionTestServer, HandshakeUnblocksFlowControlBlockedCryptoStream) {
  // Test that if the crypto stream is flow control blocked, then if the SHLO
  // contains a larger send window offset, the stream becomes unblocked.
  session_.set_writev_consumes_all_data(true);
  TestCryptoStream* crypto_stream = session_.GetCryptoStream();
  EXPECT_FALSE(crypto_stream->flow_controller()->IsBlocked());
  EXPECT_FALSE(session_.IsConnectionFlowControlBlocked());
  EXPECT_FALSE(session_.IsStreamFlowControlBlocked());
  QuicHeadersStream* headers_stream =
      QuicSpdySessionPeer::GetHeadersStream(&session_);
  EXPECT_FALSE(headers_stream->flow_controller()->IsBlocked());
  EXPECT_FALSE(session_.IsConnectionFlowControlBlocked());
  EXPECT_FALSE(session_.IsStreamFlowControlBlocked());
  // Write until the crypto stream is flow control blocked.
  EXPECT_CALL(*connection_, SendBlocked(kCryptoStreamId));
  for (QuicStreamId i = 0;
       !crypto_stream->flow_controller()->IsBlocked() && i < 1000u; i++) {
    EXPECT_FALSE(session_.IsConnectionFlowControlBlocked());
    EXPECT_FALSE(session_.IsStreamFlowControlBlocked());
    QuicConfig config;
    CryptoHandshakeMessage crypto_message;
    config.ToHandshakeMessage(&crypto_message);
    crypto_stream->SendHandshakeMessage(crypto_message);
  }
  EXPECT_TRUE(crypto_stream->flow_controller()->IsBlocked());
  EXPECT_FALSE(headers_stream->flow_controller()->IsBlocked());
  EXPECT_FALSE(session_.IsConnectionFlowControlBlocked());
  EXPECT_TRUE(session_.IsStreamFlowControlBlocked());
  EXPECT_FALSE(session_.HasDataToWrite());
  EXPECT_TRUE(crypto_stream->HasBufferedData());

  // The handshake message will call OnCanWrite, so the stream can
  // resume writing.
  EXPECT_CALL(*crypto_stream, OnCanWrite());
  // Now complete the crypto handshake, resulting in an increased flow control
  // send window.
  CryptoHandshakeMessage msg;
  session_.GetCryptoStream()->OnHandshakeMessage(msg);

  // Stream is now unblocked and will no longer have buffered data.
  EXPECT_FALSE(crypto_stream->flow_controller()->IsBlocked());
  EXPECT_FALSE(session_.IsConnectionFlowControlBlocked());
  EXPECT_FALSE(session_.IsStreamFlowControlBlocked());
}

#if !defined(OS_IOS)
// This test is failing flakily for iOS bots.
// http://crbug.com/425050
// NOTE: It's not possible to use the standard MAYBE_ convention to disable
// this test on iOS because when this test gets instantiated it ends up with
// various names that are dependent on the parameters passed.
TEST_P(QuicSessionTestServer,
       HandshakeUnblocksFlowControlBlockedHeadersStream) {
  // Test that if the header stream is flow control blocked, then if the SHLO
  // contains a larger send window offset, the stream becomes unblocked.
  session_.set_writev_consumes_all_data(true);
  TestCryptoStream* crypto_stream = session_.GetCryptoStream();
  EXPECT_FALSE(crypto_stream->flow_controller()->IsBlocked());
  EXPECT_FALSE(session_.IsConnectionFlowControlBlocked());
  EXPECT_FALSE(session_.IsStreamFlowControlBlocked());
  QuicHeadersStream* headers_stream =
      QuicSpdySessionPeer::GetHeadersStream(&session_);
  EXPECT_FALSE(headers_stream->flow_controller()->IsBlocked());
  EXPECT_FALSE(session_.IsConnectionFlowControlBlocked());
  EXPECT_FALSE(session_.IsStreamFlowControlBlocked());
  QuicStreamId stream_id = 5;
  // Write until the header stream is flow control blocked.
  EXPECT_CALL(*connection_, SendBlocked(kHeadersStreamId));
  SpdyHeaderBlock headers;
  while (!headers_stream->flow_controller()->IsBlocked() && stream_id < 2000) {
    EXPECT_FALSE(session_.IsConnectionFlowControlBlocked());
    EXPECT_FALSE(session_.IsStreamFlowControlBlocked());
    headers["header"] = base::Uint64ToString(base::RandUint64()) +
                        base::Uint64ToString(base::RandUint64()) +
                        base::Uint64ToString(base::RandUint64());
    headers_stream->WriteHeaders(stream_id, headers.Clone(), true, 0, nullptr);
    stream_id += 2;
  }
  // Write once more to ensure that the headers stream has buffered data. The
  // random headers may have exactly filled the flow control window.
  headers_stream->WriteHeaders(stream_id, std::move(headers), true, 0, nullptr);
  EXPECT_TRUE(headers_stream->HasBufferedData());

  EXPECT_TRUE(headers_stream->flow_controller()->IsBlocked());
  EXPECT_FALSE(crypto_stream->flow_controller()->IsBlocked());
  EXPECT_FALSE(session_.IsConnectionFlowControlBlocked());
  EXPECT_TRUE(session_.IsStreamFlowControlBlocked());
  EXPECT_FALSE(session_.HasDataToWrite());

  // Now complete the crypto handshake, resulting in an increased flow control
  // send window.
  CryptoHandshakeMessage msg;
  session_.GetCryptoStream()->OnHandshakeMessage(msg);

  // Stream is now unblocked and will no longer have buffered data.
  EXPECT_FALSE(headers_stream->flow_controller()->IsBlocked());
  EXPECT_FALSE(session_.IsConnectionFlowControlBlocked());
  EXPECT_FALSE(session_.IsStreamFlowControlBlocked());
  EXPECT_FALSE(headers_stream->HasBufferedData());
}
#endif  // !defined(OS_IOS)

TEST_P(QuicSessionTestServer, ConnectionFlowControlAccountingRstOutOfOrder) {
  // Test that when we receive an out of order stream RST we correctly adjust
  // our connection level flow control receive window.
  // On close, the stream should mark as consumed all bytes between the highest
  // byte consumed so far and the final byte offset from the RST frame.
  TestStream* stream = session_.CreateOutgoingDynamicStream(kDefaultPriority);

  const QuicStreamOffset kByteOffset =
      1 + kInitialSessionFlowControlWindowForTest / 2;

  // Expect no stream WINDOW_UPDATE frames, as stream read side closed.
  EXPECT_CALL(*connection_, SendWindowUpdate(stream->id(), _)).Times(0);
  // We do expect a connection level WINDOW_UPDATE when the stream is reset.
  EXPECT_CALL(*connection_,
              SendWindowUpdate(
                  0, kInitialSessionFlowControlWindowForTest + kByteOffset));

  EXPECT_CALL(*connection_, SendRstStream(stream->id(), _, _));
  QuicRstStreamFrame rst_frame(stream->id(), QUIC_STREAM_CANCELLED,
                               kByteOffset);
  session_.OnRstStream(rst_frame);
  session_.PostProcessAfterData();
  EXPECT_EQ(kByteOffset, session_.flow_controller()->bytes_consumed());
}

TEST_P(QuicSessionTestServer, ConnectionFlowControlAccountingFinAndLocalReset) {
  // Test the situation where we receive a FIN on a stream, and before we fully
  // consume all the data from the sequencer buffer we locally RST the stream.
  // The bytes between highest consumed byte, and the final byte offset that we
  // determined when the FIN arrived, should be marked as consumed at the
  // connection level flow controller when the stream is reset.
  TestStream* stream = session_.CreateOutgoingDynamicStream(kDefaultPriority);

  const QuicStreamOffset kByteOffset =
      kInitialSessionFlowControlWindowForTest / 2 - 1;
  QuicStreamFrame frame(stream->id(), true, kByteOffset, ".");
  session_.OnStreamFrame(frame);
  session_.PostProcessAfterData();
  EXPECT_TRUE(connection_->connected());

  EXPECT_EQ(0u, stream->flow_controller()->bytes_consumed());
  EXPECT_EQ(kByteOffset + frame.data_length,
            stream->flow_controller()->highest_received_byte_offset());

  // Reset stream locally.
  EXPECT_CALL(*connection_, SendRstStream(stream->id(), _, _));
  stream->Reset(QUIC_STREAM_CANCELLED);
  EXPECT_EQ(kByteOffset + frame.data_length,
            session_.flow_controller()->bytes_consumed());
}

TEST_P(QuicSessionTestServer, ConnectionFlowControlAccountingFinAfterRst) {
  // Test that when we RST the stream (and tear down stream state), and then
  // receive a FIN from the peer, we correctly adjust our connection level flow
  // control receive window.

  // Connection starts with some non-zero highest received byte offset,
  // due to other active streams.
  const uint64_t kInitialConnectionBytesConsumed = 567;
  const uint64_t kInitialConnectionHighestReceivedOffset = 1234;
  EXPECT_LT(kInitialConnectionBytesConsumed,
            kInitialConnectionHighestReceivedOffset);
  session_.flow_controller()->UpdateHighestReceivedOffset(
      kInitialConnectionHighestReceivedOffset);
  session_.flow_controller()->AddBytesConsumed(kInitialConnectionBytesConsumed);

  // Reset our stream: this results in the stream being closed locally.
  TestStream* stream = session_.CreateOutgoingDynamicStream(kDefaultPriority);
  EXPECT_CALL(*connection_, SendRstStream(stream->id(), _, _));
  stream->Reset(QUIC_STREAM_CANCELLED);

  // Now receive a response from the peer with a FIN. We should handle this by
  // adjusting the connection level flow control receive window to take into
  // account the total number of bytes sent by the peer.
  const QuicStreamOffset kByteOffset = 5678;
  string body = "hello";
  QuicStreamFrame frame(stream->id(), true, kByteOffset, StringPiece(body));
  session_.OnStreamFrame(frame);

  QuicStreamOffset total_stream_bytes_sent_by_peer =
      kByteOffset + body.length();
  EXPECT_EQ(kInitialConnectionBytesConsumed + total_stream_bytes_sent_by_peer,
            session_.flow_controller()->bytes_consumed());
  EXPECT_EQ(
      kInitialConnectionHighestReceivedOffset + total_stream_bytes_sent_by_peer,
      session_.flow_controller()->highest_received_byte_offset());
}

TEST_P(QuicSessionTestServer, ConnectionFlowControlAccountingRstAfterRst) {
  // Test that when we RST the stream (and tear down stream state), and then
  // receive a RST from the peer, we correctly adjust our connection level flow
  // control receive window.

  // Connection starts with some non-zero highest received byte offset,
  // due to other active streams.
  const uint64_t kInitialConnectionBytesConsumed = 567;
  const uint64_t kInitialConnectionHighestReceivedOffset = 1234;
  EXPECT_LT(kInitialConnectionBytesConsumed,
            kInitialConnectionHighestReceivedOffset);
  session_.flow_controller()->UpdateHighestReceivedOffset(
      kInitialConnectionHighestReceivedOffset);
  session_.flow_controller()->AddBytesConsumed(kInitialConnectionBytesConsumed);

  // Reset our stream: this results in the stream being closed locally.
  TestStream* stream = session_.CreateOutgoingDynamicStream(kDefaultPriority);
  EXPECT_CALL(*connection_, SendRstStream(stream->id(), _, _));
  stream->Reset(QUIC_STREAM_CANCELLED);
  EXPECT_TRUE(QuicStreamPeer::read_side_closed(stream));

  // Now receive a RST from the peer. We should handle this by adjusting the
  // connection level flow control receive window to take into account the total
  // number of bytes sent by the peer.
  const QuicStreamOffset kByteOffset = 5678;
  QuicRstStreamFrame rst_frame(stream->id(), QUIC_STREAM_CANCELLED,
                               kByteOffset);
  session_.OnRstStream(rst_frame);

  EXPECT_EQ(kInitialConnectionBytesConsumed + kByteOffset,
            session_.flow_controller()->bytes_consumed());
  EXPECT_EQ(kInitialConnectionHighestReceivedOffset + kByteOffset,
            session_.flow_controller()->highest_received_byte_offset());
}

TEST_P(QuicSessionTestServer, InvalidStreamFlowControlWindowInHandshake) {
  // Test that receipt of an invalid (< default) stream flow control window from
  // the peer results in the connection being torn down.
  const uint32_t kInvalidWindow = kMinimumFlowControlSendWindow - 1;
  QuicConfigPeer::SetReceivedInitialStreamFlowControlWindow(session_.config(),
                                                            kInvalidWindow);

  EXPECT_CALL(*connection_,
              CloseConnection(QUIC_FLOW_CONTROL_INVALID_WINDOW, _, _));
  session_.OnConfigNegotiated();
}

TEST_P(QuicSessionTestServer, InvalidSessionFlowControlWindowInHandshake) {
  // Test that receipt of an invalid (< default) session flow control window
  // from the peer results in the connection being torn down.
  const uint32_t kInvalidWindow = kMinimumFlowControlSendWindow - 1;
  QuicConfigPeer::SetReceivedInitialSessionFlowControlWindow(session_.config(),
                                                             kInvalidWindow);

  EXPECT_CALL(*connection_,
              CloseConnection(QUIC_FLOW_CONTROL_INVALID_WINDOW, _, _));
  session_.OnConfigNegotiated();
}

TEST_P(QuicSessionTestServer, FlowControlWithInvalidFinalOffset) {
  // Test that if we receive a stream RST with a highest byte offset that
  // violates flow control, that we close the connection.
  const uint64_t kLargeOffset = kInitialSessionFlowControlWindowForTest + 1;
  EXPECT_CALL(*connection_,
              CloseConnection(QUIC_FLOW_CONTROL_RECEIVED_TOO_MUCH_DATA, _, _))
      .Times(2);

  // Check that stream frame + FIN results in connection close.
  TestStream* stream = session_.CreateOutgoingDynamicStream(kDefaultPriority);
  EXPECT_CALL(*connection_, SendRstStream(stream->id(), _, _));
  stream->Reset(QUIC_STREAM_CANCELLED);
  QuicStreamFrame frame(stream->id(), true, kLargeOffset, StringPiece());
  session_.OnStreamFrame(frame);

  // Check that RST results in connection close.
  QuicRstStreamFrame rst_frame(stream->id(), QUIC_STREAM_CANCELLED,
                               kLargeOffset);
  session_.OnRstStream(rst_frame);
}

TEST_P(QuicSessionTestServer, WindowUpdateUnblocksHeadersStream) {
  // Test that a flow control blocked headers stream gets unblocked on recipt of
  // a WINDOW_UPDATE frame.

  // Set the headers stream to be flow control blocked.
  QuicHeadersStream* headers_stream =
      QuicSpdySessionPeer::GetHeadersStream(&session_);
  QuicFlowControllerPeer::SetSendWindowOffset(headers_stream->flow_controller(),
                                              0);
  EXPECT_TRUE(headers_stream->flow_controller()->IsBlocked());
  EXPECT_FALSE(session_.IsConnectionFlowControlBlocked());
  EXPECT_TRUE(session_.IsStreamFlowControlBlocked());

  // Unblock the headers stream by supplying a WINDOW_UPDATE.
  QuicWindowUpdateFrame window_update_frame(headers_stream->id(),
                                            2 * kMinimumFlowControlSendWindow);
  session_.OnWindowUpdateFrame(window_update_frame);
  EXPECT_FALSE(headers_stream->flow_controller()->IsBlocked());
  EXPECT_FALSE(session_.IsConnectionFlowControlBlocked());
  EXPECT_FALSE(session_.IsStreamFlowControlBlocked());
}

TEST_P(QuicSessionTestServer, TooManyUnfinishedStreamsCauseServerRejectStream) {
  // If a buggy/malicious peer creates too many streams that are not ended
  // with a FIN or RST then we send an RST to refuse streams.
  const QuicStreamId kMaxStreams = 5;
  QuicSessionPeer::SetMaxOpenIncomingStreams(&session_, kMaxStreams);
  const QuicStreamId kFirstStreamId = kClientDataStreamId1;
  const QuicStreamId kFinalStreamId = kClientDataStreamId1 + 2 * kMaxStreams;

  // Create kMaxStreams data streams, and close them all without receiving a
  // FIN or a RST_STREAM from the client.
  for (QuicStreamId i = kFirstStreamId; i < kFinalStreamId; i += 2) {
    QuicStreamFrame data1(i, false, 0, StringPiece("HT"));
    session_.OnStreamFrame(data1);
    // EXPECT_EQ(1u, session_.GetNumOpenStreams());
    EXPECT_CALL(*connection_, SendRstStream(i, _, _));
    session_.CloseStream(i);
  }

  EXPECT_CALL(*connection_,
              SendRstStream(kFinalStreamId, QUIC_REFUSED_STREAM, _))
      .Times(1);
  // Create one more data streams to exceed limit of open stream.
  QuicStreamFrame data1(kFinalStreamId, false, 0, StringPiece("HT"));
  session_.OnStreamFrame(data1);

  // Called after any new data is received by the session, and triggers the
  // call to close the connection.
  session_.PostProcessAfterData();
}

TEST_P(QuicSessionTestServer, DrainingStreamsDoNotCountAsOpened) {
  // Verify that a draining stream (which has received a FIN but not consumed
  // it) does not count against the open quota (because it is closed from the
  // protocol point of view).
  EXPECT_CALL(*connection_, SendRstStream(_, QUIC_REFUSED_STREAM, _)).Times(0);
  const QuicStreamId kMaxStreams = 5;
  QuicSessionPeer::SetMaxOpenIncomingStreams(&session_, kMaxStreams);

  // Create kMaxStreams + 1 data streams, and mark them draining.
  const QuicStreamId kFirstStreamId = kClientDataStreamId1;
  const QuicStreamId kFinalStreamId =
      kClientDataStreamId1 + 2 * kMaxStreams + 1;
  for (QuicStreamId i = kFirstStreamId; i < kFinalStreamId; i += 2) {
    QuicStreamFrame data1(i, true, 0, StringPiece("HT"));
    session_.OnStreamFrame(data1);
    EXPECT_EQ(1u, session_.GetNumOpenIncomingStreams());
    session_.StreamDraining(i);
    EXPECT_EQ(0u, session_.GetNumOpenIncomingStreams());
  }

  // Called after any new data is received by the session, and triggers the call
  // to close the connection.
  session_.PostProcessAfterData();
}

TEST_P(QuicSessionTestServer, TestMaxIncomingAndOutgoingStreamsAllowed) {
  // Tests that on server side, the value of max_open_incoming/outgoing streams
  // are setup correctly during negotiation.
  // The value for outgoing stream is limited to negotiated value and for
  // incoming stream it is set to be larger than that.
  session_.OnConfigNegotiated();
  // The max number of open outgoing streams is less than that of incoming
  // streams, and it should be same as negotiated value.
  EXPECT_LT(session_.max_open_outgoing_streams(),
            session_.max_open_incoming_streams());
  EXPECT_EQ(session_.max_open_outgoing_streams(),
            kDefaultMaxStreamsPerConnection);
  EXPECT_GT(session_.max_open_incoming_streams(),
            kDefaultMaxStreamsPerConnection);
}

TEST_P(QuicSessionTestServer, EnableFHOLThroughConfigOption) {
  QuicConfigPeer::SetReceivedForceHolBlocking(session_.config());
  session_.OnConfigNegotiated();
  if (version() <= QUIC_VERSION_35) {
    EXPECT_FALSE(session_.force_hol_blocking());
  } else {
    EXPECT_TRUE(session_.force_hol_blocking());
  }
}

class QuicSessionTestClient : public QuicSessionTestBase {
 protected:
  QuicSessionTestClient() : QuicSessionTestBase(Perspective::IS_CLIENT) {}
};

INSTANTIATE_TEST_CASE_P(Tests,
                        QuicSessionTestClient,
                        ::testing::ValuesIn(AllSupportedVersions()));

TEST_P(QuicSessionTestClient, AvailableStreamsClient) {
  ASSERT_TRUE(session_.GetOrCreateDynamicStream(6) != nullptr);
  // Both 2 and 4 should be available.
  EXPECT_TRUE(QuicSessionPeer::IsStreamAvailable(&session_, 2));
  EXPECT_TRUE(QuicSessionPeer::IsStreamAvailable(&session_, 4));
  ASSERT_TRUE(session_.GetOrCreateDynamicStream(2) != nullptr);
  ASSERT_TRUE(session_.GetOrCreateDynamicStream(4) != nullptr);
  // And 5 should be not available.
  EXPECT_FALSE(QuicSessionPeer::IsStreamAvailable(&session_, 5));
}

TEST_P(QuicSessionTestClient, RecordFinAfterReadSideClosed) {
  // Verify that an incoming FIN is recorded in a stream object even if the read
  // side has been closed.  This prevents an entry from being made in
  // locally_closed_streams_highest_offset_ (which will never be deleted).
  TestStream* stream = session_.CreateOutgoingDynamicStream(kDefaultPriority);
  QuicStreamId stream_id = stream->id();

  // Close the read side manually.
  QuicStreamPeer::CloseReadSide(stream);

  // Receive a stream data frame with FIN.
  QuicStreamFrame frame(stream_id, true, 0, StringPiece());
  session_.OnStreamFrame(frame);
  EXPECT_TRUE(stream->fin_received());

  // Reset stream locally.
  EXPECT_CALL(*connection_, SendRstStream(stream->id(), _, _));
  stream->Reset(QUIC_STREAM_CANCELLED);
  EXPECT_TRUE(QuicStreamPeer::read_side_closed(stream));

  // Allow the session to delete the stream object.
  session_.PostProcessAfterData();
  EXPECT_TRUE(connection_->connected());
  EXPECT_TRUE(QuicSessionPeer::IsStreamClosed(&session_, stream_id));
  EXPECT_FALSE(QuicSessionPeer::IsStreamCreated(&session_, stream_id));

  // The stream is not waiting for the arrival of the peer's final offset as it
  // was received with the FIN earlier.
  EXPECT_EQ(
      0u,
      QuicSessionPeer::GetLocallyClosedStreamsHighestOffset(&session_).size());
}

TEST_P(QuicSessionTestClient, TestMaxIncomingAndOutgoingStreamsAllowed) {
  // Tests that on client side, the value of max_open_incoming/outgoing streams
  // are setup correctly during negotiation.
  // When flag is true, the value for outgoing stream is limited to negotiated
  // value and for incoming stream it is set to be larger than that.
  session_.OnConfigNegotiated();
  EXPECT_LT(session_.max_open_outgoing_streams(),
            session_.max_open_incoming_streams());
  EXPECT_EQ(session_.max_open_outgoing_streams(),
            kDefaultMaxStreamsPerConnection);
}

TEST_P(QuicSessionTestClient, EnableDHDTThroughConnectionOption) {
  QuicTagVector copt;
  copt.push_back(kDHDT);
  QuicConfigPeer::SetConnectionOptionsToSend(session_.config(), copt);
  session_.OnConfigNegotiated();
  EXPECT_EQ(QuicHeadersStreamPeer::GetSpdyFramer(session_.headers_stream())
                .header_encoder_table_size(),
            0UL);
}

TEST_P(QuicSessionTestClient, EnableFHOLThroughConfigOption) {
  session_.config()->SetForceHolBlocking();
  session_.OnConfigNegotiated();
  if (version() <= QUIC_VERSION_35) {
    EXPECT_FALSE(session_.force_hol_blocking());
  } else {
    EXPECT_TRUE(session_.force_hol_blocking());
  }
}

}  // namespace
}  // namespace test
}  // namespace net
