// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/quic_server_session_base.h"

#include <cstdint>
#include <memory>

#include "base/macros.h"
#include "net/quic/core/crypto/quic_crypto_server_config.h"
#include "net/quic/core/crypto/quic_random.h"
#include "net/quic/core/proto/cached_network_parameters.pb.h"
#include "net/quic/core/quic_connection.h"
#include "net/quic/core/quic_crypto_server_stream.h"
#include "net/quic/core/quic_utils.h"
#include "net/quic/platform/api/quic_flags.h"
#include "net/quic/platform/api/quic_ptr_util.h"
#include "net/quic/platform/api/quic_socket_address.h"
#include "net/quic/platform/api/quic_test.h"
#include "net/quic/test_tools/crypto_test_utils.h"
#include "net/quic/test_tools/fake_proof_source.h"
#include "net/quic/test_tools/quic_config_peer.h"
#include "net/quic/test_tools/quic_connection_peer.h"
#include "net/quic/test_tools/quic_crypto_server_config_peer.h"
#include "net/quic/test_tools/quic_sent_packet_manager_peer.h"
#include "net/quic/test_tools/quic_session_peer.h"
#include "net/quic/test_tools/quic_spdy_session_peer.h"
#include "net/quic/test_tools/quic_spdy_stream_peer.h"
#include "net/quic/test_tools/quic_stream_peer.h"
#include "net/quic/test_tools/quic_sustained_bandwidth_recorder_peer.h"
#include "net/quic/test_tools/quic_test_utils.h"
#include "net/test/gtest_util.h"
#include "net/tools/quic/quic_epoll_connection_helper.h"
#include "net/tools/quic/quic_simple_server_stream.h"
#include "net/tools/quic/test_tools/mock_quic_session_visitor.h"

using std::string;
using testing::StrictMock;
using testing::_;

namespace net {
namespace test {

class QuicServerSessionBasePeer {
 public:
  static QuicStream* GetOrCreateDynamicStream(QuicServerSessionBase* s,
                                              QuicStreamId id) {
    return s->GetOrCreateDynamicStream(id);
  }
  static void SetCryptoStream(QuicServerSessionBase* s,
                              QuicCryptoServerStream* crypto_stream) {
    s->crypto_stream_.reset(crypto_stream);
    s->static_streams()[kCryptoStreamId] = crypto_stream;
  }
  static bool IsBandwidthResumptionEnabled(QuicServerSessionBase* s) {
    return s->bandwidth_resumption_enabled_;
  }
};

namespace {

class TestServerSession : public QuicServerSessionBase {
 public:
  TestServerSession(const QuicConfig& config,
                    QuicConnection* connection,
                    QuicSession::Visitor* visitor,
                    QuicCryptoServerStream::Helper* helper,
                    const QuicCryptoServerConfig* crypto_config,
                    QuicCompressedCertsCache* compressed_certs_cache,
                    QuicHttpResponseCache* response_cache)
      : QuicServerSessionBase(config,
                              connection,
                              visitor,
                              helper,
                              crypto_config,
                              compressed_certs_cache),
        response_cache_(response_cache) {}

  ~TestServerSession() override { delete connection(); };

 protected:
  // TODO(ckrasic) - for two below, remove when
  // quic_reloadable_flag_quic_refactor_stream_creation is deprecated.
  QuicSpdyStream* CreateIncomingDynamicStream(QuicStreamId id) override {
    if (!ShouldCreateIncomingDynamicStream(id)) {
      return nullptr;
    }
    QuicSpdyStream* stream =
        new QuicSimpleServerStream(id, this, response_cache_);
    ActivateStream(QuicWrapUnique(stream));
    return stream;
  }

  QuicSpdyStream* CreateOutgoingDynamicStream(SpdyPriority priority) override {
    if (!ShouldCreateOutgoingDynamicStream()) {
      return nullptr;
    }

    QuicSpdyStream* stream = new QuicSimpleServerStream(
        GetNextOutgoingStreamId(), this, response_cache_);
    stream->SetPriority(priority);
    ActivateStream(QuicWrapUnique(stream));
    return stream;
  }

  std::unique_ptr<QuicStream> CreateStream(QuicStreamId id) override {
    return QuicMakeUnique<QuicSimpleServerStream>(id, this, response_cache_);
  }

  QuicCryptoServerStreamBase* CreateQuicCryptoServerStream(
      const QuicCryptoServerConfig* crypto_config,
      QuicCompressedCertsCache* compressed_certs_cache) override {
    return new QuicCryptoServerStream(
        crypto_config, compressed_certs_cache,
        FLAGS_quic_reloadable_flag_enable_quic_stateless_reject_support, this,
        stream_helper());
  }

 private:
  QuicHttpResponseCache* response_cache_;  // Owned by QuicServerSessionBaseTest
};

const size_t kMaxStreamsForTest = 10;

class QuicServerSessionBaseTest : public QuicTestWithParam<QuicVersion> {
 protected:
  QuicServerSessionBaseTest()
      : QuicServerSessionBaseTest(crypto_test_utils::ProofSourceForTesting()) {}

  explicit QuicServerSessionBaseTest(std::unique_ptr<ProofSource> proof_source)
      : crypto_config_(QuicCryptoServerConfig::TESTING,
                       QuicRandom::GetInstance(),
                       std::move(proof_source)),
        compressed_certs_cache_(
            QuicCompressedCertsCache::kQuicCompressedCertsCacheSize) {
    config_.SetMaxStreamsPerConnection(kMaxStreamsForTest, kMaxStreamsForTest);
    config_.SetMaxIncomingDynamicStreamsToSend(kMaxStreamsForTest);
    QuicConfigPeer::SetReceivedMaxIncomingDynamicStreams(&config_,
                                                         kMaxStreamsForTest);
    config_.SetInitialStreamFlowControlWindowToSend(
        kInitialStreamFlowControlWindowForTest);
    config_.SetInitialSessionFlowControlWindowToSend(
        kInitialSessionFlowControlWindowForTest);

    connection_ = new StrictMock<MockQuicConnection>(
        &helper_, &alarm_factory_, Perspective::IS_SERVER,
        SupportedVersions(GetParam()));
    session_.reset(new TestServerSession(
        config_, connection_, &owner_, &stream_helper_, &crypto_config_,
        &compressed_certs_cache_, &response_cache_));
    MockClock clock;
    handshake_message_.reset(crypto_config_.AddDefaultConfig(
        QuicRandom::GetInstance(), &clock,
        QuicCryptoServerConfig::ConfigOptions()));
    session_->Initialize();
    visitor_ = QuicConnectionPeer::GetVisitor(connection_);
  }

  QuicStreamId GetNthClientInitiatedId(int n) {
    return QuicSpdySessionPeer::GetNthClientInitiatedStreamId(*session_, n);
  }

  QuicStreamId GetNthServerInitiatedId(int n) {
    return QuicSpdySessionPeer::GetNthServerInitiatedStreamId(*session_, n);
  }

  StrictMock<MockQuicSessionVisitor> owner_;
  StrictMock<MockQuicCryptoServerStreamHelper> stream_helper_;
  MockQuicConnectionHelper helper_;
  MockAlarmFactory alarm_factory_;
  StrictMock<MockQuicConnection>* connection_;
  QuicConfig config_;
  QuicCryptoServerConfig crypto_config_;
  QuicCompressedCertsCache compressed_certs_cache_;
  QuicHttpResponseCache response_cache_;
  std::unique_ptr<TestServerSession> session_;
  std::unique_ptr<CryptoHandshakeMessage> handshake_message_;
  QuicConnectionVisitorInterface* visitor_;
};

// Compares CachedNetworkParameters.
MATCHER_P(EqualsProto, network_params, "") {
  CachedNetworkParameters reference(network_params);
  return (arg->bandwidth_estimate_bytes_per_second() ==
              reference.bandwidth_estimate_bytes_per_second() &&
          arg->bandwidth_estimate_bytes_per_second() ==
              reference.bandwidth_estimate_bytes_per_second() &&
          arg->max_bandwidth_estimate_bytes_per_second() ==
              reference.max_bandwidth_estimate_bytes_per_second() &&
          arg->max_bandwidth_timestamp_seconds() ==
              reference.max_bandwidth_timestamp_seconds() &&
          arg->min_rtt_ms() == reference.min_rtt_ms() &&
          arg->previous_connection_state() ==
              reference.previous_connection_state());
}

INSTANTIATE_TEST_CASE_P(Tests,
                        QuicServerSessionBaseTest,
                        ::testing::ValuesIn(AllSupportedVersions()));
TEST_P(QuicServerSessionBaseTest, ServerPushDisabledByDefault) {
  FLAGS_quic_reloadable_flag_quic_enable_server_push_by_default = true;
  // Without the client explicitly sending kSPSH, server push will be disabled
  // at the server, until version 35 when it is enabled by default.
  EXPECT_FALSE(
      session_->config()->HasReceivedConnectionOptions() &&
      ContainsQuicTag(session_->config()->ReceivedConnectionOptions(), kSPSH));
  session_->OnConfigNegotiated();
  EXPECT_TRUE(session_->server_push_enabled());
}

TEST_P(QuicServerSessionBaseTest, CloseStreamDueToReset) {
  // Open a stream, then reset it.
  // Send two bytes of payload to open it.
  QuicStreamFrame data1(GetNthClientInitiatedId(0), false, 0,
                        QuicStringPiece("HT"));
  session_->OnStreamFrame(data1);
  EXPECT_EQ(1u, session_->GetNumOpenIncomingStreams());

  // Send a reset (and expect the peer to send a RST in response).
  QuicRstStreamFrame rst1(GetNthClientInitiatedId(0),
                          QUIC_ERROR_PROCESSING_STREAM, 0);
  EXPECT_CALL(owner_, OnRstStreamReceived(_)).Times(1);
  EXPECT_CALL(*connection_, SendRstStream(GetNthClientInitiatedId(0),
                                          QUIC_RST_ACKNOWLEDGEMENT, 0));
  visitor_->OnRstStream(rst1);
  EXPECT_EQ(0u, session_->GetNumOpenIncomingStreams());

  // Send the same two bytes of payload in a new packet.
  visitor_->OnStreamFrame(data1);

  // The stream should not be re-opened.
  EXPECT_EQ(0u, session_->GetNumOpenIncomingStreams());
  EXPECT_TRUE(connection_->connected());
}

TEST_P(QuicServerSessionBaseTest, NeverOpenStreamDueToReset) {
  // Send a reset (and expect the peer to send a RST in response).
  QuicRstStreamFrame rst1(GetNthClientInitiatedId(0),
                          QUIC_ERROR_PROCESSING_STREAM, 0);
  EXPECT_CALL(owner_, OnRstStreamReceived(_)).Times(1);
  EXPECT_CALL(*connection_, SendRstStream(GetNthClientInitiatedId(0),
                                          QUIC_RST_ACKNOWLEDGEMENT, 0));
  visitor_->OnRstStream(rst1);
  EXPECT_EQ(0u, session_->GetNumOpenIncomingStreams());

  // Send two bytes of payload.
  QuicStreamFrame data1(GetNthClientInitiatedId(0), false, 0,
                        QuicStringPiece("HT"));
  visitor_->OnStreamFrame(data1);

  // The stream should never be opened, now that the reset is received.
  EXPECT_EQ(0u, session_->GetNumOpenIncomingStreams());
  EXPECT_TRUE(connection_->connected());
}

TEST_P(QuicServerSessionBaseTest, AcceptClosedStream) {
  // Send (empty) compressed headers followed by two bytes of data.
  QuicStreamFrame frame1(GetNthClientInitiatedId(0), false, 0,
                         QuicStringPiece("\1\0\0\0\0\0\0\0HT"));
  QuicStreamFrame frame2(GetNthClientInitiatedId(1), false, 0,
                         QuicStringPiece("\2\0\0\0\0\0\0\0HT"));
  visitor_->OnStreamFrame(frame1);
  visitor_->OnStreamFrame(frame2);
  EXPECT_EQ(2u, session_->GetNumOpenIncomingStreams());

  // Send a reset (and expect the peer to send a RST in response).
  QuicRstStreamFrame rst(GetNthClientInitiatedId(0),
                         QUIC_ERROR_PROCESSING_STREAM, 0);
  EXPECT_CALL(owner_, OnRstStreamReceived(_)).Times(1);
  EXPECT_CALL(*connection_, SendRstStream(GetNthClientInitiatedId(0),
                                          QUIC_RST_ACKNOWLEDGEMENT, 0));
  visitor_->OnRstStream(rst);

  // If we were tracking, we'd probably want to reject this because it's data
  // past the reset point of stream 3.  As it's a closed stream we just drop the
  // data on the floor, but accept the packet because it has data for stream 5.
  QuicStreamFrame frame3(GetNthClientInitiatedId(0), false, 2,
                         QuicStringPiece("TP"));
  QuicStreamFrame frame4(GetNthClientInitiatedId(1), false, 2,
                         QuicStringPiece("TP"));
  visitor_->OnStreamFrame(frame3);
  visitor_->OnStreamFrame(frame4);
  // The stream should never be opened, now that the reset is received.
  EXPECT_EQ(1u, session_->GetNumOpenIncomingStreams());
  EXPECT_TRUE(connection_->connected());
}

TEST_P(QuicServerSessionBaseTest, MaxOpenStreams) {
  // Test that the server refuses if a client attempts to open too many data
  // streams.  The server accepts slightly more than the negotiated stream limit
  // to deal with rare cases where a client FIN/RST is lost.

  // The slightly increased stream limit is set during config negotiation.  It
  // is either an increase of 10 over negotiated limit, or a fixed percentage
  // scaling, whichever is larger. Test both before continuing.
  session_->OnConfigNegotiated();
  EXPECT_LT(kMaxStreamsMultiplier * kMaxStreamsForTest,
            kMaxStreamsForTest + kMaxStreamsMinimumIncrement);
  EXPECT_EQ(kMaxStreamsForTest + kMaxStreamsMinimumIncrement,
            session_->max_open_incoming_streams());
  EXPECT_EQ(0u, session_->GetNumOpenIncomingStreams());
  QuicStreamId stream_id = GetNthClientInitiatedId(0);
  // Open the max configured number of streams, should be no problem.
  for (size_t i = 0; i < kMaxStreamsForTest; ++i) {
    EXPECT_TRUE(QuicServerSessionBasePeer::GetOrCreateDynamicStream(
        session_.get(), stream_id));
    stream_id += QuicSpdySessionPeer::NextStreamId(*session_);
  }

  // Open more streams: server should accept slightly more than the limit.
  for (size_t i = 0; i < kMaxStreamsMinimumIncrement; ++i) {
    EXPECT_TRUE(QuicServerSessionBasePeer::GetOrCreateDynamicStream(
        session_.get(), stream_id));
    stream_id += QuicSpdySessionPeer::NextStreamId(*session_);
  }

  // Now violate the server's internal stream limit.
  stream_id += QuicSpdySessionPeer::NextStreamId(*session_);
  EXPECT_CALL(*connection_, CloseConnection(_, _, _)).Times(0);
  EXPECT_CALL(*connection_, SendRstStream(stream_id, QUIC_REFUSED_STREAM, 0));
  // Even if the connection remains open, the stream creation should fail.
  EXPECT_FALSE(QuicServerSessionBasePeer::GetOrCreateDynamicStream(
      session_.get(), stream_id));
}

TEST_P(QuicServerSessionBaseTest, MaxAvailableStreams) {
  // Test that the server closes the connection if a client makes too many data
  // streams available.  The server accepts slightly more than the negotiated
  // stream limit to deal with rare cases where a client FIN/RST is lost.

  session_->OnConfigNegotiated();
  const size_t kAvailableStreamLimit = session_->MaxAvailableStreams();
  EXPECT_EQ(
      session_->max_open_incoming_streams() * kMaxAvailableStreamsMultiplier,
      session_->MaxAvailableStreams());
  // The protocol specification requires that there can be at least 10 times
  // as many available streams as the connection's maximum open streams.
  EXPECT_LE(10 * kMaxStreamsForTest, kAvailableStreamLimit);

  EXPECT_EQ(0u, session_->GetNumOpenIncomingStreams());
  EXPECT_TRUE(QuicServerSessionBasePeer::GetOrCreateDynamicStream(
      session_.get(), GetNthClientInitiatedId(0)));

  // Establish available streams up to the server's limit.
  QuicStreamId next_id = QuicSpdySessionPeer::NextStreamId(*session_);
  const int kLimitingStreamId =
      GetNthClientInitiatedId(kAvailableStreamLimit + 1);
  EXPECT_TRUE(QuicServerSessionBasePeer::GetOrCreateDynamicStream(
      session_.get(), kLimitingStreamId));

  // A further available stream will result in connection close.
  EXPECT_CALL(*connection_,
              CloseConnection(QUIC_TOO_MANY_AVAILABLE_STREAMS, _, _));
  // This forces stream kLimitingStreamId + 2 to become available, which
  // violates the quota.
  EXPECT_FALSE(QuicServerSessionBasePeer::GetOrCreateDynamicStream(
      session_.get(), kLimitingStreamId + 2 * next_id));
}

// TODO(ckrasic): remove this when
// FLAGS_quic_reloadable_flag_quic_enable_server_push_by_default is
// deprecated.
TEST_P(QuicServerSessionBaseTest, EnableServerPushThroughConnectionOption) {
  FLAGS_quic_reloadable_flag_quic_enable_server_push_by_default = false;
  // Assume server received server push connection option.
  QuicTagVector copt;
  copt.push_back(kSPSH);
  QuicConfigPeer::SetReceivedConnectionOptions(session_->config(), copt);
  session_->OnConfigNegotiated();
  EXPECT_TRUE(session_->server_push_enabled());
}

TEST_P(QuicServerSessionBaseTest, GetEvenIncomingError) {
  // Incoming streams on the server session must be odd.
  EXPECT_CALL(*connection_, CloseConnection(QUIC_INVALID_STREAM_ID, _, _));
  EXPECT_EQ(nullptr, QuicServerSessionBasePeer::GetOrCreateDynamicStream(
                         session_.get(), GetNthServerInitiatedId(0)));
}

TEST_P(QuicServerSessionBaseTest, GetStreamDisconnected) {
  // Don't create new streams if the connection is disconnected.
  QuicConnectionPeer::TearDownLocalConnectionState(connection_);
  if (FLAGS_quic_reloadable_flag_quic_refactor_stream_creation) {
    EXPECT_EQ(nullptr, QuicServerSessionBasePeer::GetOrCreateDynamicStream(
                           session_.get(), GetNthClientInitiatedId(0)));
  } else {
    EXPECT_QUIC_BUG(
        QuicServerSessionBasePeer::GetOrCreateDynamicStream(
            session_.get(), GetNthClientInitiatedId(0)),
        "ShouldCreateIncomingDynamicStream called when disconnected");
  }
}

class MockQuicCryptoServerStream : public QuicCryptoServerStream {
 public:
  explicit MockQuicCryptoServerStream(
      const QuicCryptoServerConfig* crypto_config,
      QuicCompressedCertsCache* compressed_certs_cache,
      QuicServerSessionBase* session,
      QuicCryptoServerStream::Helper* helper)
      : QuicCryptoServerStream(
            crypto_config,
            compressed_certs_cache,
            FLAGS_quic_reloadable_flag_enable_quic_stateless_reject_support,
            session,
            helper) {}
  ~MockQuicCryptoServerStream() override {}

  MOCK_METHOD1(SendServerConfigUpdate,
               void(const CachedNetworkParameters* cached_network_parameters));

  void set_encryption_established(bool has_established) {
    encryption_established_ = has_established;
  }

 private:
  DISALLOW_COPY_AND_ASSIGN(MockQuicCryptoServerStream);
};

TEST_P(QuicServerSessionBaseTest, BandwidthEstimates) {
  // Test that bandwidth estimate updates are sent to the client, only when
  // bandwidth resumption is enabled, the bandwidth estimate has changed
  // sufficiently, enough time has passed,
  // and we don't have any other data to write.

  // Client has sent kBWRE connection option to trigger bandwidth resumption.
  QuicTagVector copt;
  copt.push_back(kBWRE);
  QuicConfigPeer::SetReceivedConnectionOptions(session_->config(), copt);
  session_->OnConfigNegotiated();
  EXPECT_TRUE(
      QuicServerSessionBasePeer::IsBandwidthResumptionEnabled(session_.get()));

  int32_t bandwidth_estimate_kbytes_per_second = 123;
  int32_t max_bandwidth_estimate_kbytes_per_second = 134;
  int32_t max_bandwidth_estimate_timestamp = 1122334455;
  const string serving_region = "not a real region";
  session_->set_serving_region(serving_region);

  MockQuicCryptoServerStream* crypto_stream =
      new MockQuicCryptoServerStream(&crypto_config_, &compressed_certs_cache_,
                                     session_.get(), &stream_helper_);
  QuicServerSessionBasePeer::SetCryptoStream(session_.get(), crypto_stream);

  // Set some initial bandwidth values.
  QuicSentPacketManager* sent_packet_manager =
      QuicConnectionPeer::GetSentPacketManager(session_->connection());
  QuicSustainedBandwidthRecorder& bandwidth_recorder =
      QuicSentPacketManagerPeer::GetBandwidthRecorder(sent_packet_manager);
  // Seed an rtt measurement equal to the initial default rtt.
  RttStats* rtt_stats =
      const_cast<RttStats*>(sent_packet_manager->GetRttStats());
  rtt_stats->UpdateRtt(
      QuicTime::Delta::FromMicroseconds(rtt_stats->initial_rtt_us()),
      QuicTime::Delta::Zero(), QuicTime::Zero());
  QuicSustainedBandwidthRecorderPeer::SetBandwidthEstimate(
      &bandwidth_recorder, bandwidth_estimate_kbytes_per_second);
  QuicSustainedBandwidthRecorderPeer::SetMaxBandwidthEstimate(
      &bandwidth_recorder, max_bandwidth_estimate_kbytes_per_second,
      max_bandwidth_estimate_timestamp);
  // Queue up some pending data.
  session_->MarkConnectionLevelWriteBlocked(kCryptoStreamId);
  EXPECT_TRUE(session_->HasDataToWrite());

  // There will be no update sent yet - not enough time has passed.
  QuicTime now = QuicTime::Zero();
  session_->OnCongestionWindowChange(now);

  // Bandwidth estimate has now changed sufficiently but not enough time has
  // passed to send a Server Config Update.
  bandwidth_estimate_kbytes_per_second =
      bandwidth_estimate_kbytes_per_second * 1.6;
  session_->OnCongestionWindowChange(now);

  // Bandwidth estimate has now changed sufficiently and enough time has passed,
  // but not enough packets have been sent.
  int64_t srtt_ms =
      sent_packet_manager->GetRttStats()->smoothed_rtt().ToMilliseconds();
  now = now + QuicTime::Delta::FromMilliseconds(
                  kMinIntervalBetweenServerConfigUpdatesRTTs * srtt_ms);
  session_->OnCongestionWindowChange(now);

  // The connection no longer has pending data to be written.
  session_->OnCanWrite();
  EXPECT_FALSE(session_->HasDataToWrite());
  session_->OnCongestionWindowChange(now);

  // Bandwidth estimate has now changed sufficiently, enough time has passed,
  // and enough packets have been sent.
  SerializedPacket packet(1 + kMinPacketsBetweenServerConfigUpdates,
                          PACKET_6BYTE_PACKET_NUMBER, nullptr, 1000, false,
                          false);
  sent_packet_manager->OnPacketSent(&packet, 0, now, NOT_RETRANSMISSION,
                                    HAS_RETRANSMITTABLE_DATA);

  // Verify that the proto has exactly the values we expect.
  CachedNetworkParameters expected_network_params;
  expected_network_params.set_bandwidth_estimate_bytes_per_second(
      bandwidth_recorder.BandwidthEstimate().ToBytesPerSecond());
  expected_network_params.set_max_bandwidth_estimate_bytes_per_second(
      bandwidth_recorder.MaxBandwidthEstimate().ToBytesPerSecond());
  expected_network_params.set_max_bandwidth_timestamp_seconds(
      bandwidth_recorder.MaxBandwidthTimestamp());
  expected_network_params.set_min_rtt_ms(session_->connection()
                                             ->sent_packet_manager()
                                             .GetRttStats()
                                             ->min_rtt()
                                             .ToMilliseconds());
  expected_network_params.set_previous_connection_state(
      CachedNetworkParameters::CONGESTION_AVOIDANCE);
  expected_network_params.set_timestamp(
      session_->connection()->clock()->WallNow().ToUNIXSeconds());
  expected_network_params.set_serving_region(serving_region);

  EXPECT_CALL(*crypto_stream,
              SendServerConfigUpdate(EqualsProto(expected_network_params)))
      .Times(1);
  EXPECT_CALL(*connection_, OnSendConnectionState(_)).Times(1);
  session_->OnCongestionWindowChange(now);
}

TEST_P(QuicServerSessionBaseTest, BandwidthResumptionExperiment) {
  // Test that if a client provides a CachedNetworkParameters with the same
  // serving region as the current server, and which was made within an hour of
  // now, that this data is passed down to the send algorithm.

  // Client has sent kBWRE connection option to trigger bandwidth resumption.
  QuicTagVector copt;
  copt.push_back(kBWRE);
  QuicConfigPeer::SetReceivedConnectionOptions(session_->config(), copt);

  const string kTestServingRegion = "a serving region";
  session_->set_serving_region(kTestServingRegion);

  // Set the time to be one hour + one second from the 0 baseline.
  connection_->AdvanceTime(
      QuicTime::Delta::FromSeconds(kNumSecondsPerHour + 1));

  QuicCryptoServerStream* crypto_stream = static_cast<QuicCryptoServerStream*>(
      QuicSessionPeer::GetMutableCryptoStream(session_.get()));

  // No effect if no CachedNetworkParameters provided.
  EXPECT_CALL(*connection_, ResumeConnectionState(_, _)).Times(0);
  session_->OnConfigNegotiated();

  // No effect if CachedNetworkParameters provided, but different serving
  // regions.
  CachedNetworkParameters cached_network_params;
  cached_network_params.set_bandwidth_estimate_bytes_per_second(1);
  cached_network_params.set_serving_region("different serving region");
  crypto_stream->SetPreviousCachedNetworkParams(cached_network_params);
  EXPECT_CALL(*connection_, ResumeConnectionState(_, _)).Times(0);
  session_->OnConfigNegotiated();

  // Same serving region, but timestamp is too old, should have no effect.
  cached_network_params.set_serving_region(kTestServingRegion);
  cached_network_params.set_timestamp(0);
  crypto_stream->SetPreviousCachedNetworkParams(cached_network_params);
  EXPECT_CALL(*connection_, ResumeConnectionState(_, _)).Times(0);
  session_->OnConfigNegotiated();

  // Same serving region, and timestamp is recent: estimate is stored.
  cached_network_params.set_timestamp(
      connection_->clock()->WallNow().ToUNIXSeconds());
  crypto_stream->SetPreviousCachedNetworkParams(cached_network_params);
  EXPECT_CALL(*connection_, ResumeConnectionState(_, _)).Times(1);
  session_->OnConfigNegotiated();
}

TEST_P(QuicServerSessionBaseTest, BandwidthMaxEnablesResumption) {
  EXPECT_FALSE(
      QuicServerSessionBasePeer::IsBandwidthResumptionEnabled(session_.get()));

  // Client has sent kBWMX connection option to trigger bandwidth resumption.
  QuicTagVector copt;
  copt.push_back(kBWMX);
  QuicConfigPeer::SetReceivedConnectionOptions(session_->config(), copt);
  session_->OnConfigNegotiated();
  EXPECT_TRUE(
      QuicServerSessionBasePeer::IsBandwidthResumptionEnabled(session_.get()));
}

TEST_P(QuicServerSessionBaseTest, NoBandwidthResumptionByDefault) {
  EXPECT_FALSE(
      QuicServerSessionBasePeer::IsBandwidthResumptionEnabled(session_.get()));
  session_->OnConfigNegotiated();
  EXPECT_FALSE(
      QuicServerSessionBasePeer::IsBandwidthResumptionEnabled(session_.get()));
}

// Tests which check the lifetime management of data members of
// QuicCryptoServerStream objects when async GetProof is in use.
class StreamMemberLifetimeTest : public QuicServerSessionBaseTest {
 public:
  StreamMemberLifetimeTest()
      : QuicServerSessionBaseTest(
            std::unique_ptr<FakeProofSource>(new FakeProofSource())),
        crypto_config_peer_(&crypto_config_) {
    GetFakeProofSource()->Activate();
  }

  FakeProofSource* GetFakeProofSource() const {
    return static_cast<FakeProofSource*>(crypto_config_peer_.GetProofSource());
  }

 private:
  QuicCryptoServerConfigPeer crypto_config_peer_;
};

INSTANTIATE_TEST_CASE_P(StreamMemberLifetimeTests,
                        StreamMemberLifetimeTest,
                        ::testing::ValuesIn(AllSupportedVersions()));

// Trigger an operation which causes an async invocation of
// ProofSource::GetProof.  Delay the completion of the operation until after the
// stream has been destroyed, and verify that there are no memory bugs.
TEST_P(StreamMemberLifetimeTest, Basic) {
  FLAGS_quic_reloadable_flag_enable_quic_stateless_reject_support = true;
  FLAGS_quic_reloadable_flag_quic_use_cheap_stateless_rejects = true;

  const QuicClock* clock = helper_.GetClock();
  QuicVersion version = AllSupportedVersions().front();
  CryptoHandshakeMessage chlo = crypto_test_utils::GenerateDefaultInchoateCHLO(
      clock, version, &crypto_config_);
  chlo.SetVector(kCOPT, QuicTagVector{kSREJ});
  std::vector<QuicVersion> packet_version_list = {version};
  std::unique_ptr<QuicEncryptedPacket> packet(ConstructEncryptedPacket(
      1, true, false, 1,
      string(chlo.GetSerialized(Perspective::IS_CLIENT)
                 .AsStringPiece()
                 .as_string()),
      PACKET_8BYTE_CONNECTION_ID, PACKET_6BYTE_PACKET_NUMBER,
      &packet_version_list));

  EXPECT_CALL(stream_helper_, CanAcceptClientHello(_, _, _))
      .WillOnce(testing::Return(true));
  EXPECT_CALL(stream_helper_, GenerateConnectionIdForReject(_))
      .WillOnce(testing::Return(12345));

  // Set the current packet
  QuicConnectionPeer::SetCurrentPacket(session_->connection(),
                                       packet->AsStringPiece().as_string());

  // Yes, this is horrible.  But it's the easiest way to trigger the behavior we
  // need to exercise.
  QuicCryptoServerStreamBase* crypto_stream =
      const_cast<QuicCryptoServerStreamBase*>(session_->crypto_stream());

  // Feed the CHLO into the crypto stream, which will trigger a call to
  // ProofSource::GetProof
  crypto_stream->OnHandshakeMessage(chlo);
  ASSERT_EQ(GetFakeProofSource()->NumPendingCallbacks(), 1);

  // Destroy the stream
  session_.reset();

  // Allow the async ProofSource::GetProof call to complete.  Verify (under
  // asan) that this does not result in accesses to any freed memory from the
  // session or its subobjects.
  GetFakeProofSource()->InvokePendingCallback(0);
}

}  // namespace
}  // namespace test
}  // namespace net
