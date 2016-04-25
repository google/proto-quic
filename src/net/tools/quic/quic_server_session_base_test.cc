// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/quic/quic_server_session_base.h"

#include <cstdint>
#include <memory>

#include "base/macros.h"
#include "net/quic/crypto/quic_crypto_server_config.h"
#include "net/quic/crypto/quic_random.h"
#include "net/quic/proto/cached_network_parameters.pb.h"
#include "net/quic/quic_connection.h"
#include "net/quic/quic_crypto_server_stream.h"
#include "net/quic/quic_utils.h"
#include "net/quic/test_tools/crypto_test_utils.h"
#include "net/quic/test_tools/quic_config_peer.h"
#include "net/quic/test_tools/quic_connection_peer.h"
#include "net/quic/test_tools/quic_sent_packet_manager_peer.h"
#include "net/quic/test_tools/quic_session_peer.h"
#include "net/quic/test_tools/quic_spdy_session_peer.h"
#include "net/quic/test_tools/quic_spdy_stream_peer.h"
#include "net/quic/test_tools/quic_sustained_bandwidth_recorder_peer.h"
#include "net/quic/test_tools/quic_test_utils.h"
#include "net/test/gtest_util.h"
#include "net/tools/quic/quic_simple_server_stream.h"
#include "net/tools/quic/test_tools/mock_quic_server_session_visitor.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using net::test::CryptoTestUtils;
using net::test::MockConnection;
using net::test::MockConnectionHelper;
using net::test::QuicConfigPeer;
using net::test::QuicConnectionPeer;
using net::test::QuicSpdyStreamPeer;
using net::test::QuicSentPacketManagerPeer;
using net::test::QuicSessionPeer;
using net::test::QuicSpdySessionPeer;
using net::test::QuicSustainedBandwidthRecorderPeer;
using net::test::SupportedVersions;
using net::test::ValueRestore;
using net::test::kClientDataStreamId1;
using net::test::kClientDataStreamId2;
using net::test::kClientDataStreamId3;
using net::test::kInitialSessionFlowControlWindowForTest;
using net::test::kInitialStreamFlowControlWindowForTest;
using std::string;
using testing::StrictMock;
using testing::_;

namespace net {
namespace test {

class QuicServerSessionBasePeer {
 public:
  static ReliableQuicStream* GetOrCreateDynamicStream(QuicServerSessionBase* s,
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
                    QuicServerSessionVisitor* visitor,
                    const QuicCryptoServerConfig* crypto_config,
                    QuicCompressedCertsCache* compressed_certs_cache)
      : QuicServerSessionBase(config,
                              connection,
                              visitor,
                              crypto_config,
                              compressed_certs_cache) {}

  ~TestServerSession() override{};

 protected:
  QuicSpdyStream* CreateIncomingDynamicStream(QuicStreamId id) override {
    if (!ShouldCreateIncomingDynamicStream(id)) {
      return nullptr;
    }
    QuicSpdyStream* stream = new QuicSimpleServerStream(id, this);
    ActivateStream(stream);
    return stream;
  }

  QuicSpdyStream* CreateOutgoingDynamicStream(SpdyPriority priority) override {
    if (!ShouldCreateOutgoingDynamicStream()) {
      return nullptr;
    }

    QuicSpdyStream* stream =
        new QuicSimpleServerStream(GetNextOutgoingStreamId(), this);
    stream->SetPriority(priority);
    ActivateStream(stream);
    return stream;
  }

  QuicCryptoServerStreamBase* CreateQuicCryptoServerStream(
      const QuicCryptoServerConfig* crypto_config,
      QuicCompressedCertsCache* compressed_certs_cache) override {
    return new QuicCryptoServerStream(
        crypto_config, compressed_certs_cache,
        FLAGS_enable_quic_stateless_reject_support, this);
  }
};

const size_t kMaxStreamsForTest = 10;

class QuicServerSessionBaseTest : public ::testing::TestWithParam<QuicVersion> {
 protected:
  QuicServerSessionBaseTest()
      : crypto_config_(QuicCryptoServerConfig::TESTING,
                       QuicRandom::GetInstance(),
                       CryptoTestUtils::ProofSourceForTesting()),
        compressed_certs_cache_(
            QuicCompressedCertsCache::kQuicCompressedCertsCacheSize) {
    FLAGS_quic_always_log_bugs_for_tests = true;
    config_.SetMaxStreamsPerConnection(kMaxStreamsForTest, kMaxStreamsForTest);
    config_.SetInitialStreamFlowControlWindowToSend(
        kInitialStreamFlowControlWindowForTest);
    config_.SetInitialSessionFlowControlWindowToSend(
        kInitialSessionFlowControlWindowForTest);

    connection_ = new StrictMock<MockConnection>(&helper_, &alarm_factory_,
                                                 Perspective::IS_SERVER,
                                                 SupportedVersions(GetParam()));
    session_.reset(new TestServerSession(config_, connection_, &owner_,
                                         &crypto_config_,
                                         &compressed_certs_cache_));
    MockClock clock;
    handshake_message_.reset(crypto_config_.AddDefaultConfig(
        QuicRandom::GetInstance(), &clock,
        QuicCryptoServerConfig::ConfigOptions()));
    session_->Initialize();
    visitor_ = QuicConnectionPeer::GetVisitor(connection_);
  }

  StrictMock<MockQuicServerSessionVisitor> owner_;
  MockConnectionHelper helper_;
  MockAlarmFactory alarm_factory_;
  StrictMock<MockConnection>* connection_;
  QuicConfig config_;
  QuicCryptoServerConfig crypto_config_;
  QuicCompressedCertsCache compressed_certs_cache_;
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
                        ::testing::ValuesIn(QuicSupportedVersions()));

TEST_P(QuicServerSessionBaseTest, ServerPushDisabledByDefault) {
  // Without the client explicitly sending kSPSH, server push will be disabled
  // at the server.
  EXPECT_FALSE(
      session_->config()->HasReceivedConnectionOptions() &&
      ContainsQuicTag(session_->config()->ReceivedConnectionOptions(), kSPSH));
  session_->OnConfigNegotiated();
  EXPECT_FALSE(session_->server_push_enabled());
}

TEST_P(QuicServerSessionBaseTest, CloseStreamDueToReset) {
  // Open a stream, then reset it.
  // Send two bytes of payload to open it.
  QuicStreamFrame data1(kClientDataStreamId1, false, 0, StringPiece("HT"));
  session_->OnStreamFrame(data1);
  EXPECT_EQ(1u, session_->GetNumOpenIncomingStreams());

  // Send a reset (and expect the peer to send a RST in response).
  QuicRstStreamFrame rst1(kClientDataStreamId1, QUIC_ERROR_PROCESSING_STREAM,
                          0);
  EXPECT_CALL(*connection_,
              SendRstStream(kClientDataStreamId1, QUIC_RST_ACKNOWLEDGEMENT, 0));
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
  QuicRstStreamFrame rst1(kClientDataStreamId1, QUIC_ERROR_PROCESSING_STREAM,
                          0);
  EXPECT_CALL(*connection_,
              SendRstStream(kClientDataStreamId1, QUIC_RST_ACKNOWLEDGEMENT, 0));
  visitor_->OnRstStream(rst1);
  EXPECT_EQ(0u, session_->GetNumOpenIncomingStreams());

  // Send two bytes of payload.
  QuicStreamFrame data1(kClientDataStreamId1, false, 0, StringPiece("HT"));
  visitor_->OnStreamFrame(data1);

  // The stream should never be opened, now that the reset is received.
  EXPECT_EQ(0u, session_->GetNumOpenIncomingStreams());
  EXPECT_TRUE(connection_->connected());
}

TEST_P(QuicServerSessionBaseTest, AcceptClosedStream) {
  // Send (empty) compressed headers followed by two bytes of data.
  QuicStreamFrame frame1(kClientDataStreamId1, false, 0,
                         StringPiece("\1\0\0\0\0\0\0\0HT"));
  QuicStreamFrame frame2(kClientDataStreamId2, false, 0,
                         StringPiece("\2\0\0\0\0\0\0\0HT"));
  visitor_->OnStreamFrame(frame1);
  visitor_->OnStreamFrame(frame2);
  EXPECT_EQ(2u, session_->GetNumOpenIncomingStreams());

  // Send a reset (and expect the peer to send a RST in response).
  QuicRstStreamFrame rst(kClientDataStreamId1, QUIC_ERROR_PROCESSING_STREAM, 0);
  EXPECT_CALL(*connection_,
              SendRstStream(kClientDataStreamId1, QUIC_RST_ACKNOWLEDGEMENT, 0));
  visitor_->OnRstStream(rst);

  // If we were tracking, we'd probably want to reject this because it's data
  // past the reset point of stream 3.  As it's a closed stream we just drop the
  // data on the floor, but accept the packet because it has data for stream 5.
  QuicStreamFrame frame3(kClientDataStreamId1, false, 2, StringPiece("TP"));
  QuicStreamFrame frame4(kClientDataStreamId2, false, 2, StringPiece("TP"));
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
  EXPECT_EQ(kMaxStreamsForTest, session_->max_open_incoming_streams());
  session_->OnConfigNegotiated();
  EXPECT_LT(kMaxStreamsMultiplier * kMaxStreamsForTest,
            kMaxStreamsForTest + kMaxStreamsMinimumIncrement);
  EXPECT_EQ(kMaxStreamsForTest + kMaxStreamsMinimumIncrement,
            session_->max_open_incoming_streams());
  EXPECT_EQ(0u, session_->GetNumOpenIncomingStreams());
  QuicStreamId stream_id = kClientDataStreamId1;
  // Open the max configured number of streams, should be no problem.
  for (size_t i = 0; i < kMaxStreamsForTest; ++i) {
    EXPECT_TRUE(QuicServerSessionBasePeer::GetOrCreateDynamicStream(
        session_.get(), stream_id));
    stream_id += 2;
  }

  // Open more streams: server should accept slightly more than the limit.
  for (size_t i = 0; i < kMaxStreamsMinimumIncrement; ++i) {
    EXPECT_TRUE(QuicServerSessionBasePeer::GetOrCreateDynamicStream(
        session_.get(), stream_id));
    stream_id += 2;
  }

  // Now violate the server's internal stream limit.
  stream_id += 2;
  if (connection_->version() <= QUIC_VERSION_27) {
    EXPECT_CALL(*connection_,
                CloseConnection(QUIC_TOO_MANY_OPEN_STREAMS, _, _));
    EXPECT_CALL(*connection_, SendRstStream(_, _, _)).Times(0);
  } else {
    EXPECT_CALL(*connection_, CloseConnection(_, _, _)).Times(0);
    EXPECT_CALL(*connection_, SendRstStream(stream_id, QUIC_REFUSED_STREAM, 0));
  }
  // Even if the connection remains open, the stream creation should fail.
  EXPECT_FALSE(QuicServerSessionBasePeer::GetOrCreateDynamicStream(
      session_.get(), stream_id));
}

TEST_P(QuicServerSessionBaseTest, MaxAvailableStreams) {
  // Test that the server closes the connection if a client makes too many data
  // streams available.  The server accepts slightly more than the negotiated
  // stream limit to deal with rare cases where a client FIN/RST is lost.

  // The slightly increased stream limit is set during config negotiation.
  EXPECT_EQ(kMaxStreamsForTest, session_->max_open_incoming_streams());
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
      session_.get(), kClientDataStreamId1));

  // Establish available streams up to the server's limit.
  const int kLimitingStreamId =
      kClientDataStreamId1 + (kAvailableStreamLimit)*2 + 2;
  EXPECT_TRUE(QuicServerSessionBasePeer::GetOrCreateDynamicStream(
      session_.get(), kLimitingStreamId));

  // A further available stream will result in connection close.
  EXPECT_CALL(*connection_,
              CloseConnection(QUIC_TOO_MANY_AVAILABLE_STREAMS, _, _));
  // This forces stream kLimitingStreamId + 2 to become available, which
  // violates the quota.
  EXPECT_FALSE(QuicServerSessionBasePeer::GetOrCreateDynamicStream(
      session_.get(), kLimitingStreamId + 4));
}

TEST_P(QuicServerSessionBaseTest, EnableServerPushThroughConnectionOption) {
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
                         session_.get(), 4));
}

TEST_P(QuicServerSessionBaseTest, GetStreamDisconnected) {
  // Don't create new streams if the connection is disconnected.
  QuicConnectionPeer::TearDownLocalConnectionState(connection_);
  EXPECT_DFATAL(
      QuicServerSessionBasePeer::GetOrCreateDynamicStream(session_.get(), 5),
      "ShouldCreateIncomingDynamicStream called when disconnected");
}

class MockQuicCryptoServerStream : public QuicCryptoServerStream {
 public:
  explicit MockQuicCryptoServerStream(
      const QuicCryptoServerConfig* crypto_config,
      QuicCompressedCertsCache* compressed_certs_cache,
      QuicSession* session)
      : QuicCryptoServerStream(crypto_config,
                               compressed_certs_cache,
                               FLAGS_enable_quic_stateless_reject_support,
                               session) {}
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

  MockQuicCryptoServerStream* crypto_stream = new MockQuicCryptoServerStream(
      &crypto_config_, &compressed_certs_cache_, session_.get());
  QuicServerSessionBasePeer::SetCryptoStream(session_.get(), crypto_stream);

  // Set some initial bandwidth values.
  QuicSentPacketManager* sent_packet_manager =
      QuicConnectionPeer::GetSentPacketManager(session_->connection());
  QuicSustainedBandwidthRecorder& bandwidth_recorder =
      QuicSentPacketManagerPeer::GetBandwidthRecorder(sent_packet_manager);
  // Seed an rtt measurement equal to the initial default rtt.
  RttStats* rtt_stats =
      QuicSentPacketManagerPeer::GetRttStats(sent_packet_manager);
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
  now = now.Add(QuicTime::Delta::FromMilliseconds(
      kMinIntervalBetweenServerConfigUpdatesRTTs * srtt_ms));
  session_->OnCongestionWindowChange(now);

  // The connection no longer has pending data to be written.
  session_->OnCanWrite();
  EXPECT_FALSE(session_->HasDataToWrite());
  session_->OnCongestionWindowChange(now);

  // Bandwidth estimate has now changed sufficiently, enough time has passed,
  // and enough packets have been sent.
  QuicConnectionPeer::SetPacketNumberOfLastSentPacket(
      session_->connection(), kMinPacketsBetweenServerConfigUpdates);

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
      QuicSessionPeer::GetCryptoStream(session_.get()));

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

}  // namespace
}  // namespace test
}  // namespace net
