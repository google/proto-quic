// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <ostream>
#include <string>
#include <utility>
#include <vector>

#include "base/compiler_specific.h"
#include "base/macros.h"
#include "base/memory/ptr_util.h"
#include "base/run_loop.h"
#include "base/stl_util.h"
#include "base/strings/stringprintf.h"
#include "base/test/histogram_tester.h"
#include "net/base/chunked_upload_data_stream.h"
#include "net/base/mock_network_change_notifier.h"
#include "net/base/test_completion_callback.h"
#include "net/base/test_proxy_delegate.h"
#include "net/cert/ct_policy_enforcer.h"
#include "net/cert/mock_cert_verifier.h"
#include "net/cert/multi_log_ct_verifier.h"
#include "net/dns/mock_host_resolver.h"
#include "net/http/http_auth_handler_factory.h"
#include "net/http/http_network_session.h"
#include "net/http/http_network_transaction.h"
#include "net/http/http_server_properties_impl.h"
#include "net/http/http_stream.h"
#include "net/http/http_stream_factory.h"
#include "net/http/http_transaction_test_util.h"
#include "net/http/transport_security_state.h"
#include "net/log/net_log_event_type.h"
#include "net/log/test_net_log.h"
#include "net/log/test_net_log_entry.h"
#include "net/log/test_net_log_util.h"
#include "net/proxy/proxy_config_service_fixed.h"
#include "net/proxy/proxy_resolver.h"
#include "net/proxy/proxy_service.h"
#include "net/quic/chromium/crypto/proof_verifier_chromium.h"
#include "net/quic/chromium/mock_crypto_client_stream_factory.h"
#include "net/quic/chromium/mock_quic_data.h"
#include "net/quic/chromium/quic_chromium_alarm_factory.h"
#include "net/quic/chromium/quic_http_utils.h"
#include "net/quic/chromium/quic_stream_factory_peer.h"
#include "net/quic/chromium/quic_test_packet_maker.h"
#include "net/quic/chromium/test_task_runner.h"
#include "net/quic/core/crypto/quic_decrypter.h"
#include "net/quic/core/crypto/quic_encrypter.h"
#include "net/quic/core/quic_framer.h"
#include "net/quic/platform/api/quic_string_piece.h"
#include "net/quic/platform/impl/quic_test_impl.h"
#include "net/quic/test_tools/crypto_test_utils.h"
#include "net/quic/test_tools/mock_clock.h"
#include "net/quic/test_tools/mock_random.h"
#include "net/quic/test_tools/quic_spdy_session_peer.h"
#include "net/quic/test_tools/quic_test_utils.h"
#include "net/socket/client_socket_factory.h"
#include "net/socket/mock_client_socket_pool_manager.h"
#include "net/socket/next_proto.h"
#include "net/socket/socket_performance_watcher.h"
#include "net/socket/socket_performance_watcher_factory.h"
#include "net/socket/socket_test_util.h"
#include "net/spdy/core/spdy_frame_builder.h"
#include "net/spdy/core/spdy_framer.h"
#include "net/ssl/ssl_config_service_defaults.h"
#include "net/test/cert_test_util.h"
#include "net/test/gtest_util.h"
#include "net/test/test_data_directory.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "net/url_request/url_request.h"
#include "net/url_request/url_request_job_factory_impl.h"
#include "net/url_request/url_request_test_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "testing/platform_test.h"
#include "url/gurl.h"

namespace net {
namespace test {

namespace {

enum DestinationType {
  // In pooling tests with two requests for different origins to the same
  // destination, the destination should be
  SAME_AS_FIRST,   // the same as the first origin,
  SAME_AS_SECOND,  // the same as the second origin, or
  DIFFERENT,       // different from both.
};

static const char kQuicAlternativeServiceHeader[] =
    "Alt-Svc: quic=\":443\"\r\n\r\n";
static const char kQuicAlternativeServiceWithProbabilityHeader[] =
    "Alt-Svc: quic=\":443\";p=\".5\"\r\n\r\n";
static const char kQuicAlternativeServiceDifferentPortHeader[] =
    "Alt-Svc: quic=\":137\"\r\n\r\n";

const char kDefaultServerHostName[] = "mail.example.org";
const char kDifferentHostname[] = "different.example.com";

// Run QuicNetworkTransactionWithDestinationTest instances with all value
// combinations of version and destination_type.
struct PoolingTestParams {
  friend std::ostream& operator<<(std::ostream& os,
                                  const PoolingTestParams& p) {
    os << "{ version: " << QuicVersionToString(p.version)
       << ", destination_type: ";
    switch (p.destination_type) {
      case SAME_AS_FIRST:
        os << "SAME_AS_FIRST";
        break;
      case SAME_AS_SECOND:
        os << "SAME_AS_SECOND";
        break;
      case DIFFERENT:
        os << "DIFFERENT";
        break;
    }
    os << " }";
    return os;
  }

  QuicVersion version;
  DestinationType destination_type;
};

std::vector<PoolingTestParams> GetPoolingTestParams() {
  std::vector<PoolingTestParams> params;
  QuicVersionVector all_supported_versions = AllSupportedVersions();
  for (const QuicVersion version : all_supported_versions) {
    params.push_back(PoolingTestParams{version, SAME_AS_FIRST});
    params.push_back(PoolingTestParams{version, SAME_AS_SECOND});
    params.push_back(PoolingTestParams{version, DIFFERENT});
  }
  return params;
}

}  // namespace

class HeadersHandler {
 public:
  HeadersHandler() : was_proxied_(false) {}

  bool was_proxied() { return was_proxied_; }

  void OnBeforeHeadersSent(const ProxyInfo& proxy_info,
                           HttpRequestHeaders* request_headers) {
    if (!proxy_info.is_http() && !proxy_info.is_https() &&
        !proxy_info.is_quic()) {
      return;
    }
    was_proxied_ = true;
  }

 private:
  bool was_proxied_;
};

class TestSocketPerformanceWatcher : public SocketPerformanceWatcher {
 public:
  TestSocketPerformanceWatcher(bool* should_notify_updated_rtt,
                               bool* rtt_notification_received)
      : should_notify_updated_rtt_(should_notify_updated_rtt),
        rtt_notification_received_(rtt_notification_received) {}
  ~TestSocketPerformanceWatcher() override {}

  bool ShouldNotifyUpdatedRTT() const override {
    return *should_notify_updated_rtt_;
  }

  void OnUpdatedRTTAvailable(const base::TimeDelta& rtt) override {
    *rtt_notification_received_ = true;
  }

  void OnConnectionChanged() override {}

 private:
  bool* should_notify_updated_rtt_;
  bool* rtt_notification_received_;

  DISALLOW_COPY_AND_ASSIGN(TestSocketPerformanceWatcher);
};

class TestSocketPerformanceWatcherFactory
    : public SocketPerformanceWatcherFactory {
 public:
  TestSocketPerformanceWatcherFactory()
      : watcher_count_(0u),
        should_notify_updated_rtt_(true),
        rtt_notification_received_(false) {}
  ~TestSocketPerformanceWatcherFactory() override {}

  // SocketPerformanceWatcherFactory implementation:
  std::unique_ptr<SocketPerformanceWatcher> CreateSocketPerformanceWatcher(
      const Protocol protocol) override {
    if (protocol != PROTOCOL_QUIC) {
      return nullptr;
    }
    ++watcher_count_;
    return std::unique_ptr<SocketPerformanceWatcher>(
        new TestSocketPerformanceWatcher(&should_notify_updated_rtt_,
                                         &rtt_notification_received_));
  }

  size_t watcher_count() const { return watcher_count_; }

  bool rtt_notification_received() const { return rtt_notification_received_; }

  void set_should_notify_updated_rtt(bool should_notify_updated_rtt) {
    should_notify_updated_rtt_ = should_notify_updated_rtt;
  }

 private:
  size_t watcher_count_;
  bool should_notify_updated_rtt_;
  bool rtt_notification_received_;

  DISALLOW_COPY_AND_ASSIGN(TestSocketPerformanceWatcherFactory);
};

class QuicNetworkTransactionTest
    : public PlatformTest,
      public ::testing::WithParamInterface<QuicVersion> {
 protected:
  QuicNetworkTransactionTest()
      : version_(GetParam()),
        client_maker_(version_,
                      0,
                      &clock_,
                      kDefaultServerHostName,
                      Perspective::IS_CLIENT),
        server_maker_(version_,
                      0,
                      &clock_,
                      kDefaultServerHostName,
                      Perspective::IS_SERVER),
        cert_transparency_verifier_(new MultiLogCTVerifier()),
        ssl_config_service_(new SSLConfigServiceDefaults),
        proxy_service_(ProxyService::CreateDirect()),
        auth_handler_factory_(
            HttpAuthHandlerFactory::CreateDefault(&host_resolver_)),
        random_generator_(0),
        ssl_data_(ASYNC, OK) {
    request_.method = "GET";
    std::string url("https://");
    url.append(kDefaultServerHostName);
    request_.url = GURL(url);
    request_.load_flags = 0;
    clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(20));

    scoped_refptr<X509Certificate> cert(
        ImportCertFromFile(GetTestCertsDirectory(), "wildcard.pem"));
    verify_details_.cert_verify_result.verified_cert = cert;
    verify_details_.cert_verify_result.is_issued_by_known_root = true;
    crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details_);
  }

  void SetUp() override {
    NetworkChangeNotifier::NotifyObserversOfIPAddressChangeForTests();
    base::RunLoop().RunUntilIdle();
  }

  void TearDown() override {
    NetworkChangeNotifier::NotifyObserversOfIPAddressChangeForTests();
    // Empty the current queue.
    base::RunLoop().RunUntilIdle();
    PlatformTest::TearDown();
    NetworkChangeNotifier::NotifyObserversOfIPAddressChangeForTests();
    base::RunLoop().RunUntilIdle();
    session_.reset();
  }

  std::unique_ptr<QuicEncryptedPacket> ConstructClientConnectionClosePacket(
      QuicPacketNumber num) {
    return client_maker_.MakeConnectionClosePacket(num);
  }

  std::unique_ptr<QuicEncryptedPacket> ConstructServerConnectionClosePacket(
      QuicPacketNumber num) {
    return server_maker_.MakeConnectionClosePacket(num);
  }

  std::unique_ptr<QuicEncryptedPacket> ConstructServerGoAwayPacket(
      QuicPacketNumber num,
      QuicErrorCode error_code,
      std::string reason_phrase) {
    return server_maker_.MakeGoAwayPacket(num, error_code, reason_phrase);
  }

  std::unique_ptr<QuicEncryptedPacket> ConstructClientAckPacket(
      QuicPacketNumber packet_number,
      QuicPacketNumber largest_received,
      QuicPacketNumber smallest_received,
      QuicPacketNumber least_unacked) {
    return client_maker_.MakeAckPacket(packet_number, largest_received,
                                       smallest_received, least_unacked, true);
  }

  std::unique_ptr<QuicEncryptedPacket> ConstructClientAckPacket(
      QuicPacketNumber packet_number,
      QuicPacketNumber largest_received,
      QuicPacketNumber smallest_received,
      QuicPacketNumber least_unacked,
      QuicTime::Delta ack_delay_time) {
    return client_maker_.MakeAckPacket(packet_number, largest_received,
                                       smallest_received, least_unacked, true,
                                       ack_delay_time);
  }

  std::unique_ptr<QuicEncryptedPacket> ConstructClientAckAndRstPacket(
      QuicPacketNumber num,
      QuicStreamId stream_id,
      QuicRstStreamErrorCode error_code,
      QuicPacketNumber largest_received,
      QuicPacketNumber smallest_received,
      QuicPacketNumber least_unacked) {
    return client_maker_.MakeAckAndRstPacket(
        num, false, stream_id, error_code, largest_received, smallest_received,
        least_unacked, true);
  }

  std::unique_ptr<QuicEncryptedPacket>
  ConstructClientAckAndConnectionClosePacket(QuicPacketNumber packet_number,
                                             QuicPacketNumber largest_received,
                                             QuicPacketNumber smallest_received,
                                             QuicPacketNumber least_unacked) {
    return client_maker_.MakeAckPacket(packet_number, largest_received,
                                       smallest_received, least_unacked, true);
  }

  std::unique_ptr<QuicEncryptedPacket>
  ConstructClientAckAndConnectionClosePacket(
      QuicPacketNumber num,
      QuicTime::Delta delta_time_largest_observed,
      QuicPacketNumber largest_received,
      QuicPacketNumber smallest_received,
      QuicPacketNumber least_unacked,
      QuicErrorCode quic_error,
      const std::string& quic_error_details) {
    return client_maker_.MakeAckAndConnectionClosePacket(
        num, false, delta_time_largest_observed, largest_received,
        smallest_received, least_unacked, quic_error, quic_error_details);
  }

  std::unique_ptr<QuicEncryptedPacket> ConstructServerRstPacket(
      QuicPacketNumber num,
      bool include_version,
      QuicStreamId stream_id,
      QuicRstStreamErrorCode error_code) {
    return server_maker_.MakeRstPacket(num, include_version, stream_id,
                                       error_code);
  }

  std::unique_ptr<QuicReceivedPacket> ConstructInitialSettingsPacket(
      QuicPacketNumber packet_number,
      QuicStreamOffset* offset) {
    return client_maker_.MakeInitialSettingsPacket(packet_number, offset);
  }

  std::unique_ptr<QuicReceivedPacket> ConstructServerAckPacket(
      QuicPacketNumber packet_number,
      QuicPacketNumber largest_received,
      QuicPacketNumber smallest_received,
      QuicPacketNumber least_unacked) {
    return server_maker_.MakeAckPacket(packet_number, largest_received,
                                       smallest_received, least_unacked, false);
  }

  // Uses default QuicTestPacketMaker.
  SpdyHeaderBlock GetRequestHeaders(const std::string& method,
                                    const std::string& scheme,
                                    const std::string& path) {
    return GetRequestHeaders(method, scheme, path, &client_maker_);
  }

  // Uses customized QuicTestPacketMaker.
  SpdyHeaderBlock GetRequestHeaders(const std::string& method,
                                    const std::string& scheme,
                                    const std::string& path,
                                    QuicTestPacketMaker* maker) {
    return maker->GetRequestHeaders(method, scheme, path);
  }

  SpdyHeaderBlock GetResponseHeaders(const std::string& status) {
    return server_maker_.GetResponseHeaders(status);
  }

  // Appends alt_svc headers in the response headers.
  SpdyHeaderBlock GetResponseHeaders(const std::string& status,
                                     const std::string& alt_svc) {
    return server_maker_.GetResponseHeaders(status, alt_svc);
  }

  std::unique_ptr<QuicEncryptedPacket> ConstructServerDataPacket(
      QuicPacketNumber packet_number,
      QuicStreamId stream_id,
      bool should_include_version,
      bool fin,
      QuicStreamOffset offset,
      QuicStringPiece data) {
    return server_maker_.MakeDataPacket(
        packet_number, stream_id, should_include_version, fin, offset, data);
  }

  std::unique_ptr<QuicEncryptedPacket> ConstructClientDataPacket(
      QuicPacketNumber packet_number,
      QuicStreamId stream_id,
      bool should_include_version,
      bool fin,
      QuicStreamOffset offset,
      QuicStringPiece data) {
    return client_maker_.MakeDataPacket(
        packet_number, stream_id, should_include_version, fin, offset, data);
  }

  std::unique_ptr<QuicEncryptedPacket> ConstructClientForceHolDataPacket(
      QuicPacketNumber packet_number,
      QuicStreamId stream_id,
      bool should_include_version,
      bool fin,
      QuicStreamOffset* offset,
      QuicStringPiece data) {
    return client_maker_.MakeForceHolDataPacket(
        packet_number, stream_id, should_include_version, fin, offset, data);
  }

  std::unique_ptr<QuicEncryptedPacket> ConstructClientRequestHeadersPacket(
      QuicPacketNumber packet_number,
      QuicStreamId stream_id,
      bool should_include_version,
      bool fin,
      SpdyHeaderBlock headers,
      QuicStreamOffset* offset) {
    SpdyPriority priority =
        ConvertRequestPriorityToQuicPriority(DEFAULT_PRIORITY);
    return client_maker_.MakeRequestHeadersPacketWithOffsetTracking(
        packet_number, stream_id, should_include_version, fin, priority,
        std::move(headers), offset);
  }

  std::unique_ptr<QuicEncryptedPacket> ConstructClientRequestHeadersPacket(
      QuicPacketNumber packet_number,
      QuicStreamId stream_id,
      bool should_include_version,
      bool fin,
      SpdyHeaderBlock headers) {
    return ConstructClientRequestHeadersPacket(packet_number, stream_id,
                                               should_include_version, fin,
                                               std::move(headers), nullptr);
  }

  std::unique_ptr<QuicEncryptedPacket> ConstructClientMultipleDataFramesPacket(
      QuicPacketNumber packet_number,
      QuicStreamId stream_id,
      bool should_include_version,
      bool fin,
      const std::vector<std::string>& data,
      QuicStreamOffset offset) {
    return client_maker_.MakeMultipleDataFramesPacket(
        packet_number, stream_id, should_include_version, fin, offset, data);
  }

  std::unique_ptr<QuicEncryptedPacket> ConstructServerPushPromisePacket(
      QuicPacketNumber packet_number,
      QuicStreamId stream_id,
      QuicStreamId promised_stream_id,
      bool should_include_version,
      SpdyHeaderBlock headers,
      QuicStreamOffset* offset,
      QuicTestPacketMaker* maker) {
    return maker->MakePushPromisePacket(
        packet_number, stream_id, promised_stream_id, should_include_version,
        false, std::move(headers), nullptr, offset);
  }

  std::unique_ptr<QuicEncryptedPacket> ConstructServerResponseHeadersPacket(
      QuicPacketNumber packet_number,
      QuicStreamId stream_id,
      bool should_include_version,
      bool fin,
      SpdyHeaderBlock headers) {
    return ConstructServerResponseHeadersPacket(packet_number, stream_id,
                                                should_include_version, fin,
                                                std::move(headers), nullptr);
  }

  std::unique_ptr<QuicEncryptedPacket> ConstructServerResponseHeadersPacket(
      QuicPacketNumber packet_number,
      QuicStreamId stream_id,
      bool should_include_version,
      bool fin,
      SpdyHeaderBlock headers,
      QuicStreamOffset* offset) {
    return server_maker_.MakeResponseHeadersPacketWithOffsetTracking(
        packet_number, stream_id, should_include_version, fin,
        std::move(headers), offset);
  }

  void CreateSession() {
    params_.enable_quic = true;
    params_.quic_clock = &clock_;
    params_.quic_random = &random_generator_;
    params_.client_socket_factory = &socket_factory_;
    params_.quic_crypto_client_stream_factory = &crypto_client_stream_factory_;
    params_.host_resolver = &host_resolver_;
    params_.cert_verifier = &cert_verifier_;
    params_.transport_security_state = &transport_security_state_;
    params_.cert_transparency_verifier = cert_transparency_verifier_.get();
    params_.ct_policy_enforcer = &ct_policy_enforcer_;
    params_.socket_performance_watcher_factory =
        &test_socket_performance_watcher_factory_;
    params_.proxy_service = proxy_service_.get();
    params_.ssl_config_service = ssl_config_service_.get();
    params_.http_auth_handler_factory = auth_handler_factory_.get();
    params_.http_server_properties = &http_server_properties_;
    params_.quic_supported_versions = SupportedVersions(version_);
    params_.net_log = net_log_.bound().net_log();

    session_.reset(new HttpNetworkSession(params_));
    session_->quic_stream_factory()->set_require_confirmation(false);
  }

  void CheckWasQuicResponse(HttpNetworkTransaction* trans) {
    const HttpResponseInfo* response = trans->GetResponseInfo();
    ASSERT_TRUE(response != nullptr);
    ASSERT_TRUE(response->headers.get() != nullptr);
    EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());
    EXPECT_TRUE(response->was_fetched_via_spdy);
    EXPECT_TRUE(response->was_alpn_negotiated);
    EXPECT_EQ(QuicHttpStream::ConnectionInfoFromQuicVersion(version_),
              response->connection_info);
  }

  void CheckResponsePort(HttpNetworkTransaction* trans, uint16_t port) {
    const HttpResponseInfo* response = trans->GetResponseInfo();
    ASSERT_TRUE(response != nullptr);
    EXPECT_EQ(port, response->socket_address.port());
  }

  void CheckWasHttpResponse(HttpNetworkTransaction* trans) {
    const HttpResponseInfo* response = trans->GetResponseInfo();
    ASSERT_TRUE(response != nullptr);
    ASSERT_TRUE(response->headers.get() != nullptr);
    EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());
    EXPECT_FALSE(response->was_fetched_via_spdy);
    EXPECT_FALSE(response->was_alpn_negotiated);
    EXPECT_EQ(HttpResponseInfo::CONNECTION_INFO_HTTP1_1,
              response->connection_info);
  }

  void CheckResponseData(HttpNetworkTransaction* trans,
                         const std::string& expected) {
    std::string response_data;
    ASSERT_THAT(ReadTransaction(trans, &response_data), IsOk());
    EXPECT_EQ(expected, response_data);
  }

  void RunTransaction(HttpNetworkTransaction* trans) {
    TestCompletionCallback callback;
    int rv = trans->Start(&request_, callback.callback(), net_log_.bound());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
    EXPECT_THAT(callback.WaitForResult(), IsOk());
  }

  void SendRequestAndExpectHttpResponse(const std::string& expected) {
    HttpNetworkTransaction trans(DEFAULT_PRIORITY, session_.get());
    RunTransaction(&trans);
    CheckWasHttpResponse(&trans);
    CheckResponseData(&trans, expected);
  }

  void SendRequestAndExpectHttpResponseFromProxy(const std::string& expected,
                                                 bool used_proxy,
                                                 uint16_t port) {
    HttpNetworkTransaction trans(DEFAULT_PRIORITY, session_.get());
    HeadersHandler headers_handler;
    trans.SetBeforeHeadersSentCallback(
        base::Bind(&HeadersHandler::OnBeforeHeadersSent,
                   base::Unretained(&headers_handler)));
    RunTransaction(&trans);
    CheckWasHttpResponse(&trans);
    CheckResponsePort(&trans, port);
    CheckResponseData(&trans, expected);
    EXPECT_EQ(used_proxy, headers_handler.was_proxied());
    if (used_proxy) {
      EXPECT_TRUE(trans.GetResponseInfo()->proxy_server.is_https());
    } else {
      EXPECT_TRUE(trans.GetResponseInfo()->proxy_server.is_direct());
    }
  }

  void SendRequestAndExpectQuicResponse(const std::string& expected) {
    SendRequestAndExpectQuicResponseMaybeFromProxy(expected, false, 443);
  }

  void SendRequestAndExpectQuicResponseFromProxyOnPort(
      const std::string& expected,
      uint16_t port) {
    SendRequestAndExpectQuicResponseMaybeFromProxy(expected, true, port);
  }

  void AddQuicAlternateProtocolMapping(
      MockCryptoClientStream::HandshakeMode handshake_mode) {
    crypto_client_stream_factory_.set_handshake_mode(handshake_mode);
    url::SchemeHostPort server(request_.url);
    AlternativeService alternative_service(kProtoQUIC, server.host(), 443);
    base::Time expiration = base::Time::Now() + base::TimeDelta::FromDays(1);
    http_server_properties_.SetAlternativeService(server, alternative_service,
                                                  expiration);
  }

  void AddQuicRemoteAlternativeServiceMapping(
      MockCryptoClientStream::HandshakeMode handshake_mode,
      const HostPortPair& alternative) {
    crypto_client_stream_factory_.set_handshake_mode(handshake_mode);
    url::SchemeHostPort server(request_.url);
    AlternativeService alternative_service(kProtoQUIC, alternative.host(),
                                           alternative.port());
    base::Time expiration = base::Time::Now() + base::TimeDelta::FromDays(1);
    http_server_properties_.SetAlternativeService(server, alternative_service,
                                                  expiration);
  }

  void ExpectBrokenAlternateProtocolMapping() {
    const url::SchemeHostPort server(request_.url);
    const AlternativeServiceInfoVector alternative_service_info_vector =
        http_server_properties_.GetAlternativeServiceInfos(server);
    EXPECT_EQ(1u, alternative_service_info_vector.size());
    EXPECT_TRUE(http_server_properties_.IsAlternativeServiceBroken(
        alternative_service_info_vector[0].alternative_service));
  }

  void ExpectQuicAlternateProtocolMapping() {
    const url::SchemeHostPort server(request_.url);
    const AlternativeServiceInfoVector alternative_service_info_vector =
        http_server_properties_.GetAlternativeServiceInfos(server);
    EXPECT_EQ(1u, alternative_service_info_vector.size());
    EXPECT_EQ(kProtoQUIC,
              alternative_service_info_vector[0].alternative_service.protocol);
    EXPECT_FALSE(http_server_properties_.IsAlternativeServiceBroken(
        alternative_service_info_vector[0].alternative_service));
  }

  void AddHangingNonAlternateProtocolSocketData() {
    std::unique_ptr<StaticSocketDataProvider> hanging_data;
    hanging_data.reset(new StaticSocketDataProvider());
    MockConnect hanging_connect(SYNCHRONOUS, ERR_IO_PENDING);
    hanging_data->set_connect_data(hanging_connect);
    hanging_data_.push_back(std::move(hanging_data));
    socket_factory_.AddSocketDataProvider(hanging_data_.back().get());
    socket_factory_.AddSSLSocketDataProvider(&ssl_data_);
  }

  // Fetches two non-cryptographic URL requests via a HTTPS proxy with a QUIC
  // alternative proxy. Verifies that if the alternative proxy job returns
  // |error_code|, the request is fetched successfully by the main job.
  void TestAlternativeProxy(int error_code) {
    // Use a non-cryptographic scheme for the request URL since this request
    // will be fetched via proxy with QUIC as the alternative service.
    request_.url = GURL("http://example.org/");
    // Data for the alternative proxy server job.
    MockWrite quic_writes[] = {MockWrite(SYNCHRONOUS, error_code, 1)};
    MockRead quic_reads[] = {
        MockRead(SYNCHRONOUS, error_code, 0),
    };

    SequencedSocketData quic_data(quic_reads, arraysize(quic_reads),
                                  quic_writes, arraysize(quic_writes));
    socket_factory_.AddSocketDataProvider(&quic_data);

    // Main job succeeds and the alternative job fails.
    // Add data for two requests that will be read by the main job.
    MockRead http_reads_1[] = {
        MockRead("HTTP/1.1 200 OK\r\n\r\n"), MockRead("hello from http"),
        MockRead(SYNCHRONOUS, ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ),
        MockRead(ASYNC, OK)};

    MockRead http_reads_2[] = {
        MockRead("HTTP/1.1 200 OK\r\n\r\n"), MockRead("hello from http"),
        MockRead(SYNCHRONOUS, ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ),
        MockRead(ASYNC, OK)};

    StaticSocketDataProvider http_data_1(http_reads_1, arraysize(http_reads_1),
                                         nullptr, 0);
    StaticSocketDataProvider http_data_2(http_reads_2, arraysize(http_reads_2),
                                         nullptr, 0);
    socket_factory_.AddSocketDataProvider(&http_data_1);
    socket_factory_.AddSocketDataProvider(&http_data_2);
    socket_factory_.AddSSLSocketDataProvider(&ssl_data_);
    socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

    TestProxyDelegate test_proxy_delegate;
    // Proxy URL is different from the request URL.
    test_proxy_delegate.set_alternative_proxy_server(
        ProxyServer::FromPacString("QUIC myproxy.org:443"));

    params_.proxy_delegate = &test_proxy_delegate;
    proxy_service_ =
        ProxyService::CreateFixedFromPacResult("HTTPS myproxy.org:443");

    CreateSession();
    EXPECT_TRUE(test_proxy_delegate.alternative_proxy_server().is_valid());

    // The first request should be fetched via the HTTPS proxy.
    SendRequestAndExpectHttpResponseFromProxy("hello from http", true, 443);

    // Even through the alternative proxy server job failed, the proxy should
    // not be marked as bad since the main job succeeded.
    EXPECT_TRUE(session_->proxy_service()->proxy_retry_info().empty());

    // The alternative proxy server should no longer be in use.
    EXPECT_FALSE(test_proxy_delegate.alternative_proxy_server().is_valid());

    // Verify that the second request completes successfully, and the
    // alternative proxy server job is not started.
    SendRequestAndExpectHttpResponseFromProxy("hello from http", true, 443);
  }

  QuicStreamId GetNthClientInitiatedStreamId(int n) {
    return test::GetNthClientInitiatedStreamId(version_, n);
  }

  QuicStreamId GetNthServerInitiatedStreamId(int n) {
    return test::GetNthServerInitiatedStreamId(version_, n);
  }

  const QuicVersion version_;
  QuicFlagSaver flags_;  // Save/restore all QUIC flag values.
  MockClock clock_;
  QuicTestPacketMaker client_maker_;
  QuicTestPacketMaker server_maker_;
  std::unique_ptr<HttpNetworkSession> session_;
  MockClientSocketFactory socket_factory_;
  ProofVerifyDetailsChromium verify_details_;
  MockCryptoClientStreamFactory crypto_client_stream_factory_;
  MockHostResolver host_resolver_;
  MockCertVerifier cert_verifier_;
  TransportSecurityState transport_security_state_;
  std::unique_ptr<CTVerifier> cert_transparency_verifier_;
  CTPolicyEnforcer ct_policy_enforcer_;
  TestSocketPerformanceWatcherFactory test_socket_performance_watcher_factory_;
  scoped_refptr<SSLConfigServiceDefaults> ssl_config_service_;
  std::unique_ptr<ProxyService> proxy_service_;
  std::unique_ptr<HttpAuthHandlerFactory> auth_handler_factory_;
  MockRandom random_generator_;
  HttpServerPropertiesImpl http_server_properties_;
  HttpNetworkSession::Params params_;
  HttpRequestInfo request_;
  BoundTestNetLog net_log_;
  std::vector<std::unique_ptr<StaticSocketDataProvider>> hanging_data_;
  SSLSocketDataProvider ssl_data_;

 private:
  void SendRequestAndExpectQuicResponseMaybeFromProxy(
      const std::string& expected,
      bool used_proxy,
      uint16_t port) {
    HttpNetworkTransaction trans(DEFAULT_PRIORITY, session_.get());
    HeadersHandler headers_handler;
    trans.SetBeforeHeadersSentCallback(
        base::Bind(&HeadersHandler::OnBeforeHeadersSent,
                   base::Unretained(&headers_handler)));
    RunTransaction(&trans);
    CheckWasQuicResponse(&trans);
    CheckResponsePort(&trans, port);
    CheckResponseData(&trans, expected);
    EXPECT_EQ(used_proxy, headers_handler.was_proxied());
    if (used_proxy) {
      EXPECT_TRUE(trans.GetResponseInfo()->proxy_server.is_quic());
    } else {
      EXPECT_TRUE(trans.GetResponseInfo()->proxy_server.is_direct());
    }
  }
};

INSTANTIATE_TEST_CASE_P(Version,
                        QuicNetworkTransactionTest,
                        ::testing::ValuesIn(AllSupportedVersions()));

TEST_P(QuicNetworkTransactionTest, SocketWatcherEnabled) {
  params_.origins_to_force_quic_on.insert(
      HostPortPair::FromString("mail.example.org:443"));

  MockQuicData mock_quic_data;
  QuicStreamOffset header_stream_offset = 0;
  mock_quic_data.AddWrite(
      ConstructInitialSettingsPacket(1, &header_stream_offset));
  mock_quic_data.AddWrite(ConstructClientRequestHeadersPacket(
      2, GetNthClientInitiatedStreamId(0), true, true,
      GetRequestHeaders("GET", "https", "/"), &header_stream_offset));
  mock_quic_data.AddRead(ConstructServerResponseHeadersPacket(
      1, GetNthClientInitiatedStreamId(0), false, false,
      GetResponseHeaders("200 OK")));
  mock_quic_data.AddRead(ConstructServerDataPacket(
      2, GetNthClientInitiatedStreamId(0), false, true, 0, "hello!"));
  mock_quic_data.AddWrite(ConstructClientAckPacket(3, 2, 1, 1));
  mock_quic_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);  // No more data to read

  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  CreateSession();
  test_socket_performance_watcher_factory_.set_should_notify_updated_rtt(true);

  EXPECT_FALSE(
      test_socket_performance_watcher_factory_.rtt_notification_received());
  SendRequestAndExpectQuicResponse("hello!");
  EXPECT_TRUE(
      test_socket_performance_watcher_factory_.rtt_notification_received());
}

TEST_P(QuicNetworkTransactionTest, SocketWatcherDisabled) {
  params_.origins_to_force_quic_on.insert(
      HostPortPair::FromString("mail.example.org:443"));

  MockQuicData mock_quic_data;
  QuicStreamOffset header_stream_offset = 0;
  mock_quic_data.AddWrite(
      ConstructInitialSettingsPacket(1, &header_stream_offset));
  mock_quic_data.AddWrite(ConstructClientRequestHeadersPacket(
      2, GetNthClientInitiatedStreamId(0), true, true,
      GetRequestHeaders("GET", "https", "/"), &header_stream_offset));
  mock_quic_data.AddRead(ConstructServerResponseHeadersPacket(
      1, GetNthClientInitiatedStreamId(0), false, false,
      GetResponseHeaders("200 OK")));
  mock_quic_data.AddRead(ConstructServerDataPacket(
      2, GetNthClientInitiatedStreamId(0), false, true, 0, "hello!"));
  mock_quic_data.AddWrite(ConstructClientAckPacket(3, 2, 1, 1));
  mock_quic_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);  // No more data to read

  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  CreateSession();
  test_socket_performance_watcher_factory_.set_should_notify_updated_rtt(false);

  EXPECT_FALSE(
      test_socket_performance_watcher_factory_.rtt_notification_received());
  SendRequestAndExpectQuicResponse("hello!");
  EXPECT_FALSE(
      test_socket_performance_watcher_factory_.rtt_notification_received());
}

TEST_P(QuicNetworkTransactionTest, ForceQuic) {
  params_.origins_to_force_quic_on.insert(
      HostPortPair::FromString("mail.example.org:443"));

  MockQuicData mock_quic_data;
  QuicStreamOffset header_stream_offset = 0;
  mock_quic_data.AddWrite(
      ConstructInitialSettingsPacket(1, &header_stream_offset));
  mock_quic_data.AddWrite(ConstructClientRequestHeadersPacket(
      2, GetNthClientInitiatedStreamId(0), true, true,
      GetRequestHeaders("GET", "https", "/"), &header_stream_offset));
  mock_quic_data.AddRead(ConstructServerResponseHeadersPacket(
      1, GetNthClientInitiatedStreamId(0), false, false,
      GetResponseHeaders("200 OK")));
  mock_quic_data.AddRead(ConstructServerDataPacket(
      2, GetNthClientInitiatedStreamId(0), false, true, 0, "hello!"));
  mock_quic_data.AddWrite(ConstructClientAckPacket(3, 2, 1, 1));
  mock_quic_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);  // No more data to read

  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  CreateSession();

  SendRequestAndExpectQuicResponse("hello!");

  // Check that the NetLog was filled reasonably.
  TestNetLogEntry::List entries;
  net_log_.GetEntries(&entries);
  EXPECT_LT(0u, entries.size());

  // Check that we logged a QUIC_SESSION_PACKET_RECEIVED.
  int pos = ExpectLogContainsSomewhere(
      entries, 0, NetLogEventType::QUIC_SESSION_PACKET_RECEIVED,
      NetLogEventPhase::NONE);
  EXPECT_LT(0, pos);

  // ... and also a TYPE_QUIC_SESSION_UNAUTHENTICATED_PACKET_HEADER_RECEIVED.
  pos = ExpectLogContainsSomewhere(
      entries, 0,
      NetLogEventType::QUIC_SESSION_UNAUTHENTICATED_PACKET_HEADER_RECEIVED,
      NetLogEventPhase::NONE);
  EXPECT_LT(0, pos);

  std::string packet_number;
  ASSERT_TRUE(entries[pos].GetStringValue("packet_number", &packet_number));
  EXPECT_EQ("1", packet_number);

  // ... and also a TYPE_QUIC_SESSION_PACKET_AUTHENTICATED.
  pos = ExpectLogContainsSomewhere(
      entries, 0, NetLogEventType::QUIC_SESSION_PACKET_AUTHENTICATED,
      NetLogEventPhase::NONE);
  EXPECT_LT(0, pos);

  // ... and also a QUIC_SESSION_STREAM_FRAME_RECEIVED.
  pos = ExpectLogContainsSomewhere(
      entries, 0, NetLogEventType::QUIC_SESSION_STREAM_FRAME_RECEIVED,
      NetLogEventPhase::NONE);
  EXPECT_LT(0, pos);

  int log_stream_id;
  ASSERT_TRUE(entries[pos].GetIntegerValue("stream_id", &log_stream_id));
  EXPECT_EQ(3, log_stream_id);
}

TEST_P(QuicNetworkTransactionTest, ForceQuicForAll) {
  params_.origins_to_force_quic_on.insert(HostPortPair());

  AddQuicAlternateProtocolMapping(MockCryptoClientStream::CONFIRM_HANDSHAKE);

  MockQuicData mock_quic_data;
  QuicStreamOffset header_stream_offset = 0;
  mock_quic_data.AddWrite(
      ConstructInitialSettingsPacket(1, &header_stream_offset));
  mock_quic_data.AddWrite(ConstructClientRequestHeadersPacket(
      2, GetNthClientInitiatedStreamId(0), true, true,
      GetRequestHeaders("GET", "https", "/"), &header_stream_offset));
  mock_quic_data.AddRead(ConstructServerResponseHeadersPacket(
      1, GetNthClientInitiatedStreamId(0), false, false,
      GetResponseHeaders("200 OK")));
  mock_quic_data.AddRead(ConstructServerDataPacket(
      2, GetNthClientInitiatedStreamId(0), false, true, 0, "hello!"));
  mock_quic_data.AddWrite(ConstructClientAckPacket(3, 2, 1, 1));
  mock_quic_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);  // No more data to read

  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  CreateSession();

  SendRequestAndExpectQuicResponse("hello!");
  EXPECT_TRUE(
      test_socket_performance_watcher_factory_.rtt_notification_received());
}

TEST_P(QuicNetworkTransactionTest, QuicProxy) {
  params_.enable_quic = true;
  proxy_service_ =
      ProxyService::CreateFixedFromPacResult("QUIC mail.example.org:70");

  MockQuicData mock_quic_data;
  QuicStreamOffset header_stream_offset = 0;
  mock_quic_data.AddWrite(
      ConstructInitialSettingsPacket(1, &header_stream_offset));
  mock_quic_data.AddWrite(ConstructClientRequestHeadersPacket(
      2, GetNthClientInitiatedStreamId(0), true, true,
      GetRequestHeaders("GET", "http", "/"), &header_stream_offset));
  mock_quic_data.AddRead(ConstructServerResponseHeadersPacket(
      1, GetNthClientInitiatedStreamId(0), false, false,
      GetResponseHeaders("200 OK")));
  mock_quic_data.AddRead(ConstructServerDataPacket(
      2, GetNthClientInitiatedStreamId(0), false, true, 0, "hello!"));
  mock_quic_data.AddWrite(ConstructClientAckPacket(3, 2, 1, 1));
  mock_quic_data.AddRead(ASYNC, ERR_IO_PENDING);  // No more data to read
  mock_quic_data.AddRead(ASYNC, 0);               // EOF

  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  EXPECT_FALSE(
      test_socket_performance_watcher_factory_.rtt_notification_received());
  // There is no need to set up an alternate protocol job, because
  // no attempt will be made to speak to the proxy over TCP.

  request_.url = GURL("http://mail.example.org/");
  CreateSession();

  SendRequestAndExpectQuicResponseFromProxyOnPort("hello!", 70);
  EXPECT_TRUE(
      test_socket_performance_watcher_factory_.rtt_notification_received());
}

// Regression test for https://crbug.com/492458.  Test that for an HTTP
// connection through a QUIC proxy, the certificate exhibited by the proxy is
// checked against the proxy hostname, not the origin hostname.
TEST_P(QuicNetworkTransactionTest, QuicProxyWithCert) {
  const std::string origin_host = "mail.example.com";
  const std::string proxy_host = "www.example.org";

  params_.enable_quic = true;
  proxy_service_ =
      ProxyService::CreateFixedFromPacResult("QUIC " + proxy_host + ":70");

  client_maker_.set_hostname(origin_host);
  MockQuicData mock_quic_data;
  QuicStreamOffset header_stream_offset = 0;
  mock_quic_data.AddWrite(
      ConstructInitialSettingsPacket(1, &header_stream_offset));
  mock_quic_data.AddWrite(ConstructClientRequestHeadersPacket(
      2, GetNthClientInitiatedStreamId(0), true, true,
      GetRequestHeaders("GET", "http", "/"), &header_stream_offset));
  mock_quic_data.AddRead(ConstructServerResponseHeadersPacket(
      1, GetNthClientInitiatedStreamId(0), false, false,
      GetResponseHeaders("200 OK")));
  mock_quic_data.AddRead(ConstructServerDataPacket(
      2, GetNthClientInitiatedStreamId(0), false, true, 0, "hello!"));
  mock_quic_data.AddWrite(ConstructClientAckPacket(3, 2, 1, 1));
  mock_quic_data.AddRead(ASYNC, ERR_IO_PENDING);  // No more data to read
  mock_quic_data.AddRead(ASYNC, 0);
  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  scoped_refptr<X509Certificate> cert(
      ImportCertFromFile(GetTestCertsDirectory(), "wildcard.pem"));
  ASSERT_TRUE(cert.get());
  // This certificate is valid for the proxy, but not for the origin.
  EXPECT_TRUE(cert->VerifyNameMatch(proxy_host, false));
  EXPECT_FALSE(cert->VerifyNameMatch(origin_host, false));
  ProofVerifyDetailsChromium verify_details;
  verify_details.cert_verify_result.verified_cert = cert;
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  ProofVerifyDetailsChromium verify_details2;
  verify_details2.cert_verify_result.verified_cert = cert;
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details2);

  request_.url = GURL("http://" + origin_host);
  AddHangingNonAlternateProtocolSocketData();
  CreateSession();
  AddQuicAlternateProtocolMapping(MockCryptoClientStream::CONFIRM_HANDSHAKE);
  SendRequestAndExpectQuicResponseFromProxyOnPort("hello!", 70);
}

TEST_P(QuicNetworkTransactionTest, AlternativeServicesDifferentHost) {
  HostPortPair origin("www.example.org", 443);
  HostPortPair alternative("mail.example.org", 443);

  base::FilePath certs_dir = GetTestCertsDirectory();
  scoped_refptr<X509Certificate> cert(
      ImportCertFromFile(GetTestCertsDirectory(), "wildcard.pem"));
  ASSERT_TRUE(cert.get());
  // TODO(rch): the connection should be "to" the origin, so if the cert is
  // valid for the origin but not the alternative, that should work too.
  EXPECT_TRUE(cert->VerifyNameMatch(origin.host(), false));
  EXPECT_TRUE(cert->VerifyNameMatch(alternative.host(), false));
  ProofVerifyDetailsChromium verify_details;
  verify_details.cert_verify_result.verified_cert = cert;
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  client_maker_.set_hostname(origin.host());
  MockQuicData mock_quic_data;
  QuicStreamOffset header_stream_offset = 0;
  mock_quic_data.AddWrite(
      ConstructInitialSettingsPacket(1, &header_stream_offset));
  mock_quic_data.AddWrite(ConstructClientRequestHeadersPacket(
      2, GetNthClientInitiatedStreamId(0), true, true,
      GetRequestHeaders("GET", "https", "/"), &header_stream_offset));
  mock_quic_data.AddRead(ConstructServerResponseHeadersPacket(
      1, GetNthClientInitiatedStreamId(0), false, false,
      GetResponseHeaders("200 OK")));
  mock_quic_data.AddRead(ConstructServerDataPacket(
      2, GetNthClientInitiatedStreamId(0), false, true, 0, "hello!"));
  mock_quic_data.AddWrite(ConstructClientAckPacket(3, 2, 1, 1));
  mock_quic_data.AddRead(ASYNC, ERR_IO_PENDING);  // No more data to read
  mock_quic_data.AddRead(ASYNC, 0);
  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  request_.url = GURL("https://" + origin.host());
  AddQuicRemoteAlternativeServiceMapping(
      MockCryptoClientStream::CONFIRM_HANDSHAKE, alternative);
  AddHangingNonAlternateProtocolSocketData();
  CreateSession();

  SendRequestAndExpectQuicResponse("hello!");
}

// Regression test for https://crbug.com/546991.
// The server might not be able to serve a request on an alternative connection,
// and might send a 421 Misdirected Request response status to indicate this.
// HttpNetworkTransaction should reset the request and retry without using
// alternative services.
TEST_P(QuicNetworkTransactionTest, RetryMisdirectedRequest) {
  // Set up alternative service to use QUIC.
  // Note that |origins_to_force_quic_on| cannot be used in this test, because
  // that overrides |enable_alternative_services|.
  url::SchemeHostPort server(request_.url);
  AlternativeService alternative_service(kProtoQUIC, kDefaultServerHostName,
                                         443);
  base::Time expiration = base::Time::Now() + base::TimeDelta::FromDays(1);
  http_server_properties_.SetAlternativeService(server, alternative_service,
                                                expiration);

  // First try: The alternative job uses QUIC and reports an HTTP 421
  // Misdirected Request error.  The main job uses TCP, but |http_data| below is
  // paused at Connect(), so it will never exit the socket pool. This ensures
  // that the alternate job always wins the race and keeps whether the
  // |http_data| exits the socket pool before the main job is aborted
  // deterministic. The first main job gets aborted without the socket pool ever
  // dispensing the socket, making it available for the second try.
  MockQuicData mock_quic_data;
  QuicStreamOffset request_header_offset = 0;
  mock_quic_data.AddWrite(
      ConstructInitialSettingsPacket(1, &request_header_offset));
  mock_quic_data.AddWrite(ConstructClientRequestHeadersPacket(
      2, GetNthClientInitiatedStreamId(0), true, true,
      GetRequestHeaders("GET", "https", "/"), &request_header_offset));
  mock_quic_data.AddRead(ConstructServerResponseHeadersPacket(
      1, GetNthClientInitiatedStreamId(0), false, true,
      GetResponseHeaders("421"), nullptr));
  mock_quic_data.AddWrite(ConstructClientAckAndRstPacket(
      3, GetNthClientInitiatedStreamId(0), QUIC_STREAM_CANCELLED, 1, 1, 1));
  mock_quic_data.AddRead(ASYNC, OK);
  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  // Second try: The main job uses TCP, and there is no alternate job. Once the
  // Connect() is unblocked, |http_data| will leave the socket pool, binding to
  // the main job of the second request. It then succeeds over HTTP/1.1.
  // Note that if there was an alternative QUIC Job created for the second try,
  // that would read these data, and would fail with ERR_QUIC_PROTOCOL_ERROR.
  // Therefore this test ensures that no alternative Job is created on retry.
  MockWrite writes[] = {MockWrite(ASYNC, 0, "GET / HTTP/1.1\r\n"),
                        MockWrite(ASYNC, 1, "Host: mail.example.org\r\n"),
                        MockWrite(ASYNC, 2, "Connection: keep-alive\r\n\r\n")};
  MockRead reads[] = {MockRead(ASYNC, 3, "HTTP/1.1 200 OK\r\n\r\n"),
                      MockRead(ASYNC, 4, "hello!"), MockRead(ASYNC, OK, 5)};
  SequencedSocketData http_data(MockConnect(ASYNC, ERR_IO_PENDING) /* pause */,
                                reads, arraysize(reads), writes,
                                arraysize(writes));
  socket_factory_.AddSocketDataProvider(&http_data);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  CreateSession();
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session_.get());

  // Run until |mock_quic_data| has failed and |http_data| has paused.
  TestCompletionCallback callback;
  int rv = trans.Start(&request_, callback.callback(), net_log_.bound());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  base::RunLoop().RunUntilIdle();

  // |mock_quic_data| must have run to completion.
  EXPECT_TRUE(mock_quic_data.AllReadDataConsumed());
  EXPECT_TRUE(mock_quic_data.AllWriteDataConsumed());

  // Now that the QUIC data has been consumed, unblock |http_data|.
  http_data.socket()->OnConnectComplete(MockConnect());

  // The retry logic must hide the 421 status. The transaction succeeds on
  // |http_data|.
  EXPECT_THAT(callback.WaitForResult(), IsOk());
  CheckWasHttpResponse(&trans);
  CheckResponsePort(&trans, 443);
  CheckResponseData(&trans, "hello!");
}

TEST_P(QuicNetworkTransactionTest, ForceQuicWithErrorConnecting) {
  params_.origins_to_force_quic_on.insert(
      HostPortPair::FromString("mail.example.org:443"));

  MockQuicData mock_quic_data1;
  QuicStreamOffset header_stream_offset = 0;
  mock_quic_data1.AddWrite(
      ConstructInitialSettingsPacket(1, &header_stream_offset));
  mock_quic_data1.AddRead(ASYNC, ERR_SOCKET_NOT_CONNECTED);
  MockQuicData mock_quic_data2;
  header_stream_offset = 0;
  mock_quic_data2.AddWrite(
      ConstructInitialSettingsPacket(1, &header_stream_offset));
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details_);
  mock_quic_data2.AddRead(ASYNC, ERR_SOCKET_NOT_CONNECTED);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details_);

  mock_quic_data1.AddSocketDataToFactory(&socket_factory_);
  mock_quic_data2.AddSocketDataToFactory(&socket_factory_);

  CreateSession();

  EXPECT_EQ(0U, test_socket_performance_watcher_factory_.watcher_count());
  for (size_t i = 0; i < 2; ++i) {
    HttpNetworkTransaction trans(DEFAULT_PRIORITY, session_.get());
    TestCompletionCallback callback;
    int rv = trans.Start(&request_, callback.callback(), net_log_.bound());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
    EXPECT_THAT(callback.WaitForResult(), IsError(ERR_CONNECTION_CLOSED));
    EXPECT_EQ(1 + i, test_socket_performance_watcher_factory_.watcher_count());
  }
}

TEST_P(QuicNetworkTransactionTest, DoNotForceQuicForHttps) {
  // Attempt to "force" quic on 443, which will not be honored.
  params_.origins_to_force_quic_on.insert(
      HostPortPair::FromString("www.google.com:443"));

  MockRead http_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n\r\n"), MockRead("hello world"),
      MockRead(SYNCHRONOUS, ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ),
      MockRead(ASYNC, OK)};

  StaticSocketDataProvider data(http_reads, arraysize(http_reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&data);
  SSLSocketDataProvider ssl(ASYNC, OK);
  socket_factory_.AddSSLSocketDataProvider(&ssl);

  CreateSession();

  SendRequestAndExpectHttpResponse("hello world");
  EXPECT_EQ(0U, test_socket_performance_watcher_factory_.watcher_count());
}

TEST_P(QuicNetworkTransactionTest, UseAlternativeServiceForQuic) {
  MockRead http_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"), MockRead(kQuicAlternativeServiceHeader),
      MockRead("hello world"),
      MockRead(SYNCHRONOUS, ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ),
      MockRead(ASYNC, OK)};

  StaticSocketDataProvider http_data(http_reads, arraysize(http_reads), nullptr,
                                     0);
  socket_factory_.AddSocketDataProvider(&http_data);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  MockQuicData mock_quic_data;
  QuicStreamOffset header_stream_offset = 0;
  mock_quic_data.AddWrite(
      ConstructInitialSettingsPacket(1, &header_stream_offset));
  mock_quic_data.AddWrite(ConstructClientRequestHeadersPacket(
      2, GetNthClientInitiatedStreamId(0), true, true,
      GetRequestHeaders("GET", "https", "/"), &header_stream_offset));
  mock_quic_data.AddRead(ConstructServerResponseHeadersPacket(
      1, GetNthClientInitiatedStreamId(0), false, false,
      GetResponseHeaders("200 OK")));
  mock_quic_data.AddRead(ConstructServerDataPacket(
      2, GetNthClientInitiatedStreamId(0), false, true, 0, "hello!"));
  mock_quic_data.AddWrite(ConstructClientAckPacket(3, 2, 1, 1));
  mock_quic_data.AddRead(ASYNC, ERR_IO_PENDING);  // No more data to read
  mock_quic_data.AddRead(ASYNC, 0);               // EOF

  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  AddHangingNonAlternateProtocolSocketData();
  CreateSession();

  SendRequestAndExpectHttpResponse("hello world");
  SendRequestAndExpectQuicResponse("hello!");
}

TEST_P(QuicNetworkTransactionTest,
       UseAlternativeServiceWithProbabilityForQuic) {
  MockRead http_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead(kQuicAlternativeServiceWithProbabilityHeader),
      MockRead("hello world"),
      MockRead(SYNCHRONOUS, ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ),
      MockRead(ASYNC, OK)};

  StaticSocketDataProvider http_data(http_reads, arraysize(http_reads), nullptr,
                                     0);
  socket_factory_.AddSocketDataProvider(&http_data);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  MockQuicData mock_quic_data;
  QuicStreamOffset header_stream_offset = 0;
  mock_quic_data.AddWrite(
      ConstructInitialSettingsPacket(1, &header_stream_offset));
  mock_quic_data.AddWrite(ConstructClientRequestHeadersPacket(
      2, GetNthClientInitiatedStreamId(0), true, true,
      GetRequestHeaders("GET", "https", "/"), &header_stream_offset));
  mock_quic_data.AddRead(ConstructServerResponseHeadersPacket(
      1, GetNthClientInitiatedStreamId(0), false, false,
      GetResponseHeaders("200 OK")));
  mock_quic_data.AddRead(ConstructServerDataPacket(
      2, GetNthClientInitiatedStreamId(0), false, true, 0, "hello!"));
  mock_quic_data.AddWrite(ConstructClientAckPacket(3, 2, 1, 1));
  mock_quic_data.AddRead(ASYNC, ERR_IO_PENDING);  // No more data to read
  mock_quic_data.AddRead(ASYNC, 0);               // EOF

  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  AddHangingNonAlternateProtocolSocketData();
  CreateSession();

  SendRequestAndExpectHttpResponse("hello world");
  SendRequestAndExpectQuicResponse("hello!");
}

TEST_P(QuicNetworkTransactionTest, SetAlternativeServiceWithScheme) {
  MockRead http_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Alt-Svc: quic=\"foo.example.org:443\", quic=\":444\"\r\n\r\n"),
      MockRead("hello world"),
      MockRead(SYNCHRONOUS, ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ),
      MockRead(ASYNC, OK)};

  StaticSocketDataProvider http_data(http_reads, arraysize(http_reads), nullptr,
                                     0);

  socket_factory_.AddSocketDataProvider(&http_data);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  CreateSession();
  // Send https request, ignore alternative service advertising if response
  // header advertises alternative service for mail.example.org.
  request_.url = GURL("https://mail.example.org:443");
  SendRequestAndExpectHttpResponse("hello world");
  HttpServerProperties* http_server_properties =
      session_->http_server_properties();
  url::SchemeHostPort http_server("http", "mail.example.org", 443);
  url::SchemeHostPort https_server("https", "mail.example.org", 443);
  // Check alternative service is set for the correct origin.
  EXPECT_EQ(
      2u,
      http_server_properties->GetAlternativeServiceInfos(https_server).size());
  EXPECT_TRUE(
      http_server_properties->GetAlternativeServiceInfos(http_server).empty());
}

TEST_P(QuicNetworkTransactionTest, DoNotGetAltSvcForDifferentOrigin) {
  MockRead http_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Alt-Svc: quic=\"foo.example.org:443\", quic=\":444\"\r\n\r\n"),
      MockRead("hello world"),
      MockRead(SYNCHRONOUS, ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ),
      MockRead(ASYNC, OK)};

  StaticSocketDataProvider http_data(http_reads, arraysize(http_reads), nullptr,
                                     0);

  socket_factory_.AddSocketDataProvider(&http_data);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);
  socket_factory_.AddSocketDataProvider(&http_data);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  CreateSession();

  // Send https request and set alternative services if response header
  // advertises alternative service for mail.example.org.
  SendRequestAndExpectHttpResponse("hello world");
  HttpServerProperties* http_server_properties =
      session_->http_server_properties();

  const url::SchemeHostPort https_server(request_.url);
  // Check alternative service is set.
  EXPECT_EQ(
      2u,
      http_server_properties->GetAlternativeServiceInfos(https_server).size());

  // Send http request to the same origin but with diffrent scheme, should not
  // use QUIC.
  request_.url = GURL("http://mail.example.org:443");
  SendRequestAndExpectHttpResponse("hello world");
}

TEST_P(QuicNetworkTransactionTest, UseAlternativeServiceAllSupportedVersion) {
  std::string altsvc_header =
      base::StringPrintf("Alt-Svc: quic=\":443\"; v=\"%u\"\r\n\r\n", version_);
  MockRead http_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"), MockRead(altsvc_header.c_str()),
      MockRead("hello world"),
      MockRead(SYNCHRONOUS, ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ),
      MockRead(ASYNC, OK)};

  StaticSocketDataProvider http_data(http_reads, arraysize(http_reads), nullptr,
                                     0);
  socket_factory_.AddSocketDataProvider(&http_data);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  MockQuicData mock_quic_data;
  QuicStreamOffset header_stream_offset = 0;
  mock_quic_data.AddWrite(
      ConstructInitialSettingsPacket(1, &header_stream_offset));
  mock_quic_data.AddWrite(ConstructClientRequestHeadersPacket(
      2, GetNthClientInitiatedStreamId(0), true, true,
      GetRequestHeaders("GET", "https", "/"), &header_stream_offset));
  mock_quic_data.AddRead(ConstructServerResponseHeadersPacket(
      1, GetNthClientInitiatedStreamId(0), false, false,
      GetResponseHeaders("200 OK")));
  mock_quic_data.AddRead(ConstructServerDataPacket(
      2, GetNthClientInitiatedStreamId(0), false, true, 0, "hello!"));
  mock_quic_data.AddWrite(ConstructClientAckPacket(3, 2, 1, 1));
  mock_quic_data.AddRead(ASYNC, ERR_IO_PENDING);  // No more data to read
  mock_quic_data.AddRead(ASYNC, 0);               // EOF

  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  AddHangingNonAlternateProtocolSocketData();
  CreateSession();

  SendRequestAndExpectHttpResponse("hello world");
  SendRequestAndExpectQuicResponse("hello!");
}

TEST_P(QuicNetworkTransactionTest, GoAwayWithConnectionMigrationOnPortsOnly) {
  MockQuicData mock_quic_data;
  QuicStreamOffset header_stream_offset = 0;
  mock_quic_data.AddWrite(
      ConstructInitialSettingsPacket(1, &header_stream_offset));
  mock_quic_data.AddWrite(ConstructClientRequestHeadersPacket(
      2, GetNthClientInitiatedStreamId(0), true, true,
      GetRequestHeaders("GET", "https", "/"), &header_stream_offset));
  mock_quic_data.AddRead(ConstructServerResponseHeadersPacket(
      1, GetNthClientInitiatedStreamId(0), false, false,
      GetResponseHeaders("200 OK")));
  // Read a GoAway packet with
  // QuicErrorCode: QUIC_ERROR_MIGRATING_PORT from the peer.
  mock_quic_data.AddSynchronousRead(ConstructServerGoAwayPacket(
      2, QUIC_ERROR_MIGRATING_PORT,
      "connection migration with port change only"));
  mock_quic_data.AddWrite(ConstructClientAckPacket(3, 2, 1, 1));
  mock_quic_data.AddSynchronousRead(ConstructServerDataPacket(
      3, GetNthClientInitiatedStreamId(0), false, true, 0, "hello!"));
  mock_quic_data.AddWrite(ConstructClientAckAndRstPacket(
      4, GetNthClientInitiatedStreamId(0), QUIC_STREAM_CANCELLED, 3, 3, 1));
  mock_quic_data.AddRead(ASYNC, ERR_IO_PENDING);  // No more data to read
  mock_quic_data.AddRead(ASYNC, 0);               // EOF

  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  // The non-alternate protocol job needs to hang in order to guarantee that
  // the alternate-protocol job will "win".
  AddHangingNonAlternateProtocolSocketData();

  // In order for a new QUIC session to be established via alternate-protocol
  // without racing an HTTP connection, we need the host resolution to happen
  // synchronously.  Of course, even though QUIC *could* perform a 0-RTT
  // connection to the the server, in this test we require confirmation
  // before encrypting so the HTTP job will still start.
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule("mail.example.org", "192.168.0.1",
                                           "");
  HostResolver::RequestInfo info(HostPortPair("mail.example.org", 443));
  AddressList address;
  std::unique_ptr<HostResolver::Request> request;
  host_resolver_.Resolve(info, DEFAULT_PRIORITY, &address, CompletionCallback(),
                         &request, net_log_.bound());

  CreateSession();
  session_->quic_stream_factory()->set_require_confirmation(true);
  AddQuicAlternateProtocolMapping(MockCryptoClientStream::ZERO_RTT);

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session_.get());
  TestCompletionCallback callback;
  int rv = trans.Start(&request_, callback.callback(), net_log_.bound());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  crypto_client_stream_factory_.last_stream()->SendOnCryptoHandshakeEvent(
      QuicSession::HANDSHAKE_CONFIRMED);
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  // Check whether this transaction is correctly marked as received a go-away
  // because of migrating port.
  NetErrorDetails details;
  EXPECT_FALSE(details.quic_port_migration_detected);
  trans.PopulateNetErrorDetails(&details);
  EXPECT_TRUE(details.quic_port_migration_detected);
}

// Verify that if a QUIC connection times out, the QuicHttpStream will
// return QUIC_PROTOCOL_ERROR.
TEST_P(QuicNetworkTransactionTest, TimeoutAfterHandshakeConfirmed) {
  params_.quic_idle_connection_timeout_seconds = 5;

  // The request will initially go out over QUIC.
  MockQuicData quic_data;
  QuicStreamOffset header_stream_offset = 0;
  SpdyPriority priority =
      ConvertRequestPriorityToQuicPriority(DEFAULT_PRIORITY);

  std::string request_data;
  quic_data.AddWrite(client_maker_.MakeRequestHeadersPacketAndSaveData(
      1, GetNthClientInitiatedStreamId(0), true, true, priority,
      GetRequestHeaders("GET", "https", "/"), nullptr, &header_stream_offset,
      &request_data));

  std::string settings_data;
  QuicStreamOffset settings_offset = header_stream_offset;
  quic_data.AddWrite(client_maker_.MakeInitialSettingsPacketAndSaveData(
      2, &header_stream_offset, &settings_data));
  // TLP 1
  quic_data.AddWrite(client_maker_.MakeDataPacket(3, kHeadersStreamId, true,
                                                  false, 0, request_data));
  // TLP 2
  quic_data.AddWrite(client_maker_.MakeDataPacket(
      4, kHeadersStreamId, true, false, settings_offset, settings_data));
  // RTO 1
  quic_data.AddWrite(client_maker_.MakeDataPacket(5, kHeadersStreamId, true,
                                                  false, 0, request_data));
  quic_data.AddWrite(client_maker_.MakeDataPacket(
      6, kHeadersStreamId, true, false, settings_offset, settings_data));
  // RTO 2
  quic_data.AddWrite(client_maker_.MakeDataPacket(7, kHeadersStreamId, true,
                                                  false, 0, request_data));
  quic_data.AddWrite(client_maker_.MakeDataPacket(
      8, kHeadersStreamId, true, false, settings_offset, settings_data));
  // RTO 3
  quic_data.AddWrite(client_maker_.MakeDataPacket(9, kHeadersStreamId, true,
                                                  false, 0, request_data));
  quic_data.AddWrite(client_maker_.MakeDataPacket(
      10, kHeadersStreamId, true, false, settings_offset, settings_data));

  quic_data.AddRead(ASYNC, ERR_IO_PENDING);
  quic_data.AddRead(ASYNC, OK);
  quic_data.AddSocketDataToFactory(&socket_factory_);

  // In order for a new QUIC session to be established via alternate-protocol
  // without racing an HTTP connection, we need the host resolution to happen
  // synchronously.  Of course, even though QUIC *could* perform a 0-RTT
  // connection to the the server, in this test we require confirmation
  // before encrypting so the HTTP job will still start.
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule("mail.example.org", "192.168.0.1",
                                           "");
  HostResolver::RequestInfo info(HostPortPair("mail.example.org", 443));
  AddressList address;
  std::unique_ptr<HostResolver::Request> request;
  host_resolver_.Resolve(info, DEFAULT_PRIORITY, &address, CompletionCallback(),
                         &request, net_log_.bound());

  CreateSession();
  // Use a TestTaskRunner to avoid waiting in real time for timeouts.
  scoped_refptr<TestTaskRunner> quic_task_runner_(new TestTaskRunner(&clock_));
  QuicStreamFactoryPeer::SetAlarmFactory(
      session_->quic_stream_factory(),
      base::MakeUnique<QuicChromiumAlarmFactory>(quic_task_runner_.get(),
                                                 &clock_));

  AddQuicAlternateProtocolMapping(MockCryptoClientStream::ZERO_RTT);

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session_.get());
  TestCompletionCallback callback;
  int rv = trans.Start(&request_, callback.callback(), net_log_.bound());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Pump the message loop to get the request started.
  base::RunLoop().RunUntilIdle();
  // Explicitly confirm the handshake.
  crypto_client_stream_factory_.last_stream()->SendOnCryptoHandshakeEvent(
      QuicSession::HANDSHAKE_CONFIRMED);

  // Run the QUIC session to completion.
  quic_task_runner_->RunUntilIdle();

  ExpectQuicAlternateProtocolMapping();
  ASSERT_TRUE(quic_data.AllWriteDataConsumed());
  EXPECT_THAT(callback.WaitForResult(), IsError(ERR_QUIC_PROTOCOL_ERROR));
}

// Verify that if a QUIC connection RTOs, the QuicHttpStream will
// return QUIC_PROTOCOL_ERROR.
TEST_P(QuicNetworkTransactionTest, TooManyRtosAfterHandshakeConfirmed) {
  params_.quic_connection_options.push_back(k5RTO);

  // The request will initially go out over QUIC.
  MockQuicData quic_data;
  QuicStreamOffset header_stream_offset = 0;
  SpdyPriority priority =
      ConvertRequestPriorityToQuicPriority(DEFAULT_PRIORITY);

  std::string request_data;
  quic_data.AddWrite(client_maker_.MakeRequestHeadersPacketAndSaveData(
      1, GetNthClientInitiatedStreamId(0), true, true, priority,
      GetRequestHeaders("GET", "https", "/"), nullptr, &header_stream_offset,
      &request_data));

  std::string settings_data;
  QuicStreamOffset settings_offset = header_stream_offset;
  quic_data.AddWrite(client_maker_.MakeInitialSettingsPacketAndSaveData(
      2, &header_stream_offset, &settings_data));
  // TLP 1
  quic_data.AddWrite(client_maker_.MakeDataPacket(3, kHeadersStreamId, true,
                                                  false, 0, request_data));
  // TLP 2
  quic_data.AddWrite(client_maker_.MakeDataPacket(
      4, kHeadersStreamId, true, false, settings_offset, settings_data));
  // RTO 1
  quic_data.AddWrite(client_maker_.MakeDataPacket(5, kHeadersStreamId, true,
                                                  false, 0, request_data));
  quic_data.AddWrite(client_maker_.MakeDataPacket(
      6, kHeadersStreamId, true, false, settings_offset, settings_data));
  // RTO 2
  quic_data.AddWrite(client_maker_.MakeDataPacket(7, kHeadersStreamId, true,
                                                  false, 0, request_data));
  quic_data.AddWrite(client_maker_.MakeDataPacket(
      8, kHeadersStreamId, true, false, settings_offset, settings_data));
  // RTO 3
  quic_data.AddWrite(client_maker_.MakeDataPacket(9, kHeadersStreamId, true,
                                                  false, 0, request_data));
  quic_data.AddWrite(client_maker_.MakeDataPacket(
      10, kHeadersStreamId, true, false, settings_offset, settings_data));
  // RTO 4
  quic_data.AddWrite(client_maker_.MakeDataPacket(11, kHeadersStreamId, true,
                                                  false, 0, request_data));
  quic_data.AddWrite(client_maker_.MakeDataPacket(
      12, kHeadersStreamId, true, false, settings_offset, settings_data));
  // RTO 5
  quic_data.AddWrite(client_maker_.MakeAckAndConnectionClosePacket(
      13, true, QuicTime::Delta::Infinite(), 0, 1, 1, QUIC_TOO_MANY_RTOS,
      "5 consecutive retransmission timeouts"));

  quic_data.AddRead(ASYNC, OK);
  quic_data.AddSocketDataToFactory(&socket_factory_);

  // In order for a new QUIC session to be established via alternate-protocol
  // without racing an HTTP connection, we need the host resolution to happen
  // synchronously.  Of course, even though QUIC *could* perform a 0-RTT
  // connection to the the server, in this test we require confirmation
  // before encrypting so the HTTP job will still start.
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule("mail.example.org", "192.168.0.1",
                                           "");
  HostResolver::RequestInfo info(HostPortPair("mail.example.org", 443));
  AddressList address;
  std::unique_ptr<HostResolver::Request> request;
  host_resolver_.Resolve(info, DEFAULT_PRIORITY, &address, CompletionCallback(),
                         &request, net_log_.bound());

  CreateSession();
  // Use a TestTaskRunner to avoid waiting in real time for timeouts.
  scoped_refptr<TestTaskRunner> quic_task_runner_(new TestTaskRunner(&clock_));
  QuicStreamFactoryPeer::SetAlarmFactory(
      session_->quic_stream_factory(),
      base::MakeUnique<QuicChromiumAlarmFactory>(quic_task_runner_.get(),
                                                 &clock_));

  AddQuicAlternateProtocolMapping(MockCryptoClientStream::ZERO_RTT);

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session_.get());
  TestCompletionCallback callback;
  int rv = trans.Start(&request_, callback.callback(), net_log_.bound());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Pump the message loop to get the request started.
  base::RunLoop().RunUntilIdle();
  // Explicitly confirm the handshake.
  crypto_client_stream_factory_.last_stream()->SendOnCryptoHandshakeEvent(
      QuicSession::HANDSHAKE_CONFIRMED);

  // Run the QUIC session to completion.
  quic_task_runner_->RunUntilIdle();

  ExpectQuicAlternateProtocolMapping();
  ASSERT_TRUE(quic_data.AllWriteDataConsumed());
  EXPECT_THAT(callback.WaitForResult(), IsError(ERR_QUIC_PROTOCOL_ERROR));
}

// Verify that if a QUIC connection RTOs, while there are no active streams
// QUIC will not be marked as broken.
TEST_P(QuicNetworkTransactionTest,
       TooManyRtosAfterHandshakeConfirmedAndStreamReset) {
  params_.quic_connection_options.push_back(k5RTO);

  // The request will initially go out over QUIC.
  MockQuicData quic_data;
  QuicStreamOffset header_stream_offset = 0;
  SpdyPriority priority =
      ConvertRequestPriorityToQuicPriority(DEFAULT_PRIORITY);

  std::string request_data;
  quic_data.AddWrite(client_maker_.MakeRequestHeadersPacketAndSaveData(
      1, GetNthClientInitiatedStreamId(0), true, true, priority,
      GetRequestHeaders("GET", "https", "/"), nullptr, &header_stream_offset,
      &request_data));

  std::string settings_data;
  QuicStreamOffset settings_offset = header_stream_offset;
  quic_data.AddWrite(client_maker_.MakeInitialSettingsPacketAndSaveData(
      2, &header_stream_offset, &settings_data));

  quic_data.AddWrite(client_maker_.MakeRstPacket(
      3, true, GetNthClientInitiatedStreamId(0), QUIC_STREAM_CANCELLED));
  // TLP 1
  quic_data.AddWrite(client_maker_.MakeDataPacket(4, kHeadersStreamId, true,
                                                  false, 0, request_data));
  // TLP 2
  quic_data.AddWrite(client_maker_.MakeDataPacket(
      5, kHeadersStreamId, true, false, settings_offset, settings_data));
  // RTO 1
  quic_data.AddWrite(client_maker_.MakeRstPacket(
      6, true, GetNthClientInitiatedStreamId(0), QUIC_STREAM_CANCELLED));
  quic_data.AddWrite(client_maker_.MakeDataPacket(7, kHeadersStreamId, true,
                                                  false, 0, request_data));
  // RTO 2
  quic_data.AddWrite(client_maker_.MakeDataPacket(
      8, kHeadersStreamId, true, false, settings_offset, settings_data));
  quic_data.AddWrite(client_maker_.MakeRstPacket(
      9, true, GetNthClientInitiatedStreamId(0), QUIC_STREAM_CANCELLED));
  // RTO 3
  quic_data.AddWrite(client_maker_.MakeDataPacket(10, kHeadersStreamId, true,
                                                  false, 0, request_data));
  quic_data.AddWrite(client_maker_.MakeDataPacket(
      11, kHeadersStreamId, true, false, settings_offset, settings_data));
  // RTO 4
  quic_data.AddWrite(client_maker_.MakeRstPacket(
      12, true, GetNthClientInitiatedStreamId(0), QUIC_STREAM_CANCELLED));
  quic_data.AddWrite(client_maker_.MakeDataPacket(13, kHeadersStreamId, true,
                                                  false, 0, request_data));
  // RTO 5
  quic_data.AddWrite(client_maker_.MakeAckAndConnectionClosePacket(
      14, true, QuicTime::Delta::Infinite(), 0, 1, 1, QUIC_TOO_MANY_RTOS,
      "5 consecutive retransmission timeouts"));

  quic_data.AddRead(ASYNC, OK);
  quic_data.AddSocketDataToFactory(&socket_factory_);

  // In order for a new QUIC session to be established via alternate-protocol
  // without racing an HTTP connection, we need the host resolution to happen
  // synchronously.  Of course, even though QUIC *could* perform a 0-RTT
  // connection to the the server, in this test we require confirmation
  // before encrypting so the HTTP job will still start.
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule("mail.example.org", "192.168.0.1",
                                           "");
  HostResolver::RequestInfo info(HostPortPair("mail.example.org", 443));
  AddressList address;
  std::unique_ptr<HostResolver::Request> request;
  host_resolver_.Resolve(info, DEFAULT_PRIORITY, &address, CompletionCallback(),
                         &request, net_log_.bound());

  CreateSession();
  // Use a TestTaskRunner to avoid waiting in real time for timeouts.
  scoped_refptr<TestTaskRunner> quic_task_runner_(new TestTaskRunner(&clock_));
  QuicStreamFactoryPeer::SetAlarmFactory(
      session_->quic_stream_factory(),
      base::MakeUnique<QuicChromiumAlarmFactory>(quic_task_runner_.get(),
                                                 &clock_));

  AddQuicAlternateProtocolMapping(MockCryptoClientStream::ZERO_RTT);

  auto trans = base::MakeUnique<HttpNetworkTransaction>(DEFAULT_PRIORITY,
                                                        session_.get());
  TestCompletionCallback callback;
  int rv = trans->Start(&request_, callback.callback(), net_log_.bound());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Pump the message loop to get the request started.
  base::RunLoop().RunUntilIdle();
  // Explicitly confirm the handshake.
  crypto_client_stream_factory_.last_stream()->SendOnCryptoHandshakeEvent(
      QuicSession::HANDSHAKE_CONFIRMED);

  // Now cancel the request.
  trans.reset();

  // Run the QUIC session to completion.
  quic_task_runner_->RunUntilIdle();

  ExpectQuicAlternateProtocolMapping();

  ASSERT_TRUE(quic_data.AllWriteDataConsumed());
}

// Verify that if a QUIC protocol error occurs after the handshake is confirmed
// the request fails with QUIC_PROTOCOL_ERROR.
TEST_P(QuicNetworkTransactionTest, ProtocolErrorAfterHandshakeConfirmed) {
  // The request will initially go out over QUIC.
  MockQuicData quic_data;
  QuicStreamOffset header_stream_offset = 0;
  quic_data.AddWrite(ConstructClientRequestHeadersPacket(
      1, GetNthClientInitiatedStreamId(0), true, true,
      GetRequestHeaders("GET", "https", "/"), &header_stream_offset));
  quic_data.AddWrite(ConstructInitialSettingsPacket(2, &header_stream_offset));
  // Peer sending data from an non-existing stream causes this end to raise
  // error and close connection.
  quic_data.AddRead(
      ConstructServerRstPacket(1, false, 99, QUIC_STREAM_LAST_ERROR));
  std::string quic_error_details = "Data for nonexistent stream";
  quic_data.AddWrite(ConstructClientAckAndConnectionClosePacket(
      3, QuicTime::Delta::Zero(), 1, 1, 1, QUIC_INVALID_STREAM_ID,
      quic_error_details));
  quic_data.AddSocketDataToFactory(&socket_factory_);

  // In order for a new QUIC session to be established via alternate-protocol
  // without racing an HTTP connection, we need the host resolution to happen
  // synchronously.  Of course, even though QUIC *could* perform a 0-RTT
  // connection to the the server, in this test we require confirmation
  // before encrypting so the HTTP job will still start.
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule("mail.example.org", "192.168.0.1",
                                           "");
  HostResolver::RequestInfo info(HostPortPair("mail.example.org", 443));
  AddressList address;
  std::unique_ptr<HostResolver::Request> request;
  host_resolver_.Resolve(info, DEFAULT_PRIORITY, &address, CompletionCallback(),
                         &request, net_log_.bound());

  CreateSession();

  AddQuicAlternateProtocolMapping(MockCryptoClientStream::ZERO_RTT);

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session_.get());
  TestCompletionCallback callback;
  int rv = trans.Start(&request_, callback.callback(), net_log_.bound());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Pump the message loop to get the request started.
  base::RunLoop().RunUntilIdle();
  // Explicitly confirm the handshake.
  crypto_client_stream_factory_.last_stream()->SendOnCryptoHandshakeEvent(
      QuicSession::HANDSHAKE_CONFIRMED);

  ASSERT_FALSE(quic_data.AllReadDataConsumed());

  // Run the QUIC session to completion.
  base::RunLoop().RunUntilIdle();
  ASSERT_TRUE(quic_data.AllWriteDataConsumed());
  ASSERT_TRUE(quic_data.AllReadDataConsumed());

  EXPECT_THAT(callback.WaitForResult(), IsError(ERR_QUIC_PROTOCOL_ERROR));
  ExpectQuicAlternateProtocolMapping();
  ASSERT_TRUE(quic_data.AllWriteDataConsumed());
}

// Verify that with mark_quic_broken_when_network_blackholes enabled, if a QUIC
// connection times out, then QUIC will be marked as broken and the request
// retried over TCP.
TEST_P(QuicNetworkTransactionTest, TimeoutAfterHandshakeConfirmedThenBroken) {
  params_.mark_quic_broken_when_network_blackholes = true;
  params_.quic_idle_connection_timeout_seconds = 5;

  // The request will initially go out over QUIC.
  MockQuicData quic_data;
  QuicStreamOffset header_stream_offset = 0;
  SpdyPriority priority =
      ConvertRequestPriorityToQuicPriority(DEFAULT_PRIORITY);

  std::string request_data;
  quic_data.AddWrite(client_maker_.MakeRequestHeadersPacketAndSaveData(
      1, GetNthClientInitiatedStreamId(0), true, true, priority,
      GetRequestHeaders("GET", "https", "/"), nullptr, &header_stream_offset,
      &request_data));

  std::string settings_data;
  QuicStreamOffset settings_offset = header_stream_offset;
  quic_data.AddWrite(client_maker_.MakeInitialSettingsPacketAndSaveData(
      2, &header_stream_offset, &settings_data));
  // TLP 1
  quic_data.AddWrite(client_maker_.MakeDataPacket(3, kHeadersStreamId, true,
                                                  false, 0, request_data));
  // TLP 2
  quic_data.AddWrite(client_maker_.MakeDataPacket(
      4, kHeadersStreamId, true, false, settings_offset, settings_data));
  // RTO 1
  quic_data.AddWrite(client_maker_.MakeDataPacket(5, kHeadersStreamId, true,
                                                  false, 0, request_data));
  quic_data.AddWrite(client_maker_.MakeDataPacket(
      6, kHeadersStreamId, true, false, settings_offset, settings_data));
  // RTO 2
  quic_data.AddWrite(client_maker_.MakeDataPacket(7, kHeadersStreamId, true,
                                                  false, 0, request_data));
  quic_data.AddWrite(client_maker_.MakeDataPacket(
      8, kHeadersStreamId, true, false, settings_offset, settings_data));
  // RTO 3
  quic_data.AddWrite(client_maker_.MakeDataPacket(9, kHeadersStreamId, true,
                                                  false, 0, request_data));
  quic_data.AddWrite(client_maker_.MakeDataPacket(
      10, kHeadersStreamId, true, false, settings_offset, settings_data));

  quic_data.AddRead(ASYNC, ERR_IO_PENDING);
  quic_data.AddRead(ASYNC, OK);
  quic_data.AddSocketDataToFactory(&socket_factory_);

  // After that fails, it will be resent via TCP.
  MockWrite http_writes[] = {
      MockWrite(SYNCHRONOUS, 0, "GET / HTTP/1.1\r\n"),
      MockWrite(SYNCHRONOUS, 1, "Host: mail.example.org\r\n"),
      MockWrite(SYNCHRONOUS, 2, "Connection: keep-alive\r\n\r\n")};

  MockRead http_reads[] = {
      MockRead(SYNCHRONOUS, 3, "HTTP/1.1 200 OK\r\n"),
      MockRead(SYNCHRONOUS, 4, kQuicAlternativeServiceHeader),
      MockRead(SYNCHRONOUS, 5, "hello world"), MockRead(SYNCHRONOUS, OK, 6)};
  SequencedSocketData http_data(http_reads, arraysize(http_reads), http_writes,
                                arraysize(http_writes));
  socket_factory_.AddSocketDataProvider(&http_data);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  // In order for a new QUIC session to be established via alternate-protocol
  // without racing an HTTP connection, we need the host resolution to happen
  // synchronously.  Of course, even though QUIC *could* perform a 0-RTT
  // connection to the the server, in this test we require confirmation
  // before encrypting so the HTTP job will still start.
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule("mail.example.org", "192.168.0.1",
                                           "");
  HostResolver::RequestInfo info(HostPortPair("mail.example.org", 443));
  AddressList address;
  std::unique_ptr<HostResolver::Request> request;
  host_resolver_.Resolve(info, DEFAULT_PRIORITY, &address, CompletionCallback(),
                         &request, net_log_.bound());

  CreateSession();
  // Use a TestTaskRunner to avoid waiting in real time for timeouts.
  scoped_refptr<TestTaskRunner> quic_task_runner_(new TestTaskRunner(&clock_));
  QuicStreamFactoryPeer::SetAlarmFactory(
      session_->quic_stream_factory(),
      base::MakeUnique<QuicChromiumAlarmFactory>(quic_task_runner_.get(),
                                                 &clock_));

  AddQuicAlternateProtocolMapping(MockCryptoClientStream::ZERO_RTT);

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session_.get());
  TestCompletionCallback callback;
  int rv = trans.Start(&request_, callback.callback(), net_log_.bound());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Pump the message loop to get the request started.
  base::RunLoop().RunUntilIdle();
  // Explicitly confirm the handshake.
  crypto_client_stream_factory_.last_stream()->SendOnCryptoHandshakeEvent(
      QuicSession::HANDSHAKE_CONFIRMED);

  // Run the QUIC session to completion.
  quic_task_runner_->RunUntilIdle();
  ASSERT_TRUE(quic_data.AllWriteDataConsumed());

  // Let the transaction proceed which will result in QUIC being marked
  // as broken and the request falling back to TCP.
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  ExpectBrokenAlternateProtocolMapping();
  ASSERT_TRUE(quic_data.AllWriteDataConsumed());
  ASSERT_FALSE(http_data.AllReadDataConsumed());

  // Read the response body over TCP.
  CheckResponseData(&trans, "hello world");
  ASSERT_TRUE(http_data.AllWriteDataConsumed());
  ASSERT_TRUE(http_data.AllReadDataConsumed());
}

// Verify that with retry_without_alt_svc_on_quic_errors enabled, if a QUIC
// connection times out, then QUIC will be marked as broken and the request
// retried over TCP.
TEST_P(QuicNetworkTransactionTest, TimeoutAfterHandshakeConfirmedThenBroken2) {
  params_.retry_without_alt_svc_on_quic_errors = true;
  params_.quic_idle_connection_timeout_seconds = 5;

  // The request will initially go out over QUIC.
  MockQuicData quic_data;
  QuicStreamOffset header_stream_offset = 0;
  SpdyPriority priority =
      ConvertRequestPriorityToQuicPriority(DEFAULT_PRIORITY);

  std::string request_data;
  quic_data.AddWrite(client_maker_.MakeRequestHeadersPacketAndSaveData(
      1, GetNthClientInitiatedStreamId(0), true, true, priority,
      GetRequestHeaders("GET", "https", "/"), nullptr, &header_stream_offset,
      &request_data));

  std::string settings_data;
  QuicStreamOffset settings_offset = header_stream_offset;
  quic_data.AddWrite(client_maker_.MakeInitialSettingsPacketAndSaveData(
      2, &header_stream_offset, &settings_data));
  // TLP 1
  quic_data.AddWrite(client_maker_.MakeDataPacket(3, kHeadersStreamId, true,
                                                  false, 0, request_data));
  // TLP 2
  quic_data.AddWrite(client_maker_.MakeDataPacket(
      4, kHeadersStreamId, true, false, settings_offset, settings_data));
  // RTO 1
  quic_data.AddWrite(client_maker_.MakeDataPacket(5, kHeadersStreamId, true,
                                                  false, 0, request_data));
  quic_data.AddWrite(client_maker_.MakeDataPacket(
      6, kHeadersStreamId, true, false, settings_offset, settings_data));
  // RTO 2
  quic_data.AddWrite(client_maker_.MakeDataPacket(7, kHeadersStreamId, true,
                                                  false, 0, request_data));
  quic_data.AddWrite(client_maker_.MakeDataPacket(
      8, kHeadersStreamId, true, false, settings_offset, settings_data));
  // RTO 3
  quic_data.AddWrite(client_maker_.MakeDataPacket(9, kHeadersStreamId, true,
                                                  false, 0, request_data));
  quic_data.AddWrite(client_maker_.MakeDataPacket(
      10, kHeadersStreamId, true, false, settings_offset, settings_data));

  quic_data.AddRead(ASYNC, ERR_IO_PENDING);
  quic_data.AddRead(ASYNC, OK);
  quic_data.AddSocketDataToFactory(&socket_factory_);

  // After that fails, it will be resent via TCP.
  MockWrite http_writes[] = {
      MockWrite(SYNCHRONOUS, 0, "GET / HTTP/1.1\r\n"),
      MockWrite(SYNCHRONOUS, 1, "Host: mail.example.org\r\n"),
      MockWrite(SYNCHRONOUS, 2, "Connection: keep-alive\r\n\r\n")};

  MockRead http_reads[] = {
      MockRead(SYNCHRONOUS, 3, "HTTP/1.1 200 OK\r\n"),
      MockRead(SYNCHRONOUS, 4, kQuicAlternativeServiceHeader),
      MockRead(SYNCHRONOUS, 5, "hello world"), MockRead(SYNCHRONOUS, OK, 6)};
  SequencedSocketData http_data(http_reads, arraysize(http_reads), http_writes,
                                arraysize(http_writes));
  socket_factory_.AddSocketDataProvider(&http_data);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  // In order for a new QUIC session to be established via alternate-protocol
  // without racing an HTTP connection, we need the host resolution to happen
  // synchronously.  Of course, even though QUIC *could* perform a 0-RTT
  // connection to the the server, in this test we require confirmation
  // before encrypting so the HTTP job will still start.
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule("mail.example.org", "192.168.0.1",
                                           "");
  HostResolver::RequestInfo info(HostPortPair("mail.example.org", 443));
  AddressList address;
  std::unique_ptr<HostResolver::Request> request;
  host_resolver_.Resolve(info, DEFAULT_PRIORITY, &address, CompletionCallback(),
                         &request, net_log_.bound());

  CreateSession();
  // Use a TestTaskRunner to avoid waiting in real time for timeouts.
  scoped_refptr<TestTaskRunner> quic_task_runner_(new TestTaskRunner(&clock_));
  QuicStreamFactoryPeer::SetAlarmFactory(
      session_->quic_stream_factory(),
      base::MakeUnique<QuicChromiumAlarmFactory>(quic_task_runner_.get(),
                                                 &clock_));

  AddQuicAlternateProtocolMapping(MockCryptoClientStream::ZERO_RTT);

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session_.get());
  TestCompletionCallback callback;
  int rv = trans.Start(&request_, callback.callback(), net_log_.bound());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Pump the message loop to get the request started.
  base::RunLoop().RunUntilIdle();
  // Explicitly confirm the handshake.
  crypto_client_stream_factory_.last_stream()->SendOnCryptoHandshakeEvent(
      QuicSession::HANDSHAKE_CONFIRMED);

  // Run the QUIC session to completion.
  quic_task_runner_->RunUntilIdle();
  ASSERT_TRUE(quic_data.AllWriteDataConsumed());

  ExpectQuicAlternateProtocolMapping();

  // Let the transaction proceed which will result in QUIC being marked
  // as broken and the request falling back to TCP.
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  ASSERT_TRUE(quic_data.AllWriteDataConsumed());
  ASSERT_FALSE(http_data.AllReadDataConsumed());

  // Read the response body over TCP.
  CheckResponseData(&trans, "hello world");
  ExpectBrokenAlternateProtocolMapping();
  ASSERT_TRUE(http_data.AllWriteDataConsumed());
  ASSERT_TRUE(http_data.AllReadDataConsumed());
}

// Verify that with mark_quic_broken_when_network_blackholes enabled, if a QUIC
// connection times out, then QUIC will be marked as broken but the request
// will not be retried over TCP.
TEST_P(QuicNetworkTransactionTest,
       TimeoutAfterHandshakeConfirmedAndHeadersThenBrokenNotRetried) {
  params_.mark_quic_broken_when_network_blackholes = true;
  params_.quic_idle_connection_timeout_seconds = 5;

  // The request will initially go out over QUIC.
  MockQuicData quic_data;
  QuicStreamOffset header_stream_offset = 0;
  SpdyPriority priority =
      ConvertRequestPriorityToQuicPriority(DEFAULT_PRIORITY);

  std::string request_data;
  quic_data.AddWrite(client_maker_.MakeRequestHeadersPacketAndSaveData(
      1, GetNthClientInitiatedStreamId(0), true, true, priority,
      GetRequestHeaders("GET", "https", "/"), nullptr, &header_stream_offset,
      &request_data));

  std::string settings_data;
  QuicStreamOffset settings_offset = header_stream_offset;
  quic_data.AddWrite(client_maker_.MakeInitialSettingsPacketAndSaveData(
      2, &header_stream_offset, &settings_data));

  quic_data.AddRead(ConstructServerResponseHeadersPacket(
      1, GetNthClientInitiatedStreamId(0), false, false,
      GetResponseHeaders("200 OK")));
  // quic_data.AddWrite(ConstructClientAckPacket(3, 1, 1));
  quic_data.AddWrite(ConstructClientAckPacket(
      3, 1, 1, 1, QuicTime::Delta::FromMilliseconds(25)));

  // TLP 1
  quic_data.AddWrite(client_maker_.MakeDataPacket(4, kHeadersStreamId, false,
                                                  false, 0, request_data));
  // TLP 2
  quic_data.AddWrite(client_maker_.MakeDataPacket(
      5, kHeadersStreamId, false, false, settings_offset, settings_data));
  // RTO 1
  quic_data.AddWrite(client_maker_.MakeDataPacket(6, kHeadersStreamId, false,
                                                  false, 0, request_data));
  quic_data.AddWrite(client_maker_.MakeDataPacket(
      7, kHeadersStreamId, false, false, settings_offset, settings_data));
  // RTO 2
  quic_data.AddWrite(client_maker_.MakeDataPacket(8, kHeadersStreamId, false,
                                                  false, 0, request_data));
  quic_data.AddWrite(client_maker_.MakeDataPacket(
      9, kHeadersStreamId, false, false, settings_offset, settings_data));
  // RTO 3
  quic_data.AddWrite(client_maker_.MakeDataPacket(10, kHeadersStreamId, false,
                                                  false, 0, request_data));
  quic_data.AddWrite(client_maker_.MakeDataPacket(
      11, kHeadersStreamId, false, false, settings_offset, settings_data));

  quic_data.AddRead(ASYNC, ERR_IO_PENDING);
  quic_data.AddRead(ASYNC, OK);
  quic_data.AddSocketDataToFactory(&socket_factory_);

  // In order for a new QUIC session to be established via alternate-protocol
  // without racing an HTTP connection, we need the host resolution to happen
  // synchronously.  Of course, even though QUIC *could* perform a 0-RTT
  // connection to the the server, in this test we require confirmation
  // before encrypting so the HTTP job will still start.
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule("mail.example.org", "192.168.0.1",
                                           "");
  HostResolver::RequestInfo info(HostPortPair("mail.example.org", 443));
  AddressList address;
  std::unique_ptr<HostResolver::Request> request;
  host_resolver_.Resolve(info, DEFAULT_PRIORITY, &address, CompletionCallback(),
                         &request, net_log_.bound());

  CreateSession();
  // Use a TestTaskRunner to avoid waiting in real time for timeouts.
  scoped_refptr<TestTaskRunner> quic_task_runner_(new TestTaskRunner(&clock_));
  QuicStreamFactoryPeer::SetAlarmFactory(
      session_->quic_stream_factory(),
      base::MakeUnique<QuicChromiumAlarmFactory>(quic_task_runner_.get(),
                                                 &clock_));

  AddQuicAlternateProtocolMapping(MockCryptoClientStream::ZERO_RTT);

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session_.get());
  TestCompletionCallback callback;
  int rv = trans.Start(&request_, callback.callback(), net_log_.bound());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Pump the message loop to get the request started.
  base::RunLoop().RunUntilIdle();
  // Explicitly confirm the handshake.
  crypto_client_stream_factory_.last_stream()->SendOnCryptoHandshakeEvent(
      QuicSession::HANDSHAKE_CONFIRMED);

  // Pump the message loop to get the request started.
  base::RunLoop().RunUntilIdle();

  // Run the QUIC session to completion.
  quic_task_runner_->RunUntilIdle();
  ASSERT_TRUE(quic_data.AllWriteDataConsumed());

  // Let the transaction proceed which will result in QUIC being marked
  // as broken and the request falling back to TCP.
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  ExpectBrokenAlternateProtocolMapping();
  ASSERT_TRUE(quic_data.AllWriteDataConsumed());

  std::string response_data;
  ASSERT_THAT(ReadTransaction(&trans, &response_data),
              IsError(ERR_QUIC_PROTOCOL_ERROR));
}

// Verify that with mark_quic_broken_when_network_blackholes enabled, if a QUIC
// connection RTOs, then QUIC will be marked as broken and the request retried
// over TCP.
TEST_P(QuicNetworkTransactionTest,
       TooManyRtosAfterHandshakeConfirmedThenBroken) {
  params_.mark_quic_broken_when_network_blackholes = true;
  params_.quic_connection_options.push_back(k5RTO);

  // The request will initially go out over QUIC.
  MockQuicData quic_data;
  QuicStreamOffset header_stream_offset = 0;
  SpdyPriority priority =
      ConvertRequestPriorityToQuicPriority(DEFAULT_PRIORITY);

  std::string request_data;
  quic_data.AddWrite(client_maker_.MakeRequestHeadersPacketAndSaveData(
      1, GetNthClientInitiatedStreamId(0), true, true, priority,
      GetRequestHeaders("GET", "https", "/"), nullptr, &header_stream_offset,
      &request_data));

  std::string settings_data;
  QuicStreamOffset settings_offset = header_stream_offset;
  quic_data.AddWrite(client_maker_.MakeInitialSettingsPacketAndSaveData(
      2, &header_stream_offset, &settings_data));
  // TLP 1
  quic_data.AddWrite(client_maker_.MakeDataPacket(3, kHeadersStreamId, true,
                                                  false, 0, request_data));
  // TLP 2
  quic_data.AddWrite(client_maker_.MakeDataPacket(
      4, kHeadersStreamId, true, false, settings_offset, settings_data));
  // RTO 1
  quic_data.AddWrite(client_maker_.MakeDataPacket(5, kHeadersStreamId, true,
                                                  false, 0, request_data));
  quic_data.AddWrite(client_maker_.MakeDataPacket(
      6, kHeadersStreamId, true, false, settings_offset, settings_data));
  // RTO 2
  quic_data.AddWrite(client_maker_.MakeDataPacket(7, kHeadersStreamId, true,
                                                  false, 0, request_data));
  quic_data.AddWrite(client_maker_.MakeDataPacket(
      8, kHeadersStreamId, true, false, settings_offset, settings_data));
  // RTO 3
  quic_data.AddWrite(client_maker_.MakeDataPacket(9, kHeadersStreamId, true,
                                                  false, 0, request_data));
  quic_data.AddWrite(client_maker_.MakeDataPacket(
      10, kHeadersStreamId, true, false, settings_offset, settings_data));
  // RTO 4
  quic_data.AddWrite(client_maker_.MakeDataPacket(11, kHeadersStreamId, true,
                                                  false, 0, request_data));
  quic_data.AddWrite(client_maker_.MakeDataPacket(
      12, kHeadersStreamId, true, false, settings_offset, settings_data));

  quic_data.AddWrite(client_maker_.MakeAckAndConnectionClosePacket(
      13, true, QuicTime::Delta::Infinite(), 0, 1, 1, QUIC_TOO_MANY_RTOS,
      "5 consecutive retransmission timeouts"));

  quic_data.AddRead(ASYNC, OK);
  quic_data.AddSocketDataToFactory(&socket_factory_);

  // After that fails, it will be resent via TCP.
  MockWrite http_writes[] = {
      MockWrite(SYNCHRONOUS, 0, "GET / HTTP/1.1\r\n"),
      MockWrite(SYNCHRONOUS, 1, "Host: mail.example.org\r\n"),
      MockWrite(SYNCHRONOUS, 2, "Connection: keep-alive\r\n\r\n")};

  MockRead http_reads[] = {
      MockRead(SYNCHRONOUS, 3, "HTTP/1.1 200 OK\r\n"),
      MockRead(SYNCHRONOUS, 4, kQuicAlternativeServiceHeader),
      MockRead(SYNCHRONOUS, 5, "hello world"), MockRead(SYNCHRONOUS, OK, 6)};
  SequencedSocketData http_data(http_reads, arraysize(http_reads), http_writes,
                                arraysize(http_writes));
  socket_factory_.AddSocketDataProvider(&http_data);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  // In order for a new QUIC session to be established via alternate-protocol
  // without racing an HTTP connection, we need the host resolution to happen
  // synchronously.  Of course, even though QUIC *could* perform a 0-RTT
  // connection to the the server, in this test we require confirmation
  // before encrypting so the HTTP job will still start.
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule("mail.example.org", "192.168.0.1",
                                           "");
  HostResolver::RequestInfo info(HostPortPair("mail.example.org", 443));
  AddressList address;
  std::unique_ptr<HostResolver::Request> request;
  host_resolver_.Resolve(info, DEFAULT_PRIORITY, &address, CompletionCallback(),
                         &request, net_log_.bound());

  CreateSession();
  // Use a TestTaskRunner to avoid waiting in real time for timeouts.
  scoped_refptr<TestTaskRunner> quic_task_runner_(new TestTaskRunner(&clock_));
  QuicStreamFactoryPeer::SetAlarmFactory(
      session_->quic_stream_factory(),
      base::MakeUnique<QuicChromiumAlarmFactory>(quic_task_runner_.get(),
                                                 &clock_));

  AddQuicAlternateProtocolMapping(MockCryptoClientStream::ZERO_RTT);

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session_.get());
  TestCompletionCallback callback;
  int rv = trans.Start(&request_, callback.callback(), net_log_.bound());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Pump the message loop to get the request started.
  base::RunLoop().RunUntilIdle();
  // Explicitly confirm the handshake.
  crypto_client_stream_factory_.last_stream()->SendOnCryptoHandshakeEvent(
      QuicSession::HANDSHAKE_CONFIRMED);

  // Run the QUIC session to completion.
  quic_task_runner_->RunUntilIdle();
  ASSERT_TRUE(quic_data.AllWriteDataConsumed());

  // Let the transaction proceed which will result in QUIC being marked
  // as broken and the request falling back to TCP.
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  ExpectBrokenAlternateProtocolMapping();
  ASSERT_TRUE(quic_data.AllWriteDataConsumed());
  ASSERT_FALSE(http_data.AllReadDataConsumed());

  // Read the response body over TCP.
  CheckResponseData(&trans, "hello world");
  ASSERT_TRUE(http_data.AllWriteDataConsumed());
  ASSERT_TRUE(http_data.AllReadDataConsumed());
}

// Verify that if a QUIC connection RTOs, while there are no active streams
// QUIC will be marked as broken.
TEST_P(QuicNetworkTransactionTest,
       TooManyRtosAfterHandshakeConfirmedAndStreamResetThenBroken) {
  params_.mark_quic_broken_when_network_blackholes = true;
  params_.quic_connection_options.push_back(k5RTO);

  // The request will initially go out over QUIC.
  MockQuicData quic_data;
  QuicStreamOffset header_stream_offset = 0;
  SpdyPriority priority =
      ConvertRequestPriorityToQuicPriority(DEFAULT_PRIORITY);

  std::string request_data;
  quic_data.AddWrite(client_maker_.MakeRequestHeadersPacketAndSaveData(
      1, GetNthClientInitiatedStreamId(0), true, true, priority,
      GetRequestHeaders("GET", "https", "/"), nullptr, &header_stream_offset,
      &request_data));

  std::string settings_data;
  QuicStreamOffset settings_offset = header_stream_offset;
  quic_data.AddWrite(client_maker_.MakeInitialSettingsPacketAndSaveData(
      2, &header_stream_offset, &settings_data));

  quic_data.AddWrite(client_maker_.MakeRstPacket(
      3, true, GetNthClientInitiatedStreamId(0), QUIC_STREAM_CANCELLED));
  // TLP 1
  quic_data.AddWrite(client_maker_.MakeDataPacket(4, kHeadersStreamId, true,
                                                  false, 0, request_data));
  // TLP 2
  quic_data.AddWrite(client_maker_.MakeDataPacket(
      5, kHeadersStreamId, true, false, settings_offset, settings_data));
  // RTO 1
  quic_data.AddWrite(client_maker_.MakeRstPacket(
      6, true, GetNthClientInitiatedStreamId(0), QUIC_STREAM_CANCELLED));
  quic_data.AddWrite(client_maker_.MakeDataPacket(7, kHeadersStreamId, true,
                                                  false, 0, request_data));
  // RTO 2
  quic_data.AddWrite(client_maker_.MakeDataPacket(
      8, kHeadersStreamId, true, false, settings_offset, settings_data));
  quic_data.AddWrite(client_maker_.MakeRstPacket(
      9, true, GetNthClientInitiatedStreamId(0), QUIC_STREAM_CANCELLED));
  // RTO 3
  quic_data.AddWrite(client_maker_.MakeDataPacket(10, kHeadersStreamId, true,
                                                  false, 0, request_data));
  quic_data.AddWrite(client_maker_.MakeDataPacket(
      11, kHeadersStreamId, true, false, settings_offset, settings_data));
  // RTO 4
  quic_data.AddWrite(client_maker_.MakeRstPacket(
      12, true, GetNthClientInitiatedStreamId(0), QUIC_STREAM_CANCELLED));
  quic_data.AddWrite(client_maker_.MakeDataPacket(13, kHeadersStreamId, true,
                                                  false, 0, request_data));
  // RTO 5
  quic_data.AddWrite(client_maker_.MakeAckAndConnectionClosePacket(
      14, true, QuicTime::Delta::Infinite(), 0, 1, 1, QUIC_TOO_MANY_RTOS,
      "5 consecutive retransmission timeouts"));

  quic_data.AddRead(ASYNC, OK);
  quic_data.AddSocketDataToFactory(&socket_factory_);

  // In order for a new QUIC session to be established via alternate-protocol
  // without racing an HTTP connection, we need the host resolution to happen
  // synchronously.  Of course, even though QUIC *could* perform a 0-RTT
  // connection to the the server, in this test we require confirmation
  // before encrypting so the HTTP job will still start.
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule("mail.example.org", "192.168.0.1",
                                           "");
  HostResolver::RequestInfo info(HostPortPair("mail.example.org", 443));
  AddressList address;
  std::unique_ptr<HostResolver::Request> request;
  host_resolver_.Resolve(info, DEFAULT_PRIORITY, &address, CompletionCallback(),
                         &request, net_log_.bound());

  CreateSession();
  // Use a TestTaskRunner to avoid waiting in real time for timeouts.
  scoped_refptr<TestTaskRunner> quic_task_runner_(new TestTaskRunner(&clock_));
  QuicStreamFactoryPeer::SetAlarmFactory(
      session_->quic_stream_factory(),
      base::MakeUnique<QuicChromiumAlarmFactory>(quic_task_runner_.get(),
                                                 &clock_));

  AddQuicAlternateProtocolMapping(MockCryptoClientStream::ZERO_RTT);

  auto trans = base::MakeUnique<HttpNetworkTransaction>(DEFAULT_PRIORITY,
                                                        session_.get());
  TestCompletionCallback callback;
  int rv = trans->Start(&request_, callback.callback(), net_log_.bound());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Pump the message loop to get the request started.
  base::RunLoop().RunUntilIdle();
  // Explicitly confirm the handshake.
  crypto_client_stream_factory_.last_stream()->SendOnCryptoHandshakeEvent(
      QuicSession::HANDSHAKE_CONFIRMED);

  // Now cancel the request.
  trans.reset();

  // Run the QUIC session to completion.
  quic_task_runner_->RunUntilIdle();

  ExpectBrokenAlternateProtocolMapping();

  ASSERT_TRUE(quic_data.AllWriteDataConsumed());
}

// Verify that with retry_without_alt_svc_on_quic_errors enabled, if a QUIC
// protocol error occurs after the handshake is confirmed, the request
// retried over TCP and the QUIC will be marked as broken.
TEST_P(QuicNetworkTransactionTest,
       ProtocolErrorAfterHandshakeConfirmedThenBroken) {
  params_.retry_without_alt_svc_on_quic_errors = true;
  params_.quic_idle_connection_timeout_seconds = 5;

  // The request will initially go out over QUIC.
  MockQuicData quic_data;
  QuicStreamOffset header_stream_offset = 0;
  quic_data.AddWrite(ConstructClientRequestHeadersPacket(
      1, GetNthClientInitiatedStreamId(0), true, true,
      GetRequestHeaders("GET", "https", "/"), &header_stream_offset));
  quic_data.AddWrite(ConstructInitialSettingsPacket(2, &header_stream_offset));
  // Peer sending data from an non-existing stream causes this end to raise
  // error and close connection.
  quic_data.AddRead(
      ConstructServerRstPacket(1, false, 99, QUIC_STREAM_LAST_ERROR));
  std::string quic_error_details = "Data for nonexistent stream";
  quic_data.AddWrite(ConstructClientAckAndConnectionClosePacket(
      3, QuicTime::Delta::Zero(), 1, 1, 1, QUIC_INVALID_STREAM_ID,
      quic_error_details));
  quic_data.AddSocketDataToFactory(&socket_factory_);

  // After that fails, it will be resent via TCP.
  MockWrite http_writes[] = {
      MockWrite(SYNCHRONOUS, 0, "GET / HTTP/1.1\r\n"),
      MockWrite(SYNCHRONOUS, 1, "Host: mail.example.org\r\n"),
      MockWrite(SYNCHRONOUS, 2, "Connection: keep-alive\r\n\r\n")};

  MockRead http_reads[] = {
      MockRead(SYNCHRONOUS, 3, "HTTP/1.1 200 OK\r\n"),
      MockRead(SYNCHRONOUS, 4, kQuicAlternativeServiceHeader),
      MockRead(SYNCHRONOUS, 5, "hello world"), MockRead(SYNCHRONOUS, OK, 6)};
  SequencedSocketData http_data(http_reads, arraysize(http_reads), http_writes,
                                arraysize(http_writes));
  socket_factory_.AddSocketDataProvider(&http_data);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  // In order for a new QUIC session to be established via alternate-protocol
  // without racing an HTTP connection, we need the host resolution to happen
  // synchronously.  Of course, even though QUIC *could* perform a 0-RTT
  // connection to the the server, in this test we require confirmation
  // before encrypting so the HTTP job will still start.
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule("mail.example.org", "192.168.0.1",
                                           "");
  HostResolver::RequestInfo info(HostPortPair("mail.example.org", 443));
  AddressList address;
  std::unique_ptr<HostResolver::Request> request;
  host_resolver_.Resolve(info, DEFAULT_PRIORITY, &address, CompletionCallback(),
                         &request, net_log_.bound());

  CreateSession();

  AddQuicAlternateProtocolMapping(MockCryptoClientStream::ZERO_RTT);

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session_.get());
  TestCompletionCallback callback;
  int rv = trans.Start(&request_, callback.callback(), net_log_.bound());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Pump the message loop to get the request started.
  base::RunLoop().RunUntilIdle();
  // Explicitly confirm the handshake.
  crypto_client_stream_factory_.last_stream()->SendOnCryptoHandshakeEvent(
      QuicSession::HANDSHAKE_CONFIRMED);

  // Run the QUIC session to completion.
  base::RunLoop().RunUntilIdle();
  ASSERT_TRUE(quic_data.AllWriteDataConsumed());

  ExpectQuicAlternateProtocolMapping();

  // Let the transaction proceed which will result in QUIC being marked
  // as broken and the request falling back to TCP.
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  ASSERT_TRUE(quic_data.AllWriteDataConsumed());
  ASSERT_FALSE(http_data.AllReadDataConsumed());

  // Read the response body over TCP.
  CheckResponseData(&trans, "hello world");
  ExpectBrokenAlternateProtocolMapping();
  ASSERT_TRUE(http_data.AllWriteDataConsumed());
  ASSERT_TRUE(http_data.AllReadDataConsumed());
}

TEST_P(QuicNetworkTransactionTest,
       DoNotUseAlternativeServiceQuicUnsupportedVersion) {
  std::string altsvc_header = base::StringPrintf(
      "Alt-Svc: quic=\":443\"; v=\"%u\"\r\n\r\n", version_ - 1);
  MockRead http_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"), MockRead(altsvc_header.c_str()),
      MockRead("hello world"),
      MockRead(SYNCHRONOUS, ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ),
      MockRead(ASYNC, OK)};

  StaticSocketDataProvider http_data(http_reads, arraysize(http_reads), nullptr,
                                     0);
  socket_factory_.AddSocketDataProvider(&http_data);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);
  socket_factory_.AddSocketDataProvider(&http_data);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  CreateSession();

  SendRequestAndExpectHttpResponse("hello world");
  SendRequestAndExpectHttpResponse("hello world");
}

// When multiple alternative services are advertised,
// HttpStreamFactoryImpl::RequestStreamInternal() should select the alternative
// service which uses existing QUIC session if available. If no existing QUIC
// session can be used, use the first alternative service from the list.
TEST_P(QuicNetworkTransactionTest, UseExistingAlternativeServiceForQuic) {
  MockRead http_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Alt-Svc: quic=\"foo.example.org:443\", quic=\":444\"\r\n\r\n"),
      MockRead("hello world"),
      MockRead(SYNCHRONOUS, ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ),
      MockRead(ASYNC, OK)};

  StaticSocketDataProvider http_data(http_reads, arraysize(http_reads), nullptr,
                                     0);
  socket_factory_.AddSocketDataProvider(&http_data);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  QuicStreamOffset request_header_offset = 0;
  QuicStreamOffset response_header_offset = 0;
  // First QUIC request data.
  // Open a session to foo.example.org:443 using the first entry of the
  // alternative service list.
  MockQuicData mock_quic_data;
  mock_quic_data.AddWrite(
      ConstructInitialSettingsPacket(1, &request_header_offset));
  mock_quic_data.AddWrite(ConstructClientRequestHeadersPacket(
      2, GetNthClientInitiatedStreamId(0), true, true,
      GetRequestHeaders("GET", "https", "/"), &request_header_offset));

  std::string alt_svc_list =
      "quic=\"mail.example.org:444\", quic=\"foo.example.org:443\", "
      "quic=\"bar.example.org:445\"";
  mock_quic_data.AddRead(ConstructServerResponseHeadersPacket(
      1, GetNthClientInitiatedStreamId(0), false, false,
      GetResponseHeaders("200 OK", alt_svc_list), &response_header_offset));
  mock_quic_data.AddRead(ConstructServerDataPacket(
      2, GetNthClientInitiatedStreamId(0), false, true, 0, "hello!"));
  mock_quic_data.AddWrite(ConstructClientAckPacket(3, 2, 1, 1));

  // Second QUIC request data.
  // Connection pooling, using existing session, no need to include version
  // as version negotiation has been completed.
  mock_quic_data.AddWrite(ConstructClientRequestHeadersPacket(
      4, GetNthClientInitiatedStreamId(1), false, true,
      GetRequestHeaders("GET", "https", "/"), &request_header_offset));
  mock_quic_data.AddRead(ConstructServerResponseHeadersPacket(
      3, GetNthClientInitiatedStreamId(1), false, false,
      GetResponseHeaders("200 OK"), &response_header_offset));
  mock_quic_data.AddRead(ConstructServerDataPacket(
      4, GetNthClientInitiatedStreamId(1), false, true, 0, "hello!"));
  mock_quic_data.AddWrite(
      ConstructClientAckAndConnectionClosePacket(5, 4, 3, 1));
  mock_quic_data.AddRead(ASYNC, ERR_IO_PENDING);  // No more data to read
  mock_quic_data.AddRead(ASYNC, 0);               // EOF

  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  AddHangingNonAlternateProtocolSocketData();
  CreateSession();

  SendRequestAndExpectHttpResponse("hello world");

  SendRequestAndExpectQuicResponse("hello!");
  SendRequestAndExpectQuicResponse("hello!");
}

// Check that an existing QUIC connection to an alternative proxy server is
// used.
TEST_P(QuicNetworkTransactionTest, UseExistingQUICAlternativeProxy) {
  base::HistogramTester histogram_tester;

  QuicStreamOffset request_header_offset = 0;
  QuicStreamOffset response_header_offset = 0;
  // First QUIC request data.
  // Open a session to foo.example.org:443 using the first entry of the
  // alternative service list.
  MockQuicData mock_quic_data;
  mock_quic_data.AddWrite(
      ConstructInitialSettingsPacket(1, &request_header_offset));
  mock_quic_data.AddWrite(ConstructClientRequestHeadersPacket(
      2, GetNthClientInitiatedStreamId(0), true, true,
      GetRequestHeaders("GET", "http", "/"), &request_header_offset));

  std::string alt_svc_list;
  mock_quic_data.AddRead(ConstructServerResponseHeadersPacket(
      1, GetNthClientInitiatedStreamId(0), false, false,
      GetResponseHeaders("200 OK", alt_svc_list), &response_header_offset));
  mock_quic_data.AddRead(ConstructServerDataPacket(
      2, GetNthClientInitiatedStreamId(0), false, true, 0, "hello!"));
  mock_quic_data.AddWrite(ConstructClientAckPacket(3, 2, 1, 1));

  // Second QUIC request data.
  // Connection pooling, using existing session, no need to include version
  // as version negotiation has been completed.
  mock_quic_data.AddWrite(ConstructClientRequestHeadersPacket(
      4, GetNthClientInitiatedStreamId(1), false, true,
      GetRequestHeaders("GET", "http", "/"), &request_header_offset));
  mock_quic_data.AddRead(ConstructServerResponseHeadersPacket(
      3, GetNthClientInitiatedStreamId(1), false, false,
      GetResponseHeaders("200 OK"), &response_header_offset));
  mock_quic_data.AddRead(ConstructServerDataPacket(
      4, GetNthClientInitiatedStreamId(1), false, true, 0, "hello!"));
  mock_quic_data.AddWrite(
      ConstructClientAckAndConnectionClosePacket(5, 4, 3, 1));
  mock_quic_data.AddRead(ASYNC, ERR_IO_PENDING);  // No more data to read
  mock_quic_data.AddRead(ASYNC, 0);               // EOF

  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  AddHangingNonAlternateProtocolSocketData();

  TestProxyDelegate test_proxy_delegate;

  proxy_service_ =
      ProxyService::CreateFixedFromPacResult("HTTPS mail.example.org:443");

  test_proxy_delegate.set_alternative_proxy_server(
      ProxyServer::FromPacString("QUIC mail.example.org:443"));
  params_.proxy_delegate = &test_proxy_delegate;

  request_.url = GURL("http://mail.example.org/");

  CreateSession();

  SendRequestAndExpectQuicResponseFromProxyOnPort("hello!", 443);
  histogram_tester.ExpectUniqueSample("Net.QuicAlternativeProxy.Usage",
                                      1 /* ALTERNATIVE_PROXY_USAGE_WON_RACE */,
                                      1);

  SendRequestAndExpectQuicResponseFromProxyOnPort("hello!", 443);
  histogram_tester.ExpectTotalCount("Net.QuicAlternativeProxy.Usage", 2);
  histogram_tester.ExpectBucketCount("Net.QuicAlternativeProxy.Usage",
                                     0 /* ALTERNATIVE_PROXY_USAGE_NO_RACE */,
                                     1);
}

// Pool to existing session with matching QuicServerId
// even if alternative service destination is different.
TEST_P(QuicNetworkTransactionTest, PoolByOrigin) {
  MockQuicData mock_quic_data;
  QuicStreamOffset request_header_offset(0);
  QuicStreamOffset response_header_offset(0);

  mock_quic_data.AddWrite(
      ConstructInitialSettingsPacket(1, &request_header_offset));
  // First request.
  mock_quic_data.AddWrite(ConstructClientRequestHeadersPacket(
      2, GetNthClientInitiatedStreamId(0), true, true,
      GetRequestHeaders("GET", "https", "/"), &request_header_offset));
  mock_quic_data.AddRead(ConstructServerResponseHeadersPacket(
      1, GetNthClientInitiatedStreamId(0), false, false,
      GetResponseHeaders("200 OK"), &response_header_offset));
  mock_quic_data.AddRead(ConstructServerDataPacket(
      2, GetNthClientInitiatedStreamId(0), false, true, 0, "hello!"));
  mock_quic_data.AddWrite(ConstructClientAckPacket(3, 2, 1, 1));

  // Second request.
  mock_quic_data.AddWrite(ConstructClientRequestHeadersPacket(
      4, GetNthClientInitiatedStreamId(1), false, true,
      GetRequestHeaders("GET", "https", "/"), &request_header_offset));
  mock_quic_data.AddRead(ConstructServerResponseHeadersPacket(
      3, GetNthClientInitiatedStreamId(1), false, false,
      GetResponseHeaders("200 OK"), &response_header_offset));
  mock_quic_data.AddRead(ConstructServerDataPacket(
      4, GetNthClientInitiatedStreamId(1), false, true, 0, "hello!"));
  mock_quic_data.AddWrite(
      ConstructClientAckAndConnectionClosePacket(5, 4, 3, 1));
  mock_quic_data.AddRead(ASYNC, ERR_IO_PENDING);  // No more data to read
  mock_quic_data.AddRead(ASYNC, 0);               // EOF

  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  AddHangingNonAlternateProtocolSocketData();
  AddHangingNonAlternateProtocolSocketData();

  CreateSession();

  const char destination1[] = "first.example.com";
  const char destination2[] = "second.example.com";

  // Set up alternative service entry to destination1.
  url::SchemeHostPort server(request_.url);
  AlternativeService alternative_service(kProtoQUIC, destination1, 443);
  base::Time expiration = base::Time::Now() + base::TimeDelta::FromDays(1);
  http_server_properties_.SetAlternativeService(server, alternative_service,
                                                expiration);
  // First request opens connection to |destination1|
  // with QuicServerId.host() == kDefaultServerHostName.
  SendRequestAndExpectQuicResponse("hello!");

  // Set up alternative service entry to a different destination.
  alternative_service = AlternativeService(kProtoQUIC, destination2, 443);
  http_server_properties_.SetAlternativeService(server, alternative_service,
                                                expiration);
  // Second request pools to existing connection with same QuicServerId,
  // even though alternative service destination is different.
  SendRequestAndExpectQuicResponse("hello!");
}

// Pool to existing session with matching destination and matching certificate
// even if origin is different, and even if the alternative service with
// matching destination is not the first one on the list.
TEST_P(QuicNetworkTransactionTest, PoolByDestination) {
  GURL origin1 = request_.url;
  GURL origin2("https://www.example.org/");
  ASSERT_NE(origin1.host(), origin2.host());

  MockQuicData mock_quic_data;
  QuicStreamOffset request_header_offset(0);
  QuicStreamOffset response_header_offset(0);

  mock_quic_data.AddWrite(
      ConstructInitialSettingsPacket(1, &request_header_offset));
  // First request.
  mock_quic_data.AddWrite(ConstructClientRequestHeadersPacket(
      2, GetNthClientInitiatedStreamId(0), true, true,
      GetRequestHeaders("GET", "https", "/"), &request_header_offset));
  mock_quic_data.AddRead(ConstructServerResponseHeadersPacket(
      1, GetNthClientInitiatedStreamId(0), false, false,
      GetResponseHeaders("200 OK"), &response_header_offset));
  mock_quic_data.AddRead(ConstructServerDataPacket(
      2, GetNthClientInitiatedStreamId(0), false, true, 0, "hello!"));
  mock_quic_data.AddWrite(ConstructClientAckPacket(3, 2, 1, 1));

  // Second request.
  QuicTestPacketMaker client_maker2(version_, 0, &clock_, origin2.host(),
                                    Perspective::IS_CLIENT);
  QuicTestPacketMaker server_maker2(version_, 0, &clock_, origin2.host(),
                                    Perspective::IS_SERVER);
  mock_quic_data.AddWrite(ConstructClientRequestHeadersPacket(
      4, GetNthClientInitiatedStreamId(1), false, true,
      GetRequestHeaders("GET", "https", "/", &client_maker2),
      &request_header_offset));
  mock_quic_data.AddRead(ConstructServerResponseHeadersPacket(
      3, GetNthClientInitiatedStreamId(1), false, false,
      GetResponseHeaders("200 OK"), &response_header_offset));
  mock_quic_data.AddRead(ConstructServerDataPacket(
      4, GetNthClientInitiatedStreamId(1), false, true, 0, "hello!"));
  mock_quic_data.AddWrite(
      ConstructClientAckAndConnectionClosePacket(5, 4, 3, 1));
  mock_quic_data.AddRead(ASYNC, ERR_IO_PENDING);  // No more data to read
  mock_quic_data.AddRead(ASYNC, 0);               // EOF

  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  AddHangingNonAlternateProtocolSocketData();
  AddHangingNonAlternateProtocolSocketData();

  CreateSession();

  const char destination1[] = "first.example.com";
  const char destination2[] = "second.example.com";

  // Set up alternative service for |origin1|.
  AlternativeService alternative_service1(kProtoQUIC, destination1, 443);
  base::Time expiration = base::Time::Now() + base::TimeDelta::FromDays(1);
  http_server_properties_.SetAlternativeService(
      url::SchemeHostPort(origin1), alternative_service1, expiration);

  // Set up multiple alternative service entries for |origin2|,
  // the first one with a different destination as for |origin1|,
  // the second one with the same.  The second one should be used,
  // because the request can be pooled to that one.
  AlternativeService alternative_service2(kProtoQUIC, destination2, 443);
  AlternativeServiceInfoVector alternative_services;
  alternative_services.push_back(
      AlternativeServiceInfo(alternative_service2, expiration));
  alternative_services.push_back(
      AlternativeServiceInfo(alternative_service1, expiration));
  http_server_properties_.SetAlternativeServices(url::SchemeHostPort(origin2),
                                                 alternative_services);
  // First request opens connection to |destination1|
  // with QuicServerId.host() == origin1.host().
  SendRequestAndExpectQuicResponse("hello!");

  // Second request pools to existing connection with same destination,
  // because certificate matches, even though QuicServerId is different.
  request_.url = origin2;

  SendRequestAndExpectQuicResponse("hello!");
}

// Multiple origins have listed the same alternative services. When there's a
// existing QUIC session opened by a request to other origin,
// if the cert is valid, should select this QUIC session to make the request
// if this is also the first existing QUIC session.
TEST_P(QuicNetworkTransactionTest,
       UseSharedExistingAlternativeServiceForQuicWithValidCert) {
  // Default cert is valid for *.example.org

  // HTTP data for request to www.example.org.
  MockRead http_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Alt-Svc: quic=\":443\"\r\n\r\n"),
      MockRead("hello world from www.example.org"),
      MockRead(SYNCHRONOUS, ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ),
      MockRead(ASYNC, OK)};

  StaticSocketDataProvider http_data(http_reads, arraysize(http_reads), nullptr,
                                     0);
  socket_factory_.AddSocketDataProvider(&http_data);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  // HTTP data for request to mail.example.org.
  MockRead http_reads2[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Alt-Svc: quic=\":444\", quic=\"www.example.org:443\"\r\n\r\n"),
      MockRead("hello world from mail.example.org"),
      MockRead(SYNCHRONOUS, ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ),
      MockRead(ASYNC, OK)};

  StaticSocketDataProvider http_data2(http_reads2, arraysize(http_reads2),
                                      nullptr, 0);
  socket_factory_.AddSocketDataProvider(&http_data2);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  QuicStreamOffset request_header_offset = 0;
  QuicStreamOffset response_header_offset = 0;

  QuicTestPacketMaker client_maker(version_, 0, &clock_, "mail.example.org",
                                   Perspective::IS_CLIENT);
  server_maker_.set_hostname("www.example.org");
  client_maker_.set_hostname("www.example.org");
  MockQuicData mock_quic_data;
  mock_quic_data.AddWrite(
      ConstructInitialSettingsPacket(1, &request_header_offset));
  // First QUIC request data.
  mock_quic_data.AddWrite(ConstructClientRequestHeadersPacket(
      2, GetNthClientInitiatedStreamId(0), true, true,
      GetRequestHeaders("GET", "https", "/"), &request_header_offset));

  mock_quic_data.AddRead(ConstructServerResponseHeadersPacket(
      1, GetNthClientInitiatedStreamId(0), false, false,
      GetResponseHeaders("200 OK"), &response_header_offset));
  mock_quic_data.AddRead(
      ConstructServerDataPacket(2, GetNthClientInitiatedStreamId(0), false,
                                true, 0, "hello from mail QUIC!"));
  mock_quic_data.AddWrite(ConstructClientAckPacket(3, 2, 1, 1));
  // Second QUIC request data.
  mock_quic_data.AddWrite(ConstructClientRequestHeadersPacket(
      4, GetNthClientInitiatedStreamId(1), false, true,
      GetRequestHeaders("GET", "https", "/", &client_maker),
      &request_header_offset));
  mock_quic_data.AddRead(ConstructServerResponseHeadersPacket(
      3, GetNthClientInitiatedStreamId(1), false, false,
      GetResponseHeaders("200 OK"), &response_header_offset));
  mock_quic_data.AddRead(
      ConstructServerDataPacket(4, GetNthClientInitiatedStreamId(1), false,
                                true, 0, "hello from mail QUIC!"));
  mock_quic_data.AddWrite(
      ConstructClientAckAndConnectionClosePacket(5, 4, 3, 1));
  mock_quic_data.AddRead(ASYNC, ERR_IO_PENDING);  // No more data to read
  mock_quic_data.AddRead(ASYNC, 0);               // EOF

  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  AddHangingNonAlternateProtocolSocketData();
  CreateSession();

  // Send two HTTP requests, responses set up alt-svc lists for the origins.
  request_.url = GURL("https://www.example.org/");
  SendRequestAndExpectHttpResponse("hello world from www.example.org");
  request_.url = GURL("https://mail.example.org/");
  SendRequestAndExpectHttpResponse("hello world from mail.example.org");

  // Open a QUIC session to mail.example.org:443 when making request
  // to mail.example.org.
  request_.url = GURL("https://www.example.org/");
  SendRequestAndExpectQuicResponse("hello from mail QUIC!");

  // Uses the existing QUIC session when making request to www.example.org.
  request_.url = GURL("https://mail.example.org/");
  SendRequestAndExpectQuicResponse("hello from mail QUIC!");
}

TEST_P(QuicNetworkTransactionTest, AlternativeServiceDifferentPort) {
  MockRead http_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead(kQuicAlternativeServiceDifferentPortHeader),
      MockRead("hello world"),
      MockRead(SYNCHRONOUS, ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ),
      MockRead(ASYNC, OK)};

  StaticSocketDataProvider http_data(http_reads, arraysize(http_reads), nullptr,
                                     0);
  socket_factory_.AddSocketDataProvider(&http_data);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  AddHangingNonAlternateProtocolSocketData();
  CreateSession();

  SendRequestAndExpectHttpResponse("hello world");

  url::SchemeHostPort http_server("https", kDefaultServerHostName, 443);
  AlternativeServiceInfoVector alternative_service_info_vector =
      http_server_properties_.GetAlternativeServiceInfos(http_server);
  ASSERT_EQ(1u, alternative_service_info_vector.size());
  const AlternativeService alternative_service =
      alternative_service_info_vector[0].alternative_service;
  EXPECT_EQ(kProtoQUIC, alternative_service.protocol);
  EXPECT_EQ(kDefaultServerHostName, alternative_service.host);
  EXPECT_EQ(137, alternative_service.port);
}

TEST_P(QuicNetworkTransactionTest, ConfirmAlternativeService) {
  MockRead http_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"), MockRead(kQuicAlternativeServiceHeader),
      MockRead("hello world"),
      MockRead(SYNCHRONOUS, ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ),
      MockRead(ASYNC, OK)};

  StaticSocketDataProvider http_data(http_reads, arraysize(http_reads), nullptr,
                                     0);
  socket_factory_.AddSocketDataProvider(&http_data);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  MockQuicData mock_quic_data;
  QuicStreamOffset header_stream_offset = 0;
  mock_quic_data.AddWrite(
      ConstructInitialSettingsPacket(1, &header_stream_offset));
  mock_quic_data.AddWrite(ConstructClientRequestHeadersPacket(
      2, GetNthClientInitiatedStreamId(0), true, true,
      GetRequestHeaders("GET", "https", "/"), &header_stream_offset));
  mock_quic_data.AddRead(ConstructServerResponseHeadersPacket(
      1, GetNthClientInitiatedStreamId(0), false, false,
      GetResponseHeaders("200 OK")));
  mock_quic_data.AddRead(ConstructServerDataPacket(
      2, GetNthClientInitiatedStreamId(0), false, true, 0, "hello!"));
  mock_quic_data.AddWrite(ConstructClientAckPacket(3, 2, 1, 1));
  mock_quic_data.AddRead(ASYNC, ERR_IO_PENDING);  // No more data to read
  mock_quic_data.AddRead(ASYNC, 0);               // EOF

  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  AddHangingNonAlternateProtocolSocketData();
  CreateSession();

  AlternativeService alternative_service(kProtoQUIC,
                                         HostPortPair::FromURL(request_.url));
  http_server_properties_.MarkAlternativeServiceRecentlyBroken(
      alternative_service);
  EXPECT_TRUE(http_server_properties_.WasAlternativeServiceRecentlyBroken(
      alternative_service));

  SendRequestAndExpectHttpResponse("hello world");
  SendRequestAndExpectQuicResponse("hello!");

  mock_quic_data.Resume();

  EXPECT_FALSE(http_server_properties_.WasAlternativeServiceRecentlyBroken(
      alternative_service));
  EXPECT_NE(nullptr,
            http_server_properties_.GetServerNetworkStats(
                url::SchemeHostPort("https", request_.url.host(), 443)));
}

TEST_P(QuicNetworkTransactionTest, UseAlternativeServiceForQuicForHttps) {
  MockRead http_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"), MockRead(kQuicAlternativeServiceHeader),
      MockRead("hello world"),
      MockRead(SYNCHRONOUS, ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ),
      MockRead(ASYNC, OK)};

  StaticSocketDataProvider http_data(http_reads, arraysize(http_reads), nullptr,
                                     0);
  socket_factory_.AddSocketDataProvider(&http_data);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  MockQuicData mock_quic_data;
  QuicStreamOffset header_stream_offset = 0;
  mock_quic_data.AddWrite(
      ConstructInitialSettingsPacket(1, &header_stream_offset));
  mock_quic_data.AddWrite(ConstructClientRequestHeadersPacket(
      2, GetNthClientInitiatedStreamId(0), true, true,
      GetRequestHeaders("GET", "https", "/"), &header_stream_offset));
  mock_quic_data.AddRead(ConstructServerResponseHeadersPacket(
      1, GetNthClientInitiatedStreamId(0), false, false,
      GetResponseHeaders("200 OK")));
  mock_quic_data.AddRead(ConstructServerDataPacket(
      2, GetNthClientInitiatedStreamId(0), false, true, 0, "hello!"));
  mock_quic_data.AddWrite(ConstructClientAckPacket(3, 2, 1, 1));
  mock_quic_data.AddRead(SYNCHRONOUS, 0);  // EOF

  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  AddHangingNonAlternateProtocolSocketData();
  CreateSession();

  // TODO(rtenneti): Test QUIC over HTTPS, GetSSLInfo().
  SendRequestAndExpectHttpResponse("hello world");
}

// Tests that the connection to an HTTPS proxy is raced with an available
// alternative proxy server.
TEST_P(QuicNetworkTransactionTest, QuicProxyWithRacing) {
  base::HistogramTester histogram_tester;
  proxy_service_ =
      ProxyService::CreateFixedFromPacResult("HTTPS mail.example.org:443");

  MockQuicData mock_quic_data;
  QuicStreamOffset header_stream_offset = 0;
  mock_quic_data.AddWrite(
      ConstructInitialSettingsPacket(1, &header_stream_offset));
  mock_quic_data.AddWrite(ConstructClientRequestHeadersPacket(
      2, GetNthClientInitiatedStreamId(0), true, true,
      GetRequestHeaders("GET", "http", "/"), &header_stream_offset));
  mock_quic_data.AddRead(ConstructServerResponseHeadersPacket(
      1, GetNthClientInitiatedStreamId(0), false, false,
      GetResponseHeaders("200 OK")));
  mock_quic_data.AddRead(ConstructServerDataPacket(
      2, GetNthClientInitiatedStreamId(0), false, true, 0, "hello!"));
  mock_quic_data.AddWrite(ConstructClientAckPacket(3, 2, 1, 1));
  mock_quic_data.AddRead(ASYNC, ERR_IO_PENDING);  // No more data to read
  mock_quic_data.AddRead(ASYNC, 0);               // EOF

  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  // There is no need to set up main job, because no attempt will be made to
  // speak to the proxy over TCP.
  request_.url = GURL("http://mail.example.org/");
  TestProxyDelegate test_proxy_delegate;
  const HostPortPair host_port_pair("mail.example.org", 443);

  test_proxy_delegate.set_alternative_proxy_server(
      ProxyServer::FromPacString("QUIC mail.example.org:443"));
  params_.proxy_delegate = &test_proxy_delegate;
  CreateSession();
  EXPECT_TRUE(test_proxy_delegate.alternative_proxy_server().is_quic());

  // The main job needs to hang in order to guarantee that the alternative
  // proxy server job will "win".
  AddHangingNonAlternateProtocolSocketData();

  SendRequestAndExpectQuicResponseFromProxyOnPort("hello!", 443);

  // Verify that the alternative proxy server is not marked as broken.
  EXPECT_TRUE(test_proxy_delegate.alternative_proxy_server().is_quic());

  // Verify that the proxy server is not marked as broken.
  EXPECT_TRUE(session_->proxy_service()->proxy_retry_info().empty());

  histogram_tester.ExpectUniqueSample("Net.QuicAlternativeProxy.Usage",
                                      1 /* ALTERNATIVE_PROXY_USAGE_WON_RACE */,
                                      1);
}

TEST_P(QuicNetworkTransactionTest, HungAlternativeService) {
  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::COLD_START);

  MockWrite http_writes[] = {
      MockWrite(SYNCHRONOUS, 0, "GET / HTTP/1.1\r\n"),
      MockWrite(SYNCHRONOUS, 1, "Host: mail.example.org\r\n"),
      MockWrite(SYNCHRONOUS, 2, "Connection: keep-alive\r\n\r\n")};

  MockRead http_reads[] = {
      MockRead(SYNCHRONOUS, 3, "HTTP/1.1 200 OK\r\n"),
      MockRead(SYNCHRONOUS, 4, kQuicAlternativeServiceHeader),
      MockRead(SYNCHRONOUS, 5, "hello world"), MockRead(SYNCHRONOUS, OK, 6)};

  SequencedSocketData http_data(http_reads, arraysize(http_reads), http_writes,
                                arraysize(http_writes));
  socket_factory_.AddSocketDataProvider(&http_data);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  // The QUIC transaction will not be allowed to complete.
  MockWrite quic_writes[] = {MockWrite(SYNCHRONOUS, ERR_IO_PENDING, 1)};
  MockRead quic_reads[] = {
      MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0),
  };
  SequencedSocketData quic_data(quic_reads, arraysize(quic_reads), quic_writes,
                                arraysize(quic_writes));
  socket_factory_.AddSocketDataProvider(&quic_data);

  // The HTTP transaction will complete.
  SequencedSocketData http_data2(http_reads, arraysize(http_reads), http_writes,
                                 arraysize(http_writes));
  socket_factory_.AddSocketDataProvider(&http_data2);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  CreateSession();

  // Run the first request.
  SendRequestAndExpectHttpResponse("hello world");
  ASSERT_TRUE(http_data.AllReadDataConsumed());
  ASSERT_TRUE(http_data.AllWriteDataConsumed());

  // Now run the second request in which the QUIC socket hangs,
  // and verify the the transaction continues over HTTP.
  SendRequestAndExpectHttpResponse("hello world");
  base::RunLoop().RunUntilIdle();

  ASSERT_TRUE(http_data2.AllReadDataConsumed());
  ASSERT_TRUE(http_data2.AllWriteDataConsumed());
  ASSERT_TRUE(quic_data.AllReadDataConsumed());
}

TEST_P(QuicNetworkTransactionTest, ZeroRTTWithHttpRace) {
  MockQuicData mock_quic_data;
  QuicStreamOffset header_stream_offset = 0;
  mock_quic_data.AddWrite(ConstructClientRequestHeadersPacket(
      1, GetNthClientInitiatedStreamId(0), true, true,
      GetRequestHeaders("GET", "https", "/"), &header_stream_offset));
  mock_quic_data.AddRead(ConstructServerResponseHeadersPacket(
      1, GetNthClientInitiatedStreamId(0), false, false,
      GetResponseHeaders("200 OK")));
  mock_quic_data.AddRead(ConstructServerDataPacket(
      2, GetNthClientInitiatedStreamId(0), false, true, 0, "hello!"));
  mock_quic_data.AddWrite(ConstructClientAckPacket(2, 2, 1, 1));
  mock_quic_data.AddRead(ASYNC, ERR_IO_PENDING);  // No more data to read
  mock_quic_data.AddRead(ASYNC, 0);               // EOF

  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  // The non-alternate protocol job needs to hang in order to guarantee that
  // the alternate-protocol job will "win".
  AddHangingNonAlternateProtocolSocketData();

  CreateSession();
  AddQuicAlternateProtocolMapping(MockCryptoClientStream::ZERO_RTT);
  SendRequestAndExpectQuicResponse("hello!");

  EXPECT_EQ(nullptr,
            http_server_properties_.GetServerNetworkStats(
                url::SchemeHostPort("https", request_.url.host(), 443)));
}

TEST_P(QuicNetworkTransactionTest, ZeroRTTWithNoHttpRace) {
  MockQuicData mock_quic_data;
  mock_quic_data.AddWrite(ConstructClientRequestHeadersPacket(
      1, GetNthClientInitiatedStreamId(0), true, true,
      GetRequestHeaders("GET", "https", "/")));
  mock_quic_data.AddRead(ConstructServerResponseHeadersPacket(
      1, GetNthClientInitiatedStreamId(0), false, false,
      GetResponseHeaders("200 OK")));
  mock_quic_data.AddRead(ConstructServerDataPacket(
      2, GetNthClientInitiatedStreamId(0), false, true, 0, "hello!"));
  mock_quic_data.AddWrite(ConstructClientAckPacket(2, 2, 1, 1));
  mock_quic_data.AddRead(ASYNC, ERR_IO_PENDING);  // No more data to read
  mock_quic_data.AddRead(ASYNC, 0);               // EOF
  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  // In order for a new QUIC session to be established via alternate-protocol
  // without racing an HTTP connection, we need the host resolution to happen
  // synchronously.
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule("mail.example.org", "192.168.0.1",
                                           "");
  HostResolver::RequestInfo info(HostPortPair("mail.example.org", 443));
  AddressList address;
  std::unique_ptr<HostResolver::Request> request;
  host_resolver_.Resolve(info, DEFAULT_PRIORITY, &address, CompletionCallback(),
                         &request, net_log_.bound());

  AddHangingNonAlternateProtocolSocketData();
  CreateSession();
  AddQuicAlternateProtocolMapping(MockCryptoClientStream::ZERO_RTT);
  SendRequestAndExpectQuicResponse("hello!");
}

TEST_P(QuicNetworkTransactionTest, ZeroRTTWithProxy) {
  proxy_service_ = ProxyService::CreateFixedFromPacResult("PROXY myproxy:70");

  // Since we are using a proxy, the QUIC job will not succeed.
  MockWrite http_writes[] = {
      MockWrite(SYNCHRONOUS, 0, "GET http://mail.example.org/ HTTP/1.1\r\n"),
      MockWrite(SYNCHRONOUS, 1, "Host: mail.example.org\r\n"),
      MockWrite(SYNCHRONOUS, 2, "Proxy-Connection: keep-alive\r\n\r\n")};

  MockRead http_reads[] = {
      MockRead(SYNCHRONOUS, 3, "HTTP/1.1 200 OK\r\n"),
      MockRead(SYNCHRONOUS, 4, kQuicAlternativeServiceHeader),
      MockRead(SYNCHRONOUS, 5, "hello world"), MockRead(SYNCHRONOUS, OK, 6)};

  StaticSocketDataProvider http_data(http_reads, arraysize(http_reads),
                                     http_writes, arraysize(http_writes));
  socket_factory_.AddSocketDataProvider(&http_data);

  // In order for a new QUIC session to be established via alternate-protocol
  // without racing an HTTP connection, we need the host resolution to happen
  // synchronously.
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule("mail.example.org", "192.168.0.1",
                                           "");
  HostResolver::RequestInfo info(HostPortPair("mail.example.org", 443));
  AddressList address;
  std::unique_ptr<HostResolver::Request> request;
  host_resolver_.Resolve(info, DEFAULT_PRIORITY, &address, CompletionCallback(),
                         &request, net_log_.bound());

  request_.url = GURL("http://mail.example.org/");
  CreateSession();
  AddQuicAlternateProtocolMapping(MockCryptoClientStream::ZERO_RTT);
  SendRequestAndExpectHttpResponse("hello world");
}

TEST_P(QuicNetworkTransactionTest, ZeroRTTWithConfirmationRequired) {
  MockQuicData mock_quic_data;
  QuicStreamOffset header_stream_offset = 0;
  mock_quic_data.AddWrite(
      ConstructInitialSettingsPacket(1, &header_stream_offset));
  mock_quic_data.AddWrite(ConstructClientRequestHeadersPacket(
      2, GetNthClientInitiatedStreamId(0), true, true,
      GetRequestHeaders("GET", "https", "/"), &header_stream_offset));
  mock_quic_data.AddRead(ConstructServerResponseHeadersPacket(
      1, GetNthClientInitiatedStreamId(0), false, false,
      GetResponseHeaders("200 OK")));
  mock_quic_data.AddRead(ConstructServerDataPacket(
      2, GetNthClientInitiatedStreamId(0), false, true, 0, "hello!"));
  mock_quic_data.AddWrite(ConstructClientAckPacket(3, 2, 1, 1));
  mock_quic_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);  // No more data to read
  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  // The non-alternate protocol job needs to hang in order to guarantee that
  // the alternate-protocol job will "win".
  AddHangingNonAlternateProtocolSocketData();

  // In order for a new QUIC session to be established via alternate-protocol
  // without racing an HTTP connection, we need the host resolution to happen
  // synchronously.  Of course, even though QUIC *could* perform a 0-RTT
  // connection to the the server, in this test we require confirmation
  // before encrypting so the HTTP job will still start.
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule("mail.example.org", "192.168.0.1",
                                           "");
  HostResolver::RequestInfo info(HostPortPair("mail.example.org", 443));
  AddressList address;
  std::unique_ptr<HostResolver::Request> request;
  host_resolver_.Resolve(info, DEFAULT_PRIORITY, &address, CompletionCallback(),
                         &request, net_log_.bound());

  CreateSession();
  session_->quic_stream_factory()->set_require_confirmation(true);
  AddQuicAlternateProtocolMapping(MockCryptoClientStream::ZERO_RTT);

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session_.get());
  TestCompletionCallback callback;
  int rv = trans.Start(&request_, callback.callback(), net_log_.bound());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  crypto_client_stream_factory_.last_stream()->SendOnCryptoHandshakeEvent(
      QuicSession::HANDSHAKE_CONFIRMED);
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  CheckWasQuicResponse(&trans);
  CheckResponseData(&trans, "hello!");
}

TEST_P(QuicNetworkTransactionTest,
       LogGranularQuicErrorCodeOnQuicProtocolErrorLocal) {
  MockQuicData mock_quic_data;
  QuicStreamOffset header_stream_offset = 0;
  mock_quic_data.AddWrite(
      ConstructInitialSettingsPacket(1, &header_stream_offset));
  mock_quic_data.AddWrite(ConstructClientRequestHeadersPacket(
      2, GetNthClientInitiatedStreamId(0), true, true,
      GetRequestHeaders("GET", "https", "/"), &header_stream_offset));
  // Read a close connection packet with
  // QuicErrorCode: QUIC_CRYPTO_VERSION_NOT_SUPPORTED from the peer.
  mock_quic_data.AddRead(ConstructServerConnectionClosePacket(1));
  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  // The non-alternate protocol job needs to hang in order to guarantee that
  // the alternate-protocol job will "win".
  AddHangingNonAlternateProtocolSocketData();

  // In order for a new QUIC session to be established via alternate-protocol
  // without racing an HTTP connection, we need the host resolution to happen
  // synchronously.  Of course, even though QUIC *could* perform a 0-RTT
  // connection to the the server, in this test we require confirmation
  // before encrypting so the HTTP job will still start.
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule("mail.example.org", "192.168.0.1",
                                           "");
  HostResolver::RequestInfo info(HostPortPair("mail.example.org", 443));
  AddressList address;
  std::unique_ptr<HostResolver::Request> request;
  host_resolver_.Resolve(info, DEFAULT_PRIORITY, &address, CompletionCallback(),
                         &request, net_log_.bound());

  CreateSession();
  session_->quic_stream_factory()->set_require_confirmation(true);
  AddQuicAlternateProtocolMapping(MockCryptoClientStream::ZERO_RTT);

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session_.get());
  TestCompletionCallback callback;
  int rv = trans.Start(&request_, callback.callback(), net_log_.bound());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  crypto_client_stream_factory_.last_stream()->SendOnCryptoHandshakeEvent(
      QuicSession::HANDSHAKE_CONFIRMED);
  EXPECT_THAT(callback.WaitForResult(), IsError(ERR_QUIC_PROTOCOL_ERROR));

  NetErrorDetails details;
  EXPECT_EQ(QUIC_NO_ERROR, details.quic_connection_error);

  trans.PopulateNetErrorDetails(&details);
  // Verify the error code logged is what sent by the peer.
  EXPECT_EQ(QUIC_CRYPTO_VERSION_NOT_SUPPORTED, details.quic_connection_error);
}

TEST_P(QuicNetworkTransactionTest,
       LogGranularQuicErrorCodeOnQuicProtocolErrorRemote) {
  MockQuicData mock_quic_data;
  QuicStreamOffset header_stream_offset = 0;
  mock_quic_data.AddWrite(
      ConstructInitialSettingsPacket(1, &header_stream_offset));
  mock_quic_data.AddWrite(ConstructClientRequestHeadersPacket(
      2, GetNthClientInitiatedStreamId(0), true, true,
      GetRequestHeaders("GET", "https", "/"), &header_stream_offset));
  // Peer sending data from an non-existing stream causes this end to raise
  // error and close connection.
  mock_quic_data.AddRead(
      ConstructServerRstPacket(1, false, 99, QUIC_STREAM_LAST_ERROR));
  std::string quic_error_details = "Data for nonexistent stream";
  mock_quic_data.AddWrite(ConstructClientAckAndConnectionClosePacket(
      3, QuicTime::Delta::Zero(), 1, 1, 1, QUIC_INVALID_STREAM_ID,
      quic_error_details));
  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  // The non-alternate protocol job needs to hang in order to guarantee that
  // the alternate-protocol job will "win".
  AddHangingNonAlternateProtocolSocketData();

  // In order for a new QUIC session to be established via alternate-protocol
  // without racing an HTTP connection, we need the host resolution to happen
  // synchronously.  Of course, even though QUIC *could* perform a 0-RTT
  // connection to the the server, in this test we require confirmation
  // before encrypting so the HTTP job will still start.
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule("mail.example.org", "192.168.0.1",
                                           "");
  HostResolver::RequestInfo info(HostPortPair("mail.example.org", 443));
  AddressList address;
  std::unique_ptr<HostResolver::Request> request;
  host_resolver_.Resolve(info, DEFAULT_PRIORITY, &address, CompletionCallback(),
                         &request, net_log_.bound());

  CreateSession();
  session_->quic_stream_factory()->set_require_confirmation(true);
  AddQuicAlternateProtocolMapping(MockCryptoClientStream::ZERO_RTT);

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session_.get());
  TestCompletionCallback callback;
  int rv = trans.Start(&request_, callback.callback(), net_log_.bound());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  crypto_client_stream_factory_.last_stream()->SendOnCryptoHandshakeEvent(
      QuicSession::HANDSHAKE_CONFIRMED);
  EXPECT_THAT(callback.WaitForResult(), IsError(ERR_QUIC_PROTOCOL_ERROR));
  NetErrorDetails details;
  EXPECT_EQ(QUIC_NO_ERROR, details.quic_connection_error);

  trans.PopulateNetErrorDetails(&details);
  EXPECT_EQ(QUIC_INVALID_STREAM_ID, details.quic_connection_error);
}

TEST_P(QuicNetworkTransactionTest, RstSteamErrorHandling) {
  MockQuicData mock_quic_data;
  QuicStreamOffset header_stream_offset = 0;
  mock_quic_data.AddWrite(
      ConstructInitialSettingsPacket(1, &header_stream_offset));
  mock_quic_data.AddWrite(ConstructClientRequestHeadersPacket(
      2, GetNthClientInitiatedStreamId(0), true, true,
      GetRequestHeaders("GET", "https", "/"), &header_stream_offset));
  // Read the response headers, then a RST_STREAM frame.
  mock_quic_data.AddRead(ConstructServerResponseHeadersPacket(
      1, GetNthClientInitiatedStreamId(0), false, false,
      GetResponseHeaders("200 OK")));
  mock_quic_data.AddRead(ConstructServerRstPacket(
      2, false, GetNthClientInitiatedStreamId(0), QUIC_STREAM_CANCELLED));
  mock_quic_data.AddWrite(ConstructClientAckPacket(3, 2, 1, 1));
  mock_quic_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);  // No more read data.
  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  // The non-alternate protocol job needs to hang in order to guarantee that
  // the alternate-protocol job will "win".
  AddHangingNonAlternateProtocolSocketData();

  // In order for a new QUIC session to be established via alternate-protocol
  // without racing an HTTP connection, we need the host resolution to happen
  // synchronously.  Of course, even though QUIC *could* perform a 0-RTT
  // connection to the the server, in this test we require confirmation
  // before encrypting so the HTTP job will still start.
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule("mail.example.org", "192.168.0.1",
                                           "");
  HostResolver::RequestInfo info(HostPortPair("mail.example.org", 443));
  AddressList address;
  std::unique_ptr<HostResolver::Request> request;
  host_resolver_.Resolve(info, DEFAULT_PRIORITY, &address, CompletionCallback(),
                         &request, net_log_.bound());

  CreateSession();
  session_->quic_stream_factory()->set_require_confirmation(true);
  AddQuicAlternateProtocolMapping(MockCryptoClientStream::ZERO_RTT);

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session_.get());
  TestCompletionCallback callback;
  int rv = trans.Start(&request_, callback.callback(), net_log_.bound());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  crypto_client_stream_factory_.last_stream()->SendOnCryptoHandshakeEvent(
      QuicSession::HANDSHAKE_CONFIRMED);
  // Read the headers.
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response != nullptr);
  ASSERT_TRUE(response->headers.get() != nullptr);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());
  EXPECT_TRUE(response->was_fetched_via_spdy);
  EXPECT_TRUE(response->was_alpn_negotiated);
  EXPECT_EQ(QuicHttpStream::ConnectionInfoFromQuicVersion(version_),
            response->connection_info);

  std::string response_data;
  ASSERT_EQ(ERR_QUIC_PROTOCOL_ERROR, ReadTransaction(&trans, &response_data));
}

TEST_P(QuicNetworkTransactionTest, RstSteamBeforeHeaders) {
  MockQuicData mock_quic_data;
  QuicStreamOffset header_stream_offset = 0;
  mock_quic_data.AddWrite(
      ConstructInitialSettingsPacket(1, &header_stream_offset));
  mock_quic_data.AddWrite(ConstructClientRequestHeadersPacket(
      2, GetNthClientInitiatedStreamId(0), true, true,
      GetRequestHeaders("GET", "https", "/"), &header_stream_offset));
  mock_quic_data.AddRead(ConstructServerRstPacket(
      1, false, GetNthClientInitiatedStreamId(0), QUIC_STREAM_CANCELLED));
  mock_quic_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);  // No more read data.
  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  // The non-alternate protocol job needs to hang in order to guarantee that
  // the alternate-protocol job will "win".
  AddHangingNonAlternateProtocolSocketData();

  // In order for a new QUIC session to be established via alternate-protocol
  // without racing an HTTP connection, we need the host resolution to happen
  // synchronously.  Of course, even though QUIC *could* perform a 0-RTT
  // connection to the the server, in this test we require confirmation
  // before encrypting so the HTTP job will still start.
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule("mail.example.org", "192.168.0.1",
                                           "");
  HostResolver::RequestInfo info(HostPortPair("mail.example.org", 443));
  AddressList address;
  std::unique_ptr<HostResolver::Request> request;
  host_resolver_.Resolve(info, DEFAULT_PRIORITY, &address, CompletionCallback(),
                         &request, net_log_.bound());

  CreateSession();
  session_->quic_stream_factory()->set_require_confirmation(true);
  AddQuicAlternateProtocolMapping(MockCryptoClientStream::ZERO_RTT);

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session_.get());
  TestCompletionCallback callback;
  int rv = trans.Start(&request_, callback.callback(), net_log_.bound());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  crypto_client_stream_factory_.last_stream()->SendOnCryptoHandshakeEvent(
      QuicSession::HANDSHAKE_CONFIRMED);
  // Read the headers.
  EXPECT_THAT(callback.WaitForResult(), IsError(ERR_QUIC_PROTOCOL_ERROR));
}

TEST_P(QuicNetworkTransactionTest, BrokenAlternateProtocol) {
  // Alternate-protocol job
  std::unique_ptr<QuicEncryptedPacket> close(
      ConstructServerConnectionClosePacket(1));
  MockRead quic_reads[] = {
      MockRead(ASYNC, close->data(), close->length()),
      MockRead(ASYNC, ERR_IO_PENDING),  // No more data to read
      MockRead(ASYNC, OK),              // EOF
  };
  StaticSocketDataProvider quic_data(quic_reads, arraysize(quic_reads), nullptr,
                                     0);
  socket_factory_.AddSocketDataProvider(&quic_data);

  // Main job which will succeed even though the alternate job fails.
  MockRead http_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n\r\n"), MockRead("hello from http"),
      MockRead(SYNCHRONOUS, ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ),
      MockRead(ASYNC, OK)};

  StaticSocketDataProvider http_data(http_reads, arraysize(http_reads), nullptr,
                                     0);
  socket_factory_.AddSocketDataProvider(&http_data);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  CreateSession();
  AddQuicAlternateProtocolMapping(MockCryptoClientStream::COLD_START);
  SendRequestAndExpectHttpResponse("hello from http");
  ExpectBrokenAlternateProtocolMapping();
}

TEST_P(QuicNetworkTransactionTest, BrokenAlternateProtocolReadError) {
  // Alternate-protocol job
  MockRead quic_reads[] = {
      MockRead(ASYNC, ERR_SOCKET_NOT_CONNECTED),
  };
  StaticSocketDataProvider quic_data(quic_reads, arraysize(quic_reads), nullptr,
                                     0);
  socket_factory_.AddSocketDataProvider(&quic_data);

  // Main job which will succeed even though the alternate job fails.
  MockRead http_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n\r\n"), MockRead("hello from http"),
      MockRead(SYNCHRONOUS, ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ),
      MockRead(ASYNC, OK)};

  StaticSocketDataProvider http_data(http_reads, arraysize(http_reads), nullptr,
                                     0);
  socket_factory_.AddSocketDataProvider(&http_data);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  CreateSession();

  AddQuicAlternateProtocolMapping(MockCryptoClientStream::COLD_START);
  SendRequestAndExpectHttpResponse("hello from http");
  ExpectBrokenAlternateProtocolMapping();
}

TEST_P(QuicNetworkTransactionTest, NoBrokenAlternateProtocolIfTcpFails) {
  // Alternate-protocol job will fail when the session attempts to read.
  MockRead quic_reads[] = {
      MockRead(ASYNC, ERR_SOCKET_NOT_CONNECTED),
  };
  StaticSocketDataProvider quic_data(quic_reads, arraysize(quic_reads), nullptr,
                                     0);
  socket_factory_.AddSocketDataProvider(&quic_data);

  // Main job will also fail.
  MockRead http_reads[] = {
      MockRead(ASYNC, ERR_SOCKET_NOT_CONNECTED),
  };

  StaticSocketDataProvider http_data(http_reads, arraysize(http_reads), nullptr,
                                     0);
  http_data.set_connect_data(MockConnect(ASYNC, ERR_SOCKET_NOT_CONNECTED));
  socket_factory_.AddSocketDataProvider(&http_data);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  AddHangingNonAlternateProtocolSocketData();
  CreateSession();

  AddQuicAlternateProtocolMapping(MockCryptoClientStream::COLD_START);
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session_.get());
  TestCompletionCallback callback;
  int rv = trans.Start(&request_, callback.callback(), net_log_.bound());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(), IsError(ERR_SOCKET_NOT_CONNECTED));
  ExpectQuicAlternateProtocolMapping();
}

TEST_P(QuicNetworkTransactionTest, FailedZeroRttBrokenAlternateProtocol) {
  // Alternate-protocol job
  MockRead quic_reads[] = {
      MockRead(ASYNC, ERR_SOCKET_NOT_CONNECTED),
  };
  StaticSocketDataProvider quic_data(quic_reads, arraysize(quic_reads), nullptr,
                                     0);
  socket_factory_.AddSocketDataProvider(&quic_data);

  // Second Alternate-protocol job which will race with the TCP job.
  StaticSocketDataProvider quic_data2(quic_reads, arraysize(quic_reads),
                                      nullptr, 0);
  socket_factory_.AddSocketDataProvider(&quic_data2);

  // Final job that will proceed when the QUIC job fails.
  MockRead http_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n\r\n"), MockRead("hello from http"),
      MockRead(SYNCHRONOUS, ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ),
      MockRead(ASYNC, OK)};

  StaticSocketDataProvider http_data(http_reads, arraysize(http_reads), nullptr,
                                     0);
  socket_factory_.AddSocketDataProvider(&http_data);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  AddHangingNonAlternateProtocolSocketData();
  CreateSession();

  AddQuicAlternateProtocolMapping(MockCryptoClientStream::ZERO_RTT);

  SendRequestAndExpectHttpResponse("hello from http");

  ExpectBrokenAlternateProtocolMapping();

  EXPECT_TRUE(quic_data.AllReadDataConsumed());
  EXPECT_TRUE(quic_data.AllWriteDataConsumed());
}

TEST_P(QuicNetworkTransactionTest, DISABLED_HangingZeroRttFallback) {
  // Alternate-protocol job
  MockRead quic_reads[] = {
      MockRead(SYNCHRONOUS, ERR_IO_PENDING),
  };
  StaticSocketDataProvider quic_data(quic_reads, arraysize(quic_reads), nullptr,
                                     0);
  socket_factory_.AddSocketDataProvider(&quic_data);

  // Main job that will proceed when the QUIC job fails.
  MockRead http_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n\r\n"), MockRead("hello from http"),
      MockRead(SYNCHRONOUS, ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ),
      MockRead(ASYNC, OK)};

  StaticSocketDataProvider http_data(http_reads, arraysize(http_reads), nullptr,
                                     0);
  socket_factory_.AddSocketDataProvider(&http_data);

  AddHangingNonAlternateProtocolSocketData();
  CreateSession();

  AddQuicAlternateProtocolMapping(MockCryptoClientStream::ZERO_RTT);

  SendRequestAndExpectHttpResponse("hello from http");
}

TEST_P(QuicNetworkTransactionTest, BrokenAlternateProtocolOnConnectFailure) {
  // Alternate-protocol job will fail before creating a QUIC session.
  StaticSocketDataProvider quic_data(nullptr, 0, nullptr, 0);
  quic_data.set_connect_data(MockConnect(SYNCHRONOUS, ERR_CONNECTION_FAILED));
  socket_factory_.AddSocketDataProvider(&quic_data);

  // Main job which will succeed even though the alternate job fails.
  MockRead http_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n\r\n"), MockRead("hello from http"),
      MockRead(SYNCHRONOUS, ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ),
      MockRead(ASYNC, OK)};

  StaticSocketDataProvider http_data(http_reads, arraysize(http_reads), nullptr,
                                     0);
  socket_factory_.AddSocketDataProvider(&http_data);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  CreateSession();
  AddQuicAlternateProtocolMapping(MockCryptoClientStream::COLD_START);
  SendRequestAndExpectHttpResponse("hello from http");

  ExpectBrokenAlternateProtocolMapping();
}

TEST_P(QuicNetworkTransactionTest, ConnectionCloseDuringConnect) {
  MockQuicData mock_quic_data;
  mock_quic_data.AddSynchronousRead(ConstructServerConnectionClosePacket(1));
  mock_quic_data.AddWrite(ConstructClientRequestHeadersPacket(
      1, GetNthClientInitiatedStreamId(0), true, true,
      GetRequestHeaders("GET", "https", "/")));
  mock_quic_data.AddWrite(ConstructClientAckPacket(2, 1, 1, 1));
  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  // When the QUIC connection fails, we will try the request again over HTTP.
  MockRead http_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"), MockRead(kQuicAlternativeServiceHeader),
      MockRead("hello world"),
      MockRead(SYNCHRONOUS, ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ),
      MockRead(ASYNC, OK)};

  StaticSocketDataProvider http_data(http_reads, arraysize(http_reads), nullptr,
                                     0);
  socket_factory_.AddSocketDataProvider(&http_data);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  // In order for a new QUIC session to be established via alternate-protocol
  // without racing an HTTP connection, we need the host resolution to happen
  // synchronously.
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule("mail.example.org", "192.168.0.1",
                                           "");
  HostResolver::RequestInfo info(HostPortPair("mail.example.org", 443));
  AddressList address;
  std::unique_ptr<HostResolver::Request> request;
  host_resolver_.Resolve(info, DEFAULT_PRIORITY, &address, CompletionCallback(),
                         &request, net_log_.bound());

  CreateSession();
  AddQuicAlternateProtocolMapping(MockCryptoClientStream::ZERO_RTT);
  SendRequestAndExpectHttpResponse("hello world");
}

// For an alternative proxy that supports QUIC, test that the request is
// successfully fetched by the main job when the alternate proxy job encounters
// an error.
TEST_P(QuicNetworkTransactionTest, BrokenAlternativeProxySocketNotConnected) {
  TestAlternativeProxy(ERR_SOCKET_NOT_CONNECTED);
}
TEST_P(QuicNetworkTransactionTest, BrokenAlternativeProxyConnectionFailed) {
  TestAlternativeProxy(ERR_CONNECTION_FAILED);
}
TEST_P(QuicNetworkTransactionTest, BrokenAlternativeProxyConnectionTimedOut) {
  TestAlternativeProxy(ERR_CONNECTION_TIMED_OUT);
}
TEST_P(QuicNetworkTransactionTest, BrokenAlternativeProxyConnectionRefused) {
  TestAlternativeProxy(ERR_CONNECTION_REFUSED);
}
TEST_P(QuicNetworkTransactionTest, BrokenAlternativeProxyQuicHandshakeFailed) {
  TestAlternativeProxy(ERR_QUIC_HANDSHAKE_FAILED);
}
TEST_P(QuicNetworkTransactionTest, BrokenAlternativeProxyQuicProtocolError) {
  TestAlternativeProxy(ERR_QUIC_PROTOCOL_ERROR);
}
TEST_P(QuicNetworkTransactionTest, BrokenAlternativeProxyIOPending) {
  TestAlternativeProxy(ERR_IO_PENDING);
}
TEST_P(QuicNetworkTransactionTest, BrokenAlternativeProxyAddressUnreachable) {
  TestAlternativeProxy(ERR_ADDRESS_UNREACHABLE);
}

TEST_P(QuicNetworkTransactionTest, ConnectionCloseDuringConnectProxy) {
  MockQuicData mock_quic_data;
  mock_quic_data.AddSynchronousRead(ConstructServerConnectionClosePacket(1));
  mock_quic_data.AddWrite(ConstructClientRequestHeadersPacket(
      1, GetNthClientInitiatedStreamId(0), true, true,
      GetRequestHeaders("GET", "https", "/")));
  mock_quic_data.AddWrite(ConstructClientAckPacket(2, 1, 1, 1));
  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  // When the QUIC connection fails, we will try the request again over HTTP.
  MockRead http_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"), MockRead(kQuicAlternativeServiceHeader),
      MockRead("hello world"),
      MockRead(SYNCHRONOUS, ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ),
      MockRead(ASYNC, OK)};

  StaticSocketDataProvider http_data(http_reads, arraysize(http_reads), nullptr,
                                     0);
  socket_factory_.AddSocketDataProvider(&http_data);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  TestProxyDelegate test_proxy_delegate;
  const HostPortPair host_port_pair("myproxy.org", 443);
  test_proxy_delegate.set_alternative_proxy_server(
      ProxyServer::FromPacString("QUIC myproxy.org:443"));
  EXPECT_TRUE(test_proxy_delegate.alternative_proxy_server().is_quic());

  params_.proxy_delegate = &test_proxy_delegate;
  proxy_service_ =
      ProxyService::CreateFixedFromPacResult("HTTPS myproxy.org:443");
  request_.url = GURL("http://mail.example.org/");

  // In order for a new QUIC session to be established via alternate-protocol
  // without racing an HTTP connection, we need the host resolution to happen
  // synchronously.
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule("myproxy.org", "192.168.0.1", "");
  HostResolver::RequestInfo info(HostPortPair("myproxy.org", 443));
  AddressList address;
  std::unique_ptr<HostResolver::Request> request;
  host_resolver_.Resolve(info, DEFAULT_PRIORITY, &address, CompletionCallback(),
                         &request, net_log_.bound());

  CreateSession();
  SendRequestAndExpectHttpResponseFromProxy("hello world", true, 443);
  EXPECT_FALSE(test_proxy_delegate.alternative_proxy_server().is_valid());
  EXPECT_TRUE(session_->proxy_service()->proxy_retry_info().empty());
}

TEST_P(QuicNetworkTransactionTest, SecureResourceOverSecureQuic) {
  client_maker_.set_hostname("www.example.org");
  EXPECT_FALSE(
      test_socket_performance_watcher_factory_.rtt_notification_received());
  MockQuicData mock_quic_data;
  QuicStreamOffset header_stream_offset = 0;
  mock_quic_data.AddWrite(
      ConstructInitialSettingsPacket(1, &header_stream_offset));
  mock_quic_data.AddWrite(ConstructClientRequestHeadersPacket(
      2, GetNthClientInitiatedStreamId(0), true, true,
      GetRequestHeaders("GET", "https", "/"), &header_stream_offset));
  mock_quic_data.AddRead(ConstructServerResponseHeadersPacket(
      1, GetNthClientInitiatedStreamId(0), false, false,
      GetResponseHeaders("200 OK")));
  mock_quic_data.AddRead(ConstructServerDataPacket(
      2, GetNthClientInitiatedStreamId(0), false, true, 0, "hello!"));
  mock_quic_data.AddWrite(ConstructClientAckPacket(3, 2, 1, 1));
  mock_quic_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);  // No more read data.
  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  request_.url = GURL("https://www.example.org:443");
  AddHangingNonAlternateProtocolSocketData();
  CreateSession();
  AddQuicAlternateProtocolMapping(MockCryptoClientStream::CONFIRM_HANDSHAKE);
  SendRequestAndExpectQuicResponse("hello!");
  EXPECT_TRUE(
      test_socket_performance_watcher_factory_.rtt_notification_received());
}

// TODO(zhongyi): disabled this broken test as it was not testing the correct
// code path. Need a fix to re-enable this test, tracking at crbug.com/704596.
TEST_P(QuicNetworkTransactionTest,
       DISABLED_QuicUploadToAlternativeProxyServer) {
  base::HistogramTester histogram_tester;
  proxy_service_ =
      ProxyService::CreateFixedFromPacResult("HTTPS mail.example.org:443");

  TestProxyDelegate test_proxy_delegate;

  test_proxy_delegate.set_alternative_proxy_server(
      ProxyServer::FromPacString("QUIC mail.example.org:443"));
  params_.proxy_delegate = &test_proxy_delegate;

  request_.url = GURL("http://mail.example.org/");

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  MockWrite writes[] = {MockWrite(SYNCHRONOUS, ERR_FAILED, 1)};
  SequencedSocketData socket_data(reads, arraysize(reads), writes,
                                  arraysize(writes));
  socket_factory_.AddSocketDataProvider(&socket_data);

  // The non-alternate protocol job needs to hang in order to guarantee that
  // the alternate-protocol job will "win".
  AddHangingNonAlternateProtocolSocketData();

  CreateSession();
  request_.method = "POST";
  ChunkedUploadDataStream upload_data(0);
  upload_data.AppendData("1", 1, true);

  request_.upload_data_stream = &upload_data;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session_.get());
  TestCompletionCallback callback;
  int rv = trans.Start(&request_, callback.callback(), net_log_.bound());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_NE(OK, callback.WaitForResult());

  // Verify that the alternative proxy server is not marked as broken.
  EXPECT_TRUE(test_proxy_delegate.alternative_proxy_server().is_quic());

  // Verify that the proxy server is not marked as broken.
  EXPECT_TRUE(session_->proxy_service()->proxy_retry_info().empty());

  histogram_tester.ExpectUniqueSample("Net.QuicAlternativeProxy.Usage",
                                      1 /* ALTERNATIVE_PROXY_USAGE_WON_RACE */,
                                      1);
}

TEST_P(QuicNetworkTransactionTest, QuicUpload) {
  params_.origins_to_force_quic_on.insert(
      HostPortPair::FromString("mail.example.org:443"));

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  MockWrite writes[] = {MockWrite(SYNCHRONOUS, ERR_FAILED, 1)};
  SequencedSocketData socket_data(reads, arraysize(reads), writes,
                                  arraysize(writes));
  socket_factory_.AddSocketDataProvider(&socket_data);

  // The non-alternate protocol job needs to hang in order to guarantee that
  // the alternate-protocol job will "win".
  AddHangingNonAlternateProtocolSocketData();

  CreateSession();
  request_.method = "POST";
  ChunkedUploadDataStream upload_data(0);
  upload_data.AppendData("1", 1, true);

  request_.upload_data_stream = &upload_data;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session_.get());
  TestCompletionCallback callback;
  int rv = trans.Start(&request_, callback.callback(), net_log_.bound());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_NE(OK, callback.WaitForResult());
}

TEST_P(QuicNetworkTransactionTest, QuicUploadWriteError) {
  ScopedMockNetworkChangeNotifier network_change_notifier;
  MockNetworkChangeNotifier* mock_ncn =
      network_change_notifier.mock_network_change_notifier();
  mock_ncn->ForceNetworkHandlesSupported();
  mock_ncn->SetConnectedNetworksList(
      {kDefaultNetworkForTests, kNewNetworkForTests});

  params_.origins_to_force_quic_on.insert(
      HostPortPair::FromString("mail.example.org:443"));
  params_.quic_migrate_sessions_on_network_change = true;

  MockQuicData socket_data;
  socket_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  QuicStreamOffset offset = 0;
  socket_data.AddWrite(ConstructInitialSettingsPacket(1, &offset));
  socket_data.AddWrite(ConstructClientRequestHeadersPacket(
      2, GetNthClientInitiatedStreamId(0), true, false,
      GetRequestHeaders("POST", "https", "/"), &offset));
  socket_data.AddWrite(SYNCHRONOUS, ERR_FAILED);
  socket_data.AddSocketDataToFactory(&socket_factory_);

  MockQuicData socket_data2;
  socket_data2.AddConnect(SYNCHRONOUS, ERR_ADDRESS_INVALID);
  socket_data2.AddSocketDataToFactory(&socket_factory_);

  // The non-alternate protocol job needs to hang in order to guarantee that
  // the alternate-protocol job will "win".
  AddHangingNonAlternateProtocolSocketData();

  CreateSession();
  request_.method = "POST";
  ChunkedUploadDataStream upload_data(0);

  request_.upload_data_stream = &upload_data;

  std::unique_ptr<HttpNetworkTransaction> trans(
      new HttpNetworkTransaction(DEFAULT_PRIORITY, session_.get()));
  TestCompletionCallback callback;
  int rv = trans->Start(&request_, callback.callback(), net_log_.bound());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  base::RunLoop().RunUntilIdle();
  upload_data.AppendData("1", 1, true);
  base::RunLoop().RunUntilIdle();

  EXPECT_NE(OK, callback.WaitForResult());
  trans.reset();
  session_.reset();
}

// Adds coverage to catch regression such as https://crbug.com/622043
TEST_P(QuicNetworkTransactionTest, QuicServerPush) {
  params_.origins_to_force_quic_on.insert(
      HostPortPair::FromString("mail.example.org:443"));

  MockQuicData mock_quic_data;
  QuicStreamOffset header_stream_offset = 0;
  mock_quic_data.AddWrite(
      ConstructInitialSettingsPacket(1, &header_stream_offset));
  mock_quic_data.AddWrite(ConstructClientRequestHeadersPacket(
      2, GetNthClientInitiatedStreamId(0), true, true,
      GetRequestHeaders("GET", "https", "/"), &header_stream_offset));
  QuicStreamOffset server_header_offset = 0;
  mock_quic_data.AddRead(ConstructServerPushPromisePacket(
      1, GetNthClientInitiatedStreamId(0), GetNthServerInitiatedStreamId(0),
      false, GetRequestHeaders("GET", "https", "/pushed.jpg"),
      &server_header_offset, &server_maker_));
  mock_quic_data.AddRead(ConstructServerResponseHeadersPacket(
      2, GetNthClientInitiatedStreamId(0), false, false,
      GetResponseHeaders("200 OK"), &server_header_offset));
  mock_quic_data.AddWrite(ConstructClientAckPacket(3, 2, 1, 1));
  mock_quic_data.AddRead(ConstructServerResponseHeadersPacket(
      3, GetNthServerInitiatedStreamId(0), false, false,
      GetResponseHeaders("200 OK"), &server_header_offset));
  mock_quic_data.AddRead(ConstructServerDataPacket(
      4, GetNthClientInitiatedStreamId(0), false, true, 0, "hello!"));
  mock_quic_data.AddWrite(ConstructClientAckPacket(4, 4, 3, 1));
  mock_quic_data.AddRead(ConstructServerDataPacket(
      5, GetNthServerInitiatedStreamId(0), false, true, 0, "and hello!"));
  mock_quic_data.AddWrite(ConstructClientAckAndRstPacket(
      5, GetNthServerInitiatedStreamId(0), QUIC_RST_ACKNOWLEDGEMENT, 5, 5, 1));
  mock_quic_data.AddRead(ASYNC, ERR_IO_PENDING);  // No more data to read
  mock_quic_data.AddRead(ASYNC, 0);               // EOF
  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  // The non-alternate protocol job needs to hang in order to guarantee that
  // the alternate-protocol job will "win".
  AddHangingNonAlternateProtocolSocketData();

  CreateSession();

  // PUSH_PROMISE handling in the http layer gets exercised here.
  SendRequestAndExpectQuicResponse("hello!");

  request_.url = GURL("https://mail.example.org/pushed.jpg");
  SendRequestAndExpectQuicResponse("and hello!");

  // Check that the NetLog was filled reasonably.
  TestNetLogEntry::List entries;
  net_log_.GetEntries(&entries);
  EXPECT_LT(0u, entries.size());

  // Check that we logged a QUIC_HTTP_STREAM_ADOPTED_PUSH_STREAM
  int pos = ExpectLogContainsSomewhere(
      entries, 0, NetLogEventType::QUIC_HTTP_STREAM_ADOPTED_PUSH_STREAM,
      NetLogEventPhase::NONE);
  EXPECT_LT(0, pos);
}

TEST_P(QuicNetworkTransactionTest, QuicForceHolBlocking) {
  params_.quic_force_hol_blocking = true;
  params_.origins_to_force_quic_on.insert(
      HostPortPair::FromString("mail.example.org:443"));

  MockQuicData mock_quic_data;

  QuicStreamOffset offset = 0;
  mock_quic_data.AddWrite(ConstructInitialSettingsPacket(1, &offset));
  mock_quic_data.AddWrite(ConstructClientRequestHeadersPacket(
      2, GetNthClientInitiatedStreamId(0), true, false,
      GetRequestHeaders("POST", "https", "/"), &offset));

  std::unique_ptr<QuicEncryptedPacket> packet;
  if (version_ == QUIC_VERSION_36) {
    packet = ConstructClientForceHolDataPacket(
        3, GetNthClientInitiatedStreamId(0), true, true, &offset, "1");
  } else {
    packet = ConstructClientDataPacket(3, GetNthClientInitiatedStreamId(0),
                                       true, true, 0, "1");
  }
  mock_quic_data.AddWrite(std::move(packet));

  mock_quic_data.AddRead(ConstructServerResponseHeadersPacket(
      1, GetNthClientInitiatedStreamId(0), false, false,
      GetResponseHeaders("200 OK")));

  mock_quic_data.AddRead(ConstructServerDataPacket(
      2, GetNthClientInitiatedStreamId(0), false, true, 0, "hello!"));

  mock_quic_data.AddWrite(ConstructClientAckPacket(4, 2, 1, 1));

  mock_quic_data.AddRead(ASYNC, ERR_IO_PENDING);  // No more data to read
  mock_quic_data.AddRead(ASYNC, 0);               // EOF
  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  // The non-alternate protocol job needs to hang in order to guarantee that
  // the alternate-protocol job will "win".
  AddHangingNonAlternateProtocolSocketData();

  CreateSession();
  request_.method = "POST";
  ChunkedUploadDataStream upload_data(0);
  upload_data.AppendData("1", 1, true);

  request_.upload_data_stream = &upload_data;

  SendRequestAndExpectQuicResponse("hello!");
}

class QuicURLRequestContext : public URLRequestContext {
 public:
  QuicURLRequestContext(std::unique_ptr<HttpNetworkSession> session,
                        MockClientSocketFactory* socket_factory)
      : storage_(this) {
    socket_factory_ = socket_factory;
    storage_.set_host_resolver(
        std::unique_ptr<HostResolver>(new MockHostResolver));
    storage_.set_cert_verifier(base::WrapUnique(new MockCertVerifier));
    storage_.set_transport_security_state(
        base::WrapUnique(new TransportSecurityState));
    storage_.set_proxy_service(ProxyService::CreateDirect());
    storage_.set_ssl_config_service(new SSLConfigServiceDefaults);
    storage_.set_http_auth_handler_factory(
        HttpAuthHandlerFactory::CreateDefault(host_resolver()));
    storage_.set_http_server_properties(
        std::unique_ptr<HttpServerProperties>(new HttpServerPropertiesImpl()));
    storage_.set_job_factory(base::WrapUnique(new URLRequestJobFactoryImpl()));
    storage_.set_http_network_session(std::move(session));
    storage_.set_http_transaction_factory(base::WrapUnique(
        new HttpCache(storage_.http_network_session(),
                      HttpCache::DefaultBackend::InMemory(0), false)));
  }

  ~QuicURLRequestContext() override { AssertNoURLRequests(); }

  MockClientSocketFactory& socket_factory() { return *socket_factory_; }

 private:
  MockClientSocketFactory* socket_factory_;
  URLRequestContextStorage storage_;
};

TEST_P(QuicNetworkTransactionTest, RawHeaderSizeSuccessfullRequest) {
  params_.origins_to_force_quic_on.insert(
      HostPortPair::FromString("mail.example.org:443"));

  MockQuicData mock_quic_data;
  QuicStreamOffset header_stream_offset = 0;
  mock_quic_data.AddWrite(
      ConstructInitialSettingsPacket(1, &header_stream_offset));
  SpdyHeaderBlock headers(GetRequestHeaders("GET", "https", "/"));
  headers["user-agent"] = "";
  headers["accept-encoding"] = "gzip, deflate";
  mock_quic_data.AddWrite(ConstructClientRequestHeadersPacket(
      2, GetNthClientInitiatedStreamId(0), true, true, std::move(headers),
      &header_stream_offset));

  QuicStreamOffset expected_raw_header_response_size = 0;
  mock_quic_data.AddRead(ConstructServerResponseHeadersPacket(
      1, GetNthClientInitiatedStreamId(0), false, false,
      GetResponseHeaders("200 OK"), &expected_raw_header_response_size));

  mock_quic_data.AddRead(
      ConstructServerDataPacket(2, GetNthClientInitiatedStreamId(0), false,
                                true, 0, "Main Resource Data"));
  mock_quic_data.AddWrite(ConstructClientAckPacket(3, 2, 1, 1));

  mock_quic_data.AddRead(ASYNC, 0);  // EOF

  CreateSession();

  TestDelegate delegate;
  QuicURLRequestContext quic_url_request_context(std::move(session_),
                                                 &socket_factory_);

  mock_quic_data.AddSocketDataToFactory(
      &quic_url_request_context.socket_factory());
  TestNetworkDelegate network_delegate;
  quic_url_request_context.set_network_delegate(&network_delegate);

  std::unique_ptr<URLRequest> request(quic_url_request_context.CreateRequest(
      GURL("https://mail.example.org/"), DEFAULT_PRIORITY, &delegate,
      TRAFFIC_ANNOTATION_FOR_TESTS));
  quic_url_request_context.socket_factory().AddSSLSocketDataProvider(
      &ssl_data_);

  request->Start();
  base::RunLoop().Run();

  EXPECT_LT(0, request->GetTotalSentBytes());
  EXPECT_LT(0, request->GetTotalReceivedBytes());
  EXPECT_EQ(network_delegate.total_network_bytes_sent(),
            request->GetTotalSentBytes());
  EXPECT_EQ(network_delegate.total_network_bytes_received(),
            request->GetTotalReceivedBytes());
  EXPECT_EQ(static_cast<int>(expected_raw_header_response_size),
            request->raw_header_size());
  EXPECT_TRUE(mock_quic_data.AllReadDataConsumed());
  EXPECT_TRUE(mock_quic_data.AllWriteDataConsumed());
}

TEST_P(QuicNetworkTransactionTest, RawHeaderSizeSuccessfullPushHeadersFirst) {
  params_.origins_to_force_quic_on.insert(
      HostPortPair::FromString("mail.example.org:443"));

  MockQuicData mock_quic_data;
  QuicStreamOffset header_stream_offset = 0;
  mock_quic_data.AddWrite(
      ConstructInitialSettingsPacket(1, &header_stream_offset));
  SpdyHeaderBlock headers(GetRequestHeaders("GET", "https", "/"));
  headers["user-agent"] = "";
  headers["accept-encoding"] = "gzip, deflate";
  mock_quic_data.AddWrite(ConstructClientRequestHeadersPacket(
      2, GetNthClientInitiatedStreamId(0), true, true, std::move(headers),
      &header_stream_offset));

  QuicStreamOffset server_header_offset = 0;
  QuicStreamOffset expected_raw_header_response_size = 0;

  mock_quic_data.AddRead(ConstructServerPushPromisePacket(
      1, GetNthClientInitiatedStreamId(0), GetNthServerInitiatedStreamId(0),
      false, GetRequestHeaders("GET", "https", "/pushed.jpg"),
      &server_header_offset, &server_maker_));

  expected_raw_header_response_size = server_header_offset;
  mock_quic_data.AddRead(ConstructServerResponseHeadersPacket(
      2, GetNthClientInitiatedStreamId(0), false, false,
      GetResponseHeaders("200 OK"), &server_header_offset));
  expected_raw_header_response_size =
      server_header_offset - expected_raw_header_response_size;

  mock_quic_data.AddWrite(ConstructClientAckPacket(3, 2, 1, 1));

  mock_quic_data.AddRead(ConstructServerResponseHeadersPacket(
      3, GetNthServerInitiatedStreamId(0), false, false,
      GetResponseHeaders("200 OK"), &server_header_offset));
  mock_quic_data.AddRead(
      ConstructServerDataPacket(4, GetNthServerInitiatedStreamId(0), false,
                                true, 0, "Pushed Resource Data"));

  mock_quic_data.AddWrite(ConstructClientAckPacket(4, 4, 3, 1));
  mock_quic_data.AddRead(
      ConstructServerDataPacket(5, GetNthClientInitiatedStreamId(0), false,
                                true, 0, "Main Resource Data"));

  mock_quic_data.AddRead(ConstructServerConnectionClosePacket(6));

  CreateSession();

  TestDelegate delegate;
  QuicURLRequestContext quic_url_request_context(std::move(session_),
                                                 &socket_factory_);

  mock_quic_data.AddSocketDataToFactory(
      &quic_url_request_context.socket_factory());
  TestNetworkDelegate network_delegate;
  quic_url_request_context.set_network_delegate(&network_delegate);

  std::unique_ptr<URLRequest> request(quic_url_request_context.CreateRequest(
      GURL("https://mail.example.org/"), DEFAULT_PRIORITY, &delegate,
      TRAFFIC_ANNOTATION_FOR_TESTS));
  quic_url_request_context.socket_factory().AddSSLSocketDataProvider(
      &ssl_data_);

  request->Start();
  base::RunLoop().Run();

  EXPECT_LT(0, request->GetTotalSentBytes());
  EXPECT_LT(0, request->GetTotalReceivedBytes());
  EXPECT_EQ(network_delegate.total_network_bytes_sent(),
            request->GetTotalSentBytes());
  EXPECT_EQ(network_delegate.total_network_bytes_received(),
            request->GetTotalReceivedBytes());
  EXPECT_EQ(static_cast<int>(expected_raw_header_response_size),
            request->raw_header_size());
  EXPECT_TRUE(mock_quic_data.AllReadDataConsumed());
  EXPECT_TRUE(mock_quic_data.AllWriteDataConsumed());
}

class QuicNetworkTransactionWithDestinationTest
    : public PlatformTest,
      public ::testing::WithParamInterface<PoolingTestParams> {
 protected:
  QuicNetworkTransactionWithDestinationTest()
      : version_(GetParam().version),
        destination_type_(GetParam().destination_type),
        cert_transparency_verifier_(new MultiLogCTVerifier()),
        ssl_config_service_(new SSLConfigServiceDefaults),
        proxy_service_(ProxyService::CreateDirect()),
        auth_handler_factory_(
            HttpAuthHandlerFactory::CreateDefault(&host_resolver_)),
        random_generator_(0),
        ssl_data_(ASYNC, OK) {}

  void SetUp() override {
    NetworkChangeNotifier::NotifyObserversOfIPAddressChangeForTests();
    base::RunLoop().RunUntilIdle();

    HttpNetworkSession::Params params;

    clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(20));
    params.quic_clock = &clock_;

    crypto_client_stream_factory_.set_handshake_mode(
        MockCryptoClientStream::CONFIRM_HANDSHAKE);
    params.quic_crypto_client_stream_factory = &crypto_client_stream_factory_;

    params.enable_quic = true;
    params.quic_random = &random_generator_;
    params.client_socket_factory = &socket_factory_;
    params.host_resolver = &host_resolver_;
    params.cert_verifier = &cert_verifier_;
    params.transport_security_state = &transport_security_state_;
    params.cert_transparency_verifier = cert_transparency_verifier_.get();
    params.ct_policy_enforcer = &ct_policy_enforcer_;
    params.socket_performance_watcher_factory =
        &test_socket_performance_watcher_factory_;
    params.ssl_config_service = ssl_config_service_.get();
    params.proxy_service = proxy_service_.get();
    params.http_auth_handler_factory = auth_handler_factory_.get();
    params.http_server_properties = &http_server_properties_;
    params.quic_supported_versions = SupportedVersions(version_);

    session_.reset(new HttpNetworkSession(params));
    session_->quic_stream_factory()->set_require_confirmation(true);
  }

  void TearDown() override {
    NetworkChangeNotifier::NotifyObserversOfIPAddressChangeForTests();
    // Empty the current queue.
    base::RunLoop().RunUntilIdle();
    PlatformTest::TearDown();
    NetworkChangeNotifier::NotifyObserversOfIPAddressChangeForTests();
    base::RunLoop().RunUntilIdle();
    session_.reset();
  }

  void SetAlternativeService(const std::string& origin) {
    HostPortPair destination;
    switch (destination_type_) {
      case SAME_AS_FIRST:
        destination = HostPortPair(origin1_, 443);
        break;
      case SAME_AS_SECOND:
        destination = HostPortPair(origin2_, 443);
        break;
      case DIFFERENT:
        destination = HostPortPair(kDifferentHostname, 443);
        break;
    }
    AlternativeService alternative_service(kProtoQUIC, destination);
    base::Time expiration = base::Time::Now() + base::TimeDelta::FromDays(1);
    http_server_properties_.SetAlternativeService(
        url::SchemeHostPort("https", origin, 443), alternative_service,
        expiration);
  }

  std::unique_ptr<QuicEncryptedPacket> ConstructClientRequestHeadersPacket(
      QuicPacketNumber packet_number,
      QuicStreamId stream_id,
      bool should_include_version,
      QuicStreamOffset* offset,
      QuicTestPacketMaker* maker) {
    SpdyPriority priority =
        ConvertRequestPriorityToQuicPriority(DEFAULT_PRIORITY);
    SpdyHeaderBlock headers(maker->GetRequestHeaders("GET", "https", "/"));
    return maker->MakeRequestHeadersPacketWithOffsetTracking(
        packet_number, stream_id, should_include_version, true, priority,
        std::move(headers), offset);
  }

  std::unique_ptr<QuicEncryptedPacket> ConstructClientRequestHeadersPacket(
      QuicPacketNumber packet_number,
      QuicStreamId stream_id,
      bool should_include_version,
      QuicTestPacketMaker* maker) {
    return ConstructClientRequestHeadersPacket(
        packet_number, stream_id, should_include_version, nullptr, maker);
  }

  std::unique_ptr<QuicEncryptedPacket> ConstructServerResponseHeadersPacket(
      QuicPacketNumber packet_number,
      QuicStreamId stream_id,
      QuicStreamOffset* offset,
      QuicTestPacketMaker* maker) {
    SpdyHeaderBlock headers(maker->GetResponseHeaders("200 OK"));
    return maker->MakeResponseHeadersPacketWithOffsetTracking(
        packet_number, stream_id, false, false, std::move(headers), offset);
  }

  std::unique_ptr<QuicEncryptedPacket> ConstructServerResponseHeadersPacket(
      QuicPacketNumber packet_number,
      QuicStreamId stream_id,
      QuicTestPacketMaker* maker) {
    return ConstructServerResponseHeadersPacket(packet_number, stream_id,
                                                nullptr, maker);
  }

  std::unique_ptr<QuicEncryptedPacket> ConstructServerDataPacket(
      QuicPacketNumber packet_number,
      QuicStreamId stream_id,
      QuicTestPacketMaker* maker) {
    return maker->MakeDataPacket(packet_number, stream_id, false, true, 0,
                                 "hello");
  }

  std::unique_ptr<QuicEncryptedPacket> ConstructClientAckPacket(
      QuicPacketNumber packet_number,
      QuicPacketNumber largest_received,
      QuicPacketNumber smallest_received,
      QuicPacketNumber least_unacked,
      QuicTestPacketMaker* maker) {
    return maker->MakeAckPacket(packet_number, largest_received,
                                smallest_received, least_unacked, true);
  }

  std::unique_ptr<QuicReceivedPacket> ConstructInitialSettingsPacket(
      QuicPacketNumber packet_number,
      QuicStreamOffset* offset,
      QuicTestPacketMaker* maker) {
    return maker->MakeInitialSettingsPacket(packet_number, offset);
  }

  void AddRefusedSocketData() {
    std::unique_ptr<StaticSocketDataProvider> refused_data(
        new StaticSocketDataProvider());
    MockConnect refused_connect(SYNCHRONOUS, ERR_CONNECTION_REFUSED);
    refused_data->set_connect_data(refused_connect);
    socket_factory_.AddSocketDataProvider(refused_data.get());
    static_socket_data_provider_vector_.push_back(std::move(refused_data));
  }

  void AddHangingSocketData() {
    std::unique_ptr<StaticSocketDataProvider> hanging_data(
        new StaticSocketDataProvider());
    MockConnect hanging_connect(SYNCHRONOUS, ERR_IO_PENDING);
    hanging_data->set_connect_data(hanging_connect);
    socket_factory_.AddSocketDataProvider(hanging_data.get());
    static_socket_data_provider_vector_.push_back(std::move(hanging_data));
    socket_factory_.AddSSLSocketDataProvider(&ssl_data_);
  }

  bool AllDataConsumed() {
    for (const auto& socket_data_ptr : static_socket_data_provider_vector_) {
      if (!socket_data_ptr->AllReadDataConsumed() ||
          !socket_data_ptr->AllWriteDataConsumed()) {
        return false;
      }
    }
    return true;
  }

  void SendRequestAndExpectQuicResponse(const std::string& host) {
    HttpNetworkTransaction trans(DEFAULT_PRIORITY, session_.get());
    HttpRequestInfo request;
    std::string url("https://");
    url.append(host);
    request.url = GURL(url);
    request.load_flags = 0;
    request.method = "GET";
    TestCompletionCallback callback;
    int rv = trans.Start(&request, callback.callback(), net_log_.bound());
    EXPECT_THAT(callback.GetResult(rv), IsOk());

    std::string response_data;
    ASSERT_THAT(ReadTransaction(&trans, &response_data), IsOk());
    EXPECT_EQ("hello", response_data);

    const HttpResponseInfo* response = trans.GetResponseInfo();
    ASSERT_TRUE(response != nullptr);
    ASSERT_TRUE(response->headers.get() != nullptr);
    EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());
    EXPECT_TRUE(response->was_fetched_via_spdy);
    EXPECT_TRUE(response->was_alpn_negotiated);
    EXPECT_EQ(QuicHttpStream::ConnectionInfoFromQuicVersion(version_),
              response->connection_info);
    EXPECT_EQ(443, response->socket_address.port());
  }

  QuicStreamId GetNthClientInitiatedStreamId(int n) {
    return test::GetNthClientInitiatedStreamId(version_, n);
  }

  MockClock clock_;
  QuicVersion version_;
  DestinationType destination_type_;
  std::string origin1_;
  std::string origin2_;
  std::unique_ptr<HttpNetworkSession> session_;
  MockClientSocketFactory socket_factory_;
  MockHostResolver host_resolver_;
  MockCertVerifier cert_verifier_;
  TransportSecurityState transport_security_state_;
  std::unique_ptr<CTVerifier> cert_transparency_verifier_;
  CTPolicyEnforcer ct_policy_enforcer_;
  TestSocketPerformanceWatcherFactory test_socket_performance_watcher_factory_;
  scoped_refptr<SSLConfigServiceDefaults> ssl_config_service_;
  std::unique_ptr<ProxyService> proxy_service_;
  std::unique_ptr<HttpAuthHandlerFactory> auth_handler_factory_;
  MockRandom random_generator_;
  HttpServerPropertiesImpl http_server_properties_;
  BoundTestNetLog net_log_;
  MockCryptoClientStreamFactory crypto_client_stream_factory_;
  std::vector<std::unique_ptr<StaticSocketDataProvider>>
      static_socket_data_provider_vector_;
  SSLSocketDataProvider ssl_data_;
};

INSTANTIATE_TEST_CASE_P(Version,
                        QuicNetworkTransactionWithDestinationTest,
                        ::testing::ValuesIn(GetPoolingTestParams()));

// A single QUIC request fails because the certificate does not match the origin
// hostname, regardless of whether it matches the alternative service hostname.
TEST_P(QuicNetworkTransactionWithDestinationTest, InvalidCertificate) {
  if (destination_type_ == DIFFERENT)
    return;

  GURL url("https://mail.example.com/");
  origin1_ = url.host();

  // Not used for requests, but this provides a test case where the certificate
  // is valid for the hostname of the alternative service.
  origin2_ = "mail.example.org";

  SetAlternativeService(origin1_);

  scoped_refptr<X509Certificate> cert(
      ImportCertFromFile(GetTestCertsDirectory(), "wildcard.pem"));
  ASSERT_FALSE(cert->VerifyNameMatch(origin1_, false));
  ASSERT_TRUE(cert->VerifyNameMatch(origin2_, false));

  ProofVerifyDetailsChromium verify_details;
  verify_details.cert_verify_result.verified_cert = cert;
  verify_details.cert_verify_result.is_issued_by_known_root = true;
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData mock_quic_data;
  mock_quic_data.AddRead(ASYNC, ERR_IO_PENDING);
  mock_quic_data.AddRead(ASYNC, 0);

  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  AddRefusedSocketData();

  HttpRequestInfo request;
  request.url = url;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session_.get());
  TestCompletionCallback callback;
  int rv = trans.Start(&request, callback.callback(), net_log_.bound());
  EXPECT_THAT(callback.GetResult(rv), IsError(ERR_CONNECTION_REFUSED));

  EXPECT_TRUE(AllDataConsumed());
}

// First request opens QUIC session to alternative service.  Second request
// pools to it, because destination matches and certificate is valid, even
// though QuicServerId is different.
TEST_P(QuicNetworkTransactionWithDestinationTest, PoolIfCertificateValid) {
  origin1_ = "mail.example.org";
  origin2_ = "news.example.org";

  SetAlternativeService(origin1_);
  SetAlternativeService(origin2_);

  scoped_refptr<X509Certificate> cert(
      ImportCertFromFile(GetTestCertsDirectory(), "wildcard.pem"));
  ASSERT_TRUE(cert->VerifyNameMatch(origin1_, false));
  ASSERT_TRUE(cert->VerifyNameMatch(origin2_, false));
  ASSERT_FALSE(cert->VerifyNameMatch(kDifferentHostname, false));

  ProofVerifyDetailsChromium verify_details;
  verify_details.cert_verify_result.verified_cert = cert;
  verify_details.cert_verify_result.is_issued_by_known_root = true;
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  QuicTestPacketMaker client_maker1(version_, 0, &clock_, origin1_,
                                    Perspective::IS_CLIENT);
  QuicTestPacketMaker server_maker1(version_, 0, &clock_, origin1_,
                                    Perspective::IS_SERVER);

  QuicStreamOffset request_header_offset(0);
  QuicStreamOffset response_header_offset(0);

  MockQuicData mock_quic_data;
  mock_quic_data.AddWrite(ConstructInitialSettingsPacket(
      1, &request_header_offset, &client_maker1));
  mock_quic_data.AddWrite(ConstructClientRequestHeadersPacket(
      2, GetNthClientInitiatedStreamId(0), true, &request_header_offset,
      &client_maker1));
  mock_quic_data.AddRead(ConstructServerResponseHeadersPacket(
      1, GetNthClientInitiatedStreamId(0), &response_header_offset,
      &server_maker1));
  mock_quic_data.AddRead(ConstructServerDataPacket(
      2, GetNthClientInitiatedStreamId(0), &server_maker1));
  mock_quic_data.AddWrite(ConstructClientAckPacket(3, 2, 1, 1, &client_maker1));

  QuicTestPacketMaker client_maker2(version_, 0, &clock_, origin2_,
                                    Perspective::IS_CLIENT);
  QuicTestPacketMaker server_maker2(version_, 0, &clock_, origin2_,
                                    Perspective::IS_SERVER);

  mock_quic_data.AddWrite(ConstructClientRequestHeadersPacket(
      4, GetNthClientInitiatedStreamId(1), false, &request_header_offset,
      &client_maker2));
  mock_quic_data.AddRead(ConstructServerResponseHeadersPacket(
      3, GetNthClientInitiatedStreamId(1), &response_header_offset,
      &server_maker2));
  mock_quic_data.AddRead(ConstructServerDataPacket(
      4, GetNthClientInitiatedStreamId(1), &server_maker2));
  mock_quic_data.AddWrite(ConstructClientAckPacket(5, 4, 3, 1, &client_maker2));
  mock_quic_data.AddRead(ASYNC, ERR_IO_PENDING);  // No more data to read
  mock_quic_data.AddRead(ASYNC, 0);               // EOF

  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  AddHangingSocketData();
  AddHangingSocketData();

  SendRequestAndExpectQuicResponse(origin1_);
  SendRequestAndExpectQuicResponse(origin2_);

  EXPECT_TRUE(AllDataConsumed());
}

// First request opens QUIC session to alternative service.  Second request does
// not pool to it, even though destination matches, because certificate is not
// valid.  Instead, a new QUIC session is opened to the same destination with a
// different QuicServerId.
TEST_P(QuicNetworkTransactionWithDestinationTest,
       DoNotPoolIfCertificateInvalid) {
  origin1_ = "news.example.org";
  origin2_ = "mail.example.com";

  SetAlternativeService(origin1_);
  SetAlternativeService(origin2_);

  scoped_refptr<X509Certificate> cert1(
      ImportCertFromFile(GetTestCertsDirectory(), "wildcard.pem"));
  ASSERT_TRUE(cert1->VerifyNameMatch(origin1_, false));
  ASSERT_FALSE(cert1->VerifyNameMatch(origin2_, false));
  ASSERT_FALSE(cert1->VerifyNameMatch(kDifferentHostname, false));

  scoped_refptr<X509Certificate> cert2(
      ImportCertFromFile(GetTestCertsDirectory(), "spdy_pooling.pem"));
  ASSERT_TRUE(cert2->VerifyNameMatch(origin2_, false));
  ASSERT_FALSE(cert2->VerifyNameMatch(kDifferentHostname, false));

  ProofVerifyDetailsChromium verify_details1;
  verify_details1.cert_verify_result.verified_cert = cert1;
  verify_details1.cert_verify_result.is_issued_by_known_root = true;
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details1);

  ProofVerifyDetailsChromium verify_details2;
  verify_details2.cert_verify_result.verified_cert = cert2;
  verify_details2.cert_verify_result.is_issued_by_known_root = true;
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details2);

  QuicTestPacketMaker client_maker1(version_, 0, &clock_, origin1_,
                                    Perspective::IS_CLIENT);
  QuicTestPacketMaker server_maker1(version_, 0, &clock_, origin1_,
                                    Perspective::IS_SERVER);

  MockQuicData mock_quic_data1;
  QuicStreamOffset header_stream_offset1 = 0;
  mock_quic_data1.AddWrite(ConstructInitialSettingsPacket(
      1, &header_stream_offset1, &client_maker1));
  mock_quic_data1.AddWrite(ConstructClientRequestHeadersPacket(
      2, GetNthClientInitiatedStreamId(0), true, &header_stream_offset1,
      &client_maker1));
  mock_quic_data1.AddRead(ConstructServerResponseHeadersPacket(
      1, GetNthClientInitiatedStreamId(0), &server_maker1));
  mock_quic_data1.AddRead(ConstructServerDataPacket(
      2, GetNthClientInitiatedStreamId(0), &server_maker1));
  mock_quic_data1.AddWrite(
      ConstructClientAckPacket(3, 2, 1, 1, &client_maker1));
  mock_quic_data1.AddRead(ASYNC, ERR_IO_PENDING);  // No more data to read
  mock_quic_data1.AddRead(ASYNC, 0);               // EOF

  mock_quic_data1.AddSocketDataToFactory(&socket_factory_);

  AddHangingSocketData();

  QuicTestPacketMaker client_maker2(version_, 0, &clock_, origin2_,
                                    Perspective::IS_CLIENT);
  QuicTestPacketMaker server_maker2(version_, 0, &clock_, origin2_,
                                    Perspective::IS_SERVER);

  MockQuicData mock_quic_data2;
  QuicStreamOffset header_stream_offset2 = 0;
  mock_quic_data2.AddWrite(ConstructInitialSettingsPacket(
      1, &header_stream_offset2, &client_maker2));
  mock_quic_data2.AddWrite(ConstructClientRequestHeadersPacket(
      2, GetNthClientInitiatedStreamId(0), true, &header_stream_offset2,
      &client_maker2));
  mock_quic_data2.AddRead(ConstructServerResponseHeadersPacket(
      1, GetNthClientInitiatedStreamId(0), &server_maker2));
  mock_quic_data2.AddRead(ConstructServerDataPacket(
      2, GetNthClientInitiatedStreamId(0), &server_maker2));
  mock_quic_data2.AddWrite(
      ConstructClientAckPacket(3, 2, 1, 1, &client_maker2));
  mock_quic_data2.AddRead(ASYNC, ERR_IO_PENDING);  // No more data to read
  mock_quic_data2.AddRead(ASYNC, 0);               // EOF

  mock_quic_data2.AddSocketDataToFactory(&socket_factory_);

  AddHangingSocketData();

  SendRequestAndExpectQuicResponse(origin1_);
  SendRequestAndExpectQuicResponse(origin2_);

  EXPECT_TRUE(AllDataConsumed());
}

// crbug.com/705109 - this confirms that matching request with a body
// triggers a crash (pre-fix).
TEST_P(QuicNetworkTransactionTest, QuicServerPushMatchesRequestWithBody) {
  params_.origins_to_force_quic_on.insert(
      HostPortPair::FromString("mail.example.org:443"));

  MockQuicData mock_quic_data;
  QuicStreamOffset header_stream_offset = 0;
  mock_quic_data.AddWrite(
      ConstructInitialSettingsPacket(1, &header_stream_offset));
  mock_quic_data.AddWrite(ConstructClientRequestHeadersPacket(
      2, GetNthClientInitiatedStreamId(0), true, true,
      GetRequestHeaders("GET", "https", "/"), &header_stream_offset));
  QuicStreamOffset server_header_offset = 0;
  mock_quic_data.AddRead(ConstructServerPushPromisePacket(
      1, GetNthClientInitiatedStreamId(0), GetNthServerInitiatedStreamId(0),
      false, GetRequestHeaders("GET", "https", "/pushed.jpg"),
      &server_header_offset, &server_maker_));
  mock_quic_data.AddRead(ConstructServerResponseHeadersPacket(
      2, GetNthClientInitiatedStreamId(0), false, false,
      GetResponseHeaders("200 OK"), &server_header_offset));
  mock_quic_data.AddWrite(ConstructClientAckPacket(3, 2, 1, 1));
  mock_quic_data.AddRead(ConstructServerResponseHeadersPacket(
      3, GetNthServerInitiatedStreamId(0), false, false,
      GetResponseHeaders("200 OK"), &server_header_offset));
  mock_quic_data.AddRead(ConstructServerDataPacket(
      4, GetNthClientInitiatedStreamId(0), false, true, 0, "hello!"));
  mock_quic_data.AddWrite(ConstructClientAckPacket(4, 4, 3, 1));
  mock_quic_data.AddRead(ConstructServerDataPacket(
      5, GetNthServerInitiatedStreamId(0), false, true, 0, "and hello!"));

  // Because the matching request has a body, we will see the push
  // stream get cancelled, and the matching request go out on the
  // wire.
  mock_quic_data.AddWrite(ConstructClientAckAndRstPacket(
      5, GetNthServerInitiatedStreamId(0), QUIC_STREAM_CANCELLED, 5, 5, 1));
  const char kBody[] = "1";
  mock_quic_data.AddWrite(ConstructClientRequestHeadersPacket(
      6, GetNthClientInitiatedStreamId(1), false, false,
      GetRequestHeaders("GET", "https", "/pushed.jpg"), &header_stream_offset));
  mock_quic_data.AddWrite(ConstructClientMultipleDataFramesPacket(
      7, GetNthClientInitiatedStreamId(1), false, true, {kBody}, 0));

  // We see the same response as for the earlier pushed and cancelled
  // stream.
  mock_quic_data.AddRead(ConstructServerResponseHeadersPacket(
      6, GetNthClientInitiatedStreamId(1), false, false,
      GetResponseHeaders("200 OK"), &server_header_offset));
  mock_quic_data.AddRead(ConstructServerDataPacket(
      7, GetNthClientInitiatedStreamId(1), false, true, 0, "and hello!"));

  mock_quic_data.AddWrite(ConstructClientAckPacket(8, 7, 6, 1));
  mock_quic_data.AddRead(ASYNC, ERR_IO_PENDING);  // No more data to read
  mock_quic_data.AddRead(ASYNC, 0);               // EOF
  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  // The non-alternate protocol job needs to hang in order to guarantee that
  // the alternate-protocol job will "win".
  AddHangingNonAlternateProtocolSocketData();

  CreateSession();

  // PUSH_PROMISE handling in the http layer gets exercised here.
  SendRequestAndExpectQuicResponse("hello!");

  request_.url = GURL("https://mail.example.org/pushed.jpg");
  ChunkedUploadDataStream upload_data(0);
  upload_data.AppendData("1", 1, true);
  request_.upload_data_stream = &upload_data;
  SendRequestAndExpectQuicResponse("and hello!");
}

}  // namespace test
}  // namespace net
