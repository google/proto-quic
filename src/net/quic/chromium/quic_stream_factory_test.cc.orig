// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/chromium/quic_stream_factory.h"

#include <ostream>
#include <utility>

#include "base/bind.h"
#include "base/callback.h"
#include "base/run_loop.h"
#include "base/strings/string_util.h"
#include "base/threading/thread_task_runner_handle.h"
#include "net/cert/cert_verifier.h"
#include "net/cert/ct_policy_enforcer.h"
#include "net/cert/multi_log_ct_verifier.h"
#include "net/dns/mock_host_resolver.h"
#include "net/http/http_response_headers.h"
#include "net/http/http_response_info.h"
#include "net/http/http_server_properties_impl.h"
#include "net/http/http_util.h"
#include "net/http/transport_security_state.h"
#include "net/quic/chromium/crypto/proof_verifier_chromium.h"
#include "net/quic/core/crypto/crypto_handshake.h"
#include "net/quic/core/crypto/properties_based_quic_server_info.h"
#include "net/quic/core/crypto/quic_crypto_client_config.h"
#include "net/quic/core/crypto/quic_decrypter.h"
#include "net/quic/core/crypto/quic_encrypter.h"
#include "net/quic/core/crypto/quic_server_info.h"
#include "net/quic/core/quic_client_promised_info.h"
#include "net/quic/core/quic_http_utils.h"
#include "net/quic/test_tools/mock_clock.h"
#include "net/quic/test_tools/mock_crypto_client_stream_factory.h"
#include "net/quic/test_tools/mock_random.h"
#include "net/quic/test_tools/quic_config_peer.h"
#include "net/quic/test_tools/quic_stream_factory_peer.h"
#include "net/quic/test_tools/quic_test_packet_maker.h"
#include "net/quic/test_tools/quic_test_utils.h"
#include "net/quic/test_tools/test_task_runner.h"
#include "net/socket/socket_test_util.h"
#include "net/spdy/spdy_session_test_util.h"
#include "net/spdy/spdy_test_utils.h"
#include "net/ssl/channel_id_service.h"
#include "net/ssl/default_channel_id_store.h"
#include "net/test/cert_test_util.h"
#include "net/test/gtest_util.h"
#include "net/test/test_data_directory.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"

using net::test::IsError;
using net::test::IsOk;

using std::string;
using std::vector;

namespace net {

namespace {

class MockSSLConfigService : public SSLConfigService {
 public:
  MockSSLConfigService() {}

  void GetSSLConfig(SSLConfig* config) override { *config = config_; }

 private:
  ~MockSSLConfigService() override {}

  SSLConfig config_;
};

}  // namespace

namespace test {

namespace {

enum DestinationType {
  // In pooling tests with two requests for different origins to the same
  // destination, the destination should be
  SAME_AS_FIRST,   // the same as the first origin,
  SAME_AS_SECOND,  // the same as the second origin, or
  DIFFERENT,       // different from both.
};

const char kDefaultServerHostName[] = "www.example.org";
const char kServer2HostName[] = "mail.example.org";
const char kServer3HostName[] = "docs.example.org";
const char kServer4HostName[] = "images.example.org";
const char kDifferentHostname[] = "different.example.com";
const int kDefaultServerPort = 443;
const char kDefaultUrl[] = "https://www.example.org/";
const char kServer2Url[] = "https://mail.example.org/";
const char kServer3Url[] = "https://docs.example.org/";
const char kServer4Url[] = "https://images.example.org/";

// Run QuicStreamFactoryTest instances with all value combinations of version
// and enable_connection_racting.
struct TestParams {
  friend std::ostream& operator<<(std::ostream& os, const TestParams& p) {
    os << "{ version: " << QuicVersionToString(p.version)
       << ", enable_connection_racing: "
       << (p.enable_connection_racing ? "true" : "false") << " }";
    return os;
  }

  QuicVersion version;
  bool enable_connection_racing;
};

vector<TestParams> GetTestParams() {
  vector<TestParams> params;
  QuicVersionVector all_supported_versions = AllSupportedVersions();
  for (const QuicVersion version : all_supported_versions) {
    params.push_back(TestParams{version, false});
    params.push_back(TestParams{version, true});
  }
  return params;
}

// Run QuicStreamFactoryWithDestinationTest instances with all value
// combinations of version, enable_connection_racting, and destination_type.
struct PoolingTestParams {
  friend std::ostream& operator<<(std::ostream& os,
                                  const PoolingTestParams& p) {
    os << "{ version: " << QuicVersionToString(p.version)
       << ", enable_connection_racing: "
       << (p.enable_connection_racing ? "true" : "false")
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
  bool enable_connection_racing;
  DestinationType destination_type;
};

vector<PoolingTestParams> GetPoolingTestParams() {
  vector<PoolingTestParams> params;
  QuicVersionVector all_supported_versions = AllSupportedVersions();
  for (const QuicVersion version : all_supported_versions) {
    params.push_back(PoolingTestParams{version, false, SAME_AS_FIRST});
    params.push_back(PoolingTestParams{version, false, SAME_AS_SECOND});
    params.push_back(PoolingTestParams{version, false, DIFFERENT});
    params.push_back(PoolingTestParams{version, true, SAME_AS_FIRST});
    params.push_back(PoolingTestParams{version, true, SAME_AS_SECOND});
    params.push_back(PoolingTestParams{version, true, DIFFERENT});
  }
  return params;
}

}  // namespace

class QuicHttpStreamPeer {
 public:
  static QuicChromiumClientSession* GetSession(QuicHttpStream* stream) {
    return stream->session_.get();
  }
};

class MockQuicServerInfo : public QuicServerInfo {
 public:
  explicit MockQuicServerInfo(const QuicServerId& server_id)
      : QuicServerInfo(server_id) {}
  ~MockQuicServerInfo() override {}

  void Start() override {}

  int WaitForDataReady(const CompletionCallback& callback) override {
    return ERR_IO_PENDING;
  }

  void ResetWaitForDataReadyCallback() override {}

  void CancelWaitForDataReadyCallback() override {}

  bool IsDataReady() override { return false; }

  bool IsReadyToPersist() override { return false; }

  void Persist() override {}

  void OnExternalCacheHit() override {}
};

class MockQuicServerInfoFactory : public QuicServerInfoFactory {
 public:
  MockQuicServerInfoFactory() {}
  ~MockQuicServerInfoFactory() override {}

  QuicServerInfo* GetForServer(const QuicServerId& server_id) override {
    return new MockQuicServerInfo(server_id);
  }
};

class MockNetworkChangeNotifier : public NetworkChangeNotifier {
 public:
  MockNetworkChangeNotifier() : force_network_handles_supported_(false) {}

  ConnectionType GetCurrentConnectionType() const override {
    return CONNECTION_UNKNOWN;
  }

  void ForceNetworkHandlesSupported() {
    force_network_handles_supported_ = true;
  }

  bool AreNetworkHandlesCurrentlySupported() const override {
    return force_network_handles_supported_;
  }

  void SetConnectedNetworksList(const NetworkList& network_list) {
    connected_networks_ = network_list;
  }

  void GetCurrentConnectedNetworks(NetworkList* network_list) const override {
    network_list->clear();
    *network_list = connected_networks_;
  }

  void NotifyNetworkSoonToDisconnect(
      NetworkChangeNotifier::NetworkHandle network) {
    NetworkChangeNotifier::NotifyObserversOfSpecificNetworkChange(
        NetworkChangeNotifier::SOON_TO_DISCONNECT, network);
    // Spin the message loop so the notification is delivered.
    base::RunLoop().RunUntilIdle();
  }

  void NotifyNetworkDisconnected(NetworkChangeNotifier::NetworkHandle network) {
    NetworkChangeNotifier::NotifyObserversOfSpecificNetworkChange(
        NetworkChangeNotifier::DISCONNECTED, network);
    // Spin the message loop so the notification is delivered.
    base::RunLoop().RunUntilIdle();
  }

 private:
  bool force_network_handles_supported_;
  NetworkChangeNotifier::NetworkList connected_networks_;
};

// Class to replace existing NetworkChangeNotifier singleton with a
// MockNetworkChangeNotifier for a test. To use, simply create a
// ScopedMockNetworkChangeNotifier object in the test.
class ScopedMockNetworkChangeNotifier {
 public:
  ScopedMockNetworkChangeNotifier()
      : disable_network_change_notifier_for_tests_(
            new NetworkChangeNotifier::DisableForTest()),
        mock_network_change_notifier_(new MockNetworkChangeNotifier()) {}

  MockNetworkChangeNotifier* mock_network_change_notifier() {
    return mock_network_change_notifier_.get();
  }

 private:
  std::unique_ptr<NetworkChangeNotifier::DisableForTest>
      disable_network_change_notifier_for_tests_;
  std::unique_ptr<MockNetworkChangeNotifier> mock_network_change_notifier_;
};

class QuicStreamFactoryTestBase {
 protected:
  QuicStreamFactoryTestBase(QuicVersion version, bool enable_connection_racing)
      : ssl_config_service_(new MockSSLConfigService),
        random_generator_(0),
        clock_(new MockClock()),
        runner_(new TestTaskRunner(clock_)),
        version_(version),
        client_maker_(version_,
                      0,
                      clock_,
                      kDefaultServerHostName,
                      Perspective::IS_CLIENT),
        server_maker_(version_,
                      0,
                      clock_,
                      kDefaultServerHostName,
                      Perspective::IS_SERVER),
        cert_verifier_(CertVerifier::CreateDefault()),
        channel_id_service_(
            new ChannelIDService(new DefaultChannelIDStore(nullptr),
                                 base::ThreadTaskRunnerHandle::Get())),
        cert_transparency_verifier_(new MultiLogCTVerifier()),
        scoped_mock_network_change_notifier_(nullptr),
        factory_(nullptr),
        host_port_pair_(kDefaultServerHostName, kDefaultServerPort),
        url_(kDefaultUrl),
        url2_(kServer2Url),
        url3_(kServer3Url),
        url4_(kServer4Url),
        privacy_mode_(PRIVACY_MODE_DISABLED),
        enable_port_selection_(true),
        always_require_handshake_confirmation_(false),
        disable_connection_pooling_(false),
        load_server_info_timeout_srtt_multiplier_(0.0f),
        enable_connection_racing_(enable_connection_racing),
        enable_non_blocking_io_(true),
        disable_disk_cache_(false),
        prefer_aes_(false),
        max_number_of_lossy_connections_(0),
        packet_loss_threshold_(1.0f),
        max_disabled_reasons_(3),
        threshold_timeouts_with_open_streams_(2),
        threshold_public_resets_post_handshake_(2),
        receive_buffer_size_(0),
        delay_tcp_race_(true),
        close_sessions_on_ip_change_(false),
        disable_quic_on_timeout_with_open_streams_(false),
        idle_connection_timeout_seconds_(kIdleConnectionTimeoutSeconds),
        migrate_sessions_on_network_change_(false),
        migrate_sessions_early_(false),
        allow_server_migration_(false),
        force_hol_blocking_(false),
        race_cert_verification_(false) {
    clock_->AdvanceTime(QuicTime::Delta::FromSeconds(1));
  }

  ~QuicStreamFactoryTestBase() {
    // If |factory_| was initialized, then it took over ownership of |clock_|.
    // If |factory_| was not initialized, then |clock_| needs to be destroyed.
    if (!factory_)
      delete clock_;
  }

  void Initialize() {
    DCHECK(!factory_);
    factory_.reset(new QuicStreamFactory(
        net_log_.net_log(), &host_resolver_, ssl_config_service_.get(),
        &socket_factory_, &http_server_properties_, cert_verifier_.get(),
        &ct_policy_enforcer_, channel_id_service_.get(),
        &transport_security_state_, cert_transparency_verifier_.get(),
        /*SocketPerformanceWatcherFactory*/ nullptr,
        &crypto_client_stream_factory_, &random_generator_, clock_,
        kDefaultMaxPacketSize, string(), SupportedVersions(version_),
        enable_port_selection_, always_require_handshake_confirmation_,
        disable_connection_pooling_, load_server_info_timeout_srtt_multiplier_,
        enable_connection_racing_, enable_non_blocking_io_, disable_disk_cache_,
        prefer_aes_, max_number_of_lossy_connections_, packet_loss_threshold_,
        max_disabled_reasons_, threshold_timeouts_with_open_streams_,
        threshold_public_resets_post_handshake_, receive_buffer_size_,
        delay_tcp_race_, /*max_server_configs_stored_in_properties*/ 0,
        close_sessions_on_ip_change_,
        disable_quic_on_timeout_with_open_streams_,
        idle_connection_timeout_seconds_, migrate_sessions_on_network_change_,
        migrate_sessions_early_, allow_server_migration_, force_hol_blocking_,
        race_cert_verification_, QuicTagVector(),
        /*enable_token_binding*/ false));
    factory_->set_require_confirmation(false);
    EXPECT_FALSE(factory_->has_quic_server_info_factory());
    factory_->set_quic_server_info_factory(new MockQuicServerInfoFactory());
    EXPECT_TRUE(factory_->has_quic_server_info_factory());
  }

  void InitializeConnectionMigrationTest(
      NetworkChangeNotifier::NetworkList connected_networks) {
    scoped_mock_network_change_notifier_.reset(
        new ScopedMockNetworkChangeNotifier());
    MockNetworkChangeNotifier* mock_ncn =
        scoped_mock_network_change_notifier_->mock_network_change_notifier();
    mock_ncn->ForceNetworkHandlesSupported();
    mock_ncn->SetConnectedNetworksList(connected_networks);
    migrate_sessions_on_network_change_ = true;
    migrate_sessions_early_ = true;
    Initialize();
  }

  bool HasActiveSession(const HostPortPair& host_port_pair) {
    QuicServerId server_id(host_port_pair, PRIVACY_MODE_DISABLED);
    return QuicStreamFactoryPeer::HasActiveSession(factory_.get(), server_id);
  }

  bool HasActiveCertVerifierJob(const QuicServerId& server_id) {
    return QuicStreamFactoryPeer::HasActiveCertVerifierJob(factory_.get(),
                                                           server_id);
  }

  QuicChromiumClientSession* GetActiveSession(
      const HostPortPair& host_port_pair) {
    QuicServerId server_id(host_port_pair, PRIVACY_MODE_DISABLED);
    return QuicStreamFactoryPeer::GetActiveSession(factory_.get(), server_id);
  }

  std::unique_ptr<QuicHttpStream> CreateFromSession(
      const HostPortPair& host_port_pair) {
    QuicChromiumClientSession* session = GetActiveSession(host_port_pair);
    return QuicStreamFactoryPeer::CreateFromSession(factory_.get(), session);
  }

  int GetSourcePortForNewSession(const HostPortPair& destination) {
    return GetSourcePortForNewSessionInner(destination, false);
  }

  int GetSourcePortForNewSessionAndGoAway(const HostPortPair& destination) {
    return GetSourcePortForNewSessionInner(destination, true);
  }

  int GetSourcePortForNewSessionInner(const HostPortPair& destination,
                                      bool goaway_received) {
    // Should only be called if there is no active session for this destination.
    EXPECT_FALSE(HasActiveSession(destination));
    size_t socket_count = socket_factory_.udp_client_socket_ports().size();

    MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
    SequencedSocketData socket_data(reads, arraysize(reads), nullptr, 0);
    socket_factory_.AddSocketDataProvider(&socket_data);

    QuicStreamRequest request(factory_.get());
    GURL url("https://" + destination.host() + "/");
    EXPECT_EQ(ERR_IO_PENDING,
              request.Request(destination, privacy_mode_,
                              /*cert_verify_flags=*/0, url, "GET", net_log_,
                              callback_.callback()));

    EXPECT_THAT(callback_.WaitForResult(), IsOk());
    std::unique_ptr<QuicHttpStream> stream = request.CreateStream();
    EXPECT_TRUE(stream.get());
    stream.reset();

    QuicChromiumClientSession* session = GetActiveSession(destination);

    if (socket_count + 1 != socket_factory_.udp_client_socket_ports().size()) {
      ADD_FAILURE();
      return 0;
    }

    if (goaway_received) {
      QuicGoAwayFrame goaway(QUIC_NO_ERROR, 1, "");
      session->connection()->OnGoAwayFrame(goaway);
    }

    factory_->OnSessionClosed(session);
    EXPECT_FALSE(HasActiveSession(destination));
    EXPECT_TRUE(socket_data.AllReadDataConsumed());
    EXPECT_TRUE(socket_data.AllWriteDataConsumed());
    return socket_factory_.udp_client_socket_ports()[socket_count];
  }

  std::unique_ptr<QuicEncryptedPacket> ConstructClientConnectionClosePacket(
      QuicPacketNumber num) {
    return client_maker_.MakeConnectionClosePacket(num);
  }

  std::unique_ptr<QuicEncryptedPacket> ConstructClientRstPacket() {
    QuicStreamId stream_id = kClientDataStreamId1;
    return client_maker_.MakeRstPacket(
        1, true, stream_id,
        AdjustErrorForVersion(QUIC_RST_ACKNOWLEDGEMENT, version_));
  }

  static ProofVerifyDetailsChromium DefaultProofVerifyDetails() {
    // Load a certificate that is valid for *.example.org
    scoped_refptr<X509Certificate> test_cert(
        ImportCertFromFile(GetTestCertsDirectory(), "wildcard.pem"));
    EXPECT_TRUE(test_cert.get());
    ProofVerifyDetailsChromium verify_details;
    verify_details.cert_verify_result.verified_cert = test_cert;
    verify_details.cert_verify_result.is_issued_by_known_root = true;
    return verify_details;
  }

  void NotifyIPAddressChanged() {
    NetworkChangeNotifier::NotifyObserversOfIPAddressChangeForTests();
    // Spin the message loop so the notification is delivered.
    base::RunLoop().RunUntilIdle();
  }

  std::unique_ptr<QuicEncryptedPacket> ConstructGetRequestPacket(
      QuicPacketNumber packet_number,
      QuicStreamId stream_id,
      bool should_include_version,
      bool fin) {
    SpdyHeaderBlock headers =
        client_maker_.GetRequestHeaders("GET", "https", "/");
    SpdyPriority priority =
        ConvertRequestPriorityToQuicPriority(DEFAULT_PRIORITY);
    size_t spdy_headers_frame_len;
    return client_maker_.MakeRequestHeadersPacket(
        packet_number, stream_id, should_include_version, fin, priority,
        std::move(headers), &spdy_headers_frame_len);
  }

  std::unique_ptr<QuicEncryptedPacket> ConstructOkResponsePacket(
      QuicPacketNumber packet_number,
      QuicStreamId stream_id,
      bool should_include_version,
      bool fin) {
    SpdyHeaderBlock headers = server_maker_.GetResponseHeaders("200 OK");
    size_t spdy_headers_frame_len;
    return server_maker_.MakeResponseHeadersPacket(
        packet_number, stream_id, should_include_version, fin,
        std::move(headers), &spdy_headers_frame_len);
  }

  MockHostResolver host_resolver_;
  scoped_refptr<SSLConfigService> ssl_config_service_;
  MockClientSocketFactory socket_factory_;
  MockCryptoClientStreamFactory crypto_client_stream_factory_;
  MockRandom random_generator_;
  MockClock* clock_;  // Owned by |factory_| once created.
  scoped_refptr<TestTaskRunner> runner_;
  QuicVersion version_;
  QuicTestPacketMaker client_maker_;
  QuicTestPacketMaker server_maker_;
  HttpServerPropertiesImpl http_server_properties_;
  std::unique_ptr<CertVerifier> cert_verifier_;
  std::unique_ptr<ChannelIDService> channel_id_service_;
  TransportSecurityState transport_security_state_;
  std::unique_ptr<CTVerifier> cert_transparency_verifier_;
  CTPolicyEnforcer ct_policy_enforcer_;
  std::unique_ptr<ScopedMockNetworkChangeNotifier>
      scoped_mock_network_change_notifier_;
  std::unique_ptr<QuicStreamFactory> factory_;
  HostPortPair host_port_pair_;
  GURL url_;
  GURL url2_;
  GURL url3_;
  GURL url4_;

  PrivacyMode privacy_mode_;
  BoundNetLog net_log_;
  TestCompletionCallback callback_;

  // Variables to configure QuicStreamFactory.
  bool enable_port_selection_;
  bool always_require_handshake_confirmation_;
  bool disable_connection_pooling_;
  double load_server_info_timeout_srtt_multiplier_;
  bool enable_connection_racing_;
  bool enable_non_blocking_io_;
  bool disable_disk_cache_;
  bool prefer_aes_;
  int max_number_of_lossy_connections_;
  double packet_loss_threshold_;
  int max_disabled_reasons_;
  int threshold_timeouts_with_open_streams_;
  int threshold_public_resets_post_handshake_;
  int receive_buffer_size_;
  bool delay_tcp_race_;
  bool close_sessions_on_ip_change_;
  bool disable_quic_on_timeout_with_open_streams_;
  int idle_connection_timeout_seconds_;
  bool migrate_sessions_on_network_change_;
  bool migrate_sessions_early_;
  bool allow_server_migration_;
  bool force_hol_blocking_;
  bool race_cert_verification_;
};

class QuicStreamFactoryTest : public QuicStreamFactoryTestBase,
                              public ::testing::TestWithParam<TestParams> {
 protected:
  QuicStreamFactoryTest()
      : QuicStreamFactoryTestBase(GetParam().version,
                                  GetParam().enable_connection_racing) {}
};

INSTANTIATE_TEST_CASE_P(Version,
                        QuicStreamFactoryTest,
                        ::testing::ValuesIn(GetTestParams()));

TEST_P(QuicStreamFactoryTest, Create) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data);

  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request.Request(host_port_pair_, privacy_mode_,
                            /*cert_verify_flags=*/0, url_, "GET", net_log_,
                            callback_.callback()));

  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<QuicHttpStream> stream = request.CreateStream();
  EXPECT_TRUE(stream.get());

  // Will reset stream 3.
  stream = CreateFromSession(host_port_pair_);
  EXPECT_TRUE(stream.get());

  // TODO(rtenneti): We should probably have a tests that HTTP and HTTPS result
  // in streams on different sessions.
  QuicStreamRequest request2(factory_.get());
  EXPECT_EQ(OK, request2.Request(host_port_pair_, privacy_mode_,
                                 /*cert_verify_flags=*/0, url_, "GET", net_log_,
                                 callback_.callback()));
  stream = request2.CreateStream();   // Will reset stream 5.
  stream.reset();                     // Will reset stream 7.

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, CreateZeroRtt) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data);

  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::ZERO_RTT);
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule(host_port_pair_.host(),
                                           "192.168.0.1", "");

  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(OK, request.Request(host_port_pair_, privacy_mode_,
                                /*cert_verify_flags=*/0, url_, "GET", net_log_,
                                callback_.callback()));

  std::unique_ptr<QuicHttpStream> stream = request.CreateStream();
  EXPECT_TRUE(stream.get());
  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, CreateZeroRttPost) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data);

  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::ZERO_RTT);
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule(host_port_pair_.host(),
                                           "192.168.0.1", "");

  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(OK, request.Request(host_port_pair_, privacy_mode_,
                                /*cert_verify_flags=*/0, url_, "POST", net_log_,
                                callback_.callback()));

  std::unique_ptr<QuicHttpStream> stream = request.CreateStream();
  EXPECT_TRUE(stream.get());
  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, GoAway) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data);

  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request.Request(host_port_pair_, privacy_mode_,
                            /*cert_verify_flags=*/0, url_, "GET", net_log_,
                            callback_.callback()));

  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<QuicHttpStream> stream = request.CreateStream();
  EXPECT_TRUE(stream.get());

  QuicChromiumClientSession* session = GetActiveSession(host_port_pair_);

  session->OnGoAway(QuicGoAwayFrame());

  EXPECT_FALSE(HasActiveSession(host_port_pair_));

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, GoAwayForConnectionMigrationWithPortOnly) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data);

  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request.Request(host_port_pair_, privacy_mode_,
                            /*cert_verify_flags=*/0, url_, "GET", net_log_,
                            callback_.callback()));

  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<QuicHttpStream> stream = request.CreateStream();
  EXPECT_TRUE(stream.get());

  QuicChromiumClientSession* session = GetActiveSession(host_port_pair_);

  session->OnGoAway(
      QuicGoAwayFrame(QUIC_ERROR_MIGRATING_PORT, 0,
                      "peer connection migration due to port change only"));
  NetErrorDetails details;
  EXPECT_FALSE(details.quic_port_migration_detected);
  session->PopulateNetErrorDetails(&details);
  EXPECT_TRUE(details.quic_port_migration_detected);
  details.quic_port_migration_detected = false;
  stream->PopulateNetErrorDetails(&details);
  EXPECT_TRUE(details.quic_port_migration_detected);

  EXPECT_FALSE(HasActiveSession(host_port_pair_));

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, Pooling) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data);

  HostPortPair server2(kServer2HostName, kDefaultServerPort);
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule(host_port_pair_.host(),
                                           "192.168.0.1", "");
  host_resolver_.rules()->AddIPLiteralRule(server2.host(), "192.168.0.1", "");

  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(OK, request.Request(host_port_pair_, privacy_mode_,
                                /*cert_verify_flags=*/0, url_, "GET", net_log_,
                                callback_.callback()));
  std::unique_ptr<QuicHttpStream> stream = request.CreateStream();
  EXPECT_TRUE(stream.get());

  TestCompletionCallback callback;
  QuicStreamRequest request2(factory_.get());
  EXPECT_EQ(OK, request2.Request(server2, privacy_mode_,
                                 /*cert_verify_flags=*/0, url2_, "GET",
                                 net_log_, callback.callback()));
  std::unique_ptr<QuicHttpStream> stream2 = request2.CreateStream();
  EXPECT_TRUE(stream2.get());

  EXPECT_EQ(GetActiveSession(host_port_pair_), GetActiveSession(server2));

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, NoPoolingIfDisabled) {
  disable_connection_pooling_ = true;
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data1(reads, arraysize(reads), nullptr, 0);
  SequencedSocketData socket_data2(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data1);
  socket_factory_.AddSocketDataProvider(&socket_data2);

  HostPortPair server2(kServer2HostName, kDefaultServerPort);
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule(host_port_pair_.host(),
                                           "192.168.0.1", "");
  host_resolver_.rules()->AddIPLiteralRule(server2.host(), "192.168.0.1", "");

  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(OK, request.Request(host_port_pair_, privacy_mode_,
                                /*cert_verify_flags=*/0, url_, "GET", net_log_,
                                callback_.callback()));
  std::unique_ptr<QuicHttpStream> stream = request.CreateStream();
  EXPECT_TRUE(stream.get());

  TestCompletionCallback callback;
  QuicStreamRequest request2(factory_.get());
  EXPECT_EQ(OK, request2.Request(server2, privacy_mode_,
                                 /*cert_verify_flags=*/0, url2_, "GET",
                                 net_log_, callback.callback()));
  std::unique_ptr<QuicHttpStream> stream2 = request2.CreateStream();
  EXPECT_TRUE(stream2.get());

  EXPECT_NE(GetActiveSession(host_port_pair_), GetActiveSession(server2));

  EXPECT_TRUE(socket_data1.AllReadDataConsumed());
  EXPECT_TRUE(socket_data1.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data2.AllReadDataConsumed());
  EXPECT_TRUE(socket_data2.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, NoPoolingAfterGoAway) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data1(reads, arraysize(reads), nullptr, 0);
  SequencedSocketData socket_data2(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data1);
  socket_factory_.AddSocketDataProvider(&socket_data2);

  HostPortPair server2(kServer2HostName, kDefaultServerPort);
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule(host_port_pair_.host(),
                                           "192.168.0.1", "");
  host_resolver_.rules()->AddIPLiteralRule(server2.host(), "192.168.0.1", "");

  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(OK, request.Request(host_port_pair_, privacy_mode_,
                                /*cert_verify_flags=*/0, url_, "GET", net_log_,
                                callback_.callback()));
  std::unique_ptr<QuicHttpStream> stream = request.CreateStream();
  EXPECT_TRUE(stream.get());

  TestCompletionCallback callback;
  QuicStreamRequest request2(factory_.get());
  EXPECT_EQ(OK, request2.Request(server2, privacy_mode_,
                                 /*cert_verify_flags=*/0, url2_, "GET",
                                 net_log_, callback.callback()));
  std::unique_ptr<QuicHttpStream> stream2 = request2.CreateStream();
  EXPECT_TRUE(stream2.get());

  factory_->OnSessionGoingAway(GetActiveSession(host_port_pair_));
  EXPECT_FALSE(HasActiveSession(host_port_pair_));
  EXPECT_FALSE(HasActiveSession(server2));

  TestCompletionCallback callback3;
  QuicStreamRequest request3(factory_.get());
  EXPECT_EQ(OK, request3.Request(server2, privacy_mode_,
                                 /*cert_verify_flags=*/0, url2_, "GET",
                                 net_log_, callback3.callback()));
  std::unique_ptr<QuicHttpStream> stream3 = request3.CreateStream();
  EXPECT_TRUE(stream3.get());

  EXPECT_TRUE(HasActiveSession(server2));

  EXPECT_TRUE(socket_data1.AllReadDataConsumed());
  EXPECT_TRUE(socket_data1.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data2.AllReadDataConsumed());
  EXPECT_TRUE(socket_data2.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, HttpsPooling) {
  Initialize();

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data);

  HostPortPair server1(kDefaultServerHostName, 443);
  HostPortPair server2(kServer2HostName, 443);

  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule(server1.host(), "192.168.0.1", "");
  host_resolver_.rules()->AddIPLiteralRule(server2.host(), "192.168.0.1", "");

  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(OK, request.Request(server1, privacy_mode_,
                                /*cert_verify_flags=*/0, url_, "GET", net_log_,
                                callback_.callback()));
  std::unique_ptr<QuicHttpStream> stream = request.CreateStream();
  EXPECT_TRUE(stream.get());

  TestCompletionCallback callback;
  QuicStreamRequest request2(factory_.get());
  EXPECT_EQ(OK, request2.Request(server2, privacy_mode_,
                                 /*cert_verify_flags=*/0, url2_, "GET",
                                 net_log_, callback_.callback()));
  std::unique_ptr<QuicHttpStream> stream2 = request2.CreateStream();
  EXPECT_TRUE(stream2.get());

  EXPECT_EQ(GetActiveSession(server1), GetActiveSession(server2));

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, NoHttpsPoolingIfDisabled) {
  disable_connection_pooling_ = true;
  Initialize();

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data1(reads, arraysize(reads), nullptr, 0);
  SequencedSocketData socket_data2(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data1);
  socket_factory_.AddSocketDataProvider(&socket_data2);

  HostPortPair server1(kDefaultServerHostName, 443);
  HostPortPair server2(kServer2HostName, 443);

  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule(server1.host(), "192.168.0.1", "");
  host_resolver_.rules()->AddIPLiteralRule(server2.host(), "192.168.0.1", "");

  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(OK, request.Request(server1, privacy_mode_,
                                /*cert_verify_flags=*/0, url_, "GET", net_log_,
                                callback_.callback()));
  std::unique_ptr<QuicHttpStream> stream = request.CreateStream();
  EXPECT_TRUE(stream.get());

  TestCompletionCallback callback;
  QuicStreamRequest request2(factory_.get());
  EXPECT_EQ(OK, request2.Request(server2, privacy_mode_,
                                 /*cert_verify_flags=*/0, url2_, "GET",
                                 net_log_, callback_.callback()));
  std::unique_ptr<QuicHttpStream> stream2 = request2.CreateStream();
  EXPECT_TRUE(stream2.get());

  EXPECT_NE(GetActiveSession(server1), GetActiveSession(server2));

  EXPECT_TRUE(socket_data1.AllReadDataConsumed());
  EXPECT_TRUE(socket_data1.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data2.AllReadDataConsumed());
  EXPECT_TRUE(socket_data2.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, HttpsPoolingWithMatchingPins) {
  Initialize();
  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data);

  HostPortPair server1(kDefaultServerHostName, 443);
  HostPortPair server2(kServer2HostName, 443);
  uint8_t primary_pin = 1;
  uint8_t backup_pin = 2;
  test::AddPin(&transport_security_state_, kServer2HostName, primary_pin,
               backup_pin);

  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  verify_details.cert_verify_result.public_key_hashes.push_back(
      test::GetTestHashValue(primary_pin));
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule(server1.host(), "192.168.0.1", "");
  host_resolver_.rules()->AddIPLiteralRule(server2.host(), "192.168.0.1", "");

  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(OK, request.Request(server1, privacy_mode_,
                                /*cert_verify_flags=*/0, url_, "GET", net_log_,
                                callback_.callback()));
  std::unique_ptr<QuicHttpStream> stream = request.CreateStream();
  EXPECT_TRUE(stream.get());

  TestCompletionCallback callback;
  QuicStreamRequest request2(factory_.get());
  EXPECT_EQ(OK, request2.Request(server2, privacy_mode_,
                                 /*cert_verify_flags=*/0, url2_, "GET",
                                 net_log_, callback_.callback()));
  std::unique_ptr<QuicHttpStream> stream2 = request2.CreateStream();
  EXPECT_TRUE(stream2.get());

  EXPECT_EQ(GetActiveSession(server1), GetActiveSession(server2));

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, NoHttpsPoolingWithMatchingPinsIfDisabled) {
  disable_connection_pooling_ = true;
  Initialize();

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data1(reads, arraysize(reads), nullptr, 0);
  SequencedSocketData socket_data2(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data1);
  socket_factory_.AddSocketDataProvider(&socket_data2);

  HostPortPair server1(kDefaultServerHostName, 443);
  HostPortPair server2(kServer2HostName, 443);
  uint8_t primary_pin = 1;
  uint8_t backup_pin = 2;
  test::AddPin(&transport_security_state_, kServer2HostName, primary_pin,
               backup_pin);

  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  verify_details.cert_verify_result.public_key_hashes.push_back(
      test::GetTestHashValue(primary_pin));
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule(server1.host(), "192.168.0.1", "");
  host_resolver_.rules()->AddIPLiteralRule(server2.host(), "192.168.0.1", "");

  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(OK, request.Request(server1, privacy_mode_,
                                /*cert_verify_flags=*/0, url_, "GET", net_log_,
                                callback_.callback()));
  std::unique_ptr<QuicHttpStream> stream = request.CreateStream();
  EXPECT_TRUE(stream.get());

  TestCompletionCallback callback;
  QuicStreamRequest request2(factory_.get());
  EXPECT_EQ(OK, request2.Request(server2, privacy_mode_,
                                 /*cert_verify_flags=*/0, url2_, "GET",
                                 net_log_, callback_.callback()));
  std::unique_ptr<QuicHttpStream> stream2 = request2.CreateStream();
  EXPECT_TRUE(stream2.get());

  EXPECT_NE(GetActiveSession(server1), GetActiveSession(server2));

  EXPECT_TRUE(socket_data1.AllReadDataConsumed());
  EXPECT_TRUE(socket_data1.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data2.AllReadDataConsumed());
  EXPECT_TRUE(socket_data2.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, NoHttpsPoolingWithDifferentPins) {
  Initialize();
  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data1(reads, arraysize(reads), nullptr, 0);
  SequencedSocketData socket_data2(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data1);
  socket_factory_.AddSocketDataProvider(&socket_data2);

  HostPortPair server1(kDefaultServerHostName, 443);
  HostPortPair server2(kServer2HostName, 443);
  uint8_t primary_pin = 1;
  uint8_t backup_pin = 2;
  uint8_t bad_pin = 3;
  test::AddPin(&transport_security_state_, kServer2HostName, primary_pin,
               backup_pin);

  ProofVerifyDetailsChromium verify_details1 = DefaultProofVerifyDetails();
  verify_details1.cert_verify_result.public_key_hashes.push_back(
      test::GetTestHashValue(bad_pin));
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details1);

  ProofVerifyDetailsChromium verify_details2 = DefaultProofVerifyDetails();
  verify_details2.cert_verify_result.public_key_hashes.push_back(
      test::GetTestHashValue(primary_pin));
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details2);

  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule(server1.host(), "192.168.0.1", "");
  host_resolver_.rules()->AddIPLiteralRule(server2.host(), "192.168.0.1", "");

  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(OK, request.Request(server1, privacy_mode_,
                                /*cert_verify_flags=*/0, url_, "GET", net_log_,
                                callback_.callback()));
  std::unique_ptr<QuicHttpStream> stream = request.CreateStream();
  EXPECT_TRUE(stream.get());

  TestCompletionCallback callback;
  QuicStreamRequest request2(factory_.get());
  EXPECT_EQ(OK, request2.Request(server2, privacy_mode_,
                                 /*cert_verify_flags=*/0, url2_, "GET",
                                 net_log_, callback_.callback()));
  std::unique_ptr<QuicHttpStream> stream2 = request2.CreateStream();
  EXPECT_TRUE(stream2.get());

  EXPECT_NE(GetActiveSession(server1), GetActiveSession(server2));

  EXPECT_TRUE(socket_data1.AllReadDataConsumed());
  EXPECT_TRUE(socket_data1.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data2.AllReadDataConsumed());
  EXPECT_TRUE(socket_data2.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, Goaway) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data);
  SequencedSocketData socket_data2(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data2);

  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request.Request(host_port_pair_, privacy_mode_,
                            /*cert_verify_flags=*/0, url_, "GET", net_log_,
                            callback_.callback()));

  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<QuicHttpStream> stream = request.CreateStream();
  EXPECT_TRUE(stream.get());

  // Mark the session as going away.  Ensure that while it is still alive
  // that it is no longer active.
  QuicChromiumClientSession* session = GetActiveSession(host_port_pair_);
  factory_->OnSessionGoingAway(session);
  EXPECT_EQ(true,
            QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_FALSE(HasActiveSession(host_port_pair_));

  // Create a new request for the same destination and verify that a
  // new session is created.
  QuicStreamRequest request2(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request2.Request(host_port_pair_, privacy_mode_,
                             /*cert_verify_flags=*/0, url_, "GET", net_log_,
                             callback_.callback()));
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<QuicHttpStream> stream2 = request2.CreateStream();
  EXPECT_TRUE(stream2.get());

  EXPECT_TRUE(HasActiveSession(host_port_pair_));
  EXPECT_NE(session, GetActiveSession(host_port_pair_));
  EXPECT_EQ(true,
            QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));

  stream2.reset();
  stream.reset();

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data2.AllReadDataConsumed());
  EXPECT_TRUE(socket_data2.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, MaxOpenStream) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  QuicStreamId stream_id = kClientDataStreamId1;
  std::unique_ptr<QuicEncryptedPacket> client_rst(
      client_maker_.MakeRstPacket(1, true, stream_id, QUIC_STREAM_CANCELLED));
  MockWrite writes[] = {
      MockWrite(ASYNC, client_rst->data(), client_rst->length(), 0),
  };
  std::unique_ptr<QuicEncryptedPacket> server_rst(
      server_maker_.MakeRstPacket(1, false, stream_id, QUIC_STREAM_CANCELLED));
  MockRead reads[] = {
      MockRead(ASYNC, server_rst->data(), server_rst->length(), 1),
      MockRead(SYNCHRONOUS, ERR_IO_PENDING, 2)};
  SequencedSocketData socket_data(reads, arraysize(reads), writes,
                                  arraysize(writes));
  socket_factory_.AddSocketDataProvider(&socket_data);

  HttpRequestInfo request_info;
  vector<QuicHttpStream*> streams;
  // The MockCryptoClientStream sets max_open_streams to be
  // kDefaultMaxStreamsPerConnection / 2.
  for (size_t i = 0; i < kDefaultMaxStreamsPerConnection / 2; i++) {
    QuicStreamRequest request(factory_.get());
    int rv = request.Request(host_port_pair_, privacy_mode_,
                             /*cert_verify_flags=*/0, url_, "GET", net_log_,
                             callback_.callback());
    if (i == 0) {
      EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
      EXPECT_THAT(callback_.WaitForResult(), IsOk());
    } else {
      EXPECT_THAT(rv, IsOk());
    }
    std::unique_ptr<QuicHttpStream> stream = request.CreateStream();
    EXPECT_TRUE(stream);
    EXPECT_EQ(OK, stream->InitializeStream(&request_info, DEFAULT_PRIORITY,
                                           net_log_, CompletionCallback()));
    streams.push_back(stream.release());
  }

  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(OK, request.Request(host_port_pair_, privacy_mode_,
                                /*cert_verify_flags=*/0, url_, "GET", net_log_,
                                CompletionCallback()));
  std::unique_ptr<QuicHttpStream> stream = request.CreateStream();
  EXPECT_TRUE(stream);
  EXPECT_EQ(ERR_IO_PENDING,
            stream->InitializeStream(&request_info, DEFAULT_PRIORITY, net_log_,
                                     callback_.callback()));

  // Close the first stream.
  streams.front()->Close(false);
  // Trigger exchange of RSTs that in turn allow progress for the last
  // stream.
  EXPECT_THAT(callback_.WaitForResult(), IsOk());

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());

  // Force close of the connection to suppress the generation of RST
  // packets when streams are torn down, which wouldn't be relevant to
  // this test anyway.
  QuicChromiumClientSession* session = GetActiveSession(host_port_pair_);
  session->connection()->CloseConnection(QUIC_PUBLIC_RESET, "test",
                                         ConnectionCloseBehavior::SILENT_CLOSE);

  base::STLDeleteElements(&streams);
}

TEST_P(QuicStreamFactoryTest, ResolutionErrorInCreate) {
  Initialize();
  SequencedSocketData socket_data(nullptr, 0, nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data);

  host_resolver_.rules()->AddSimulatedFailure(kDefaultServerHostName);

  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request.Request(host_port_pair_, privacy_mode_,
                            /*cert_verify_flags=*/0, url_, "GET", net_log_,
                            callback_.callback()));

  EXPECT_THAT(callback_.WaitForResult(), IsError(ERR_NAME_NOT_RESOLVED));

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, ConnectErrorInCreate) {
  Initialize();
  MockConnect connect(SYNCHRONOUS, ERR_ADDRESS_IN_USE);
  SequencedSocketData socket_data(nullptr, 0, nullptr, 0);
  socket_data.set_connect_data(connect);
  socket_factory_.AddSocketDataProvider(&socket_data);

  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request.Request(host_port_pair_, privacy_mode_,
                            /*cert_verify_flags=*/0, url_, "GET", net_log_,
                            callback_.callback()));

  EXPECT_THAT(callback_.WaitForResult(), IsError(ERR_ADDRESS_IN_USE));

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, CancelCreate) {
  Initialize();
  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data);
  {
    QuicStreamRequest request(factory_.get());
    EXPECT_EQ(ERR_IO_PENDING,
              request.Request(host_port_pair_, privacy_mode_,
                              /*cert_verify_flags=*/0, url_, "GET", net_log_,
                              callback_.callback()));
  }

  base::RunLoop().RunUntilIdle();

  std::unique_ptr<QuicHttpStream> stream(CreateFromSession(host_port_pair_));
  EXPECT_TRUE(stream.get());
  stream.reset();

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, CreateConsistentEphemeralPort) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  // Sequentially connect to the default host, then another host, and then the
  // default host.  Verify that the default host gets a consistent ephemeral
  // port, that is different from the other host's connection.

  string other_server_name = kServer2HostName;
  EXPECT_NE(kDefaultServerHostName, other_server_name);
  HostPortPair host_port_pair2(other_server_name, kDefaultServerPort);

  int original_port = GetSourcePortForNewSession(host_port_pair_);
  EXPECT_NE(original_port, GetSourcePortForNewSession(host_port_pair2));
  EXPECT_EQ(original_port, GetSourcePortForNewSession(host_port_pair_));
}

TEST_P(QuicStreamFactoryTest, GoAwayDisablesConsistentEphemeralPort) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  // Get a session to the host using the port suggester.
  int original_port = GetSourcePortForNewSessionAndGoAway(host_port_pair_);
  // Verify that the port is different after the goaway.
  EXPECT_NE(original_port, GetSourcePortForNewSession(host_port_pair_));
  // Since the previous session did not goaway we should see the original port.
  EXPECT_EQ(original_port, GetSourcePortForNewSession(host_port_pair_));
}

TEST_P(QuicStreamFactoryTest, CloseAllSessions) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  std::unique_ptr<QuicEncryptedPacket> rst(ConstructClientRstPacket());
  vector<MockWrite> writes;
  writes.push_back(MockWrite(ASYNC, rst->data(), rst->length(), 1));
  SequencedSocketData socket_data(reads, arraysize(reads),
                                  writes.empty() ? nullptr : &writes[0],
                                  writes.size());
  socket_factory_.AddSocketDataProvider(&socket_data);

  MockRead reads2[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data2(reads2, arraysize(reads2), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data2);

  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request.Request(host_port_pair_, privacy_mode_,
                            /*cert_verify_flags=*/0, url_, "GET", net_log_,
                            callback_.callback()));

  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<QuicHttpStream> stream = request.CreateStream();
  HttpRequestInfo request_info;
  EXPECT_EQ(OK, stream->InitializeStream(&request_info, DEFAULT_PRIORITY,
                                         net_log_, CompletionCallback()));

  // Close the session and verify that stream saw the error.
  factory_->CloseAllSessions(ERR_INTERNET_DISCONNECTED, QUIC_INTERNAL_ERROR);
  EXPECT_EQ(ERR_INTERNET_DISCONNECTED,
            stream->ReadResponseHeaders(callback_.callback()));

  // Now attempting to request a stream to the same origin should create
  // a new session.

  QuicStreamRequest request2(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request2.Request(host_port_pair_, privacy_mode_,
                             /*cert_verify_flags=*/0, url_, "GET", net_log_,
                             callback_.callback()));

  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  stream = request2.CreateStream();
  stream.reset();  // Will reset stream 3.

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data2.AllReadDataConsumed());
  EXPECT_TRUE(socket_data2.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, OnIPAddressChanged) {
  close_sessions_on_ip_change_ = true;
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  std::unique_ptr<QuicEncryptedPacket> rst(ConstructClientRstPacket());
  vector<MockWrite> writes;
  writes.push_back(MockWrite(ASYNC, rst->data(), rst->length(), 1));
  SequencedSocketData socket_data(reads, arraysize(reads),
                                  writes.empty() ? nullptr : &writes[0],
                                  writes.size());
  socket_factory_.AddSocketDataProvider(&socket_data);

  MockRead reads2[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data2(reads2, arraysize(reads2), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data2);

  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request.Request(host_port_pair_, privacy_mode_,
                            /*cert_verify_flags=*/0, url_, "GET", net_log_,
                            callback_.callback()));

  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<QuicHttpStream> stream = request.CreateStream();
  HttpRequestInfo request_info;
  EXPECT_EQ(OK, stream->InitializeStream(&request_info, DEFAULT_PRIORITY,
                                         net_log_, CompletionCallback()));

  // Change the IP address and verify that stream saw the error.
  NotifyIPAddressChanged();
  EXPECT_EQ(ERR_NETWORK_CHANGED,
            stream->ReadResponseHeaders(callback_.callback()));
  EXPECT_TRUE(factory_->require_confirmation());

  // Now attempting to request a stream to the same origin should create
  // a new session.

  QuicStreamRequest request2(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request2.Request(host_port_pair_, privacy_mode_,
                             /*cert_verify_flags=*/0, url_, "GET", net_log_,
                             callback_.callback()));

  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  stream = request2.CreateStream();
  stream.reset();  // Will reset stream 3.

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data2.AllReadDataConsumed());
  EXPECT_TRUE(socket_data2.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, OnNetworkChangeSoonToDisconnect) {
  InitializeConnectionMigrationTest(
      {kDefaultNetworkForTests, kNewNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  std::unique_ptr<QuicEncryptedPacket> request_packet(
      ConstructGetRequestPacket(1, kClientDataStreamId1, true, true));
  MockWrite writes[] = {MockWrite(SYNCHRONOUS, request_packet->data(),
                                  request_packet->length(), 1)};
  SequencedSocketData socket_data(reads, arraysize(reads), writes,
                                  arraysize(writes));
  socket_factory_.AddSocketDataProvider(&socket_data);

  // Create request and QuicHttpStream.
  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request.Request(host_port_pair_, privacy_mode_,
                            /*cert_verify_flags=*/0, url_, "GET", net_log_,
                            callback_.callback()));
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<QuicHttpStream> stream = request.CreateStream();
  EXPECT_TRUE(stream.get());

  // Cause QUIC stream to be created.
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = url_;
  EXPECT_EQ(OK, stream->InitializeStream(&request_info, DEFAULT_PRIORITY,
                                         net_log_, CompletionCallback()));

  // Ensure that session is alive and active.
  QuicChromiumClientSession* session = GetActiveSession(host_port_pair_);
  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(host_port_pair_));

  // Send GET request on stream.
  HttpResponseInfo response;
  HttpRequestHeaders request_headers;
  EXPECT_EQ(OK, stream->SendRequest(request_headers, &response,
                                    callback_.callback()));

  // Set up second socket data provider that is used after migration.
  // The response to the earlier request is read on this new socket.
  std::unique_ptr<QuicEncryptedPacket> ping(
      client_maker_.MakePingPacket(2, /*include_version=*/true));
  std::unique_ptr<QuicEncryptedPacket> client_rst(
      client_maker_.MakeAckAndRstPacket(3, false, kClientDataStreamId1,
                                        QUIC_STREAM_CANCELLED, 1, 1, 1, true));
  MockWrite writes1[] = {
      MockWrite(SYNCHRONOUS, ping->data(), ping->length(), 0),
      MockWrite(SYNCHRONOUS, client_rst->data(), client_rst->length(), 3)};
  std::unique_ptr<QuicEncryptedPacket> response_headers_packet(
      ConstructOkResponsePacket(1, kClientDataStreamId1, false, false));
  MockRead reads1[] = {MockRead(ASYNC, response_headers_packet->data(),
                                response_headers_packet->length(), 1),
                       MockRead(SYNCHRONOUS, ERR_IO_PENDING, 2)};
  SequencedSocketData socket_data1(reads1, arraysize(reads1), writes1,
                                   arraysize(writes1));
  socket_factory_.AddSocketDataProvider(&socket_data1);

  // Trigger connection migration. This should cause a PING frame
  // to be emitted.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkSoonToDisconnect(kDefaultNetworkForTests);

  // The session should now be marked as going away. Ensure that
  // while it is still alive, it is no longer active.
  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_FALSE(HasActiveSession(host_port_pair_));
  EXPECT_EQ(1u, session->GetNumActiveStreams());

  // Verify that response headers on the migrated socket were delivered to the
  // stream.
  EXPECT_THAT(stream->ReadResponseHeaders(callback_.callback()), IsOk());
  EXPECT_EQ(200, response.headers->response_code());

  // Create a new request for the same destination and verify that a
  // new session is created.
  MockRead reads2[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data2(reads2, arraysize(reads2), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data2);

  QuicStreamRequest request2(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request2.Request(host_port_pair_, privacy_mode_,
                             /*cert_verify_flags=*/0, url_, "GET", net_log_,
                             callback_.callback()));
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<QuicHttpStream> stream2 = request2.CreateStream();
  EXPECT_TRUE(stream2.get());

  EXPECT_TRUE(HasActiveSession(host_port_pair_));
  QuicChromiumClientSession* new_session = GetActiveSession(host_port_pair_);
  EXPECT_NE(session, new_session);

  // On a DISCONNECTED notification, nothing happens to the migrated
  // session, but the new session is closed since it has no open
  // streams.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkDisconnected(kDefaultNetworkForTests);
  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_EQ(1u, session->GetNumActiveStreams());
  EXPECT_FALSE(
      QuicStreamFactoryPeer::IsLiveSession(factory_.get(), new_session));
  stream.reset();

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data1.AllReadDataConsumed());
  EXPECT_TRUE(socket_data1.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data2.AllReadDataConsumed());
  EXPECT_TRUE(socket_data2.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, OnNetworkChangeDisconnected) {
  InitializeConnectionMigrationTest(
      {kDefaultNetworkForTests, kNewNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  std::unique_ptr<QuicEncryptedPacket> request_packet(
      ConstructGetRequestPacket(1, kClientDataStreamId1, true, true));
  MockWrite writes[] = {MockWrite(SYNCHRONOUS, request_packet->data(),
                                  request_packet->length(), 1)};
  SequencedSocketData socket_data(reads, arraysize(reads), writes,
                                  arraysize(writes));
  socket_factory_.AddSocketDataProvider(&socket_data);

  // Create request and QuicHttpStream.
  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request.Request(host_port_pair_, privacy_mode_,
                            /*cert_verify_flags=*/0, url_, "GET", net_log_,
                            callback_.callback()));
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<QuicHttpStream> stream = request.CreateStream();
  EXPECT_TRUE(stream.get());

  // Cause QUIC stream to be created.
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = url_;
  EXPECT_EQ(OK, stream->InitializeStream(&request_info, DEFAULT_PRIORITY,
                                         net_log_, CompletionCallback()));

  // Ensure that session is alive and active.
  QuicChromiumClientSession* session = GetActiveSession(host_port_pair_);
  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(host_port_pair_));

  // Send GET request on stream.
  HttpResponseInfo response_info;
  HttpRequestHeaders request_headers;
  EXPECT_EQ(OK, stream->SendRequest(request_headers, &response_info,
                                    callback_.callback()));

  // Set up second socket data provider that is used after migration.
  std::unique_ptr<QuicEncryptedPacket> ping(
      client_maker_.MakePingPacket(2, /*include_version=*/true));
  std::unique_ptr<QuicEncryptedPacket> client_rst(
      client_maker_.MakeAckAndRstPacket(3, false, kClientDataStreamId1,
                                        QUIC_STREAM_CANCELLED, 1, 1, 1, true));
  MockWrite writes1[] = {
      MockWrite(SYNCHRONOUS, ping->data(), ping->length(), 0),
      MockWrite(SYNCHRONOUS, client_rst->data(), client_rst->length(), 3)};
  std::unique_ptr<QuicEncryptedPacket> response_packet(
      ConstructOkResponsePacket(1, kClientDataStreamId1, false, false));
  MockRead reads1[] = {
      MockRead(ASYNC, response_packet->data(), response_packet->length(), 1),
      MockRead(SYNCHRONOUS, ERR_IO_PENDING, 2)};
  SequencedSocketData socket_data1(reads1, arraysize(reads1), writes1,
                                   arraysize(writes1));
  socket_factory_.AddSocketDataProvider(&socket_data1);

  // Trigger connection migration. This should cause a PING frame
  // to be emitted.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkDisconnected(kDefaultNetworkForTests);

  // The session should now be marked as going away. Ensure that
  // while it is still alive, it is no longer active.
  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_FALSE(HasActiveSession(host_port_pair_));
  EXPECT_EQ(1u, session->GetNumActiveStreams());

  // Create a new request for the same destination and verify that a
  // new session is created.
  MockRead reads2[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data2(reads2, arraysize(reads2), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data2);

  QuicStreamRequest request2(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request2.Request(host_port_pair_, privacy_mode_,
                             /*cert_verify_flags=*/0, url_, "GET", net_log_,
                             callback_.callback()));
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<QuicHttpStream> stream2 = request2.CreateStream();
  EXPECT_TRUE(stream2.get());

  EXPECT_TRUE(HasActiveSession(host_port_pair_));
  EXPECT_NE(session, GetActiveSession(host_port_pair_));
  EXPECT_EQ(true,
            QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));

  stream.reset();

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data1.AllReadDataConsumed());
  EXPECT_TRUE(socket_data1.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data2.AllReadDataConsumed());
  EXPECT_TRUE(socket_data2.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, OnNetworkChangeSoonToDisconnectNoNetworks) {
  NetworkChangeNotifier::NetworkList no_networks(0);
  InitializeConnectionMigrationTest(no_networks);
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  std::unique_ptr<QuicEncryptedPacket> client_rst(client_maker_.MakeRstPacket(
      1, true, kClientDataStreamId1, QUIC_STREAM_CANCELLED));
  MockWrite writes[] = {
      MockWrite(SYNCHRONOUS, client_rst->data(), client_rst->length(), 1),
  };
  SequencedSocketData socket_data(reads, arraysize(reads), writes,
                                  arraysize(writes));
  socket_factory_.AddSocketDataProvider(&socket_data);

  // Create request and QuicHttpStream.
  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request.Request(host_port_pair_, privacy_mode_,
                            /*cert_verify_flags=*/0, url_, "GET", net_log_,
                            callback_.callback()));
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<QuicHttpStream> stream = request.CreateStream();
  EXPECT_TRUE(stream.get());

  // Cause QUIC stream to be created.
  HttpRequestInfo request_info;
  EXPECT_EQ(OK, stream->InitializeStream(&request_info, DEFAULT_PRIORITY,
                                         net_log_, CompletionCallback()));

  // Ensure that session is alive and active.
  QuicChromiumClientSession* session = GetActiveSession(host_port_pair_);
  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(host_port_pair_));
  EXPECT_EQ(1u, session->GetNumActiveStreams());

  // Trigger connection migration. Since there are no networks
  // to migrate to, this should cause the session to continue on the same
  // socket, but be marked as going away.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkSoonToDisconnect(kDefaultNetworkForTests);

  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_FALSE(HasActiveSession(host_port_pair_));
  EXPECT_EQ(1u, session->GetNumActiveStreams());

  stream.reset();

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, OnNetworkChangeDisconnectedNoNetworks) {
  NetworkChangeNotifier::NetworkList no_networks(0);
  InitializeConnectionMigrationTest(no_networks);
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  std::unique_ptr<QuicEncryptedPacket> client_rst(client_maker_.MakeRstPacket(
      1, true, kClientDataStreamId1, QUIC_RST_ACKNOWLEDGEMENT));
  MockWrite writes[] = {
      MockWrite(ASYNC, client_rst->data(), client_rst->length(), 1),
  };
  SequencedSocketData socket_data(reads, arraysize(reads), writes,
                                  arraysize(writes));
  socket_factory_.AddSocketDataProvider(&socket_data);

  // Create request and QuicHttpStream.
  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request.Request(host_port_pair_, privacy_mode_,
                            /*cert_verify_flags=*/0, url_, "GET", net_log_,
                            callback_.callback()));
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<QuicHttpStream> stream = request.CreateStream();
  EXPECT_TRUE(stream.get());

  // Cause QUIC stream to be created.
  HttpRequestInfo request_info;
  EXPECT_EQ(OK, stream->InitializeStream(&request_info, DEFAULT_PRIORITY,
                                         net_log_, CompletionCallback()));

  // Ensure that session is alive and active.
  QuicChromiumClientSession* session = GetActiveSession(host_port_pair_);
  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(host_port_pair_));

  // Trigger connection migration. Since there are no networks
  // to migrate to, this should cause a RST_STREAM frame to be emitted
  // and the session to be closed.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkDisconnected(kDefaultNetworkForTests);

  EXPECT_FALSE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_FALSE(HasActiveSession(host_port_pair_));

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, OnNetworkChangeSoonToDisconnectNoNewNetwork) {
  InitializeConnectionMigrationTest({kDefaultNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  std::unique_ptr<QuicEncryptedPacket> client_rst(client_maker_.MakeRstPacket(
      1, true, kClientDataStreamId1, QUIC_STREAM_CANCELLED));
  MockWrite writes[] = {
      MockWrite(SYNCHRONOUS, client_rst->data(), client_rst->length(), 1),
  };
  SequencedSocketData socket_data(reads, arraysize(reads), writes,
                                  arraysize(writes));
  socket_factory_.AddSocketDataProvider(&socket_data);

  // Create request and QuicHttpStream.
  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request.Request(host_port_pair_, privacy_mode_,
                            /*cert_verify_flags=*/0, url_, "GET", net_log_,
                            callback_.callback()));
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<QuicHttpStream> stream = request.CreateStream();
  EXPECT_TRUE(stream.get());

  // Cause QUIC stream to be created.
  HttpRequestInfo request_info;
  EXPECT_EQ(OK, stream->InitializeStream(&request_info, DEFAULT_PRIORITY,
                                         net_log_, CompletionCallback()));

  // Ensure that session is alive and active.
  QuicChromiumClientSession* session = GetActiveSession(host_port_pair_);
  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(host_port_pair_));

  // Trigger connection migration. Since there are no networks
  // to migrate to, this should cause session to be continue but be marked as
  // going away.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkSoonToDisconnect(kDefaultNetworkForTests);

  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_FALSE(HasActiveSession(host_port_pair_));
  EXPECT_EQ(1u, session->GetNumActiveStreams());

  stream.reset();

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, OnNetworkChangeDisconnectedNoNewNetwork) {
  InitializeConnectionMigrationTest({kDefaultNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  std::unique_ptr<QuicEncryptedPacket> client_rst(client_maker_.MakeRstPacket(
      1, true, kClientDataStreamId1, QUIC_RST_ACKNOWLEDGEMENT));
  MockWrite writes[] = {
      MockWrite(ASYNC, client_rst->data(), client_rst->length(), 1),
  };
  SequencedSocketData socket_data(reads, arraysize(reads), writes,
                                  arraysize(writes));
  socket_factory_.AddSocketDataProvider(&socket_data);

  // Create request and QuicHttpStream.
  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request.Request(host_port_pair_, privacy_mode_,
                            /*cert_verify_flags=*/0, url_, "GET", net_log_,
                            callback_.callback()));
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<QuicHttpStream> stream = request.CreateStream();
  EXPECT_TRUE(stream.get());

  // Cause QUIC stream to be created.
  HttpRequestInfo request_info;
  EXPECT_EQ(OK, stream->InitializeStream(&request_info, DEFAULT_PRIORITY,
                                         net_log_, CompletionCallback()));

  // Ensure that session is alive and active.
  QuicChromiumClientSession* session = GetActiveSession(host_port_pair_);
  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(host_port_pair_));

  // Trigger connection migration. Since there are no networks
  // to migrate to, this should cause a RST_STREAM frame to be emitted
  // with QUIC_RST_ACKNOWLEDGEMENT error code, and the session will be closed.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkDisconnected(kDefaultNetworkForTests);

  EXPECT_FALSE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_FALSE(HasActiveSession(host_port_pair_));

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest,
       OnNetworkChangeSoonToDisconnectNonMigratableStream) {
  InitializeConnectionMigrationTest(
      {kDefaultNetworkForTests, kNewNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  std::unique_ptr<QuicEncryptedPacket> client_rst(client_maker_.MakeRstPacket(
      1, true, kClientDataStreamId1, QUIC_STREAM_CANCELLED));
  MockWrite writes[] = {
      MockWrite(SYNCHRONOUS, client_rst->data(), client_rst->length(), 1),
  };
  SequencedSocketData socket_data(reads, arraysize(reads), writes,
                                  arraysize(writes));
  socket_factory_.AddSocketDataProvider(&socket_data);

  // Create request and QuicHttpStream.
  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request.Request(host_port_pair_, privacy_mode_,
                            /*cert_verify_flags=*/0, url_, "GET", net_log_,
                            callback_.callback()));
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<QuicHttpStream> stream = request.CreateStream();
  EXPECT_TRUE(stream.get());

  // Cause QUIC stream to be created, but marked as non-migratable.
  HttpRequestInfo request_info;
  request_info.load_flags |= LOAD_DISABLE_CONNECTION_MIGRATION;
  EXPECT_EQ(OK, stream->InitializeStream(&request_info, DEFAULT_PRIORITY,
                                         net_log_, CompletionCallback()));

  // Ensure that session is alive and active.
  QuicChromiumClientSession* session = GetActiveSession(host_port_pair_);
  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(host_port_pair_));

  // Trigger connection migration. Since there is a non-migratable stream,
  // this should cause session to continue but be marked as going away.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkSoonToDisconnect(kDefaultNetworkForTests);

  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_FALSE(HasActiveSession(host_port_pair_));
  EXPECT_EQ(1u, session->GetNumActiveStreams());

  stream.reset();

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest,
       OnNetworkChangeSoonToDisconnectConnectionMigrationDisabled) {
  InitializeConnectionMigrationTest(
      {kDefaultNetworkForTests, kNewNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  std::unique_ptr<QuicEncryptedPacket> client_rst(client_maker_.MakeRstPacket(
      1, true, kClientDataStreamId1, QUIC_STREAM_CANCELLED));
  MockWrite writes[] = {
      MockWrite(SYNCHRONOUS, client_rst->data(), client_rst->length(), 1),
  };
  SequencedSocketData socket_data(reads, arraysize(reads), writes,
                                  arraysize(writes));
  socket_factory_.AddSocketDataProvider(&socket_data);

  // Create request and QuicHttpStream.
  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request.Request(host_port_pair_, privacy_mode_,
                            /*cert_verify_flags=*/0, url_, "GET", net_log_,
                            callback_.callback()));
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<QuicHttpStream> stream = request.CreateStream();
  EXPECT_TRUE(stream.get());

  // Cause QUIC stream to be created.
  HttpRequestInfo request_info;
  EXPECT_EQ(OK, stream->InitializeStream(&request_info, DEFAULT_PRIORITY,
                                         net_log_, CompletionCallback()));

  // Ensure that session is alive and active.
  QuicChromiumClientSession* session = GetActiveSession(host_port_pair_);
  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(host_port_pair_));

  // Set session config to have connection migration disabled.
  QuicConfigPeer::SetReceivedDisableConnectionMigration(session->config());
  EXPECT_TRUE(session->config()->DisableConnectionMigration());

  // Trigger connection migration. Since there is a non-migratable stream,
  // this should cause session to continue but be marked as going away.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkSoonToDisconnect(kDefaultNetworkForTests);

  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_FALSE(HasActiveSession(host_port_pair_));
  EXPECT_EQ(1u, session->GetNumActiveStreams());

  stream.reset();

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, OnNetworkChangeDisconnectedNonMigratableStream) {
  InitializeConnectionMigrationTest(
      {kDefaultNetworkForTests, kNewNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  std::unique_ptr<QuicEncryptedPacket> client_rst(client_maker_.MakeRstPacket(
      1, true, kClientDataStreamId1, QUIC_RST_ACKNOWLEDGEMENT));
  MockWrite writes[] = {
      MockWrite(ASYNC, client_rst->data(), client_rst->length(), 1),
  };
  SequencedSocketData socket_data(reads, arraysize(reads), writes,
                                  arraysize(writes));
  socket_factory_.AddSocketDataProvider(&socket_data);

  // Create request and QuicHttpStream.
  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request.Request(host_port_pair_, privacy_mode_,
                            /*cert_verify_flags=*/0, url_, "GET", net_log_,
                            callback_.callback()));
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<QuicHttpStream> stream = request.CreateStream();
  EXPECT_TRUE(stream.get());

  // Cause QUIC stream to be created, but marked as non-migratable.
  HttpRequestInfo request_info;
  request_info.load_flags |= LOAD_DISABLE_CONNECTION_MIGRATION;
  EXPECT_EQ(OK, stream->InitializeStream(&request_info, DEFAULT_PRIORITY,
                                         net_log_, CompletionCallback()));

  // Ensure that session is alive and active.
  QuicChromiumClientSession* session = GetActiveSession(host_port_pair_);
  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(host_port_pair_));

  // Trigger connection migration. Since there is a non-migratable stream,
  // this should cause a RST_STREAM frame to be emitted with
  // QUIC_RST_ACKNOWLEDGEMENT error code, and the session will be closed.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkDisconnected(kDefaultNetworkForTests);

  EXPECT_FALSE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_FALSE(HasActiveSession(host_port_pair_));

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest,
       OnNetworkChangeDisconnectedConnectionMigrationDisabled) {
  InitializeConnectionMigrationTest(
      {kDefaultNetworkForTests, kNewNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  std::unique_ptr<QuicEncryptedPacket> client_rst(client_maker_.MakeRstPacket(
      1, true, kClientDataStreamId1, QUIC_RST_ACKNOWLEDGEMENT));
  MockWrite writes[] = {
      MockWrite(ASYNC, client_rst->data(), client_rst->length(), 1),
  };
  SequencedSocketData socket_data(reads, arraysize(reads), writes,
                                  arraysize(writes));
  socket_factory_.AddSocketDataProvider(&socket_data);

  // Create request and QuicHttpStream.
  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request.Request(host_port_pair_, privacy_mode_,
                            /*cert_verify_flags=*/0, url_, "GET", net_log_,
                            callback_.callback()));
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<QuicHttpStream> stream = request.CreateStream();
  EXPECT_TRUE(stream.get());

  // Cause QUIC stream to be created.
  HttpRequestInfo request_info;
  EXPECT_EQ(OK, stream->InitializeStream(&request_info, DEFAULT_PRIORITY,
                                         net_log_, CompletionCallback()));

  // Ensure that session is alive and active.
  QuicChromiumClientSession* session = GetActiveSession(host_port_pair_);
  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(host_port_pair_));

  // Set session config to have connection migration disabled.
  QuicConfigPeer::SetReceivedDisableConnectionMigration(session->config());
  EXPECT_TRUE(session->config()->DisableConnectionMigration());

  // Trigger connection migration. Since there is a non-migratable stream,
  // this should cause a RST_STREAM frame to be emitted with
  // QUIC_RST_ACKNOWLEDGEMENT error code, and the session will be closed.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkDisconnected(kDefaultNetworkForTests);

  EXPECT_FALSE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_FALSE(HasActiveSession(host_port_pair_));

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, OnNetworkChangeSoonToDisconnectNoOpenStreams) {
  InitializeConnectionMigrationTest(
      {kDefaultNetworkForTests, kNewNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data(reads, arraysize(reads), nullptr, 0u);
  socket_factory_.AddSocketDataProvider(&socket_data);

  // Create request and QuicHttpStream.
  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request.Request(host_port_pair_, privacy_mode_,
                            /*cert_verify_flags=*/0, url_, "GET", net_log_,
                            callback_.callback()));
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<QuicHttpStream> stream = request.CreateStream();
  EXPECT_TRUE(stream.get());

  // Ensure that session is alive and active.
  QuicChromiumClientSession* session = GetActiveSession(host_port_pair_);
  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(host_port_pair_));

  // Trigger connection migration. Since there are no active streams,
  // the session will be closed.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkDisconnected(kDefaultNetworkForTests);

  EXPECT_FALSE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_FALSE(HasActiveSession(host_port_pair_));

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, OnNetworkChangeDisconnectedNoOpenStreams) {
  InitializeConnectionMigrationTest(
      {kDefaultNetworkForTests, kNewNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data(reads, arraysize(reads), nullptr, 0u);
  socket_factory_.AddSocketDataProvider(&socket_data);

  // Create request and QuicHttpStream.
  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request.Request(host_port_pair_, privacy_mode_,
                            /*cert_verify_flags=*/0, url_, "GET", net_log_,
                            callback_.callback()));
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<QuicHttpStream> stream = request.CreateStream();
  EXPECT_TRUE(stream.get());

  // Ensure that session is alive and active.
  QuicChromiumClientSession* session = GetActiveSession(host_port_pair_);
  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(host_port_pair_));

  // Trigger connection migration. Since there are no active streams,
  // the session will be closed.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkDisconnected(kDefaultNetworkForTests);

  EXPECT_FALSE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_FALSE(HasActiveSession(host_port_pair_));

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, MigrateSessionEarly) {
  InitializeConnectionMigrationTest(
      {kDefaultNetworkForTests, kNewNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  std::unique_ptr<QuicEncryptedPacket> request_packet(
      ConstructGetRequestPacket(1, kClientDataStreamId1, true, true));
  MockWrite writes[] = {MockWrite(SYNCHRONOUS, request_packet->data(),
                                  request_packet->length(), 1)};
  SequencedSocketData socket_data(reads, arraysize(reads), writes,
                                  arraysize(writes));
  socket_factory_.AddSocketDataProvider(&socket_data);

  // Create request and QuicHttpStream.
  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request.Request(host_port_pair_, privacy_mode_,
                            /*cert_verify_flags=*/0, url_, "GET", net_log_,
                            callback_.callback()));
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<QuicHttpStream> stream = request.CreateStream();
  EXPECT_TRUE(stream.get());

  // Cause QUIC stream to be created.
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = url_;
  EXPECT_EQ(OK, stream->InitializeStream(&request_info, DEFAULT_PRIORITY,
                                         net_log_, CompletionCallback()));

  // Ensure that session is alive and active.
  QuicChromiumClientSession* session = GetActiveSession(host_port_pair_);
  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(host_port_pair_));

  // Send GET request on stream.
  HttpResponseInfo response;
  HttpRequestHeaders request_headers;
  EXPECT_EQ(OK, stream->SendRequest(request_headers, &response,
                                    callback_.callback()));

  // Set up second socket data provider that is used after migration.
  // The response to the earlier request is read on this new socket.
  std::unique_ptr<QuicEncryptedPacket> ping(
      client_maker_.MakePingPacket(2, /*include_version=*/true));
  std::unique_ptr<QuicEncryptedPacket> client_rst(
      client_maker_.MakeAckAndRstPacket(3, false, kClientDataStreamId1,
                                        QUIC_STREAM_CANCELLED, 1, 1, 1, true));
  MockWrite writes1[] = {
      MockWrite(SYNCHRONOUS, ping->data(), ping->length(), 0),
      MockWrite(SYNCHRONOUS, client_rst->data(), client_rst->length(), 3)};
  std::unique_ptr<QuicEncryptedPacket> response_headers_packet(
      ConstructOkResponsePacket(1, kClientDataStreamId1, false, false));
  MockRead reads1[] = {MockRead(ASYNC, response_headers_packet->data(),
                                response_headers_packet->length(), 1),
                       MockRead(SYNCHRONOUS, ERR_IO_PENDING, 2)};
  SequencedSocketData socket_data1(reads1, arraysize(reads1), writes1,
                                   arraysize(writes1));
  socket_factory_.AddSocketDataProvider(&socket_data1);

  // Trigger early connection migration. This should cause a PING frame
  // to be emitted.
  session->OnPathDegrading();

  // Run the message loop so that data queued in the new socket is read by the
  // packet reader.
  base::RunLoop().RunUntilIdle();

  // The session should now be marked as going away. Ensure that
  // while it is still alive, it is no longer active.
  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_FALSE(HasActiveSession(host_port_pair_));
  EXPECT_EQ(1u, session->GetNumActiveStreams());

  // Verify that response headers on the migrated socket were delivered to the
  // stream.
  EXPECT_THAT(stream->ReadResponseHeaders(callback_.callback()), IsOk());
  EXPECT_EQ(200, response.headers->response_code());

  // Create a new request for the same destination and verify that a
  // new session is created.
  MockRead reads2[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data2(reads2, arraysize(reads2), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data2);

  QuicStreamRequest request2(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request2.Request(host_port_pair_, privacy_mode_,
                             /*cert_verify_flags=*/0, url_, "GET", net_log_,
                             callback_.callback()));
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<QuicHttpStream> stream2 = request2.CreateStream();
  EXPECT_TRUE(stream2.get());

  EXPECT_TRUE(HasActiveSession(host_port_pair_));
  QuicChromiumClientSession* new_session = GetActiveSession(host_port_pair_);
  EXPECT_NE(session, new_session);

  // On a SOON_TO_DISCONNECT notification, nothing happens to the
  // migrated session, but the new session is closed since it has no
  // open streams.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkSoonToDisconnect(kDefaultNetworkForTests);
  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_EQ(1u, session->GetNumActiveStreams());
  EXPECT_FALSE(
      QuicStreamFactoryPeer::IsLiveSession(factory_.get(), new_session));

  // On a DISCONNECTED notification, nothing happens to the migrated session.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkDisconnected(kDefaultNetworkForTests);
  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_EQ(1u, session->GetNumActiveStreams());

  stream.reset();
  stream2.reset();

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data1.AllReadDataConsumed());
  EXPECT_TRUE(socket_data1.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data2.AllReadDataConsumed());
  EXPECT_TRUE(socket_data2.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, MigrateSessionEarlyWithAsyncWrites) {
  // Nearly identical to MigrateSessionEarly except that the write to
  // the second socket is asynchronous.  Ensures that the callback
  // infrastructure for asynchronous writes is set up correctly for
  // the old connection on the migrated socket.
  InitializeConnectionMigrationTest(
      {kDefaultNetworkForTests, kNewNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  std::unique_ptr<QuicEncryptedPacket> request_packet(
      ConstructGetRequestPacket(1, kClientDataStreamId1, true, true));
  MockWrite writes[] = {MockWrite(SYNCHRONOUS, request_packet->data(),
                                  request_packet->length(), 1)};
  SequencedSocketData socket_data(reads, arraysize(reads), writes,
                                  arraysize(writes));
  socket_factory_.AddSocketDataProvider(&socket_data);

  // Create request and QuicHttpStream.
  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request.Request(host_port_pair_, privacy_mode_,
                            /*cert_verify_flags=*/0, url_, "GET", net_log_,
                            callback_.callback()));
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<QuicHttpStream> stream = request.CreateStream();
  EXPECT_TRUE(stream.get());

  // Cause QUIC stream to be created.
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = url_;
  EXPECT_EQ(OK, stream->InitializeStream(&request_info, DEFAULT_PRIORITY,
                                         net_log_, CompletionCallback()));

  // Ensure that session is alive and active.
  QuicChromiumClientSession* session = GetActiveSession(host_port_pair_);
  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(host_port_pair_));

  // Send GET request on stream.
  HttpResponseInfo response;
  HttpRequestHeaders request_headers;
  EXPECT_EQ(OK, stream->SendRequest(request_headers, &response,
                                    callback_.callback()));

  // Set up second socket data provider that is used after migration.
  // The response to the earlier request is read on this new socket.
  std::unique_ptr<QuicEncryptedPacket> ping(
      client_maker_.MakePingPacket(2, /*include_version=*/true));
  std::unique_ptr<QuicEncryptedPacket> client_rst(
      client_maker_.MakeAckAndRstPacket(3, false, kClientDataStreamId1,
                                        QUIC_STREAM_CANCELLED, 1, 1, 1, true));
  MockWrite writes1[] = {
      MockWrite(ASYNC, ping->data(), ping->length(), 0),
      MockWrite(SYNCHRONOUS, client_rst->data(), client_rst->length(), 3)};
  std::unique_ptr<QuicEncryptedPacket> response_headers_packet(
      ConstructOkResponsePacket(1, kClientDataStreamId1, false, false));
  MockRead reads1[] = {MockRead(ASYNC, response_headers_packet->data(),
                                response_headers_packet->length(), 1),
                       MockRead(SYNCHRONOUS, ERR_IO_PENDING, 2)};
  SequencedSocketData socket_data1(reads1, arraysize(reads1), writes1,
                                   arraysize(writes1));
  socket_factory_.AddSocketDataProvider(&socket_data1);

  // Trigger early connection migration. This should cause a PING frame
  // to be emitted.
  session->OnPathDegrading();

  // Run the message loop so that data queued in the new socket is read by the
  // packet reader.
  base::RunLoop().RunUntilIdle();

  // The session should now be marked as going away. Ensure that
  // while it is still alive, it is no longer active.
  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_FALSE(HasActiveSession(host_port_pair_));
  EXPECT_EQ(1u, session->GetNumActiveStreams());

  // Verify that response headers on the migrated socket were delivered to the
  // stream.
  EXPECT_THAT(stream->ReadResponseHeaders(callback_.callback()), IsOk());
  EXPECT_EQ(200, response.headers->response_code());

  // Create a new request for the same destination and verify that a
  // new session is created.
  MockRead reads2[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data2(reads2, arraysize(reads2), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data2);

  QuicStreamRequest request2(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request2.Request(host_port_pair_, privacy_mode_,
                             /*cert_verify_flags=*/0, url_, "GET", net_log_,
                             callback_.callback()));
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<QuicHttpStream> stream2 = request2.CreateStream();
  EXPECT_TRUE(stream2.get());

  EXPECT_TRUE(HasActiveSession(host_port_pair_));
  QuicChromiumClientSession* new_session = GetActiveSession(host_port_pair_);
  EXPECT_NE(session, new_session);

  // On a SOON_TO_DISCONNECT notification, nothing happens to the
  // migrated session, but the new session is closed since it has no
  // open streams.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkSoonToDisconnect(kDefaultNetworkForTests);
  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_EQ(1u, session->GetNumActiveStreams());
  EXPECT_FALSE(
      QuicStreamFactoryPeer::IsLiveSession(factory_.get(), new_session));

  // On a DISCONNECTED notification, nothing happens to the migrated session.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkDisconnected(kDefaultNetworkForTests);
  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_EQ(1u, session->GetNumActiveStreams());

  stream.reset();
  stream2.reset();

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data1.AllReadDataConsumed());
  EXPECT_TRUE(socket_data1.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data2.AllReadDataConsumed());
  EXPECT_TRUE(socket_data2.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, MigrateSessionEarlyNoNewNetwork) {
  InitializeConnectionMigrationTest({kDefaultNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  std::unique_ptr<QuicEncryptedPacket> client_rst(client_maker_.MakeRstPacket(
      1, true, kClientDataStreamId1, QUIC_STREAM_CANCELLED));
  MockWrite writes[] = {
      MockWrite(SYNCHRONOUS, client_rst->data(), client_rst->length(), 1),
  };
  SequencedSocketData socket_data(reads, arraysize(reads), writes,
                                  arraysize(writes));
  socket_factory_.AddSocketDataProvider(&socket_data);

  // Create request and QuicHttpStream.
  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request.Request(host_port_pair_, privacy_mode_,
                            /*cert_verify_flags=*/0, url_, "GET", net_log_,
                            callback_.callback()));
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<QuicHttpStream> stream = request.CreateStream();
  EXPECT_TRUE(stream.get());

  // Cause QUIC stream to be created.
  HttpRequestInfo request_info;
  EXPECT_EQ(OK, stream->InitializeStream(&request_info, DEFAULT_PRIORITY,
                                         net_log_, CompletionCallback()));

  // Ensure that session is alive and active.
  QuicChromiumClientSession* session = GetActiveSession(host_port_pair_);
  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(host_port_pair_));

  // Trigger connection migration. Since there are no networks
  // to migrate to, this should cause session to be continue but be marked as
  // going away.
  session->OnPathDegrading();

  // Run the message loop so that data queued in the new socket is read by the
  // packet reader.
  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(host_port_pair_));
  EXPECT_EQ(1u, session->GetNumActiveStreams());

  stream.reset();

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, MigrateSessionEarlyNonMigratableStream) {
  InitializeConnectionMigrationTest(
      {kDefaultNetworkForTests, kNewNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  std::unique_ptr<QuicEncryptedPacket> client_rst(client_maker_.MakeRstPacket(
      1, true, kClientDataStreamId1, QUIC_STREAM_CANCELLED));
  MockWrite writes[] = {
      MockWrite(SYNCHRONOUS, client_rst->data(), client_rst->length(), 1),
  };
  SequencedSocketData socket_data(reads, arraysize(reads), writes,
                                  arraysize(writes));
  socket_factory_.AddSocketDataProvider(&socket_data);

  // Create request and QuicHttpStream.
  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request.Request(host_port_pair_, privacy_mode_,
                            /*cert_verify_flags=*/0, url_, "GET", net_log_,
                            callback_.callback()));
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<QuicHttpStream> stream = request.CreateStream();
  EXPECT_TRUE(stream.get());

  // Cause QUIC stream to be created, but marked as non-migratable.
  HttpRequestInfo request_info;
  request_info.load_flags |= LOAD_DISABLE_CONNECTION_MIGRATION;
  EXPECT_EQ(OK, stream->InitializeStream(&request_info, DEFAULT_PRIORITY,
                                         net_log_, CompletionCallback()));

  // Ensure that session is alive and active.
  QuicChromiumClientSession* session = GetActiveSession(host_port_pair_);
  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(host_port_pair_));

  // Trigger connection migration. Since there is a non-migratable stream,
  // this should cause session to be continue without migrating.
  session->OnPathDegrading();

  // Run the message loop so that data queued in the new socket is read by the
  // packet reader.
  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(host_port_pair_));
  EXPECT_EQ(1u, session->GetNumActiveStreams());

  stream.reset();

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, MigrateSessionEarlyConnectionMigrationDisabled) {
  InitializeConnectionMigrationTest(
      {kDefaultNetworkForTests, kNewNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  std::unique_ptr<QuicEncryptedPacket> client_rst(client_maker_.MakeRstPacket(
      1, true, kClientDataStreamId1, QUIC_STREAM_CANCELLED));
  MockWrite writes[] = {
      MockWrite(SYNCHRONOUS, client_rst->data(), client_rst->length(), 1),
  };
  SequencedSocketData socket_data(reads, arraysize(reads), writes,
                                  arraysize(writes));
  socket_factory_.AddSocketDataProvider(&socket_data);

  // Create request and QuicHttpStream.
  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request.Request(host_port_pair_, privacy_mode_,
                            /*cert_verify_flags=*/0, url_, "GET", net_log_,
                            callback_.callback()));
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<QuicHttpStream> stream = request.CreateStream();
  EXPECT_TRUE(stream.get());

  // Cause QUIC stream to be created.
  HttpRequestInfo request_info;
  EXPECT_EQ(OK, stream->InitializeStream(&request_info, DEFAULT_PRIORITY,
                                         net_log_, CompletionCallback()));

  // Ensure that session is alive and active.
  QuicChromiumClientSession* session = GetActiveSession(host_port_pair_);
  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(host_port_pair_));

  // Set session config to have connection migration disabled.
  QuicConfigPeer::SetReceivedDisableConnectionMigration(session->config());
  EXPECT_TRUE(session->config()->DisableConnectionMigration());

  // Trigger connection migration. Since there is a non-migratable stream,
  // this should cause session to be continue without migrating.
  session->OnPathDegrading();

  // Run the message loop so that data queued in the new socket is read by the
  // packet reader.
  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(host_port_pair_));
  EXPECT_EQ(1u, session->GetNumActiveStreams());

  stream.reset();

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, MigrateSessionOnWriteError) {
  InitializeConnectionMigrationTest(
      {kDefaultNetworkForTests, kNewNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  MockWrite writes[] = {MockWrite(SYNCHRONOUS, ERR_ADDRESS_UNREACHABLE, 1)};
  SequencedSocketData socket_data(reads, arraysize(reads), writes,
                                  arraysize(writes));
  socket_factory_.AddSocketDataProvider(&socket_data);

  // Create request and QuicHttpStream.
  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request.Request(host_port_pair_, privacy_mode_,
                            /*cert_verify_flags=*/0, url_, "GET", net_log_,
                            callback_.callback()));
  EXPECT_EQ(OK, callback_.WaitForResult());
  std::unique_ptr<QuicHttpStream> stream = request.CreateStream();
  EXPECT_TRUE(stream.get());

  // Cause QUIC stream to be created.
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.example.org/");
  EXPECT_EQ(OK, stream->InitializeStream(&request_info, DEFAULT_PRIORITY,
                                         net_log_, CompletionCallback()));

  // Ensure that session is alive and active.
  QuicChromiumClientSession* session = GetActiveSession(host_port_pair_);
  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(host_port_pair_));

  // Set up second socket data provider that is used after
  // migration. The request is rewritten to this new socket, and the
  // response to the request is read on this new socket.
  std::unique_ptr<QuicEncryptedPacket> request_packet(
      ConstructGetRequestPacket(1, kClientDataStreamId1, true, true));
  std::unique_ptr<QuicEncryptedPacket> client_rst(
      client_maker_.MakeAckAndRstPacket(2, false, kClientDataStreamId1,
                                        QUIC_STREAM_CANCELLED, 1, 1, 1, true));
  MockWrite writes1[] = {
      MockWrite(SYNCHRONOUS, request_packet->data(), request_packet->length(),
                0),
      MockWrite(SYNCHRONOUS, client_rst->data(), client_rst->length(), 3)};
  std::unique_ptr<QuicEncryptedPacket> response_headers_packet(
      ConstructOkResponsePacket(1, kClientDataStreamId1, false, false));
  MockRead reads1[] = {MockRead(ASYNC, response_headers_packet->data(),
                                response_headers_packet->length(), 1),
                       MockRead(SYNCHRONOUS, ERR_IO_PENDING, 2)};
  SequencedSocketData socket_data1(reads1, arraysize(reads1), writes1,
                                   arraysize(writes1));
  socket_factory_.AddSocketDataProvider(&socket_data1);

  // Send GET request on stream. This should cause a write error, which triggers
  // a connection migration attempt.
  HttpResponseInfo response;
  HttpRequestHeaders request_headers;
  EXPECT_EQ(OK, stream->SendRequest(request_headers, &response,
                                    callback_.callback()));

  // Run the message loop so that data queued in the new socket is read by the
  // packet reader.
  base::RunLoop().RunUntilIdle();

  // The session should now be marked as going away. Ensure that
  // while it is still alive, it is no longer active.
  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_FALSE(HasActiveSession(host_port_pair_));
  EXPECT_EQ(1u, session->GetNumActiveStreams());

  // Verify that response headers on the migrated socket were delivered to the
  // stream.
  EXPECT_EQ(OK, stream->ReadResponseHeaders(callback_.callback()));
  EXPECT_EQ(200, response.headers->response_code());

  stream.reset();

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data1.AllReadDataConsumed());
  EXPECT_TRUE(socket_data1.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, MigrateSessionOnWriteErrorNoNewNetwork) {
  InitializeConnectionMigrationTest({kDefaultNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  std::unique_ptr<QuicEncryptedPacket> client_rst(client_maker_.MakeRstPacket(
      1, true, kClientDataStreamId1, QUIC_STREAM_CANCELLED));
  MockWrite writes[] = {MockWrite(SYNCHRONOUS, ERR_ADDRESS_UNREACHABLE, 1)};
  SequencedSocketData socket_data(reads, arraysize(reads), writes,
                                  arraysize(writes));
  socket_factory_.AddSocketDataProvider(&socket_data);

  // Create request and QuicHttpStream.
  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request.Request(host_port_pair_, privacy_mode_,
                            /*cert_verify_flags=*/0, url_, "GET", net_log_,
                            callback_.callback()));
  EXPECT_EQ(OK, callback_.WaitForResult());
  std::unique_ptr<QuicHttpStream> stream = request.CreateStream();
  EXPECT_TRUE(stream.get());

  // Cause QUIC stream to be created.
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.example.org/");
  EXPECT_EQ(OK, stream->InitializeStream(&request_info, DEFAULT_PRIORITY,
                                         net_log_, CompletionCallback()));

  // Ensure that session is alive and active.
  QuicChromiumClientSession* session = GetActiveSession(host_port_pair_);
  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(host_port_pair_));

  // Send GET request on stream. This should cause a write error, which triggers
  // a connection migration attempt.
  HttpResponseInfo response;
  HttpRequestHeaders request_headers;
  EXPECT_EQ(
      ERR_QUIC_PROTOCOL_ERROR,
      stream->SendRequest(request_headers, &response, callback_.callback()));

  // Migration fails, and session is marked as going away.
  EXPECT_FALSE(HasActiveSession(host_port_pair_));

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, MigrateSessionOnWriteErrorNonMigratableStream) {
  InitializeConnectionMigrationTest(
      {kDefaultNetworkForTests, kNewNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  std::unique_ptr<QuicEncryptedPacket> client_rst(client_maker_.MakeRstPacket(
      1, true, kClientDataStreamId1, QUIC_STREAM_CANCELLED));
  MockWrite writes[] = {MockWrite(SYNCHRONOUS, ERR_ADDRESS_UNREACHABLE, 1)};
  SequencedSocketData socket_data(reads, arraysize(reads), writes,
                                  arraysize(writes));
  socket_factory_.AddSocketDataProvider(&socket_data);

  // Create request and QuicHttpStream.
  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request.Request(host_port_pair_, privacy_mode_,
                            /*cert_verify_flags=*/0, url_, "GET", net_log_,
                            callback_.callback()));
  EXPECT_EQ(OK, callback_.WaitForResult());
  std::unique_ptr<QuicHttpStream> stream = request.CreateStream();
  EXPECT_TRUE(stream.get());

  // Cause QUIC stream to be created, but marked as non-migratable.
  HttpRequestInfo request_info;
  request_info.load_flags |= LOAD_DISABLE_CONNECTION_MIGRATION;
  request_info.method = "GET";
  request_info.url = GURL("https://www.example.org/");
  EXPECT_EQ(OK, stream->InitializeStream(&request_info, DEFAULT_PRIORITY,
                                         net_log_, CompletionCallback()));

  // Ensure that session is alive and active.
  QuicChromiumClientSession* session = GetActiveSession(host_port_pair_);
  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(host_port_pair_));

  // Send GET request on stream. This should cause a write error, which triggers
  // a connection migration attempt.
  HttpResponseInfo response;
  HttpRequestHeaders request_headers;
  EXPECT_EQ(
      ERR_QUIC_PROTOCOL_ERROR,
      stream->SendRequest(request_headers, &response, callback_.callback()));

  // Migration fails, and session is marked as going away.
  EXPECT_FALSE(HasActiveSession(host_port_pair_));

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, MigrateSessionOnWriteErrorMigrationDisabled) {
  InitializeConnectionMigrationTest(
      {kDefaultNetworkForTests, kNewNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  std::unique_ptr<QuicEncryptedPacket> client_rst(client_maker_.MakeRstPacket(
      1, true, kClientDataStreamId1, QUIC_STREAM_CANCELLED));
  MockWrite writes[] = {MockWrite(SYNCHRONOUS, ERR_ADDRESS_UNREACHABLE, 1)};
  SequencedSocketData socket_data(reads, arraysize(reads), writes,
                                  arraysize(writes));
  socket_factory_.AddSocketDataProvider(&socket_data);

  // Create request and QuicHttpStream.
  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request.Request(host_port_pair_, privacy_mode_,
                            /*cert_verify_flags=*/0, url_, "GET", net_log_,
                            callback_.callback()));
  EXPECT_EQ(OK, callback_.WaitForResult());
  std::unique_ptr<QuicHttpStream> stream = request.CreateStream();
  EXPECT_TRUE(stream.get());

  // Cause QUIC stream to be created.
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.example.org/");
  EXPECT_EQ(OK, stream->InitializeStream(&request_info, DEFAULT_PRIORITY,
                                         net_log_, CompletionCallback()));

  // Ensure that session is alive and active.
  QuicChromiumClientSession* session = GetActiveSession(host_port_pair_);
  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(host_port_pair_));

  // Set session config to have connection migration disabled.
  QuicConfigPeer::SetReceivedDisableConnectionMigration(session->config());
  EXPECT_TRUE(session->config()->DisableConnectionMigration());

  // Send GET request on stream. This should cause a write error, which triggers
  // a connection migration attempt.
  HttpResponseInfo response;
  HttpRequestHeaders request_headers;
  EXPECT_EQ(
      ERR_QUIC_PROTOCOL_ERROR,
      stream->SendRequest(request_headers, &response, callback_.callback()));

  // Migration fails, and session is marked as going away.
  EXPECT_FALSE(HasActiveSession(host_port_pair_));

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, MigrateSessionEarlyToBadSocket) {
  // This simulates the case where we attempt to migrate to a new
  // socket but the socket is unusable, such as an ipv4/ipv6 mismatch.
  InitializeConnectionMigrationTest(
      {kDefaultNetworkForTests, kNewNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  std::unique_ptr<QuicEncryptedPacket> request_packet(
      ConstructGetRequestPacket(1, kClientDataStreamId1, true, true));
  MockWrite writes[] = {MockWrite(SYNCHRONOUS, request_packet->data(),
                                  request_packet->length(), 1)};
  SequencedSocketData socket_data(reads, arraysize(reads), writes,
                                  arraysize(writes));
  socket_factory_.AddSocketDataProvider(&socket_data);

  // Create request and QuicHttpStream.
  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request.Request(host_port_pair_, privacy_mode_,
                            /*cert_verify_flags=*/0, url_, "GET", net_log_,
                            callback_.callback()));
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<QuicHttpStream> stream = request.CreateStream();
  EXPECT_TRUE(stream.get());

  // Cause QUIC stream to be created.
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = url_;
  EXPECT_EQ(OK, stream->InitializeStream(&request_info, DEFAULT_PRIORITY,
                                         net_log_, CompletionCallback()));

  // Ensure that session is alive and active.
  QuicChromiumClientSession* session = GetActiveSession(host_port_pair_);
  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(host_port_pair_));

  // Send GET request on stream.
  HttpResponseInfo response;
  HttpRequestHeaders request_headers;
  EXPECT_EQ(OK, stream->SendRequest(request_headers, &response,
                                    callback_.callback()));

  // Set up second socket that will immediately return disconnected.
  // The stream factory will attempt to migrate to the new socket and
  // immediately fail.
  MockConnect connect_result =
      MockConnect(SYNCHRONOUS, ERR_INTERNET_DISCONNECTED);
  SequencedSocketData socket_data1(connect_result, nullptr, 0, nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data1);

  // Trigger early connection migration.
  session->OnPathDegrading();

  // Migration fails, and the session is marked as going away.
  EXPECT_FALSE(HasActiveSession(host_port_pair_));

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, ServerMigration) {
  allow_server_migration_ = true;
  Initialize();

  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  std::unique_ptr<QuicEncryptedPacket> request_packet(
      ConstructGetRequestPacket(1, kClientDataStreamId1, true, true));
  MockWrite writes1[] = {MockWrite(SYNCHRONOUS, request_packet->data(),
                                   request_packet->length(), 1)};
  MockRead reads1[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data1(reads1, arraysize(reads1), writes1,
                                   arraysize(writes1));
  socket_factory_.AddSocketDataProvider(&socket_data1);

  // Create request and QuicHttpStream.
  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request.Request(host_port_pair_, privacy_mode_,
                            /*cert_verify_flags=*/0, url_, "GET", net_log_,
                            callback_.callback()));
  EXPECT_EQ(OK, callback_.WaitForResult());
  std::unique_ptr<QuicHttpStream> stream = request.CreateStream();
  EXPECT_TRUE(stream.get());

  // Cause QUIC stream to be created.
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.example.org/");
  EXPECT_EQ(OK, stream->InitializeStream(&request_info, DEFAULT_PRIORITY,
                                         net_log_, CompletionCallback()));

  // Ensure that session is alive and active.
  QuicChromiumClientSession* session = GetActiveSession(host_port_pair_);
  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(host_port_pair_));

  // Send GET request on stream.
  HttpResponseInfo response;
  HttpRequestHeaders request_headers;
  EXPECT_EQ(OK, stream->SendRequest(request_headers, &response,
                                    callback_.callback()));

  IPEndPoint ip;
  session->GetDefaultSocket()->GetPeerAddress(&ip);
  DVLOG(1) << "Socket connected to: " << ip.address().ToString() << " "
           << ip.port();

  // Set up second socket data provider that is used after
  // migration. The request is rewritten to this new socket, and the
  // response to the request is read on this new socket.
  std::unique_ptr<QuicEncryptedPacket> ping(
      client_maker_.MakePingPacket(2, /*include_version=*/true));
  std::unique_ptr<QuicEncryptedPacket> client_rst(
      client_maker_.MakeAckAndRstPacket(3, false, kClientDataStreamId1,
                                        QUIC_STREAM_CANCELLED, 1, 1, 1, true));
  MockWrite writes2[] = {
      MockWrite(SYNCHRONOUS, ping->data(), ping->length(), 0),
      MockWrite(SYNCHRONOUS, client_rst->data(), client_rst->length(), 3)};
  std::unique_ptr<QuicEncryptedPacket> response_headers_packet(
      ConstructOkResponsePacket(1, kClientDataStreamId1, false, false));
  MockRead reads2[] = {MockRead(ASYNC, response_headers_packet->data(),
                                response_headers_packet->length(), 1),
                       MockRead(SYNCHRONOUS, ERR_IO_PENDING, 2)};
  SequencedSocketData socket_data2(reads2, arraysize(reads2), writes2,
                                   arraysize(writes2));
  socket_factory_.AddSocketDataProvider(&socket_data2);

  const uint8_t kTestIpAddress[] = {1, 2, 3, 4};
  const uint16_t kTestPort = 123;
  factory_->MigrateSessionToNewPeerAddress(
      session, IPEndPoint(IPAddress(kTestIpAddress), kTestPort), net_log_);

  session->GetDefaultSocket()->GetPeerAddress(&ip);
  DVLOG(1) << "Socket migrated to: " << ip.address().ToString() << " "
           << ip.port();

  // The session should be alive and active.
  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(host_port_pair_));
  EXPECT_EQ(1u, session->GetNumActiveStreams());

  // Run the message loop so that data queued in the new socket is read by the
  // packet reader.
  base::RunLoop().RunUntilIdle();

  // Verify that response headers on the migrated socket were delivered to the
  // stream.
  EXPECT_EQ(OK, stream->ReadResponseHeaders(callback_.callback()));
  EXPECT_EQ(200, response.headers->response_code());

  stream.reset();

  EXPECT_TRUE(socket_data1.AllReadDataConsumed());
  EXPECT_TRUE(socket_data1.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data2.AllReadDataConsumed());
  EXPECT_TRUE(socket_data2.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, OnSSLConfigChanged) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  std::unique_ptr<QuicEncryptedPacket> rst(ConstructClientRstPacket());
  vector<MockWrite> writes;
  writes.push_back(MockWrite(ASYNC, rst->data(), rst->length(), 1));
  SequencedSocketData socket_data(reads, arraysize(reads),
                                  writes.empty() ? nullptr : &writes[0],
                                  writes.size());
  socket_factory_.AddSocketDataProvider(&socket_data);

  MockRead reads2[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data2(reads2, arraysize(reads2), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data2);

  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request.Request(host_port_pair_, privacy_mode_,
                            /*cert_verify_flags=*/0, url_, "GET", net_log_,
                            callback_.callback()));

  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<QuicHttpStream> stream = request.CreateStream();
  HttpRequestInfo request_info;
  EXPECT_EQ(OK, stream->InitializeStream(&request_info, DEFAULT_PRIORITY,
                                         net_log_, CompletionCallback()));

  ssl_config_service_->NotifySSLConfigChange();
  EXPECT_EQ(ERR_CERT_DATABASE_CHANGED,
            stream->ReadResponseHeaders(callback_.callback()));
  EXPECT_FALSE(factory_->require_confirmation());

  // Now attempting to request a stream to the same origin should create
  // a new session.

  QuicStreamRequest request2(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request2.Request(host_port_pair_, privacy_mode_,
                             /*cert_verify_flags=*/0, url_, "GET", net_log_,
                             callback_.callback()));

  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  stream = request2.CreateStream();
  stream.reset();  // Will reset stream 3.

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data2.AllReadDataConsumed());
  EXPECT_TRUE(socket_data2.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, OnCertAdded) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  std::unique_ptr<QuicEncryptedPacket> rst(ConstructClientRstPacket());
  vector<MockWrite> writes;
  writes.push_back(MockWrite(ASYNC, rst->data(), rst->length(), 1));
  SequencedSocketData socket_data(reads, arraysize(reads),
                                  writes.empty() ? nullptr : &writes[0],
                                  writes.size());
  socket_factory_.AddSocketDataProvider(&socket_data);

  MockRead reads2[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data2(reads2, arraysize(reads2), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data2);

  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request.Request(host_port_pair_, privacy_mode_,
                            /*cert_verify_flags=*/0, url_, "GET", net_log_,
                            callback_.callback()));

  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<QuicHttpStream> stream = request.CreateStream();
  HttpRequestInfo request_info;
  EXPECT_EQ(OK, stream->InitializeStream(&request_info, DEFAULT_PRIORITY,
                                         net_log_, CompletionCallback()));

  // Add a cert and verify that stream saw the event.
  factory_->OnCertAdded(nullptr);
  EXPECT_EQ(ERR_CERT_DATABASE_CHANGED,
            stream->ReadResponseHeaders(callback_.callback()));
  EXPECT_FALSE(factory_->require_confirmation());

  // Now attempting to request a stream to the same origin should create
  // a new session.

  QuicStreamRequest request2(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request2.Request(host_port_pair_, privacy_mode_,
                             /*cert_verify_flags=*/0, url_, "GET", net_log_,
                             callback_.callback()));

  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  stream = request2.CreateStream();
  stream.reset();  // Will reset stream 3.

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data2.AllReadDataConsumed());
  EXPECT_TRUE(socket_data2.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, OnCACertChanged) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  std::unique_ptr<QuicEncryptedPacket> rst(ConstructClientRstPacket());
  vector<MockWrite> writes;
  writes.push_back(MockWrite(ASYNC, rst->data(), rst->length(), 1));
  SequencedSocketData socket_data(reads, arraysize(reads),
                                  writes.empty() ? nullptr : &writes[0],
                                  writes.size());
  socket_factory_.AddSocketDataProvider(&socket_data);

  MockRead reads2[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data2(reads2, arraysize(reads2), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data2);

  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request.Request(host_port_pair_, privacy_mode_,
                            /*cert_verify_flags=*/0, url_, "GET", net_log_,
                            callback_.callback()));

  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<QuicHttpStream> stream = request.CreateStream();
  HttpRequestInfo request_info;
  EXPECT_EQ(OK, stream->InitializeStream(&request_info, DEFAULT_PRIORITY,
                                         net_log_, CompletionCallback()));

  // Change the CA cert and verify that stream saw the event.
  factory_->OnCACertChanged(nullptr);
  EXPECT_EQ(ERR_CERT_DATABASE_CHANGED,
            stream->ReadResponseHeaders(callback_.callback()));
  EXPECT_FALSE(factory_->require_confirmation());

  // Now attempting to request a stream to the same origin should create
  // a new session.

  QuicStreamRequest request2(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request2.Request(host_port_pair_, privacy_mode_,
                             /*cert_verify_flags=*/0, url_, "GET", net_log_,
                             callback_.callback()));

  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  stream = request2.CreateStream();
  stream.reset();  // Will reset stream 3.

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data2.AllReadDataConsumed());
  EXPECT_TRUE(socket_data2.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, SharedCryptoConfig) {
  Initialize();

  vector<string> cannoncial_suffixes;
  cannoncial_suffixes.push_back(string(".c.youtube.com"));
  cannoncial_suffixes.push_back(string(".googlevideo.com"));

  for (unsigned i = 0; i < cannoncial_suffixes.size(); ++i) {
    string r1_host_name("r1");
    string r2_host_name("r2");
    r1_host_name.append(cannoncial_suffixes[i]);
    r2_host_name.append(cannoncial_suffixes[i]);

    HostPortPair host_port_pair1(r1_host_name, 80);
    QuicCryptoClientConfig* crypto_config =
        QuicStreamFactoryPeer::GetCryptoConfig(factory_.get());
    QuicServerId server_id1(host_port_pair1, privacy_mode_);
    QuicCryptoClientConfig::CachedState* cached1 =
        crypto_config->LookupOrCreate(server_id1);
    EXPECT_FALSE(cached1->proof_valid());
    EXPECT_TRUE(cached1->source_address_token().empty());

    // Mutate the cached1 to have different data.
    // TODO(rtenneti): mutate other members of CachedState.
    cached1->set_source_address_token(r1_host_name);
    cached1->SetProofValid();

    HostPortPair host_port_pair2(r2_host_name, 80);
    QuicServerId server_id2(host_port_pair2, privacy_mode_);
    QuicCryptoClientConfig::CachedState* cached2 =
        crypto_config->LookupOrCreate(server_id2);
    EXPECT_EQ(cached1->source_address_token(), cached2->source_address_token());
    EXPECT_TRUE(cached2->proof_valid());
  }
}

TEST_P(QuicStreamFactoryTest, CryptoConfigWhenProofIsInvalid) {
  Initialize();
  vector<string> cannoncial_suffixes;
  cannoncial_suffixes.push_back(string(".c.youtube.com"));
  cannoncial_suffixes.push_back(string(".googlevideo.com"));

  for (unsigned i = 0; i < cannoncial_suffixes.size(); ++i) {
    string r3_host_name("r3");
    string r4_host_name("r4");
    r3_host_name.append(cannoncial_suffixes[i]);
    r4_host_name.append(cannoncial_suffixes[i]);

    HostPortPair host_port_pair1(r3_host_name, 80);
    QuicCryptoClientConfig* crypto_config =
        QuicStreamFactoryPeer::GetCryptoConfig(factory_.get());
    QuicServerId server_id1(host_port_pair1, privacy_mode_);
    QuicCryptoClientConfig::CachedState* cached1 =
        crypto_config->LookupOrCreate(server_id1);
    EXPECT_FALSE(cached1->proof_valid());
    EXPECT_TRUE(cached1->source_address_token().empty());

    // Mutate the cached1 to have different data.
    // TODO(rtenneti): mutate other members of CachedState.
    cached1->set_source_address_token(r3_host_name);
    cached1->SetProofInvalid();

    HostPortPair host_port_pair2(r4_host_name, 80);
    QuicServerId server_id2(host_port_pair2, privacy_mode_);
    QuicCryptoClientConfig::CachedState* cached2 =
        crypto_config->LookupOrCreate(server_id2);
    EXPECT_NE(cached1->source_address_token(), cached2->source_address_token());
    EXPECT_TRUE(cached2->source_address_token().empty());
    EXPECT_FALSE(cached2->proof_valid());
  }
}

TEST_P(QuicStreamFactoryTest, RacingConnections) {
  disable_disk_cache_ = false;
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  if (!enable_connection_racing_)
    return;

  QuicStreamFactoryPeer::SetTaskRunner(factory_.get(), runner_.get());

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data);

  MockRead reads2[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data2(reads2, arraysize(reads2), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data2);

  const AlternativeService alternative_service1(QUIC, host_port_pair_.host(),
                                                host_port_pair_.port());
  AlternativeServiceInfoVector alternative_service_info_vector;
  base::Time expiration = base::Time::Now() + base::TimeDelta::FromDays(1);
  alternative_service_info_vector.push_back(
      AlternativeServiceInfo(alternative_service1, expiration));

  http_server_properties_.SetAlternativeServices(
      url::SchemeHostPort(url_), alternative_service_info_vector);

  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::ZERO_RTT);
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule(host_port_pair_.host(),
                                           "192.168.0.1", "");

  QuicStreamRequest request(factory_.get());
  QuicServerId server_id(host_port_pair_, privacy_mode_);
  EXPECT_EQ(ERR_IO_PENDING,
            request.Request(host_port_pair_, privacy_mode_,
                            /*cert_verify_flags=*/0, url_, "GET", net_log_,
                            callback_.callback()));
  EXPECT_EQ(2u, QuicStreamFactoryPeer::GetNumberOfActiveJobs(factory_.get(),
                                                             server_id));

  runner_->RunNextTask();

  std::unique_ptr<QuicHttpStream> stream = request.CreateStream();
  EXPECT_TRUE(stream.get());
  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
  EXPECT_EQ(0u, QuicStreamFactoryPeer::GetNumberOfActiveJobs(factory_.get(),
                                                             server_id));
}

TEST_P(QuicStreamFactoryTest, EnableNotLoadFromDiskCache) {
  disable_disk_cache_ = true;
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  QuicStreamFactoryPeer::SetTaskRunner(factory_.get(), runner_.get());

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data);

  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::ZERO_RTT);
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule(host_port_pair_.host(),
                                           "192.168.0.1", "");

  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(OK, request.Request(host_port_pair_, privacy_mode_,
                                /*cert_verify_flags=*/0, url_, "GET", net_log_,
                                callback_.callback()));

  // If we are waiting for disk cache, we would have posted a task. Verify that
  // the CancelWaitForDataReady task hasn't been posted.
  ASSERT_EQ(0u, runner_->GetPostedTasks().size());

  std::unique_ptr<QuicHttpStream> stream = request.CreateStream();
  EXPECT_TRUE(stream.get());
  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, BadPacketLoss) {
  disable_disk_cache_ = false;
  max_number_of_lossy_connections_ = 2;
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  QuicStreamFactoryPeer::SetTaskRunner(factory_.get(), runner_.get());

  EXPECT_FALSE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(),
                                                     host_port_pair_.port()));
  EXPECT_EQ(0, QuicStreamFactoryPeer::GetNumberOfLossyConnections(
                   factory_.get(), host_port_pair_.port()));

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data);

  SequencedSocketData socket_data2(nullptr, 0, nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data2);

  SequencedSocketData socket_data3(nullptr, 0, nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data3);

  SequencedSocketData socket_data4(nullptr, 0, nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data4);

  HostPortPair server2(kServer2HostName, kDefaultServerPort);
  HostPortPair server3(kServer3HostName, kDefaultServerPort);
  HostPortPair server4(kServer4HostName, kDefaultServerPort);

  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::ZERO_RTT);
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule(host_port_pair_.host(),
                                           "192.168.0.1", "");
  host_resolver_.rules()->AddIPLiteralRule(server2.host(), "192.168.0.1", "");
  host_resolver_.rules()->AddIPLiteralRule(server3.host(), "192.168.0.1", "");
  host_resolver_.rules()->AddIPLiteralRule(server4.host(), "192.168.0.1", "");

  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(OK, request.Request(host_port_pair_, privacy_mode_,
                                /*cert_verify_flags=*/0, url_, "GET", net_log_,
                                callback_.callback()));

  QuicChromiumClientSession* session = GetActiveSession(host_port_pair_);

  DVLOG(1) << "Create 1st session and test packet loss";

  // Set packet_loss_rate to a lower value than packet_loss_threshold.
  EXPECT_FALSE(
      factory_->OnHandshakeConfirmed(session, /*packet_loss_rate=*/0.9f));
  EXPECT_TRUE(session->connection()->connected());
  EXPECT_TRUE(HasActiveSession(host_port_pair_));
  EXPECT_FALSE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(),
                                                     host_port_pair_.port()));
  EXPECT_EQ(0, QuicStreamFactoryPeer::GetNumberOfLossyConnections(
                   factory_.get(), host_port_pair_.port()));

  // Set packet_loss_rate to a higher value than packet_loss_threshold only once
  // and that shouldn't close the session and it shouldn't disable QUIC.
  EXPECT_FALSE(
      factory_->OnHandshakeConfirmed(session, /*packet_loss_rate=*/1.0f));
  EXPECT_EQ(1, QuicStreamFactoryPeer::GetNumberOfLossyConnections(
                   factory_.get(), host_port_pair_.port()));
  EXPECT_TRUE(session->connection()->connected());
  EXPECT_FALSE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(),
                                                     host_port_pair_.port()));
  EXPECT_TRUE(HasActiveSession(host_port_pair_));

  // Test N-in-a-row high packet loss connections.

  DVLOG(1) << "Create 2nd session and test packet loss";

  TestCompletionCallback callback2;
  QuicStreamRequest request2(factory_.get());
  EXPECT_EQ(OK, request2.Request(server2, privacy_mode_,
                                 /*cert_verify_flags=*/0, url2_, "GET",
                                 net_log_, callback2.callback()));
  QuicChromiumClientSession* session2 = GetActiveSession(server2);

  // If there is no packet loss during handshake confirmation, number of lossy
  // connections for the port should be 0.
  EXPECT_EQ(1, QuicStreamFactoryPeer::GetNumberOfLossyConnections(
                   factory_.get(), server2.port()));
  EXPECT_FALSE(
      factory_->OnHandshakeConfirmed(session2, /*packet_loss_rate=*/0.9f));
  EXPECT_EQ(0, QuicStreamFactoryPeer::GetNumberOfLossyConnections(
                   factory_.get(), server2.port()));
  EXPECT_FALSE(
      QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(), server2.port()));

  // Set packet_loss_rate to a higher value than packet_loss_threshold only once
  // and that shouldn't close the session and it shouldn't disable QUIC.
  EXPECT_FALSE(
      factory_->OnHandshakeConfirmed(session2, /*packet_loss_rate=*/1.0f));
  EXPECT_EQ(1, QuicStreamFactoryPeer::GetNumberOfLossyConnections(
                   factory_.get(), server2.port()));
  EXPECT_TRUE(session2->connection()->connected());
  EXPECT_FALSE(
      QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(), server2.port()));
  EXPECT_TRUE(HasActiveSession(server2));

  DVLOG(1) << "Create 3rd session which also has packet loss";

  TestCompletionCallback callback3;
  QuicStreamRequest request3(factory_.get());
  EXPECT_EQ(OK, request3.Request(server3, privacy_mode_,
                                 /*cert_verify_flags=*/0, url3_, "GET",
                                 net_log_, callback3.callback()));
  QuicChromiumClientSession* session3 = GetActiveSession(server3);

  DVLOG(1) << "Create 4th session with packet loss and test IsQuicDisabled()";
  TestCompletionCallback callback4;
  QuicStreamRequest request4(factory_.get());
  EXPECT_EQ(OK, request4.Request(server4, privacy_mode_,
                                 /*cert_verify_flags=*/0, url4_, "GET",
                                 net_log_, callback4.callback()));
  QuicChromiumClientSession* session4 = GetActiveSession(server4);

  // Set packet_loss_rate to higher value than packet_loss_threshold 2nd time in
  // a row and that should close the session and disable QUIC.
  EXPECT_TRUE(
      factory_->OnHandshakeConfirmed(session3, /*packet_loss_rate=*/1.0f));
  EXPECT_EQ(2, QuicStreamFactoryPeer::GetNumberOfLossyConnections(
                   factory_.get(), server3.port()));
  EXPECT_FALSE(session3->connection()->connected());
  EXPECT_TRUE(
      QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(), server3.port()));
  EXPECT_FALSE(HasActiveSession(server3));

  // Set packet_loss_rate to higher value than packet_loss_threshold 3rd time in
  // a row and IsQuicDisabled() should close the session.
  EXPECT_TRUE(
      factory_->OnHandshakeConfirmed(session4, /*packet_loss_rate=*/1.0f));
  EXPECT_EQ(3, QuicStreamFactoryPeer::GetNumberOfLossyConnections(
                   factory_.get(), server4.port()));
  EXPECT_FALSE(session4->connection()->connected());
  EXPECT_TRUE(
      QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(), server4.port()));
  EXPECT_FALSE(HasActiveSession(server4));

  std::unique_ptr<QuicHttpStream> stream = request.CreateStream();
  EXPECT_TRUE(stream.get());
  std::unique_ptr<QuicHttpStream> stream2 = request2.CreateStream();
  EXPECT_TRUE(stream2.get());
  std::unique_ptr<QuicHttpStream> stream3 = request3.CreateStream();
  EXPECT_TRUE(stream3.get());
  std::unique_ptr<QuicHttpStream> stream4 = request4.CreateStream();
  EXPECT_TRUE(stream4.get());
  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data2.AllReadDataConsumed());
  EXPECT_TRUE(socket_data2.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data3.AllReadDataConsumed());
  EXPECT_TRUE(socket_data3.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data4.AllReadDataConsumed());
  EXPECT_TRUE(socket_data4.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, PublicResetPostHandshakeTwoOfTwo) {
  disable_disk_cache_ = false;
  threshold_public_resets_post_handshake_ = 2;
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  QuicStreamFactoryPeer::SetTaskRunner(factory_.get(), runner_.get());

  EXPECT_FALSE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(),
                                                     host_port_pair_.port()));
  EXPECT_EQ(0, QuicStreamFactoryPeer::GetNumberOfLossyConnections(
                   factory_.get(), host_port_pair_.port()));

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data);

  SequencedSocketData socket_data2(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data2);

  HostPortPair server2(kServer2HostName, kDefaultServerPort);

  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::CONFIRM_HANDSHAKE);
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule(host_port_pair_.host(),
                                           "192.168.0.1", "");
  host_resolver_.rules()->AddIPLiteralRule(server2.host(), "192.168.0.1", "");

  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(OK, request.Request(host_port_pair_, privacy_mode_,
                                /*cert_verify_flags=*/0, url_, "GET", net_log_,
                                callback_.callback()));

  QuicChromiumClientSession* session = GetActiveSession(host_port_pair_);

  DVLOG(1) << "Created 1st session. Now trigger public reset post handshake";
  session->connection()->CloseConnection(QUIC_PUBLIC_RESET, "test",
                                         ConnectionCloseBehavior::SILENT_CLOSE);
  // Need to spin the loop now to ensure that
  // QuicStreamFactory::OnSessionClosed() runs.
  base::RunLoop run_loop;
  run_loop.RunUntilIdle();

  EXPECT_EQ(1, QuicStreamFactoryPeer::GetNumPublicResetsPostHandshake(
                   factory_.get()));
  EXPECT_FALSE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(),
                                                     host_port_pair_.port()));

  // Test two-in-a-row public reset post handshakes..
  DVLOG(1) << "Create 2nd session and trigger public reset post handshake";
  TestCompletionCallback callback2;
  QuicStreamRequest request2(factory_.get());
  EXPECT_EQ(OK, request2.Request(server2, privacy_mode_,
                                 /*cert_verify_flags=*/0, url2_, "GET",
                                 net_log_, callback2.callback()));
  QuicChromiumClientSession* session2 = GetActiveSession(server2);

  session2->connection()->CloseConnection(
      QUIC_PUBLIC_RESET, "test", ConnectionCloseBehavior::SILENT_CLOSE);
  // Need to spin the loop now to ensure that
  // QuicStreamFactory::OnSessionClosed() runs.
  base::RunLoop run_loop2;
  run_loop2.RunUntilIdle();
  EXPECT_EQ(2, QuicStreamFactoryPeer::GetNumPublicResetsPostHandshake(
                   factory_.get()));
  EXPECT_TRUE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(),
                                                    host_port_pair_.port()));
  EXPECT_EQ(
      QuicChromiumClientSession::QUIC_DISABLED_PUBLIC_RESET_POST_HANDSHAKE,
      factory_->QuicDisabledReason(host_port_pair_.port()));

  std::unique_ptr<QuicHttpStream> stream = request.CreateStream();
  EXPECT_FALSE(stream.get());  // Session is already closed.
  std::unique_ptr<QuicHttpStream> stream2 = request2.CreateStream();
  EXPECT_FALSE(stream2.get());  // Session is already closed.
  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data2.AllReadDataConsumed());
  EXPECT_TRUE(socket_data2.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, TimeoutsWithOpenStreamsTwoOfTwo) {
  disable_disk_cache_ = true;
  threshold_timeouts_with_open_streams_ = 2;
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  QuicStreamFactoryPeer::SetTaskRunner(factory_.get(), runner_.get());
  EXPECT_FALSE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(),
                                                     host_port_pair_.port()));
  EXPECT_EQ(0, QuicStreamFactoryPeer::GetNumberOfLossyConnections(
                   factory_.get(), host_port_pair_.port()));

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data);

  SequencedSocketData socket_data2(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data2);

  HostPortPair server2(kServer2HostName, kDefaultServerPort);

  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::CONFIRM_HANDSHAKE);
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule(host_port_pair_.host(),
                                           "192.168.0.1", "");
  host_resolver_.rules()->AddIPLiteralRule(server2.host(), "192.168.0.1", "");

  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(OK, request.Request(host_port_pair_, privacy_mode_,
                                /*cert_verify_flags=*/0, url_, "GET", net_log_,
                                callback_.callback()));

  QuicChromiumClientSession* session = GetActiveSession(host_port_pair_);

  std::unique_ptr<QuicHttpStream> stream = request.CreateStream();
  EXPECT_TRUE(stream.get());
  HttpRequestInfo request_info;
  EXPECT_EQ(OK, stream->InitializeStream(&request_info, DEFAULT_PRIORITY,
                                         net_log_, CompletionCallback()));

  DVLOG(1)
      << "Created 1st session and initialized a stream. Now trigger timeout";
  session->connection()->CloseConnection(QUIC_NETWORK_IDLE_TIMEOUT, "test",
                                         ConnectionCloseBehavior::SILENT_CLOSE);
  // Need to spin the loop now to ensure that
  // QuicStreamFactory::OnSessionClosed() runs.
  base::RunLoop run_loop;
  run_loop.RunUntilIdle();

  EXPECT_EQ(
      1, QuicStreamFactoryPeer::GetNumTimeoutsWithOpenStreams(factory_.get()));
  EXPECT_FALSE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(),
                                                     host_port_pair_.port()));

  // Test two-in-a-row timeouts with open streams.
  DVLOG(1) << "Create 2nd session and timeout with open stream";
  TestCompletionCallback callback2;
  QuicStreamRequest request2(factory_.get());
  EXPECT_EQ(OK, request2.Request(server2, privacy_mode_,
                                 /*cert_verify_flags=*/0, url2_, "GET",
                                 net_log_, callback2.callback()));
  QuicChromiumClientSession* session2 = GetActiveSession(server2);

  std::unique_ptr<QuicHttpStream> stream2 = request2.CreateStream();
  EXPECT_TRUE(stream2.get());
  EXPECT_EQ(OK, stream2->InitializeStream(&request_info, DEFAULT_PRIORITY,
                                          net_log_, CompletionCallback()));

  session2->connection()->CloseConnection(
      QUIC_NETWORK_IDLE_TIMEOUT, "test", ConnectionCloseBehavior::SILENT_CLOSE);
  // Need to spin the loop now to ensure that
  // QuicStreamFactory::OnSessionClosed() runs.
  base::RunLoop run_loop2;
  run_loop2.RunUntilIdle();
  EXPECT_EQ(
      2, QuicStreamFactoryPeer::GetNumTimeoutsWithOpenStreams(factory_.get()));
  EXPECT_TRUE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(),
                                                    host_port_pair_.port()));
  EXPECT_EQ(QuicChromiumClientSession::QUIC_DISABLED_TIMEOUT_WITH_OPEN_STREAMS,
            factory_->QuicDisabledReason(host_port_pair_.port()));

  // Verify that QUIC is un-disabled after a TCP job fails.
  factory_->OnTcpJobCompleted(/*succeeded=*/false);
  EXPECT_EQ(
      0, QuicStreamFactoryPeer::GetNumTimeoutsWithOpenStreams(factory_.get()));
  EXPECT_FALSE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(),
                                                     host_port_pair_.port()));

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data2.AllReadDataConsumed());
  EXPECT_TRUE(socket_data2.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, PublicResetPostHandshakeTwoOfThree) {
  disable_disk_cache_ = true;
  threshold_public_resets_post_handshake_ = 2;
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  EXPECT_FALSE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(),
                                                     host_port_pair_.port()));
  EXPECT_EQ(0, QuicStreamFactoryPeer::GetNumberOfLossyConnections(
                   factory_.get(), host_port_pair_.port()));

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data);

  SequencedSocketData socket_data2(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data2);

  SequencedSocketData socket_data3(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data3);

  HostPortPair server2(kServer2HostName, kDefaultServerPort);
  HostPortPair server3(kServer3HostName, kDefaultServerPort);

  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::CONFIRM_HANDSHAKE);
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule(host_port_pair_.host(),
                                           "192.168.0.1", "");
  host_resolver_.rules()->AddIPLiteralRule(server2.host(), "192.168.0.1", "");
  host_resolver_.rules()->AddIPLiteralRule(server3.host(), "192.168.0.1", "");

  // Test first and third out of three public reset post handshakes.
  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(OK, request.Request(host_port_pair_, privacy_mode_,
                                /*cert_verify_flags=*/0, url_, "GET", net_log_,
                                callback_.callback()));

  QuicChromiumClientSession* session = GetActiveSession(host_port_pair_);

  DVLOG(1) << "Created 1st session. Now trigger public reset post handshake";
  session->connection()->CloseConnection(QUIC_PUBLIC_RESET, "test",
                                         ConnectionCloseBehavior::SILENT_CLOSE);
  // Need to spin the loop now to ensure that
  // QuicStreamFactory::OnSessionClosed() runs.
  base::RunLoop run_loop;
  run_loop.RunUntilIdle();

  EXPECT_EQ(1, QuicStreamFactoryPeer::GetNumPublicResetsPostHandshake(
                   factory_.get()));
  EXPECT_FALSE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(),
                                                     host_port_pair_.port()));

  DVLOG(1) << "Create 2nd session without disable trigger";
  TestCompletionCallback callback2;
  QuicStreamRequest request2(factory_.get());
  EXPECT_EQ(OK, request2.Request(server2, privacy_mode_,
                                 /*cert_verify_flags=*/0, url2_, "GET",
                                 net_log_, callback2.callback()));
  QuicChromiumClientSession* session2 = GetActiveSession(server2);

  session2->connection()->CloseConnection(
      QUIC_NO_ERROR, "test", ConnectionCloseBehavior::SILENT_CLOSE);
  // Need to spin the loop now to ensure that
  // QuicStreamFactory::OnSessionClosed() runs.
  base::RunLoop run_loop2;
  run_loop2.RunUntilIdle();
  EXPECT_EQ(1, QuicStreamFactoryPeer::GetNumPublicResetsPostHandshake(
                   factory_.get()));
  EXPECT_FALSE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(),
                                                     host_port_pair_.port()));

  DVLOG(1) << "Create 3rd session with public reset post handshake,"
           << " will disable QUIC";
  TestCompletionCallback callback3;
  QuicStreamRequest request3(factory_.get());
  EXPECT_EQ(OK, request3.Request(server3, privacy_mode_,
                                 /*cert_verify_flags=*/0, url3_, "GET",
                                 net_log_, callback3.callback()));
  QuicChromiumClientSession* session3 = GetActiveSession(server3);

  session3->connection()->CloseConnection(
      QUIC_PUBLIC_RESET, "test", ConnectionCloseBehavior::SILENT_CLOSE);
  // Need to spin the loop now to ensure that
  // QuicStreamFactory::OnSessionClosed() runs.
  base::RunLoop run_loop3;
  run_loop3.RunUntilIdle();
  EXPECT_EQ(2, QuicStreamFactoryPeer::GetNumPublicResetsPostHandshake(
                   factory_.get()));
  EXPECT_TRUE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(),
                                                    host_port_pair_.port()));
  EXPECT_EQ(
      QuicChromiumClientSession::QUIC_DISABLED_PUBLIC_RESET_POST_HANDSHAKE,
      factory_->QuicDisabledReason(host_port_pair_.port()));

  std::unique_ptr<QuicHttpStream> stream = request.CreateStream();
  EXPECT_FALSE(stream.get());  // Session is already closed.
  std::unique_ptr<QuicHttpStream> stream2 = request2.CreateStream();
  EXPECT_FALSE(stream2.get());  // Session is already closed.
  std::unique_ptr<QuicHttpStream> stream3 = request3.CreateStream();
  EXPECT_FALSE(stream3.get());  // Session is already closed.

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data2.AllReadDataConsumed());
  EXPECT_TRUE(socket_data2.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data3.AllReadDataConsumed());
  EXPECT_TRUE(socket_data3.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, TimeoutsWithOpenStreamsTwoOfThree) {
  disable_disk_cache_ = true;
  threshold_public_resets_post_handshake_ = 2;
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  QuicStreamFactoryPeer::SetTaskRunner(factory_.get(), runner_.get());

  EXPECT_FALSE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(),
                                                     host_port_pair_.port()));
  EXPECT_EQ(0, QuicStreamFactoryPeer::GetNumberOfLossyConnections(
                   factory_.get(), host_port_pair_.port()));

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data);

  //  SequencedSocketData socket_data2(nullptr, 0, nullptr, 0);
  SequencedSocketData socket_data2(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data2);

  SequencedSocketData socket_data3(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data3);

  HostPortPair server2(kServer2HostName, kDefaultServerPort);
  HostPortPair server3(kServer3HostName, kDefaultServerPort);

  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::CONFIRM_HANDSHAKE);
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule(host_port_pair_.host(),
                                           "192.168.0.1", "");
  host_resolver_.rules()->AddIPLiteralRule(server2.host(), "192.168.0.1", "");
  host_resolver_.rules()->AddIPLiteralRule(server3.host(), "192.168.0.1", "");

  // Test first and third out of three timeouts with open streams.
  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(OK, request.Request(host_port_pair_, privacy_mode_,
                                /*cert_verify_flags=*/0, url_, "GET", net_log_,
                                callback_.callback()));

  QuicChromiumClientSession* session = GetActiveSession(host_port_pair_);

  std::unique_ptr<QuicHttpStream> stream = request.CreateStream();
  EXPECT_TRUE(stream.get());
  HttpRequestInfo request_info;
  EXPECT_EQ(OK, stream->InitializeStream(&request_info, DEFAULT_PRIORITY,
                                         net_log_, CompletionCallback()));

  DVLOG(1)
      << "Created 1st session and initialized a stream. Now trigger timeout";
  session->connection()->CloseConnection(QUIC_NETWORK_IDLE_TIMEOUT, "test",
                                         ConnectionCloseBehavior::SILENT_CLOSE);
  // Need to spin the loop now to ensure that
  // QuicStreamFactory::OnSessionClosed() runs.
  base::RunLoop run_loop;
  run_loop.RunUntilIdle();

  EXPECT_EQ(
      1, QuicStreamFactoryPeer::GetNumTimeoutsWithOpenStreams(factory_.get()));
  EXPECT_FALSE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(),
                                                     host_port_pair_.port()));

  // Test two-in-a-row timeouts with open streams.
  DVLOG(1) << "Create 2nd session without timeout";
  TestCompletionCallback callback2;
  QuicStreamRequest request2(factory_.get());
  EXPECT_EQ(OK, request2.Request(server2, privacy_mode_,
                                 /*cert_verify_flags=*/0, url2_, "GET",
                                 net_log_, callback2.callback()));
  QuicChromiumClientSession* session2 = GetActiveSession(server2);

  session2->connection()->CloseConnection(
      QUIC_NO_ERROR, "test", ConnectionCloseBehavior::SILENT_CLOSE);
  // Need to spin the loop now to ensure that
  // QuicStreamFactory::OnSessionClosed() runs.
  base::RunLoop run_loop2;
  run_loop2.RunUntilIdle();
  EXPECT_EQ(
      1, QuicStreamFactoryPeer::GetNumTimeoutsWithOpenStreams(factory_.get()));
  EXPECT_FALSE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(),
                                                     host_port_pair_.port()));

  DVLOG(1) << "Create 3rd session with timeout with open streams,"
           << " will disable QUIC";

  TestCompletionCallback callback3;
  QuicStreamRequest request3(factory_.get());
  EXPECT_EQ(OK, request3.Request(server3, privacy_mode_,
                                 /*cert_verify_flags=*/0, url3_, "GET",
                                 net_log_, callback3.callback()));
  QuicChromiumClientSession* session3 = GetActiveSession(server3);

  std::unique_ptr<QuicHttpStream> stream3 = request3.CreateStream();
  EXPECT_TRUE(stream3.get());
  EXPECT_EQ(OK, stream3->InitializeStream(&request_info, DEFAULT_PRIORITY,
                                          net_log_, CompletionCallback()));
  session3->connection()->CloseConnection(
      QUIC_NETWORK_IDLE_TIMEOUT, "test", ConnectionCloseBehavior::SILENT_CLOSE);
  // Need to spin the loop now to ensure that
  // QuicStreamFactory::OnSessionClosed() runs.
  base::RunLoop run_loop3;
  run_loop3.RunUntilIdle();
  EXPECT_EQ(
      2, QuicStreamFactoryPeer::GetNumTimeoutsWithOpenStreams(factory_.get()));
  EXPECT_TRUE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(),
                                                    host_port_pair_.port()));
  EXPECT_EQ(QuicChromiumClientSession::QUIC_DISABLED_TIMEOUT_WITH_OPEN_STREAMS,
            factory_->QuicDisabledReason(host_port_pair_.port()));

  std::unique_ptr<QuicHttpStream> stream2 = request2.CreateStream();
  EXPECT_FALSE(stream2.get());  // Session is already closed.

  // Verify that QUIC is un-disabled after a network change.
  factory_->OnIPAddressChanged();
  EXPECT_FALSE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(),
                                                     host_port_pair_.port()));
  EXPECT_EQ(
      0, QuicStreamFactoryPeer::GetNumTimeoutsWithOpenStreams(factory_.get()));

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data2.AllReadDataConsumed());
  EXPECT_TRUE(socket_data2.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data3.AllReadDataConsumed());
  EXPECT_TRUE(socket_data3.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, DisableQuicWhenTimeoutsWithOpenStreams) {
  disable_disk_cache_ = true;
  disable_quic_on_timeout_with_open_streams_ = true;
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  QuicStreamFactoryPeer::SetTaskRunner(factory_.get(), runner_.get());

  EXPECT_FALSE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(),
                                                     host_port_pair_.port()));
  EXPECT_EQ(0, QuicStreamFactoryPeer::GetNumberOfLossyConnections(
                   factory_.get(), host_port_pair_.port()));

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data);

  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::CONFIRM_HANDSHAKE);
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule(host_port_pair_.host(),
                                           "192.168.0.1", "");

  // Test first timeouts with open streams will disable QUIC.
  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(OK, request.Request(host_port_pair_, privacy_mode_,
                                /*cert_verify_flags=*/0, url_, "GET", net_log_,
                                callback_.callback()));

  QuicChromiumClientSession* session = GetActiveSession(host_port_pair_);

  std::unique_ptr<QuicHttpStream> stream = request.CreateStream();
  EXPECT_TRUE(stream.get());
  HttpRequestInfo request_info;
  EXPECT_EQ(OK, stream->InitializeStream(&request_info, DEFAULT_PRIORITY,
                                         net_log_, CompletionCallback()));

  DVLOG(1)
      << "Created 1st session and initialized a stream. Now trigger timeout."
      << "Will disable QUIC.";
  session->connection()->CloseConnection(QUIC_NETWORK_IDLE_TIMEOUT, "test",
                                         ConnectionCloseBehavior::SILENT_CLOSE);
  // Need to spin the loop now to ensure that
  // QuicStreamFactory::OnSessionClosed() runs.
  base::RunLoop run_loop;
  run_loop.RunUntilIdle();

  EXPECT_EQ(
      1, QuicStreamFactoryPeer::GetNumTimeoutsWithOpenStreams(factory_.get()));
  EXPECT_TRUE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(),
                                                    host_port_pair_.port()));

  EXPECT_EQ(QuicChromiumClientSession::QUIC_DISABLED_TIMEOUT_WITH_OPEN_STREAMS,
            factory_->QuicDisabledReason(host_port_pair_.port()));

  // Verify that QUIC is fully disabled after a TCP job succeeds.
  factory_->OnTcpJobCompleted(/*succeeded=*/true);
  EXPECT_TRUE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(),
                                                    host_port_pair_.port()));

  // Verify that QUIC stays disabled after a TCP job succeeds.
  factory_->OnTcpJobCompleted(/*succeeded=*/false);
  EXPECT_TRUE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(),
                                                    host_port_pair_.port()));

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, PublicResetPostHandshakeTwoOfFour) {
  disable_disk_cache_ = true;
  threshold_public_resets_post_handshake_ = 2;
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  QuicStreamFactoryPeer::SetTaskRunner(factory_.get(), runner_.get());

  EXPECT_FALSE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(),
                                                     host_port_pair_.port()));
  EXPECT_EQ(0, QuicStreamFactoryPeer::GetNumberOfLossyConnections(
                   factory_.get(), host_port_pair_.port()));

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data);

  SequencedSocketData socket_data2(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data2);

  SequencedSocketData socket_data3(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data3);

  SequencedSocketData socket_data4(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data4);

  HostPortPair server2(kServer2HostName, kDefaultServerPort);
  HostPortPair server3(kServer3HostName, kDefaultServerPort);
  HostPortPair server4(kServer4HostName, kDefaultServerPort);

  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::CONFIRM_HANDSHAKE);
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule(host_port_pair_.host(),
                                           "192.168.0.1", "");
  host_resolver_.rules()->AddIPLiteralRule(server2.host(), "192.168.0.1", "");
  host_resolver_.rules()->AddIPLiteralRule(server3.host(), "192.168.0.1", "");
  host_resolver_.rules()->AddIPLiteralRule(server4.host(), "192.168.0.1", "");

  // Test first and fourth out of four public reset post handshakes.
  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(OK, request.Request(host_port_pair_, privacy_mode_,
                                /*cert_verify_flags=*/0, url_, "GET", net_log_,
                                callback_.callback()));

  QuicChromiumClientSession* session = GetActiveSession(host_port_pair_);

  DVLOG(1) << "Created 1st session. Now trigger public reset post handshake";
  session->connection()->CloseConnection(QUIC_PUBLIC_RESET, "test",
                                         ConnectionCloseBehavior::SILENT_CLOSE);
  // Need to spin the loop now to ensure that
  // QuicStreamFactory::OnSessionClosed() runs.
  base::RunLoop run_loop;
  run_loop.RunUntilIdle();

  EXPECT_EQ(1, QuicStreamFactoryPeer::GetNumPublicResetsPostHandshake(
                   factory_.get()));
  EXPECT_FALSE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(),
                                                     host_port_pair_.port()));

  DVLOG(1) << "Create 2nd and 3rd sessions without disable trigger";
  TestCompletionCallback callback2;
  QuicStreamRequest request2(factory_.get());
  EXPECT_EQ(OK, request2.Request(server2, privacy_mode_,
                                 /*cert_verify_flags=*/0, url2_, "GET",
                                 net_log_, callback2.callback()));
  QuicChromiumClientSession* session2 = GetActiveSession(server2);

  session2->connection()->CloseConnection(
      QUIC_NO_ERROR, "test", ConnectionCloseBehavior::SILENT_CLOSE);
  // Need to spin the loop now to ensure that
  // QuicStreamFactory::OnSessionClosed() runs.
  base::RunLoop run_loop2;
  run_loop2.RunUntilIdle();
  EXPECT_EQ(1, QuicStreamFactoryPeer::GetNumPublicResetsPostHandshake(
                   factory_.get()));
  EXPECT_FALSE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(),
                                                     host_port_pair_.port()));

  TestCompletionCallback callback3;
  QuicStreamRequest request3(factory_.get());
  EXPECT_EQ(OK, request3.Request(server3, privacy_mode_,
                                 /*cert_verify_flags=*/0, url3_, "GET",
                                 net_log_, callback3.callback()));
  QuicChromiumClientSession* session3 = GetActiveSession(server3);

  session3->connection()->CloseConnection(
      QUIC_NO_ERROR, "test", ConnectionCloseBehavior::SILENT_CLOSE);
  // Need to spin the loop now to ensure that
  // QuicStreamFactory::OnSessionClosed() runs.
  base::RunLoop run_loop3;
  run_loop3.RunUntilIdle();
  EXPECT_EQ(1, QuicStreamFactoryPeer::GetNumPublicResetsPostHandshake(
                   factory_.get()));
  EXPECT_FALSE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(),
                                                     host_port_pair_.port()));

  DVLOG(1) << "Create 4rd session with public reset post handshake,"
           << " will not disable QUIC";
  TestCompletionCallback callback4;
  QuicStreamRequest request4(factory_.get());
  EXPECT_EQ(OK, request4.Request(server4, privacy_mode_,
                                 /*cert_verify_flags=*/0, url4_, "GET",
                                 net_log_, callback4.callback()));
  QuicChromiumClientSession* session4 = GetActiveSession(server4);

  session4->connection()->CloseConnection(
      QUIC_PUBLIC_RESET, "test", ConnectionCloseBehavior::SILENT_CLOSE);
  // Need to spin the loop now to ensure that
  // QuicStreamFactory::OnSessionClosed() runs.
  base::RunLoop run_loop4;
  run_loop4.RunUntilIdle();
  EXPECT_EQ(1, QuicStreamFactoryPeer::GetNumPublicResetsPostHandshake(
                   factory_.get()));
  EXPECT_FALSE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(),
                                                     host_port_pair_.port()));

  std::unique_ptr<QuicHttpStream> stream = request.CreateStream();
  EXPECT_FALSE(stream.get());  // Session is already closed.
  std::unique_ptr<QuicHttpStream> stream2 = request2.CreateStream();
  EXPECT_FALSE(stream2.get());  // Session is already closed.
  std::unique_ptr<QuicHttpStream> stream3 = request3.CreateStream();
  EXPECT_FALSE(stream3.get());  // Session is already closed.
  std::unique_ptr<QuicHttpStream> stream4 = request4.CreateStream();
  EXPECT_FALSE(stream4.get());  // Session is already closed.

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data2.AllReadDataConsumed());
  EXPECT_TRUE(socket_data2.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data3.AllReadDataConsumed());
  EXPECT_TRUE(socket_data3.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data4.AllReadDataConsumed());
  EXPECT_TRUE(socket_data4.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, TimeoutsWithOpenStreamsTwoOfFour) {
  disable_disk_cache_ = true;
  threshold_public_resets_post_handshake_ = 2;
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  QuicStreamFactoryPeer::SetTaskRunner(factory_.get(), runner_.get());

  EXPECT_FALSE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(),
                                                     host_port_pair_.port()));
  EXPECT_EQ(0, QuicStreamFactoryPeer::GetNumberOfLossyConnections(
                   factory_.get(), host_port_pair_.port()));

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data);

  //  SequencedSocketData socket_data2(nullptr, 0, nullptr, 0);
  SequencedSocketData socket_data2(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data2);

  SequencedSocketData socket_data3(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data3);

  SequencedSocketData socket_data4(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data4);

  HostPortPair server2(kServer2HostName, kDefaultServerPort);
  HostPortPair server3(kServer3HostName, kDefaultServerPort);
  HostPortPair server4(kServer4HostName, kDefaultServerPort);

  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::CONFIRM_HANDSHAKE);
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule(host_port_pair_.host(),
                                           "192.168.0.1", "");
  host_resolver_.rules()->AddIPLiteralRule(server2.host(), "192.168.0.1", "");
  host_resolver_.rules()->AddIPLiteralRule(server3.host(), "192.168.0.1", "");
  host_resolver_.rules()->AddIPLiteralRule(server4.host(), "192.168.0.1", "");

  // Test first and fourth out of three timeouts with open streams.
  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(OK, request.Request(host_port_pair_, privacy_mode_,
                                /*cert_verify_flags=*/0, url_, "GET", net_log_,
                                callback_.callback()));

  QuicChromiumClientSession* session = GetActiveSession(host_port_pair_);

  std::unique_ptr<QuicHttpStream> stream = request.CreateStream();
  EXPECT_TRUE(stream.get());
  HttpRequestInfo request_info;
  EXPECT_EQ(OK, stream->InitializeStream(&request_info, DEFAULT_PRIORITY,
                                         net_log_, CompletionCallback()));

  DVLOG(1)
      << "Created 1st session and initialized a stream. Now trigger timeout";
  session->connection()->CloseConnection(QUIC_NETWORK_IDLE_TIMEOUT, "test",
                                         ConnectionCloseBehavior::SILENT_CLOSE);
  // Need to spin the loop now to ensure that
  // QuicStreamFactory::OnSessionClosed() runs.
  base::RunLoop run_loop;
  run_loop.RunUntilIdle();

  EXPECT_EQ(
      1, QuicStreamFactoryPeer::GetNumTimeoutsWithOpenStreams(factory_.get()));
  EXPECT_FALSE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(),
                                                     host_port_pair_.port()));

  DVLOG(1) << "Create 2nd and 3rd sessions without timeout";
  TestCompletionCallback callback2;
  QuicStreamRequest request2(factory_.get());
  EXPECT_EQ(OK, request2.Request(server2, privacy_mode_,
                                 /*cert_verify_flags=*/0, url2_, "GET",
                                 net_log_, callback2.callback()));
  QuicChromiumClientSession* session2 = GetActiveSession(server2);

  session2->connection()->CloseConnection(
      QUIC_NO_ERROR, "test", ConnectionCloseBehavior::SILENT_CLOSE);
  // Need to spin the loop now to ensure that
  // QuicStreamFactory::OnSessionClosed() runs.
  base::RunLoop run_loop2;
  run_loop2.RunUntilIdle();
  EXPECT_EQ(
      1, QuicStreamFactoryPeer::GetNumTimeoutsWithOpenStreams(factory_.get()));
  EXPECT_FALSE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(),
                                                     host_port_pair_.port()));

  TestCompletionCallback callback3;
  QuicStreamRequest request3(factory_.get());
  EXPECT_EQ(OK, request3.Request(server3, privacy_mode_,
                                 /*cert_verify_flags=*/0, url3_, "GET",
                                 net_log_, callback3.callback()));
  QuicChromiumClientSession* session3 = GetActiveSession(server3);

  session3->connection()->CloseConnection(
      QUIC_NO_ERROR, "test", ConnectionCloseBehavior::SILENT_CLOSE);
  // Need to spin the loop now to ensure that
  // QuicStreamFactory::OnSessionClosed() runs.
  base::RunLoop run_loop3;
  run_loop3.RunUntilIdle();
  EXPECT_EQ(
      1, QuicStreamFactoryPeer::GetNumTimeoutsWithOpenStreams(factory_.get()));
  EXPECT_FALSE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(),
                                                     host_port_pair_.port()));

  DVLOG(1) << "Create 4th session with timeout with open streams,"
           << " will not disable QUIC";

  TestCompletionCallback callback4;
  QuicStreamRequest request4(factory_.get());
  EXPECT_EQ(OK, request4.Request(server4, privacy_mode_,
                                 /*cert_verify_flags=*/0, url4_, "GET",
                                 net_log_, callback4.callback()));
  QuicChromiumClientSession* session4 = GetActiveSession(server4);

  std::unique_ptr<QuicHttpStream> stream4 = request4.CreateStream();
  EXPECT_TRUE(stream4.get());
  EXPECT_EQ(OK, stream4->InitializeStream(&request_info, DEFAULT_PRIORITY,
                                          net_log_, CompletionCallback()));
  session4->connection()->CloseConnection(
      QUIC_NETWORK_IDLE_TIMEOUT, "test", ConnectionCloseBehavior::SILENT_CLOSE);
  // Need to spin the loop now to ensure that
  // QuicStreamFactory::OnSessionClosed() runs.
  base::RunLoop run_loop4;
  run_loop4.RunUntilIdle();
  EXPECT_EQ(
      1, QuicStreamFactoryPeer::GetNumTimeoutsWithOpenStreams(factory_.get()));
  EXPECT_FALSE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get(),
                                                     host_port_pair_.port()));

  std::unique_ptr<QuicHttpStream> stream2 = request2.CreateStream();
  EXPECT_FALSE(stream2.get());  // Session is already closed.
  std::unique_ptr<QuicHttpStream> stream3 = request3.CreateStream();
  EXPECT_FALSE(stream3.get());  // Session is already closed.

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data2.AllReadDataConsumed());
  EXPECT_TRUE(socket_data2.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data3.AllReadDataConsumed());
  EXPECT_TRUE(socket_data3.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data4.AllReadDataConsumed());
  EXPECT_TRUE(socket_data4.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, EnableDelayTcpRace) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  bool delay_tcp_race = QuicStreamFactoryPeer::GetDelayTcpRace(factory_.get());
  QuicStreamFactoryPeer::SetDelayTcpRace(factory_.get(), false);
  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data);

  ServerNetworkStats stats1;
  stats1.srtt = base::TimeDelta::FromMicroseconds(10);
  http_server_properties_.SetServerNetworkStats(url::SchemeHostPort(url_),
                                                stats1);

  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::COLD_START);
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule(host_port_pair_.host(),
                                           "192.168.0.1", "");

  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request.Request(host_port_pair_, privacy_mode_,
                            /*cert_verify_flags=*/0, url_, "POST", net_log_,
                            callback_.callback()));

  // If we don't delay TCP connection, then time delay should be 0.
  EXPECT_FALSE(factory_->delay_tcp_race());
  EXPECT_EQ(base::TimeDelta(), request.GetTimeDelayForWaitingJob());

  // Enable |delay_tcp_race_| param and verify delay is one RTT and that
  // server supports QUIC.
  QuicStreamFactoryPeer::SetDelayTcpRace(factory_.get(), true);
  EXPECT_TRUE(factory_->delay_tcp_race());
  EXPECT_EQ(base::TimeDelta::FromMicroseconds(15),
            request.GetTimeDelayForWaitingJob());

  // Confirm the handshake and verify that the stream is created.
  crypto_client_stream_factory_.last_stream()->SendOnCryptoHandshakeEvent(
      QuicSession::HANDSHAKE_CONFIRMED);

  EXPECT_THAT(callback_.WaitForResult(), IsOk());

  std::unique_ptr<QuicHttpStream> stream = request.CreateStream();
  EXPECT_TRUE(stream.get());
  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
  QuicStreamFactoryPeer::SetDelayTcpRace(factory_.get(), delay_tcp_race);
}

TEST_P(QuicStreamFactoryTest, MaybeInitialize) {
  idle_connection_timeout_seconds_ = 500;
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  const QuicConfig* config = QuicStreamFactoryPeer::GetConfig(factory_.get());
  EXPECT_EQ(500, config->IdleConnectionStateLifetime().ToSeconds());

  QuicStreamFactoryPeer::SetTaskRunner(factory_.get(), runner_.get());

  const AlternativeService alternative_service1(QUIC, host_port_pair_.host(),
                                                host_port_pair_.port());
  AlternativeServiceInfoVector alternative_service_info_vector;
  base::Time expiration = base::Time::Now() + base::TimeDelta::FromDays(1);
  alternative_service_info_vector.push_back(
      AlternativeServiceInfo(alternative_service1, expiration));
  http_server_properties_.SetAlternativeServices(
      url::SchemeHostPort(url_), alternative_service_info_vector);

  HostPortPair host_port_pair2(kServer2HostName, kDefaultServerPort);
  url::SchemeHostPort server2("https", kServer2HostName, kDefaultServerPort);
  const AlternativeService alternative_service2(QUIC, host_port_pair2.host(),
                                                host_port_pair2.port());
  AlternativeServiceInfoVector alternative_service_info_vector2;
  alternative_service_info_vector2.push_back(
      AlternativeServiceInfo(alternative_service2, expiration));
  http_server_properties_.SetAlternativeServices(
      server2, alternative_service_info_vector2);

  http_server_properties_.SetMaxServerConfigsStoredInProperties(
      kMaxQuicServersToPersist);

  QuicServerId quic_server_id(kDefaultServerHostName, 80,
                              PRIVACY_MODE_DISABLED);
  QuicServerInfoFactory* quic_server_info_factory =
      new PropertiesBasedQuicServerInfoFactory(&http_server_properties_);
  factory_->set_quic_server_info_factory(quic_server_info_factory);

  std::unique_ptr<QuicServerInfo> quic_server_info(
      quic_server_info_factory->GetForServer(quic_server_id));

  // Update quic_server_info's server_config and persist it.
  QuicServerInfo::State* state = quic_server_info->mutable_state();
  // Minimum SCFG that passes config validation checks.
  const char scfg[] = {// SCFG
                       0x53, 0x43, 0x46, 0x47,
                       // num entries
                       0x01, 0x00,
                       // padding
                       0x00, 0x00,
                       // EXPY
                       0x45, 0x58, 0x50, 0x59,
                       // EXPY end offset
                       0x08, 0x00, 0x00, 0x00,
                       // Value
                       '1', '2', '3', '4', '5', '6', '7', '8'};

  // Create temporary strings becasue Persist() clears string data in |state|.
  string server_config(reinterpret_cast<const char*>(&scfg), sizeof(scfg));
  string source_address_token("test_source_address_token");
  string cert_sct("test_cert_sct");
  string chlo_hash("test_chlo_hash");
  string signature("test_signature");
  string test_cert("test_cert");
  vector<string> certs;
  certs.push_back(test_cert);
  state->server_config = server_config;
  state->source_address_token = source_address_token;
  state->cert_sct = cert_sct;
  state->chlo_hash = chlo_hash;
  state->server_config_sig = signature;
  state->certs = certs;

  quic_server_info->Persist();

  QuicServerId quic_server_id2(kServer2HostName, 80, PRIVACY_MODE_DISABLED);
  std::unique_ptr<QuicServerInfo> quic_server_info2(
      quic_server_info_factory->GetForServer(quic_server_id2));

  // Update quic_server_info2's server_config and persist it.
  QuicServerInfo::State* state2 = quic_server_info2->mutable_state();

  // Minimum SCFG that passes config validation checks.
  const char scfg2[] = {// SCFG
                        0x53, 0x43, 0x46, 0x47,
                        // num entries
                        0x01, 0x00,
                        // padding
                        0x00, 0x00,
                        // EXPY
                        0x45, 0x58, 0x50, 0x59,
                        // EXPY end offset
                        0x08, 0x00, 0x00, 0x00,
                        // Value
                        '8', '7', '3', '4', '5', '6', '2', '1'};

  // Create temporary strings becasue Persist() clears string data in |state2|.
  string server_config2(reinterpret_cast<const char*>(&scfg2), sizeof(scfg2));
  string source_address_token2("test_source_address_token2");
  string cert_sct2("test_cert_sct2");
  string chlo_hash2("test_chlo_hash2");
  string signature2("test_signature2");
  string test_cert2("test_cert2");
  vector<string> certs2;
  certs2.push_back(test_cert2);
  state2->server_config = server_config2;
  state2->source_address_token = source_address_token2;
  state2->cert_sct = cert_sct2;
  state2->chlo_hash = chlo_hash2;
  state2->server_config_sig = signature2;
  state2->certs = certs2;

  quic_server_info2->Persist();

  QuicStreamFactoryPeer::MaybeInitialize(factory_.get());
  EXPECT_TRUE(QuicStreamFactoryPeer::HasInitializedData(factory_.get()));

  // Verify the MRU order is maintained.
  const QuicServerInfoMap& quic_server_info_map =
      http_server_properties_.quic_server_info_map();
  EXPECT_EQ(2u, quic_server_info_map.size());
  QuicServerInfoMap::const_iterator quic_server_info_map_it =
      quic_server_info_map.begin();
  EXPECT_EQ(quic_server_info_map_it->first, quic_server_id2);
  ++quic_server_info_map_it;
  EXPECT_EQ(quic_server_info_map_it->first, quic_server_id);

  EXPECT_TRUE(QuicStreamFactoryPeer::SupportsQuicAtStartUp(factory_.get(),
                                                           host_port_pair_));
  EXPECT_FALSE(QuicStreamFactoryPeer::CryptoConfigCacheIsEmpty(factory_.get(),
                                                               quic_server_id));
  QuicCryptoClientConfig* crypto_config =
      QuicStreamFactoryPeer::GetCryptoConfig(factory_.get());
  QuicCryptoClientConfig::CachedState* cached =
      crypto_config->LookupOrCreate(quic_server_id);
  EXPECT_FALSE(cached->server_config().empty());
  EXPECT_TRUE(cached->GetServerConfig());
  EXPECT_EQ(server_config, cached->server_config());
  EXPECT_EQ(source_address_token, cached->source_address_token());
  EXPECT_EQ(cert_sct, cached->cert_sct());
  EXPECT_EQ(chlo_hash, cached->chlo_hash());
  EXPECT_EQ(signature, cached->signature());
  ASSERT_EQ(1U, cached->certs().size());
  EXPECT_EQ(test_cert, cached->certs()[0]);

  EXPECT_TRUE(QuicStreamFactoryPeer::SupportsQuicAtStartUp(factory_.get(),
                                                           host_port_pair2));
  EXPECT_FALSE(QuicStreamFactoryPeer::CryptoConfigCacheIsEmpty(
      factory_.get(), quic_server_id2));
  QuicCryptoClientConfig::CachedState* cached2 =
      crypto_config->LookupOrCreate(quic_server_id2);
  EXPECT_FALSE(cached2->server_config().empty());
  EXPECT_TRUE(cached2->GetServerConfig());
  EXPECT_EQ(server_config2, cached2->server_config());
  EXPECT_EQ(source_address_token2, cached2->source_address_token());
  EXPECT_EQ(cert_sct2, cached2->cert_sct());
  EXPECT_EQ(chlo_hash2, cached2->chlo_hash());
  EXPECT_EQ(signature2, cached2->signature());
  ASSERT_EQ(1U, cached->certs().size());
  EXPECT_EQ(test_cert2, cached2->certs()[0]);
}

TEST_P(QuicStreamFactoryTest, StartCertVerifyJob) {
  Initialize();

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data);

  // Save current state of |race_cert_verification|.
  bool race_cert_verification =
      QuicStreamFactoryPeer::GetRaceCertVerification(factory_.get());

  // Load server config.
  HostPortPair host_port_pair(kDefaultServerHostName, kDefaultServerPort);
  QuicServerId quic_server_id(host_port_pair_, privacy_mode_);
  QuicStreamFactoryPeer::CacheDummyServerConfig(factory_.get(), quic_server_id);

  QuicStreamFactoryPeer::SetRaceCertVerification(factory_.get(), true);
  EXPECT_FALSE(HasActiveCertVerifierJob(quic_server_id));

  // Start CertVerifyJob.
  QuicAsyncStatus status = QuicStreamFactoryPeer::StartCertVerifyJob(
      factory_.get(), quic_server_id, /*cert_verify_flags=*/0, net_log_);
  if (status == QUIC_PENDING) {
    // Verify CertVerifierJob has started.
    EXPECT_TRUE(HasActiveCertVerifierJob(quic_server_id));

    while (HasActiveCertVerifierJob(quic_server_id)) {
      base::RunLoop().RunUntilIdle();
    }
  }
  // Verify CertVerifierJob has finished.
  EXPECT_FALSE(HasActiveCertVerifierJob(quic_server_id));

  // Start a QUIC request.
  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request.Request(host_port_pair_, privacy_mode_,
                            /*cert_verify_flags=*/0, url_, "GET", net_log_,
                            callback_.callback()));

  EXPECT_EQ(OK, callback_.WaitForResult());

  std::unique_ptr<QuicHttpStream> stream = request.CreateStream();
  EXPECT_TRUE(stream.get());

  // Restore |race_cert_verification|.
  QuicStreamFactoryPeer::SetRaceCertVerification(factory_.get(),
                                                 race_cert_verification);

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());

  // Verify there are no outstanding CertVerifierJobs after request has
  // finished.
  EXPECT_FALSE(HasActiveCertVerifierJob(quic_server_id));
}

TEST_P(QuicStreamFactoryTest, QuicDoingZeroRTT) {
  Initialize();

  factory_->set_require_confirmation(true);
  QuicServerId quic_server_id(host_port_pair_, PRIVACY_MODE_DISABLED);
  EXPECT_FALSE(factory_->ZeroRTTEnabledFor(quic_server_id));

  factory_->set_require_confirmation(false);
  EXPECT_FALSE(factory_->ZeroRTTEnabledFor(quic_server_id));

  // Load server config and verify QUIC will do 0RTT.
  QuicStreamFactoryPeer::CacheDummyServerConfig(factory_.get(), quic_server_id);
  EXPECT_TRUE(factory_->ZeroRTTEnabledFor(quic_server_id));
}

TEST_P(QuicStreamFactoryTest, YieldAfterPackets) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  QuicStreamFactoryPeer::SetYieldAfterPackets(factory_.get(), 0);

  std::unique_ptr<QuicEncryptedPacket> close_packet(
      ConstructClientConnectionClosePacket(0));
  vector<MockRead> reads;
  reads.push_back(
      MockRead(SYNCHRONOUS, close_packet->data(), close_packet->length(), 0));
  reads.push_back(MockRead(ASYNC, OK, 1));
  SequencedSocketData socket_data(&reads[0], reads.size(), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data);

  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::ZERO_RTT);
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule(host_port_pair_.host(),
                                           "192.168.0.1", "");

  // Set up the TaskObserver to verify QuicChromiumPacketReader::StartReading
  // posts a task.
  // TODO(rtenneti): Change SpdySessionTestTaskObserver to NetTestTaskObserver??
  SpdySessionTestTaskObserver observer("quic_chromium_packet_reader.cc",
                                       "StartReading");

  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(OK, request.Request(host_port_pair_, privacy_mode_,
                                /*cert_verify_flags=*/0, url_, "GET", net_log_,
                                callback_.callback()));

  // Call run_loop so that QuicChromiumPacketReader::OnReadComplete() gets
  // called.
  base::RunLoop run_loop;
  run_loop.RunUntilIdle();

  // Verify task that the observer's executed_count is 1, which indicates
  // QuicChromiumPacketReader::StartReading() has posted only one task and
  // yielded the read.
  EXPECT_EQ(1u, observer.executed_count());

  std::unique_ptr<QuicHttpStream> stream = request.CreateStream();
  EXPECT_FALSE(stream.get());  // Session is already closed.
  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, YieldAfterDuration) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  QuicStreamFactoryPeer::SetYieldAfterDuration(
      factory_.get(), QuicTime::Delta::FromMilliseconds(-1));

  std::unique_ptr<QuicEncryptedPacket> close_packet(
      ConstructClientConnectionClosePacket(0));
  vector<MockRead> reads;
  reads.push_back(
      MockRead(SYNCHRONOUS, close_packet->data(), close_packet->length(), 0));
  reads.push_back(MockRead(ASYNC, OK, 1));
  SequencedSocketData socket_data(&reads[0], reads.size(), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data);

  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::ZERO_RTT);
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule(host_port_pair_.host(),
                                           "192.168.0.1", "");

  // Set up the TaskObserver to verify QuicChromiumPacketReader::StartReading
  // posts a task.
  // TODO(rtenneti): Change SpdySessionTestTaskObserver to NetTestTaskObserver??
  SpdySessionTestTaskObserver observer("quic_chromium_packet_reader.cc",
                                       "StartReading");

  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(OK, request.Request(host_port_pair_, privacy_mode_,
                                /*cert_verify_flags=*/0, url_, "GET", net_log_,
                                callback_.callback()));

  // Call run_loop so that QuicChromiumPacketReader::OnReadComplete() gets
  // called.
  base::RunLoop run_loop;
  run_loop.RunUntilIdle();

  // Verify task that the observer's executed_count is 1, which indicates
  // QuicChromiumPacketReader::StartReading() has posted only one task and
  // yielded the read.
  EXPECT_EQ(1u, observer.executed_count());

  std::unique_ptr<QuicHttpStream> stream = request.CreateStream();
  EXPECT_FALSE(stream.get());  // Session is already closed.
  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, ServerPushSessionAffinity) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data);

  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request.Request(host_port_pair_, privacy_mode_,
                            /*cert_verify_flags=*/0, url_, "GET", net_log_,
                            callback_.callback()));

  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<QuicHttpStream> stream = request.CreateStream();
  EXPECT_TRUE(stream.get());

  EXPECT_EQ(0, QuicStreamFactoryPeer::GetNumPushStreamsCreated(factory_.get()));

  string url = "https://www.example.org/";

  QuicChromiumClientSession* session = GetActiveSession(host_port_pair_);

  QuicClientPromisedInfo promised(session, kServerDataStreamId1, kDefaultUrl);
  (*QuicStreamFactoryPeer::GetPushPromiseIndex(factory_.get())
        ->promised_by_url())[kDefaultUrl] = &promised;

  QuicStreamRequest request2(factory_.get());
  EXPECT_EQ(OK, request2.Request(host_port_pair_, privacy_mode_,
                                 /*cert_verify_flags=*/0, url_, "GET", net_log_,
                                 callback_.callback()));

  EXPECT_EQ(1, QuicStreamFactoryPeer::GetNumPushStreamsCreated(factory_.get()));
}

TEST_P(QuicStreamFactoryTest, ServerPushPrivacyModeMismatch) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};

  std::unique_ptr<QuicEncryptedPacket> client_rst(client_maker_.MakeRstPacket(
      1, true, kServerDataStreamId1, QUIC_STREAM_CANCELLED));
  MockWrite writes[] = {
      MockWrite(SYNCHRONOUS, client_rst->data(), client_rst->length(), 1),
  };

  SequencedSocketData socket_data1(reads, arraysize(reads), writes,
                                   arraysize(writes));
  SequencedSocketData socket_data2(reads, arraysize(reads), nullptr, 0);

  socket_factory_.AddSocketDataProvider(&socket_data1);
  socket_factory_.AddSocketDataProvider(&socket_data2);

  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request.Request(host_port_pair_, privacy_mode_,
                            /*cert_verify_flags=*/0, url_, "GET", net_log_,
                            callback_.callback()));

  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<QuicHttpStream> stream = request.CreateStream();
  EXPECT_TRUE(stream.get());

  EXPECT_EQ(0, QuicStreamFactoryPeer::GetNumPushStreamsCreated(factory_.get()));

  string url = "https://www.example.org/";
  QuicChromiumClientSession* session = GetActiveSession(host_port_pair_);

  QuicClientPromisedInfo promised(session, kServerDataStreamId1, kDefaultUrl);

  QuicClientPushPromiseIndex* index =
      QuicStreamFactoryPeer::GetPushPromiseIndex(factory_.get());

  (*index->promised_by_url())[kDefaultUrl] = &promised;
  EXPECT_EQ(index->GetPromised(kDefaultUrl), &promised);

  // Doing the request should not use the push stream, but rather
  // cancel it because the privacy modes do not match.
  QuicStreamRequest request2(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request2.Request(host_port_pair_, PRIVACY_MODE_ENABLED,
                             /*cert_verify_flags=*/0, url_, "GET", net_log_,
                             callback_.callback()));

  EXPECT_EQ(0, QuicStreamFactoryPeer::GetNumPushStreamsCreated(factory_.get()));
  EXPECT_EQ(index->GetPromised(kDefaultUrl), nullptr);

  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<QuicHttpStream> stream2 = request2.CreateStream();
  EXPECT_TRUE(stream2.get());

  EXPECT_TRUE(socket_data1.AllReadDataConsumed());
  EXPECT_TRUE(socket_data1.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data2.AllReadDataConsumed());
  EXPECT_TRUE(socket_data2.AllWriteDataConsumed());
}

// Pool to existing session with matching QuicServerId
// even if destination is different.
TEST_P(QuicStreamFactoryTest, PoolByOrigin) {
  Initialize();

  HostPortPair destination1("first.example.com", 443);
  HostPortPair destination2("second.example.com", 443);

  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data);

  QuicStreamRequest request1(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request1.Request(destination1, privacy_mode_,
                             /*cert_verify_flags=*/0, url_, "GET", net_log_,
                             callback_.callback()));
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<QuicHttpStream> stream1 = request1.CreateStream();
  EXPECT_TRUE(stream1.get());
  EXPECT_TRUE(HasActiveSession(host_port_pair_));

  // Second request returns synchronously because it pools to existing session.
  TestCompletionCallback callback2;
  QuicStreamRequest request2(factory_.get());
  EXPECT_EQ(OK, request2.Request(destination2, privacy_mode_,
                                 /*cert_verify_flags=*/0, url_, "GET", net_log_,
                                 callback2.callback()));
  std::unique_ptr<QuicHttpStream> stream2 = request2.CreateStream();
  EXPECT_TRUE(stream2.get());

  QuicChromiumClientSession* session1 =
      QuicHttpStreamPeer::GetSession(stream1.get());
  QuicChromiumClientSession* session2 =
      QuicHttpStreamPeer::GetSession(stream2.get());
  EXPECT_EQ(session1, session2);
  EXPECT_EQ(QuicServerId(host_port_pair_, privacy_mode_),
            session1->server_id());

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, ForceHolBlockingEnabled) {
  force_hol_blocking_ = true;
  Initialize();

  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data);

  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request.Request(host_port_pair_, privacy_mode_,
                            /*cert_verify_flags=*/0, url_, "GET", net_log_,
                            callback_.callback()));

  EXPECT_EQ(OK, callback_.WaitForResult());

  QuicChromiumClientSession* session = GetActiveSession(host_port_pair_);
  if (session->connection()->version() > QUIC_VERSION_35) {
    EXPECT_TRUE(session->force_hol_blocking());
  } else {
    EXPECT_FALSE(session->force_hol_blocking());
  }
}

class QuicStreamFactoryWithDestinationTest
    : public QuicStreamFactoryTestBase,
      public ::testing::TestWithParam<PoolingTestParams> {
 protected:
  QuicStreamFactoryWithDestinationTest()
      : QuicStreamFactoryTestBase(GetParam().version,
                                  GetParam().enable_connection_racing),
        destination_type_(GetParam().destination_type),
        hanging_read_(SYNCHRONOUS, ERR_IO_PENDING, 0) {}

  HostPortPair GetDestination() {
    switch (destination_type_) {
      case SAME_AS_FIRST:
        return origin1_;
      case SAME_AS_SECOND:
        return origin2_;
      case DIFFERENT:
        return HostPortPair(kDifferentHostname, 443);
      default:
        NOTREACHED();
        return HostPortPair();
    }
  }

  void AddHangingSocketData() {
    std::unique_ptr<SequencedSocketData> sequenced_socket_data(
        new SequencedSocketData(&hanging_read_, 1, nullptr, 0));
    socket_factory_.AddSocketDataProvider(sequenced_socket_data.get());
    sequenced_socket_data_vector_.push_back(std::move(sequenced_socket_data));
  }

  bool AllDataConsumed() {
    for (const auto& socket_data_ptr : sequenced_socket_data_vector_) {
      if (!socket_data_ptr->AllReadDataConsumed() ||
          !socket_data_ptr->AllWriteDataConsumed()) {
        return false;
      }
    }
    return true;
  }

  DestinationType destination_type_;
  HostPortPair origin1_;
  HostPortPair origin2_;
  MockRead hanging_read_;
  vector<std::unique_ptr<SequencedSocketData>> sequenced_socket_data_vector_;
};

INSTANTIATE_TEST_CASE_P(Version,
                        QuicStreamFactoryWithDestinationTest,
                        ::testing::ValuesIn(GetPoolingTestParams()));

// A single QUIC request fails because the certificate does not match the origin
// hostname, regardless of whether it matches the alternative service hostname.
TEST_P(QuicStreamFactoryWithDestinationTest, InvalidCertificate) {
  if (destination_type_ == DIFFERENT)
    return;

  Initialize();

  GURL url("https://mail.example.com/");
  origin1_ = HostPortPair::FromURL(url);

  // Not used for requests, but this provides a test case where the certificate
  // is valid for the hostname of the alternative service.
  origin2_ = HostPortPair("mail.example.org", 433);

  HostPortPair destination = GetDestination();

  scoped_refptr<X509Certificate> cert(
      ImportCertFromFile(GetTestCertsDirectory(), "wildcard.pem"));
  bool unused;
  ASSERT_FALSE(cert->VerifyNameMatch(origin1_.host(), &unused));
  ASSERT_TRUE(cert->VerifyNameMatch(origin2_.host(), &unused));

  ProofVerifyDetailsChromium verify_details;
  verify_details.cert_verify_result.verified_cert = cert;
  verify_details.cert_verify_result.is_issued_by_known_root = true;
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  AddHangingSocketData();

  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING, request.Request(destination, privacy_mode_,
                                            /*cert_verify_flags=*/0, url, "GET",
                                            net_log_, callback_.callback()));

  EXPECT_THAT(callback_.WaitForResult(), IsError(ERR_QUIC_HANDSHAKE_FAILED));

  EXPECT_TRUE(AllDataConsumed());
}

// QuicStreamRequest is pooled based on |destination| if certificate matches.
TEST_P(QuicStreamFactoryWithDestinationTest, SharedCertificate) {
  Initialize();

  GURL url1("https://www.example.org/");
  GURL url2("https://mail.example.org/");
  origin1_ = HostPortPair::FromURL(url1);
  origin2_ = HostPortPair::FromURL(url2);

  HostPortPair destination = GetDestination();

  scoped_refptr<X509Certificate> cert(
      ImportCertFromFile(GetTestCertsDirectory(), "wildcard.pem"));
  bool unused;
  ASSERT_TRUE(cert->VerifyNameMatch(origin1_.host(), &unused));
  ASSERT_TRUE(cert->VerifyNameMatch(origin2_.host(), &unused));
  ASSERT_FALSE(cert->VerifyNameMatch(kDifferentHostname, &unused));

  ProofVerifyDetailsChromium verify_details;
  verify_details.cert_verify_result.verified_cert = cert;
  verify_details.cert_verify_result.is_issued_by_known_root = true;
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  AddHangingSocketData();

  QuicStreamRequest request1(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request1.Request(destination, privacy_mode_,
                             /*cert_verify_flags=*/0, url1, "GET", net_log_,
                             callback_.callback()));
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<QuicHttpStream> stream1 = request1.CreateStream();
  EXPECT_TRUE(stream1.get());
  EXPECT_TRUE(HasActiveSession(origin1_));

  // Second request returns synchronously because it pools to existing session.
  TestCompletionCallback callback2;
  QuicStreamRequest request2(factory_.get());
  EXPECT_EQ(OK, request2.Request(destination, privacy_mode_,
                                 /*cert_verify_flags=*/0, url2, "GET", net_log_,
                                 callback2.callback()));
  std::unique_ptr<QuicHttpStream> stream2 = request2.CreateStream();
  EXPECT_TRUE(stream2.get());

  QuicChromiumClientSession* session1 =
      QuicHttpStreamPeer::GetSession(stream1.get());
  QuicChromiumClientSession* session2 =
      QuicHttpStreamPeer::GetSession(stream2.get());
  EXPECT_EQ(session1, session2);

  EXPECT_EQ(QuicServerId(origin1_, privacy_mode_), session1->server_id());

  EXPECT_TRUE(AllDataConsumed());
}

// QuicStreamRequest is not pooled if PrivacyMode differs.
TEST_P(QuicStreamFactoryWithDestinationTest, DifferentPrivacyMode) {
  Initialize();

  GURL url1("https://www.example.org/");
  GURL url2("https://mail.example.org/");
  origin1_ = HostPortPair::FromURL(url1);
  origin2_ = HostPortPair::FromURL(url2);

  HostPortPair destination = GetDestination();

  scoped_refptr<X509Certificate> cert(
      ImportCertFromFile(GetTestCertsDirectory(), "wildcard.pem"));
  bool unused;
  ASSERT_TRUE(cert->VerifyNameMatch(origin1_.host(), &unused));
  ASSERT_TRUE(cert->VerifyNameMatch(origin2_.host(), &unused));
  ASSERT_FALSE(cert->VerifyNameMatch(kDifferentHostname, &unused));

  ProofVerifyDetailsChromium verify_details1;
  verify_details1.cert_verify_result.verified_cert = cert;
  verify_details1.cert_verify_result.is_issued_by_known_root = true;
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details1);

  ProofVerifyDetailsChromium verify_details2;
  verify_details2.cert_verify_result.verified_cert = cert;
  verify_details2.cert_verify_result.is_issued_by_known_root = true;
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details2);

  AddHangingSocketData();
  AddHangingSocketData();

  QuicStreamRequest request1(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request1.Request(destination, PRIVACY_MODE_DISABLED,
                             /*cert_verify_flags=*/0, url1, "GET", net_log_,
                             callback_.callback()));
  EXPECT_EQ(OK, callback_.WaitForResult());
  std::unique_ptr<QuicHttpStream> stream1 = request1.CreateStream();
  EXPECT_TRUE(stream1.get());
  EXPECT_TRUE(HasActiveSession(origin1_));

  TestCompletionCallback callback2;
  QuicStreamRequest request2(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request2.Request(destination, PRIVACY_MODE_ENABLED,
                             /*cert_verify_flags=*/0, url2, "GET", net_log_,
                             callback2.callback()));
  EXPECT_EQ(OK, callback2.WaitForResult());
  std::unique_ptr<QuicHttpStream> stream2 = request2.CreateStream();
  EXPECT_TRUE(stream2.get());

  // |request2| does not pool to the first session, because PrivacyMode does not
  // match.  Instead, another session is opened to the same destination, but
  // with a different QuicServerId.
  QuicChromiumClientSession* session1 =
      QuicHttpStreamPeer::GetSession(stream1.get());
  QuicChromiumClientSession* session2 =
      QuicHttpStreamPeer::GetSession(stream2.get());
  EXPECT_NE(session1, session2);

  EXPECT_EQ(QuicServerId(origin1_, PRIVACY_MODE_DISABLED),
            session1->server_id());
  EXPECT_EQ(QuicServerId(origin2_, PRIVACY_MODE_ENABLED),
            session2->server_id());

  EXPECT_TRUE(AllDataConsumed());
}

// QuicStreamRequest is not pooled if certificate does not match its origin.
TEST_P(QuicStreamFactoryWithDestinationTest, DisjointCertificate) {
  Initialize();

  GURL url1("https://news.example.org/");
  GURL url2("https://mail.example.com/");
  origin1_ = HostPortPair::FromURL(url1);
  origin2_ = HostPortPair::FromURL(url2);

  HostPortPair destination = GetDestination();

  scoped_refptr<X509Certificate> cert1(
      ImportCertFromFile(GetTestCertsDirectory(), "wildcard.pem"));
  bool unused;
  ASSERT_TRUE(cert1->VerifyNameMatch(origin1_.host(), &unused));
  ASSERT_FALSE(cert1->VerifyNameMatch(origin2_.host(), &unused));
  ASSERT_FALSE(cert1->VerifyNameMatch(kDifferentHostname, &unused));

  ProofVerifyDetailsChromium verify_details1;
  verify_details1.cert_verify_result.verified_cert = cert1;
  verify_details1.cert_verify_result.is_issued_by_known_root = true;
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details1);

  scoped_refptr<X509Certificate> cert2(
      ImportCertFromFile(GetTestCertsDirectory(), "spdy_pooling.pem"));
  ASSERT_TRUE(cert2->VerifyNameMatch(origin2_.host(), &unused));
  ASSERT_FALSE(cert2->VerifyNameMatch(kDifferentHostname, &unused));

  ProofVerifyDetailsChromium verify_details2;
  verify_details2.cert_verify_result.verified_cert = cert2;
  verify_details2.cert_verify_result.is_issued_by_known_root = true;
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details2);

  AddHangingSocketData();
  AddHangingSocketData();

  QuicStreamRequest request1(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request1.Request(destination, privacy_mode_,
                             /*cert_verify_flags=*/0, url1, "GET", net_log_,
                             callback_.callback()));
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<QuicHttpStream> stream1 = request1.CreateStream();
  EXPECT_TRUE(stream1.get());
  EXPECT_TRUE(HasActiveSession(origin1_));

  TestCompletionCallback callback2;
  QuicStreamRequest request2(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request2.Request(destination, privacy_mode_,
                             /*cert_verify_flags=*/0, url2, "GET", net_log_,
                             callback2.callback()));
  EXPECT_THAT(callback2.WaitForResult(), IsOk());
  std::unique_ptr<QuicHttpStream> stream2 = request2.CreateStream();
  EXPECT_TRUE(stream2.get());

  // |request2| does not pool to the first session, because the certificate does
  // not match.  Instead, another session is opened to the same destination, but
  // with a different QuicServerId.
  QuicChromiumClientSession* session1 =
      QuicHttpStreamPeer::GetSession(stream1.get());
  QuicChromiumClientSession* session2 =
      QuicHttpStreamPeer::GetSession(stream2.get());
  EXPECT_NE(session1, session2);

  EXPECT_EQ(QuicServerId(origin1_, privacy_mode_), session1->server_id());
  EXPECT_EQ(QuicServerId(origin2_, privacy_mode_), session2->server_id());

  EXPECT_TRUE(AllDataConsumed());
}

// This test verifies that QuicStreamFactory::ClearCachedStatesInCryptoConfig
// correctly transform an origin filter to a ServerIdFilter. Whether the
// deletion itself works correctly is tested in QuicCryptoClientConfigTest.
TEST_P(QuicStreamFactoryTest, ClearCachedStatesInCryptoConfig) {
  Initialize();
  QuicCryptoClientConfig* crypto_config =
      QuicStreamFactoryPeer::GetCryptoConfig(factory_.get());

  struct TestCase {
    TestCase(const std::string& host,
             int port,
             PrivacyMode privacy_mode,
             QuicCryptoClientConfig* crypto_config)
        : server_id(host, port, privacy_mode),
          state(crypto_config->LookupOrCreate(server_id)) {
      vector<string> certs(1);
      certs[0] = "cert";
      state->SetProof(certs, "cert_sct", "chlo_hash", "signature");
      state->set_source_address_token("TOKEN");
      state->SetProofValid();

      EXPECT_FALSE(state->certs().empty());
    }

    QuicServerId server_id;
    QuicCryptoClientConfig::CachedState* state;
  } test_cases[] = {
      TestCase("www.google.com", 443, privacy_mode_, crypto_config),
      TestCase("www.example.com", 443, privacy_mode_, crypto_config),
      TestCase("www.example.com", 4433, privacy_mode_, crypto_config)};

  // Clear cached states for the origin https://www.example.com:4433.
  GURL origin("https://www.example.com:4433");
  factory_->ClearCachedStatesInCryptoConfig(
      base::Bind(&GURL::operator==, base::Unretained(&origin)));
  EXPECT_FALSE(test_cases[0].state->certs().empty());
  EXPECT_FALSE(test_cases[1].state->certs().empty());
  EXPECT_TRUE(test_cases[2].state->certs().empty());

  // Clear all cached states.
  factory_->ClearCachedStatesInCryptoConfig(
      base::Callback<bool(const GURL&)>());
  EXPECT_TRUE(test_cases[0].state->certs().empty());
  EXPECT_TRUE(test_cases[1].state->certs().empty());
  EXPECT_TRUE(test_cases[2].state->certs().empty());
}

}  // namespace test
}  // namespace net
