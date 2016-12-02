// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/chromium/quic_stream_factory.h"

#include <memory>
#include <ostream>
#include <utility>

#include "base/bind.h"
#include "base/callback.h"
#include "base/memory/ptr_util.h"
#include "base/run_loop.h"
#include "base/strings/string_util.h"
#include "base/threading/thread_task_runner_handle.h"
#include "net/base/test_proxy_delegate.h"
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
#include "net/quic/chromium/mock_network_change_notifier.h"
#include "net/quic/chromium/mock_quic_data.h"
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
#include "net/socket/next_proto.h"
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

std::vector<TestParams> GetTestParams() {
  std::vector<TestParams> params;
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

std::vector<PoolingTestParams> GetPoolingTestParams() {
  std::vector<PoolingTestParams> params;
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
        always_require_handshake_confirmation_(false),
        disable_connection_pooling_(false),
        load_server_info_timeout_srtt_multiplier_(0.0f),
        enable_connection_racing_(enable_connection_racing),
        enable_non_blocking_io_(true),
        disable_disk_cache_(false),
        prefer_aes_(false),
        receive_buffer_size_(0),
        delay_tcp_race_(true),
        close_sessions_on_ip_change_(false),
        disable_quic_on_timeout_with_open_streams_(false),
        idle_connection_timeout_seconds_(kIdleConnectionTimeoutSeconds),
        reduced_ping_timeout_seconds_(kPingTimeoutSecs),
        packet_reader_yield_after_duration_milliseconds_(
            kQuicYieldAfterDurationMilliseconds),
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
        &socket_factory_, &http_server_properties_, &test_proxy_delegate_,
        cert_verifier_.get(), &ct_policy_enforcer_, channel_id_service_.get(),
        &transport_security_state_, cert_transparency_verifier_.get(),
        /*SocketPerformanceWatcherFactory*/ nullptr,
        &crypto_client_stream_factory_, &random_generator_, clock_,
        kDefaultMaxPacketSize, string(), SupportedVersions(version_),
        always_require_handshake_confirmation_, disable_connection_pooling_,
        load_server_info_timeout_srtt_multiplier_, enable_connection_racing_,
        enable_non_blocking_io_, disable_disk_cache_, prefer_aes_,
        receive_buffer_size_, delay_tcp_race_,
        /*max_server_configs_stored_in_properties*/ 0,
        close_sessions_on_ip_change_,
        disable_quic_on_timeout_with_open_streams_,
        idle_connection_timeout_seconds_, reduced_ping_timeout_seconds_,
        packet_reader_yield_after_duration_milliseconds_,
        migrate_sessions_on_network_change_, migrate_sessions_early_,
        allow_server_migration_, force_hol_blocking_, race_cert_verification_,
        /*do_not_fragment*/ true, QuicTagVector(),
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

    MockQuicData socket_data;
    socket_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
    socket_data.AddSocketDataToFactory(&socket_factory_);

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
    return client_maker_.MakeRstPacket(1, true, stream_id,
                                       QUIC_RST_ACKNOWLEDGEMENT);
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

  // Helper method for server migration tests.
  void VerifyServerMigration(QuicConfig& config, IPEndPoint expected_address) {
    allow_server_migration_ = true;
    Initialize();

    ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
    crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
    crypto_client_stream_factory_.SetConfig(config);

    // Set up first socket data provider.
    MockQuicData socket_data1;
    socket_data1.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
    socket_data1.AddSocketDataToFactory(&socket_factory_);

    // Set up second socket data provider that is used after
    // migration.
    MockQuicData socket_data2;
    socket_data2.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
    socket_data2.AddWrite(
        client_maker_.MakePingPacket(1, /*include_version=*/true));
    socket_data2.AddWrite(client_maker_.MakeRstPacket(
        2, true, kClientDataStreamId1, QUIC_STREAM_CANCELLED));
    socket_data2.AddSocketDataToFactory(&socket_factory_);

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

    IPEndPoint actual_address;
    session->GetDefaultSocket()->GetPeerAddress(&actual_address);
    EXPECT_EQ(actual_address, expected_address);
    DVLOG(1) << "Socket connected to: " << actual_address.address().ToString()
             << " " << actual_address.port();
    DVLOG(1) << "Expected address: " << expected_address.address().ToString()
             << " " << expected_address.port();

    stream.reset();
    EXPECT_TRUE(socket_data1.AllReadDataConsumed());
    EXPECT_TRUE(socket_data2.AllReadDataConsumed());
    EXPECT_TRUE(socket_data2.AllWriteDataConsumed());
  }

  // Verifies that the QUIC stream factory is initialized correctly.
  // If |proxy_delegate_provides_quic_supported_proxy| is true, then
  // ProxyDelegate provides a proxy that supports QUIC at startup. Otherwise,
  // a non proxy server that support alternative services is added to the
  // HttpServerProperties map.
  void VerifyInitialization(bool proxy_delegate_provides_quic_supported_proxy) {
    idle_connection_timeout_seconds_ = 500;
    Initialize();
    ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
    crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
    const QuicConfig* config = QuicStreamFactoryPeer::GetConfig(factory_.get());
    EXPECT_EQ(500, config->IdleNetworkTimeout().ToSeconds());

    QuicStreamFactoryPeer::SetTaskRunner(factory_.get(), runner_.get());

    const AlternativeService alternative_service1(
        kProtoQUIC, host_port_pair_.host(), host_port_pair_.port());
    AlternativeServiceInfoVector alternative_service_info_vector;
    base::Time expiration = base::Time::Now() + base::TimeDelta::FromDays(1);
    alternative_service_info_vector.push_back(
        AlternativeServiceInfo(alternative_service1, expiration));
    http_server_properties_.SetAlternativeServices(
        url::SchemeHostPort(url_), alternative_service_info_vector);

    HostPortPair host_port_pair2(kServer2HostName, kDefaultServerPort);
    url::SchemeHostPort server2("https", kServer2HostName, kDefaultServerPort);
    const AlternativeService alternative_service2(
        kProtoQUIC, host_port_pair2.host(), host_port_pair2.port());
    AlternativeServiceInfoVector alternative_service_info_vector2;
    alternative_service_info_vector2.push_back(
        AlternativeServiceInfo(alternative_service2, expiration));
    if (!proxy_delegate_provides_quic_supported_proxy) {
      http_server_properties_.SetAlternativeServices(
          server2, alternative_service_info_vector2);
      // Verify that the properties of both QUIC servers are stored in the
      // HTTP properties map.
      EXPECT_EQ(2U, http_server_properties_.alternative_service_map().size());
    } else {
      test_proxy_delegate_.set_alternative_proxy_server(net::ProxyServer(
          net::ProxyServer::SCHEME_QUIC,
          net::HostPortPair(kServer2HostName, kDefaultServerPort)));
      // Verify that the properties of only the first QUIC server are stored in
      // the HTTP properties map.
      EXPECT_EQ(1U, http_server_properties_.alternative_service_map().size());
    }

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
    std::vector<string> certs;
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

    // Create temporary strings becasue Persist() clears string data in
    // |state2|.
    string server_config2(reinterpret_cast<const char*>(&scfg2), sizeof(scfg2));
    string source_address_token2("test_source_address_token2");
    string cert_sct2("test_cert_sct2");
    string chlo_hash2("test_chlo_hash2");
    string signature2("test_signature2");
    string test_cert2("test_cert2");
    std::vector<string> certs2;
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
    EXPECT_FALSE(QuicStreamFactoryPeer::CryptoConfigCacheIsEmpty(
        factory_.get(), quic_server_id));
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

  void RunTestLoopUntilIdle() {
    while (!runner_->GetPostedTasks().empty())
      runner_->RunNextTask();
  }

  // Helper methods for tests of connection migration on write error.
  void TestMigrationOnWriteErrorNonMigratableStream(IoMode write_error_mode);
  void TestMigrationOnWriteErrorMigrationDisabled(IoMode write_error_mode);
  void TestMigrationOnWriteError(IoMode write_error_mode);
  void TestMigrationOnWriteErrorNoNewNetwork(IoMode write_error_mode);
  void TestMigrationOnMultipleWriteErrors(IoMode first_write_error_mode,
                                          IoMode second_write_error_mode);
  void TestMigrationOnWriteErrorWithNotificationQueued(bool disconnected);
  void TestMigrationOnNotificationWithWriteErrorQueued(bool disconnected);
  void OnNetworkDisconnected(bool async_write_before);
  void OnNetworkMadeDefault(bool async_write_before);
  void TestMigrationOnWriteErrorPauseBeforeConnected(IoMode write_error_mode);
  void OnNetworkDisconnectedWithNetworkList(
      NetworkChangeNotifier::NetworkList network_list);
  void TestMigrationOnWriteErrorWithNetworkAddedBeforeNotification(
      IoMode write_error_mode,
      bool disconnected);

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
  TestProxyDelegate test_proxy_delegate_;
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
  NetLogWithSource net_log_;
  TestCompletionCallback callback_;

  // Variables to configure QuicStreamFactory.
  bool always_require_handshake_confirmation_;
  bool disable_connection_pooling_;
  double load_server_info_timeout_srtt_multiplier_;
  bool enable_connection_racing_;
  bool enable_non_blocking_io_;
  bool disable_disk_cache_;
  bool prefer_aes_;
  int receive_buffer_size_;
  bool delay_tcp_race_;
  bool close_sessions_on_ip_change_;
  bool disable_quic_on_timeout_with_open_streams_;
  int idle_connection_timeout_seconds_;
  int reduced_ping_timeout_seconds_;
  int packet_reader_yield_after_duration_milliseconds_;
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

  MockQuicData socket_data;
  socket_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data.AddSocketDataToFactory(&socket_factory_);

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

  MockQuicData socket_data;
  socket_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data.AddSocketDataToFactory(&socket_factory_);

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

  MockQuicData socket_data;
  socket_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data.AddSocketDataToFactory(&socket_factory_);

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

  MockQuicData socket_data;
  socket_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data.AddSocketDataToFactory(&socket_factory_);

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

  MockQuicData socket_data;
  socket_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data.AddSocketDataToFactory(&socket_factory_);

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

  MockQuicData socket_data;
  socket_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data.AddSocketDataToFactory(&socket_factory_);

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

TEST_P(QuicStreamFactoryTest, PoolingWithServerMigration) {
  // Set up session to migrate.
  host_resolver_.rules()->AddIPLiteralRule(host_port_pair_.host(),
                                           "192.168.0.1", "");
  IPEndPoint alt_address = IPEndPoint(IPAddress(1, 2, 3, 4), 443);
  QuicConfig config;
  config.SetAlternateServerAddressToSend(
      QuicSocketAddress(QuicSocketAddressImpl(alt_address)));

  VerifyServerMigration(config, alt_address);

  // Close server-migrated session.
  QuicChromiumClientSession* session = GetActiveSession(host_port_pair_);
  session->CloseSessionOnError(0u, QUIC_NO_ERROR);

  // Set up server IP, socket, proof, and config for new session.
  HostPortPair server2(kServer2HostName, kDefaultServerPort);
  host_resolver_.rules()->AddIPLiteralRule(server2.host(), "192.168.0.1", "");

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  SequencedSocketData socket_data(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data);

  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  QuicConfig config2;
  crypto_client_stream_factory_.SetConfig(config2);

  // Create new request to cause new session creation.
  TestCompletionCallback callback;
  QuicStreamRequest request2(factory_.get());
  EXPECT_EQ(ERR_IO_PENDING,
            request2.Request(server2, privacy_mode_,
                             /*cert_verify_flags=*/0, url2_, "GET", net_log_,
                             callback.callback()));
  EXPECT_EQ(OK, callback.WaitForResult());
  std::unique_ptr<QuicHttpStream> stream2 = request2.CreateStream();
  EXPECT_TRUE(stream2.get());

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
  // EXPECT_EQ(GetActiveSession(host_port_pair_), GetActiveSession(server2));
}

TEST_P(QuicStreamFactoryTest, NoPoolingIfDisabled) {
  disable_connection_pooling_ = true;
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data1;
  socket_data1.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data1.AddSocketDataToFactory(&socket_factory_);
  MockQuicData socket_data2;
  socket_data2.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data2.AddSocketDataToFactory(&socket_factory_);

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

  MockQuicData socket_data1;
  socket_data1.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data1.AddSocketDataToFactory(&socket_factory_);
  MockQuicData socket_data2;
  socket_data2.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data2.AddSocketDataToFactory(&socket_factory_);

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

  MockQuicData socket_data;
  socket_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data.AddSocketDataToFactory(&socket_factory_);

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

  MockQuicData socket_data1;
  socket_data1.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data1.AddSocketDataToFactory(&socket_factory_);
  MockQuicData socket_data2;
  socket_data2.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data2.AddSocketDataToFactory(&socket_factory_);

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
  MockQuicData socket_data;
  socket_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data.AddSocketDataToFactory(&socket_factory_);

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

  MockQuicData socket_data1;
  socket_data1.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data1.AddSocketDataToFactory(&socket_factory_);
  MockQuicData socket_data2;
  socket_data2.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data2.AddSocketDataToFactory(&socket_factory_);

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

  MockQuicData socket_data1;
  socket_data1.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data1.AddSocketDataToFactory(&socket_factory_);
  MockQuicData socket_data2;
  socket_data2.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data2.AddSocketDataToFactory(&socket_factory_);

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

  MockQuicData socket_data;
  socket_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data.AddSocketDataToFactory(&socket_factory_);
  MockQuicData socket_data2;
  socket_data2.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data2.AddSocketDataToFactory(&socket_factory_);

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
  MockQuicData socket_data;
  socket_data.AddWrite(
      client_maker_.MakeRstPacket(1, true, stream_id, QUIC_STREAM_CANCELLED));
  socket_data.AddRead(
      server_maker_.MakeRstPacket(1, false, stream_id, QUIC_STREAM_CANCELLED));
  socket_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data.AddSocketDataToFactory(&socket_factory_);

  HttpRequestInfo request_info;
  std::vector<std::unique_ptr<QuicHttpStream>> streams;
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
    streams.push_back(std::move(stream));
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
}

TEST_P(QuicStreamFactoryTest, ResolutionErrorInCreate) {
  Initialize();
  MockQuicData socket_data;
  socket_data.AddSocketDataToFactory(&socket_factory_);

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

  MockQuicData socket_data;
  socket_data.AddConnect(SYNCHRONOUS, ERR_ADDRESS_IN_USE);
  socket_data.AddSocketDataToFactory(&socket_factory_);

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
  MockQuicData socket_data;
  socket_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data.AddSocketDataToFactory(&socket_factory_);
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

TEST_P(QuicStreamFactoryTest, CloseAllSessions) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data;
  socket_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data.AddWrite(ConstructClientRstPacket());
  socket_data.AddSocketDataToFactory(&socket_factory_);

  MockQuicData socket_data2;
  socket_data2.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data2.AddSocketDataToFactory(&socket_factory_);

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

  MockQuicData socket_data;
  socket_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data.AddWrite(ConstructClientRstPacket());
  socket_data.AddSocketDataToFactory(&socket_factory_);

  MockQuicData socket_data2;
  socket_data2.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data2.AddSocketDataToFactory(&socket_factory_);

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

TEST_P(QuicStreamFactoryTest, OnNetworkMadeDefaultWithSynchronousWriteBefore) {
  OnNetworkMadeDefault(/*async_write_before=*/false);
}

TEST_P(QuicStreamFactoryTest, OnNetworkMadeDefaultWithAsyncWriteBefore) {
  OnNetworkMadeDefault(/*async_write_before=*/true);
}

void QuicStreamFactoryTestBase::OnNetworkMadeDefault(bool async_write_before) {
  InitializeConnectionMigrationTest(
      {kDefaultNetworkForTests, kNewNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  int packet_number = 1;
  MockQuicData socket_data;
  socket_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data.AddWrite(ConstructGetRequestPacket(
      packet_number++, kClientDataStreamId1, true, true));
  if (async_write_before) {
    socket_data.AddWrite(ASYNC, OK);
    packet_number++;
  }
  socket_data.AddSocketDataToFactory(&socket_factory_);

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

  // Do an async write to leave writer blocked.
  if (async_write_before)
    session->connection()->SendPing();

  // Set up second socket data provider that is used after migration.
  // The response to the earlier request is read on this new socket.
  MockQuicData socket_data1;
  socket_data1.AddWrite(
      client_maker_.MakePingPacket(packet_number++, /*include_version=*/true));
  socket_data1.AddRead(
      ConstructOkResponsePacket(1, kClientDataStreamId1, false, false));
  socket_data1.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data1.AddWrite(client_maker_.MakeAckAndRstPacket(
      packet_number++, false, kClientDataStreamId1, QUIC_STREAM_CANCELLED, 1, 1,
      1, true));
  socket_data1.AddSocketDataToFactory(&socket_factory_);

  // Trigger connection migration. This should cause a PING frame
  // to be emitted.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkMadeDefault(kNewNetworkForTests);

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
  MockQuicData socket_data2;
  socket_data2.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data2.AddSocketDataToFactory(&socket_factory_);

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

TEST_P(QuicStreamFactoryTest, OnNetworkDisconnectedWithSynchronousWriteBefore) {
  OnNetworkDisconnected(/*async_write_before=*/false);
}

TEST_P(QuicStreamFactoryTest, OnNetworkDisconnectedWithAsyncWriteBefore) {
  OnNetworkDisconnected(/*async_write_before=*/true);
}

void QuicStreamFactoryTestBase::OnNetworkDisconnected(bool async_write_before) {
  InitializeConnectionMigrationTest(
      {kDefaultNetworkForTests, kNewNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  int packet_number = 1;
  MockQuicData socket_data;
  socket_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data.AddWrite(ConstructGetRequestPacket(
      packet_number++, kClientDataStreamId1, true, true));
  if (async_write_before) {
    socket_data.AddWrite(ASYNC, OK);
    packet_number++;
  }
  socket_data.AddSocketDataToFactory(&socket_factory_);

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

  // Do an async write to leave writer blocked.
  if (async_write_before)
    session->connection()->SendPing();

  // Set up second socket data provider that is used after migration.
  // The response to the earlier request is read on this new socket.
  MockQuicData socket_data1;
  socket_data1.AddWrite(
      client_maker_.MakePingPacket(packet_number++, /*include_version=*/true));
  socket_data1.AddRead(
      ConstructOkResponsePacket(1, kClientDataStreamId1, false, false));
  socket_data1.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data1.AddWrite(client_maker_.MakeAckAndRstPacket(
      packet_number++, false, kClientDataStreamId1, QUIC_STREAM_CANCELLED, 1, 1,
      1, true));
  socket_data1.AddSocketDataToFactory(&socket_factory_);

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
  MockQuicData socket_data2;
  socket_data2.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data2.AddSocketDataToFactory(&socket_factory_);

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

TEST_P(QuicStreamFactoryTest, OnNetworkDisconnectedNoNetworks) {
  NetworkChangeNotifier::NetworkList no_networks(0);
  OnNetworkDisconnectedWithNetworkList(no_networks);
}

TEST_P(QuicStreamFactoryTest, OnNetworkDisconnectedNoNewNetwork) {
  OnNetworkDisconnectedWithNetworkList({kDefaultNetworkForTests});
}

void QuicStreamFactoryTestBase::OnNetworkDisconnectedWithNetworkList(
    NetworkChangeNotifier::NetworkList network_list) {
  InitializeConnectionMigrationTest(network_list);
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  // Use the test task runner, to force the migration alarm timeout later.
  QuicStreamFactoryPeer::SetTaskRunner(factory_.get(), runner_.get());

  MockQuicData socket_data;
  socket_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data.AddSocketDataToFactory(&socket_factory_);

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
  // to migrate to, this should cause the session to wait for a new network.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkDisconnected(kDefaultNetworkForTests);

  // The migration will not fail until the migration alarm timeout.
  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_FALSE(HasActiveSession(host_port_pair_));
  EXPECT_EQ(1u, session->GetNumActiveStreams());
  EXPECT_EQ(ERR_IO_PENDING, stream->ReadResponseHeaders(callback_.callback()));
  EXPECT_EQ(true, session->connection()->writer()->IsWriteBlocked());

  // Force the migration alarm timeout to run.
  RunTestLoopUntilIdle();

  // The connection should now be closed. A request for response
  // headers should fail.
  EXPECT_FALSE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_FALSE(HasActiveSession(host_port_pair_));
  EXPECT_EQ(ERR_NETWORK_CHANGED, callback_.WaitForResult());

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, OnNetworkMadeDefaultNonMigratableStream) {
  InitializeConnectionMigrationTest(
      {kDefaultNetworkForTests, kNewNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data;
  socket_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data.AddWrite(client_maker_.MakeRstPacket(
      1, true, kClientDataStreamId1, QUIC_STREAM_CANCELLED));
  socket_data.AddSocketDataToFactory(&socket_factory_);

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
      ->NotifyNetworkMadeDefault(kNewNetworkForTests);

  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_FALSE(HasActiveSession(host_port_pair_));
  EXPECT_EQ(1u, session->GetNumActiveStreams());

  stream.reset();

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, OnNetworkMadeDefaultConnectionMigrationDisabled) {
  InitializeConnectionMigrationTest(
      {kDefaultNetworkForTests, kNewNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data;
  socket_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data.AddWrite(client_maker_.MakeRstPacket(
      1, true, kClientDataStreamId1, QUIC_STREAM_CANCELLED));
  socket_data.AddSocketDataToFactory(&socket_factory_);

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
      ->NotifyNetworkMadeDefault(kNewNetworkForTests);

  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_FALSE(HasActiveSession(host_port_pair_));
  EXPECT_EQ(1u, session->GetNumActiveStreams());

  stream.reset();

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, OnNetworkDisconnectedNonMigratableStream) {
  InitializeConnectionMigrationTest(
      {kDefaultNetworkForTests, kNewNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data;
  socket_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data.AddWrite(client_maker_.MakeRstPacket(
      1, true, kClientDataStreamId1, QUIC_RST_ACKNOWLEDGEMENT));
  socket_data.AddSocketDataToFactory(&socket_factory_);

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
       OnNetworkDisconnectedConnectionMigrationDisabled) {
  InitializeConnectionMigrationTest(
      {kDefaultNetworkForTests, kNewNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data;
  socket_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data.AddWrite(client_maker_.MakeRstPacket(
      1, true, kClientDataStreamId1, QUIC_RST_ACKNOWLEDGEMENT));
  socket_data.AddSocketDataToFactory(&socket_factory_);

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

TEST_P(QuicStreamFactoryTest, OnNetworkMadeDefaultNoOpenStreams) {
  InitializeConnectionMigrationTest(
      {kDefaultNetworkForTests, kNewNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data;
  socket_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data.AddSocketDataToFactory(&socket_factory_);

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
      ->NotifyNetworkMadeDefault(kNewNetworkForTests);

  EXPECT_FALSE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_FALSE(HasActiveSession(host_port_pair_));

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, OnNetworkDisconnectedNoOpenStreams) {
  InitializeConnectionMigrationTest(
      {kDefaultNetworkForTests, kNewNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data;
  socket_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data.AddSocketDataToFactory(&socket_factory_);

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

TEST_P(QuicStreamFactoryTest, OnNetworkChangeDisconnectedPauseBeforeConnected) {
  InitializeConnectionMigrationTest({kDefaultNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data;
  socket_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data.AddWrite(
      ConstructGetRequestPacket(1, kClientDataStreamId1, true, true));
  socket_data.AddSocketDataToFactory(&socket_factory_);

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

  // Trigger connection migration. Since there are no networks
  // to migrate to, this should cause the session to wait for a new network.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkDisconnected(kDefaultNetworkForTests);

  // The connection should still be alive, but marked as going away.
  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_FALSE(HasActiveSession(host_port_pair_));
  EXPECT_EQ(1u, session->GetNumActiveStreams());
  EXPECT_EQ(ERR_IO_PENDING, stream->ReadResponseHeaders(callback_.callback()));

  // Set up second socket data provider that is used after migration.
  // The response to the earlier request is read on this new socket.
  MockQuicData socket_data1;
  socket_data1.AddWrite(
      client_maker_.MakePingPacket(2, /*include_version=*/true));
  socket_data1.AddRead(
      ConstructOkResponsePacket(1, kClientDataStreamId1, false, false));
  socket_data1.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data1.AddWrite(client_maker_.MakeAckAndRstPacket(
      3, false, kClientDataStreamId1, QUIC_STREAM_CANCELLED, 1, 1, 1, true));
  socket_data1.AddSocketDataToFactory(&socket_factory_);

  // Add a new network and notify the stream factory of a new connected network.
  // This causes a PING packet to be sent over the new network.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->SetConnectedNetworksList({kNewNetworkForTests});
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkConnected(kNewNetworkForTests);

  // Ensure that the session is still alive.
  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_FALSE(HasActiveSession(host_port_pair_));
  EXPECT_EQ(1u, session->GetNumActiveStreams());

  // Run the message loop so that data queued in the new socket is read by the
  // packet reader.
  base::RunLoop().RunUntilIdle();

  // Response headers are received over the new network.
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  EXPECT_EQ(200, response.headers->response_code());

  // Create a new request and verify that a new session is created.
  MockQuicData socket_data2;
  socket_data2.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data2.AddSocketDataToFactory(&socket_factory_);
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
  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));

  stream.reset();
  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data1.AllReadDataConsumed());
  EXPECT_TRUE(socket_data1.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data2.AllReadDataConsumed());
  EXPECT_TRUE(socket_data2.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest,
       OnNetworkChangeDisconnectedPauseBeforeConnectedMultipleSessions) {
  InitializeConnectionMigrationTest({kDefaultNetworkForTests});

  MockQuicData socket_data1;
  socket_data1.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data1.AddWrite(ASYNC, OK);
  socket_data1.AddSocketDataToFactory(&socket_factory_);
  MockQuicData socket_data2;
  socket_data2.AddRead(SYNCHRONOUS, ERR_IO_PENDING);

  socket_data2.AddWrite(ASYNC, OK);
  socket_data2.AddSocketDataToFactory(&socket_factory_);

  HostPortPair server1(kDefaultServerHostName, 443);
  HostPortPair server2(kServer2HostName, 443);

  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule(server1.host(), "192.168.0.1", "");
  host_resolver_.rules()->AddIPLiteralRule(server2.host(), "192.168.0.2", "");

  // Create request and QuicHttpStream to create session1.
  QuicStreamRequest request1(factory_.get());
  EXPECT_EQ(OK, request1.Request(server1, privacy_mode_,
                                 /*cert_verify_flags=*/0, url_, "GET", net_log_,
                                 callback_.callback()));
  std::unique_ptr<QuicHttpStream> stream1 = request1.CreateStream();
  EXPECT_TRUE(stream1.get());

  // Create request and QuicHttpStream to create session2.
  QuicStreamRequest request2(factory_.get());
  EXPECT_EQ(OK, request2.Request(server2, privacy_mode_,
                                 /*cert_verify_flags=*/0, url2_, "GET",
                                 net_log_, callback_.callback()));
  std::unique_ptr<QuicHttpStream> stream2 = request2.CreateStream();
  EXPECT_TRUE(stream2.get());

  QuicChromiumClientSession* session1 = GetActiveSession(server1);
  QuicChromiumClientSession* session2 = GetActiveSession(server2);
  EXPECT_NE(session1, session2);

  // Cause QUIC stream to be created and send GET so session1 has an open
  // stream.
  HttpRequestInfo request_info1;
  request_info1.method = "GET";
  request_info1.url = url_;
  EXPECT_EQ(OK, stream1->InitializeStream(&request_info1, DEFAULT_PRIORITY,
                                          net_log_, CompletionCallback()));
  HttpResponseInfo response1;
  HttpRequestHeaders request_headers1;
  EXPECT_EQ(OK, stream1->SendRequest(request_headers1, &response1,
                                     callback_.callback()));

  // Cause QUIC stream to be created and send GET so session2 has an open
  // stream.
  HttpRequestInfo request_info2;
  request_info2.method = "GET";
  request_info2.url = url_;
  EXPECT_EQ(OK, stream2->InitializeStream(&request_info2, DEFAULT_PRIORITY,
                                          net_log_, CompletionCallback()));
  HttpResponseInfo response2;
  HttpRequestHeaders request_headers2;
  EXPECT_EQ(OK, stream2->SendRequest(request_headers2, &response2,
                                     callback_.callback()));

  // Cause both sessions to be paused due to DISCONNECTED.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkDisconnected(kDefaultNetworkForTests);

  // Ensure that both sessions are paused but alive.
  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session1));
  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session2));

  // Add new sockets to use post migration.
  MockConnect connect_result =
      MockConnect(SYNCHRONOUS, ERR_INTERNET_DISCONNECTED);
  SequencedSocketData socket_data3(connect_result, nullptr, 0, nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data3);
  SequencedSocketData socket_data4(connect_result, nullptr, 0, nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data4);

  // Add a new network and cause migration to bad sockets, causing sessions to
  // close.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->SetConnectedNetworksList({kNewNetworkForTests});
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkConnected(kNewNetworkForTests);

  EXPECT_FALSE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session1));
  EXPECT_FALSE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session2));

  EXPECT_TRUE(socket_data1.AllReadDataConsumed());
  EXPECT_TRUE(socket_data1.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data2.AllReadDataConsumed());
  EXPECT_TRUE(socket_data2.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, MigrateSessionEarly) {
  InitializeConnectionMigrationTest(
      {kDefaultNetworkForTests, kNewNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data;
  socket_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data.AddWrite(
      ConstructGetRequestPacket(1, kClientDataStreamId1, true, true));
  socket_data.AddSocketDataToFactory(&socket_factory_);

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

  MockQuicData socket_data1;
  socket_data1.AddWrite(
      client_maker_.MakePingPacket(2, /*include_version=*/true));
  socket_data1.AddRead(
      ConstructOkResponsePacket(1, kClientDataStreamId1, false, false));
  socket_data1.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data1.AddWrite(client_maker_.MakeAckAndRstPacket(
      3, false, kClientDataStreamId1, QUIC_STREAM_CANCELLED, 1, 1, 1, true));
  socket_data1.AddSocketDataToFactory(&socket_factory_);

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
  MockQuicData socket_data2;
  socket_data2.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data2.AddSocketDataToFactory(&socket_factory_);

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

  // On a NETWORK_MADE_DEFAULT notification, nothing happens to the
  // migrated session, but the new session is closed since it has no
  // open streams.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkMadeDefault(kNewNetworkForTests);
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

  MockQuicData socket_data;
  socket_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data.AddWrite(
      ConstructGetRequestPacket(1, kClientDataStreamId1, true, true));
  socket_data.AddSocketDataToFactory(&socket_factory_);

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
  MockQuicData socket_data1;
  socket_data1.AddWrite(
      client_maker_.MakePingPacket(2, /*include_version=*/true));
  socket_data1.AddRead(
      ConstructOkResponsePacket(1, kClientDataStreamId1, false, false));
  socket_data1.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data1.AddWrite(client_maker_.MakeAckAndRstPacket(
      3, false, kClientDataStreamId1, QUIC_STREAM_CANCELLED, 1, 1, 1, true));
  socket_data1.AddSocketDataToFactory(&socket_factory_);

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
  MockQuicData socket_data2;
  socket_data2.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data2.AddSocketDataToFactory(&socket_factory_);

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

  // On a NETWORK_MADE_DEFAULT notification, nothing happens to the
  // migrated session, but the new session is closed since it has no
  // open streams.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkMadeDefault(kNewNetworkForTests);
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

  MockQuicData socket_data;
  socket_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data.AddWrite(client_maker_.MakeRstPacket(
      1, true, kClientDataStreamId1, QUIC_STREAM_CANCELLED));
  socket_data.AddSocketDataToFactory(&socket_factory_);

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

  MockQuicData socket_data;
  socket_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data.AddWrite(client_maker_.MakeRstPacket(
      1, true, kClientDataStreamId1, QUIC_STREAM_CANCELLED));
  socket_data.AddSocketDataToFactory(&socket_factory_);

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

  MockQuicData socket_data;
  socket_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data.AddWrite(client_maker_.MakeRstPacket(
      1, true, kClientDataStreamId1, QUIC_STREAM_CANCELLED));
  socket_data.AddSocketDataToFactory(&socket_factory_);

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

void QuicStreamFactoryTestBase::TestMigrationOnWriteError(
    IoMode write_error_mode) {
  InitializeConnectionMigrationTest(
      {kDefaultNetworkForTests, kNewNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data;
  socket_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data.AddWrite(write_error_mode, ERR_ADDRESS_UNREACHABLE);
  socket_data.AddSocketDataToFactory(&socket_factory_);

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
  MockQuicData socket_data1;
  socket_data1.AddWrite(
      ConstructGetRequestPacket(1, kClientDataStreamId1, true, true));
  socket_data1.AddRead(
      ConstructOkResponsePacket(1, kClientDataStreamId1, false, false));
  socket_data1.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data1.AddWrite(client_maker_.MakeAckAndRstPacket(
      2, false, kClientDataStreamId1, QUIC_STREAM_CANCELLED, 1, 1, 1, true));
  socket_data1.AddSocketDataToFactory(&socket_factory_);

  // Send GET request on stream. This should cause a write error, which triggers
  // a connection migration attempt.
  HttpResponseInfo response;
  HttpRequestHeaders request_headers;
  EXPECT_EQ(OK, stream->SendRequest(request_headers, &response,
                                    callback_.callback()));

  // Run the message loop so that the migration attempt is executed and
  // data queued in the new socket is read by the packet reader.
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

TEST_P(QuicStreamFactoryTest, MigrateSessionOnWriteErrorSynchronous) {
  TestMigrationOnWriteError(SYNCHRONOUS);
}

TEST_P(QuicStreamFactoryTest, MigrateSessionOnWriteErrorAsync) {
  TestMigrationOnWriteError(ASYNC);
}

void QuicStreamFactoryTestBase::TestMigrationOnWriteErrorNoNewNetwork(
    IoMode write_error_mode) {
  InitializeConnectionMigrationTest({kDefaultNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  // Use the test task runner, to force the migration alarm timeout later.
  QuicStreamFactoryPeer::SetTaskRunner(factory_.get(), runner_.get());

  MockQuicData socket_data;
  socket_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data.AddWrite(write_error_mode, ERR_ADDRESS_UNREACHABLE);
  socket_data.AddSocketDataToFactory(&socket_factory_);

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

  // Send GET request on stream. This causes a write error, which triggers
  // a connection migration attempt. Since there are no networks
  // to migrate to, this causes the session to wait for a new network.
  HttpResponseInfo response;
  HttpRequestHeaders request_headers;
  EXPECT_EQ(OK, stream->SendRequest(request_headers, &response,
                                    callback_.callback()));

  // Complete any pending writes. Pending async MockQuicData writes
  // are run on the message loop, not on the test runner.
  base::RunLoop().RunUntilIdle();

  // Write error causes migration task to be posted. Spin the loop.
  if (write_error_mode == ASYNC)
    runner_->RunNextTask();

  // Migration has not yet failed. The session should be alive and active.
  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(host_port_pair_));
  EXPECT_EQ(1u, session->GetNumActiveStreams());
  EXPECT_TRUE(session->connection()->writer()->IsWriteBlocked());

  // The migration will not fail until the migration alarm timeout.
  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(host_port_pair_));
  EXPECT_EQ(1u, session->GetNumActiveStreams());
  EXPECT_EQ(ERR_IO_PENDING, stream->ReadResponseHeaders(callback_.callback()));

  // Force migration alarm timeout to run.
  RunTestLoopUntilIdle();

  // The connection should be closed. A request for response headers
  // should fail.
  EXPECT_FALSE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_FALSE(HasActiveSession(host_port_pair_));
  EXPECT_EQ(ERR_NETWORK_CHANGED, callback_.WaitForResult());
  EXPECT_EQ(ERR_NETWORK_CHANGED,
            stream->ReadResponseHeaders(callback_.callback()));

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest,
       MigrateSessionOnWriteErrorNoNewNetworkSynchronous) {
  TestMigrationOnWriteErrorNoNewNetwork(SYNCHRONOUS);
}

TEST_P(QuicStreamFactoryTest, MigrateSessionOnWriteErrorNoNewNetworkAsync) {
  TestMigrationOnWriteErrorNoNewNetwork(ASYNC);
}

void QuicStreamFactoryTestBase::TestMigrationOnWriteErrorNonMigratableStream(
    IoMode write_error_mode) {
  DVLOG(1) << "Mode: "
           << ((write_error_mode == SYNCHRONOUS) ? "SYNCHRONOUS" : "ASYNC");
  InitializeConnectionMigrationTest(
      {kDefaultNetworkForTests, kNewNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data;
  socket_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data.AddWrite(write_error_mode, ERR_ADDRESS_UNREACHABLE);
  socket_data.AddSocketDataToFactory(&socket_factory_);

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
  EXPECT_EQ(OK, stream->SendRequest(request_headers, &response,
                                    callback_.callback()));

  // Run message loop to execute migration attempt.
  base::RunLoop().RunUntilIdle();

  // Migration fails, and session is closed and deleted.
  EXPECT_FALSE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_FALSE(HasActiveSession(host_port_pair_));

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest,
       MigrateSessionOnWriteErrorNonMigratableStreamSynchronous) {
  TestMigrationOnWriteErrorNonMigratableStream(SYNCHRONOUS);
}

TEST_P(QuicStreamFactoryTest,
       MigrateSessionOnWriteErrorNonMigratableStreamAsync) {
  TestMigrationOnWriteErrorNonMigratableStream(ASYNC);
}

void QuicStreamFactoryTestBase::TestMigrationOnWriteErrorMigrationDisabled(
    IoMode write_error_mode) {
  InitializeConnectionMigrationTest(
      {kDefaultNetworkForTests, kNewNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data;
  socket_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data.AddWrite(write_error_mode, ERR_ADDRESS_UNREACHABLE);
  socket_data.AddSocketDataToFactory(&socket_factory_);

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
  EXPECT_EQ(OK, stream->SendRequest(request_headers, &response,
                                    callback_.callback()));
  // Run message loop to execute migration attempt.
  base::RunLoop().RunUntilIdle();
  // Migration fails, and session is closed and deleted.
  EXPECT_FALSE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_FALSE(HasActiveSession(host_port_pair_));
  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest,
       MigrateSessionOnWriteErrorMigrationDisabledSynchronous) {
  TestMigrationOnWriteErrorMigrationDisabled(SYNCHRONOUS);
}

TEST_P(QuicStreamFactoryTest,
       MigrateSessionOnWriteErrorMigrationDisabledAsync) {
  TestMigrationOnWriteErrorMigrationDisabled(ASYNC);
}

void QuicStreamFactoryTestBase::TestMigrationOnMultipleWriteErrors(
    IoMode first_write_error_mode,
    IoMode second_write_error_mode) {
  const int kMaxReadersPerQuicSession = 5;
  InitializeConnectionMigrationTest(
      {kDefaultNetworkForTests, kNewNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  // Set up kMaxReadersPerQuicSession socket data providers, since
  // migration will cause kMaxReadersPerQuicSession write failures as
  // the session hops repeatedly between the two networks.
  MockQuicData socket_data[kMaxReadersPerQuicSession + 1];
  for (int i = 0; i <= kMaxReadersPerQuicSession; ++i) {
    // The last socket is created but never used.
    if (i < kMaxReadersPerQuicSession) {
      socket_data[i].AddRead(SYNCHRONOUS, ERR_IO_PENDING);
      socket_data[i].AddWrite(
          (i % 2 == 0) ? first_write_error_mode : second_write_error_mode,
          ERR_FAILED);
    }
    socket_data[i].AddSocketDataToFactory(&socket_factory_);
  }

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
  EXPECT_EQ(OK, stream->SendRequest(request_headers, &response,
                                    callback_.callback()));
  EXPECT_EQ(ERR_IO_PENDING, stream->ReadResponseHeaders(callback_.callback()));

  // Run the message loop so that data queued in the new socket is read by the
  // packet reader.
  base::RunLoop().RunUntilIdle();

  // The connection should be closed because of a write error after migration.
  EXPECT_FALSE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_FALSE(HasActiveSession(host_port_pair_));
  EXPECT_EQ(ERR_QUIC_PROTOCOL_ERROR,
            stream->ReadResponseHeaders(callback_.callback()));

  stream.reset();
  for (int i = 0; i <= kMaxReadersPerQuicSession; ++i) {
    DLOG(INFO) << "Socket number: " << i;
    EXPECT_TRUE(socket_data[i].AllReadDataConsumed());
    EXPECT_TRUE(socket_data[i].AllWriteDataConsumed());
  }
}

TEST_P(QuicStreamFactoryTest, MigrateSessionOnMultipleWriteErrorsSyncSync) {
  TestMigrationOnMultipleWriteErrors(SYNCHRONOUS, SYNCHRONOUS);
}

TEST_P(QuicStreamFactoryTest, MigrateSessionOnMultipleWriteErrorsSyncAsync) {
  TestMigrationOnMultipleWriteErrors(SYNCHRONOUS, ASYNC);
}

TEST_P(QuicStreamFactoryTest, MigrateSessionOnMultipleWriteErrorsAsyncSync) {
  TestMigrationOnMultipleWriteErrors(ASYNC, SYNCHRONOUS);
}

TEST_P(QuicStreamFactoryTest, MigrateSessionOnMultipleWriteErrorsAsyncAsync) {
  TestMigrationOnMultipleWriteErrors(ASYNC, ASYNC);
}

void QuicStreamFactoryTestBase::TestMigrationOnWriteErrorWithNotificationQueued(
    bool disconnected) {
  InitializeConnectionMigrationTest(
      {kDefaultNetworkForTests, kNewNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data;
  socket_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data.AddWrite(SYNCHRONOUS, ERR_ADDRESS_UNREACHABLE);
  socket_data.AddSocketDataToFactory(&socket_factory_);

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
  MockQuicData socket_data1;
  socket_data1.AddWrite(
      ConstructGetRequestPacket(1, kClientDataStreamId1, true, true));
  socket_data1.AddRead(
      ConstructOkResponsePacket(1, kClientDataStreamId1, false, false));
  socket_data1.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data1.AddWrite(client_maker_.MakeAckAndRstPacket(
      2, false, kClientDataStreamId1, QUIC_STREAM_CANCELLED, 1, 1, 1, true));
  socket_data1.AddSocketDataToFactory(&socket_factory_);

  // First queue a network change notification in the message loop.
  if (disconnected) {
    scoped_mock_network_change_notifier_->mock_network_change_notifier()
        ->QueueNetworkDisconnected(kDefaultNetworkForTests);
  } else {
    scoped_mock_network_change_notifier_->mock_network_change_notifier()
        ->QueueNetworkMadeDefault(kNewNetworkForTests);
  }
  // Send GET request on stream. This should cause a write error,
  // which triggers a connection migration attempt. This will queue a
  // migration attempt behind the notification in the message loop.
  HttpResponseInfo response;
  HttpRequestHeaders request_headers;
  EXPECT_EQ(OK, stream->SendRequest(request_headers, &response,
                                    callback_.callback()));

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

TEST_P(QuicStreamFactoryTest,
       MigrateSessionOnWriteErrorWithNetworkDisconnectedQueued) {
  TestMigrationOnWriteErrorWithNotificationQueued(/*disconnected=*/true);
}

TEST_P(QuicStreamFactoryTest,
       MigrateSessionOnWriteErrorWithNetworkMadeDefaultQueued) {
  TestMigrationOnWriteErrorWithNotificationQueued(/*disconnected=*/false);
}

void QuicStreamFactoryTestBase::TestMigrationOnNotificationWithWriteErrorQueued(
    bool disconnected) {
  InitializeConnectionMigrationTest(
      {kDefaultNetworkForTests, kNewNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data;
  socket_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data.AddWrite(SYNCHRONOUS, ERR_ADDRESS_UNREACHABLE);
  socket_data.AddSocketDataToFactory(&socket_factory_);

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
  MockQuicData socket_data1;
  socket_data1.AddWrite(
      ConstructGetRequestPacket(1, kClientDataStreamId1, true, true));
  socket_data1.AddRead(
      ConstructOkResponsePacket(1, kClientDataStreamId1, false, false));
  socket_data1.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data1.AddWrite(client_maker_.MakeAckAndRstPacket(
      2, false, kClientDataStreamId1, QUIC_STREAM_CANCELLED, 1, 1, 1, true));
  socket_data1.AddSocketDataToFactory(&socket_factory_);

  // Send GET request on stream. This should cause a write error,
  // which triggers a connection migration attempt. This will queue a
  // migration attempt in the message loop.
  HttpResponseInfo response;
  HttpRequestHeaders request_headers;
  EXPECT_EQ(OK, stream->SendRequest(request_headers, &response,
                                    callback_.callback()));

  // Now queue a network change notification in the message loop behind
  // the migration attempt.
  if (disconnected) {
    scoped_mock_network_change_notifier_->mock_network_change_notifier()
        ->QueueNetworkDisconnected(kDefaultNetworkForTests);
  } else {
    scoped_mock_network_change_notifier_->mock_network_change_notifier()
        ->QueueNetworkMadeDefault(kNewNetworkForTests);
  }

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

TEST_P(QuicStreamFactoryTest,
       MigrateSessionOnNetworkDisconnectedWithWriteErrorQueued) {
  TestMigrationOnNotificationWithWriteErrorQueued(/*disconnected=*/true);
}

TEST_P(QuicStreamFactoryTest,
       MigrateSessionOnNetworkMadeDefaultWithWriteErrorQueued) {
  TestMigrationOnNotificationWithWriteErrorQueued(/*disconnected=*/true);
}

void QuicStreamFactoryTestBase::TestMigrationOnWriteErrorPauseBeforeConnected(
    IoMode write_error_mode) {
  InitializeConnectionMigrationTest({kDefaultNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data;
  socket_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data.AddWrite(SYNCHRONOUS, ERR_FAILED);
  socket_data.AddSocketDataToFactory(&socket_factory_);

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
  EXPECT_EQ(OK, stream->SendRequest(request_headers, &response,
                                    callback_.callback()));

  // Run the message loop so that data queued in the new socket is read by the
  // packet reader.
  base::RunLoop().RunUntilIdle();

  // In this particular code path, the network will not yet be marked
  // as going away and the session will still be alive.
  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(host_port_pair_));
  EXPECT_EQ(1u, session->GetNumActiveStreams());
  EXPECT_EQ(ERR_IO_PENDING, stream->ReadResponseHeaders(callback_.callback()));

  // On a DISCONNECTED notification, nothing happens.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkDisconnected(kDefaultNetworkForTests);

  // Set up second socket data provider that is used after
  // migration. The request is rewritten to this new socket, and the
  // response to the request is read on this new socket.
  MockQuicData socket_data1;
  socket_data1.AddWrite(
      ConstructGetRequestPacket(1, kClientDataStreamId1, true, true));
  socket_data1.AddRead(
      ConstructOkResponsePacket(1, kClientDataStreamId1, false, false));
  socket_data1.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data1.AddWrite(client_maker_.MakeAckAndRstPacket(
      2, false, kClientDataStreamId1, QUIC_STREAM_CANCELLED, 1, 1, 1, true));
  socket_data1.AddSocketDataToFactory(&socket_factory_);

  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->SetConnectedNetworksList({kNewNetworkForTests});
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkConnected(kNewNetworkForTests);

  // The session should now be marked as going away. Ensure that
  // while it is still alive, it is no longer active.
  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_FALSE(HasActiveSession(host_port_pair_));
  EXPECT_EQ(1u, session->GetNumActiveStreams());

  // This is the callback for the response headers that returned
  // pending previously, because no result was available.  Check that
  // the result is now available due to the successful migration.
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  EXPECT_EQ(200, response.headers->response_code());

  // Create a new request for the same destination and verify that a
  // new session is created.
  MockQuicData socket_data2;
  socket_data2.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data2.AddSocketDataToFactory(&socket_factory_);

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

  stream.reset();
  stream2.reset();

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data1.AllReadDataConsumed());
  EXPECT_TRUE(socket_data1.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data2.AllReadDataConsumed());
  EXPECT_TRUE(socket_data2.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest,
       MigrateSessionOnWriteErrorPauseBeforeConnectedSync) {
  TestMigrationOnWriteErrorPauseBeforeConnected(SYNCHRONOUS);
}

TEST_P(QuicStreamFactoryTest,
       MigrateSessionOnWriteErrorPauseBeforeConnectedAsync) {
  TestMigrationOnWriteErrorPauseBeforeConnected(ASYNC);
}

void QuicStreamFactoryTestBase::
    TestMigrationOnWriteErrorWithNetworkAddedBeforeNotification(
        IoMode write_error_mode,
        bool disconnected) {
  InitializeConnectionMigrationTest({kDefaultNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data;
  socket_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data.AddWrite(SYNCHRONOUS, ERR_FAILED);
  socket_data.AddSocketDataToFactory(&socket_factory_);

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
  EXPECT_EQ(OK, stream->SendRequest(request_headers, &response,
                                    callback_.callback()));

  // Run the message loop so that data queued in the new socket is read by the
  // packet reader.
  base::RunLoop().RunUntilIdle();

  // In this particular code path, the network will not yet be marked
  // as going away and the session will still be alive.
  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(host_port_pair_));
  EXPECT_EQ(1u, session->GetNumActiveStreams());
  EXPECT_EQ(ERR_IO_PENDING, stream->ReadResponseHeaders(callback_.callback()));

  // Set up second socket data provider that is used after
  // migration. The request is rewritten to this new socket, and the
  // response to the request is read on this new socket.
  MockQuicData socket_data1;
  socket_data1.AddWrite(
      ConstructGetRequestPacket(1, kClientDataStreamId1, true, true));
  socket_data1.AddRead(
      ConstructOkResponsePacket(1, kClientDataStreamId1, false, false));
  socket_data1.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data1.AddWrite(client_maker_.MakeAckAndRstPacket(
      2, false, kClientDataStreamId1, QUIC_STREAM_CANCELLED, 1, 1, 1, true));
  socket_data1.AddSocketDataToFactory(&socket_factory_);

  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->SetConnectedNetworksList(
          {kDefaultNetworkForTests, kNewNetworkForTests});

  // A notification triggers and completes migration.
  if (disconnected) {
    scoped_mock_network_change_notifier_->mock_network_change_notifier()
        ->NotifyNetworkDisconnected(kDefaultNetworkForTests);
  } else {
    scoped_mock_network_change_notifier_->mock_network_change_notifier()
        ->NotifyNetworkMadeDefault(kNewNetworkForTests);
  }
  // The session should now be marked as going away. Ensure that
  // while it is still alive, it is no longer active.
  EXPECT_TRUE(QuicStreamFactoryPeer::IsLiveSession(factory_.get(), session));
  EXPECT_FALSE(HasActiveSession(host_port_pair_));
  EXPECT_EQ(1u, session->GetNumActiveStreams());

  // This is the callback for the response headers that returned
  // pending previously, because no result was available.  Check that
  // the result is now available due to the successful migration.
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  EXPECT_EQ(200, response.headers->response_code());

  // Now deliver a CONNECTED notification. Nothing happens since
  // migration was already finished earlier.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkConnected(kNewNetworkForTests);

  // Create a new request for the same destination and verify that a
  // new session is created.
  MockQuicData socket_data2;
  socket_data2.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data2.AddSocketDataToFactory(&socket_factory_);

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

  stream.reset();
  stream2.reset();

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data1.AllReadDataConsumed());
  EXPECT_TRUE(socket_data1.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data2.AllReadDataConsumed());
  EXPECT_TRUE(socket_data2.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest,
       MigrateSessionOnWriteErrorWithNetworkAddedBeforeDisconnectedSync) {
  TestMigrationOnWriteErrorWithNetworkAddedBeforeNotification(SYNCHRONOUS,
                                                              true);
}

TEST_P(QuicStreamFactoryTest,
       MigrateSessionOnWriteErrorWithNetworkAddedBeforeDisconnectedAsync) {
  TestMigrationOnWriteErrorWithNetworkAddedBeforeNotification(ASYNC, true);
}

TEST_P(QuicStreamFactoryTest,
       MigrateSessionOnWriteErrorWithNetworkAddedBeforeMadeDefaultSync) {
  TestMigrationOnWriteErrorWithNetworkAddedBeforeNotification(SYNCHRONOUS,
                                                              false);
}

TEST_P(QuicStreamFactoryTest,
       MigrateSessionOnWriteErrorWithNetworkAddedBeforeMadeDefaultAsync) {
  TestMigrationOnWriteErrorWithNetworkAddedBeforeNotification(ASYNC, false);
}

TEST_P(QuicStreamFactoryTest, MigrateSessionEarlyToBadSocket) {
  // This simulates the case where we attempt to migrate to a new
  // socket but the socket is unusable, such as an ipv4/ipv6 mismatch.
  InitializeConnectionMigrationTest(
      {kDefaultNetworkForTests, kNewNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data;
  socket_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data.AddWrite(
      ConstructGetRequestPacket(1, kClientDataStreamId1, true, true));
  socket_data.AddSocketDataToFactory(&socket_factory_);

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

  MockQuicData socket_data1;
  socket_data1.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data1.AddWrite(
      ConstructGetRequestPacket(1, kClientDataStreamId1, true, true));
  socket_data1.AddSocketDataToFactory(&socket_factory_);

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
  MockQuicData socket_data2;
  socket_data2.AddWrite(
      client_maker_.MakePingPacket(2, /*include_version=*/true));
  socket_data2.AddRead(
      ConstructOkResponsePacket(1, kClientDataStreamId1, false, false));
  socket_data2.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data2.AddWrite(client_maker_.MakeAckAndRstPacket(
      3, false, kClientDataStreamId1, QUIC_STREAM_CANCELLED, 1, 1, 1, true));
  socket_data2.AddSocketDataToFactory(&socket_factory_);

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

TEST_P(QuicStreamFactoryTest, ServerMigrationIPv4ToIPv4) {
  // Add alternate IPv4 server address to config.
  IPEndPoint alt_address = IPEndPoint(IPAddress(1, 2, 3, 4), 123);
  QuicConfig config;
  config.SetAlternateServerAddressToSend(
      QuicSocketAddress(QuicSocketAddressImpl(alt_address)));
  VerifyServerMigration(config, alt_address);
}

TEST_P(QuicStreamFactoryTest, ServerMigrationIPv6ToIPv6) {
  // Add a resolver rule to make initial connection to an IPv6 address.
  host_resolver_.rules()->AddIPLiteralRule(host_port_pair_.host(),
                                           "fe80::aebc:32ff:febb:1e33", "");
  // Add alternate IPv6 server address to config.
  IPEndPoint alt_address = IPEndPoint(
      IPAddress(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16), 123);
  QuicConfig config;
  config.SetAlternateServerAddressToSend(
      QuicSocketAddress(QuicSocketAddressImpl(alt_address)));
  VerifyServerMigration(config, alt_address);
}

TEST_P(QuicStreamFactoryTest, ServerMigrationIPv6ToIPv4) {
  // Add a resolver rule to make initial connection to an IPv6 address.
  host_resolver_.rules()->AddIPLiteralRule(host_port_pair_.host(),
                                           "fe80::aebc:32ff:febb:1e33", "");
  // Add alternate IPv4 server address to config.
  IPEndPoint alt_address = IPEndPoint(IPAddress(1, 2, 3, 4), 123);
  QuicConfig config;
  config.SetAlternateServerAddressToSend(
      QuicSocketAddress(QuicSocketAddressImpl(alt_address)));
  IPEndPoint expected_address(
      ConvertIPv4ToIPv4MappedIPv6(alt_address.address()), alt_address.port());
  VerifyServerMigration(config, expected_address);
}

TEST_P(QuicStreamFactoryTest, ServerMigrationIPv4ToIPv6Fails) {
  allow_server_migration_ = true;
  Initialize();

  // Add a resolver rule to make initial connection to an IPv4 address.
  host_resolver_.rules()->AddIPLiteralRule(host_port_pair_.host(), "1.2.3.4",
                                           "");
  // Add alternate IPv6 server address to config.
  IPEndPoint alt_address = IPEndPoint(
      IPAddress(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16), 123);
  QuicConfig config;
  config.SetAlternateServerAddressToSend(
      QuicSocketAddress(QuicSocketAddressImpl(alt_address)));

  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  crypto_client_stream_factory_.SetConfig(config);

  // Set up only socket data provider.
  MockQuicData socket_data1;
  socket_data1.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data1.AddWrite(client_maker_.MakeRstPacket(
      1, true, kClientDataStreamId1, QUIC_STREAM_CANCELLED));
  socket_data1.AddSocketDataToFactory(&socket_factory_);

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

  IPEndPoint actual_address;
  session->GetDefaultSocket()->GetPeerAddress(&actual_address);
  // No migration should have happened.
  IPEndPoint expected_address =
      IPEndPoint(IPAddress(1, 2, 3, 4), kDefaultServerPort);
  EXPECT_EQ(actual_address, expected_address);
  DVLOG(1) << "Socket connected to: " << actual_address.address().ToString()
           << " " << actual_address.port();
  DVLOG(1) << "Expected address: " << expected_address.address().ToString()
           << " " << expected_address.port();

  stream.reset();
  EXPECT_TRUE(socket_data1.AllReadDataConsumed());
  EXPECT_TRUE(socket_data1.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, OnSSLConfigChanged) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data;
  socket_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data.AddWrite(ConstructClientRstPacket());
  socket_data.AddSocketDataToFactory(&socket_factory_);

  MockQuicData socket_data2;
  socket_data2.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data2.AddSocketDataToFactory(&socket_factory_);

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

TEST_P(QuicStreamFactoryTest, OnCertDBChanged) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data;
  socket_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data.AddWrite(ConstructClientRstPacket());
  socket_data.AddSocketDataToFactory(&socket_factory_);

  MockQuicData socket_data2;
  socket_data2.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data2.AddSocketDataToFactory(&socket_factory_);

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
  factory_->OnCertDBChanged(nullptr);
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

  std::vector<string> cannoncial_suffixes;
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
  std::vector<string> cannoncial_suffixes;
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

  MockQuicData socket_data;
  socket_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data.AddSocketDataToFactory(&socket_factory_);

  MockQuicData socket_data2;
  socket_data2.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data2.AddSocketDataToFactory(&socket_factory_);

  const AlternativeService alternative_service1(
      kProtoQUIC, host_port_pair_.host(), host_port_pair_.port());
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

  MockQuicData socket_data;
  socket_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data.AddSocketDataToFactory(&socket_factory_);

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

TEST_P(QuicStreamFactoryTest, ReducePingTimeoutOnConnectionTimeOutOpenStreams) {
  reduced_ping_timeout_seconds_ = 10;
  disable_disk_cache_ = true;
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  QuicStreamFactoryPeer::SetTaskRunner(factory_.get(), runner_.get());
  EXPECT_FALSE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get()));

  MockQuicData socket_data;
  socket_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data.AddSocketDataToFactory(&socket_factory_);

  MockQuicData socket_data2;
  socket_data2.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data2.AddSocketDataToFactory(&socket_factory_);

  HostPortPair server2(kServer2HostName, kDefaultServerPort);

  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::CONFIRM_HANDSHAKE);
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule(host_port_pair_.host(),
                                           "192.168.0.1", "");
  host_resolver_.rules()->AddIPLiteralRule(server2.host(), "192.168.0.1", "");

  // Quic should use default PING timeout when no previous connection times out
  // with open stream.
  EXPECT_EQ(QuicTime::Delta::FromSeconds(kPingTimeoutSecs),
            QuicStreamFactoryPeer::GetPingTimeout(factory_.get()));
  QuicStreamRequest request(factory_.get());
  EXPECT_EQ(OK, request.Request(host_port_pair_, privacy_mode_,
                                /*cert_verify_flags=*/0, url_, "GET", net_log_,
                                callback_.callback()));

  QuicChromiumClientSession* session = GetActiveSession(host_port_pair_);
  EXPECT_EQ(QuicTime::Delta::FromSeconds(kPingTimeoutSecs),
            session->connection()->ping_timeout());

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

  EXPECT_FALSE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get()));

  // The first connection times out with open stream, QUIC should reduce initial
  // PING time for subsequent connections.
  EXPECT_EQ(QuicTime::Delta::FromSeconds(10),
            QuicStreamFactoryPeer::GetPingTimeout(factory_.get()));

  // Test two-in-a-row timeouts with open streams.
  DVLOG(1) << "Create 2nd session and timeout with open stream";
  TestCompletionCallback callback2;
  QuicStreamRequest request2(factory_.get());
  EXPECT_EQ(OK, request2.Request(server2, privacy_mode_,
                                 /*cert_verify_flags=*/0, url2_, "GET",
                                 net_log_, callback2.callback()));
  QuicChromiumClientSession* session2 = GetActiveSession(server2);
  EXPECT_EQ(QuicTime::Delta::FromSeconds(10),
            session2->connection()->ping_timeout());

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
  EXPECT_FALSE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get()));

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
  EXPECT_TRUE(socket_data2.AllReadDataConsumed());
  EXPECT_TRUE(socket_data2.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, DisableQuicWhenTimeoutsWithOpenStreams) {
  disable_disk_cache_ = true;
  disable_quic_on_timeout_with_open_streams_ = true;
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  QuicStreamFactoryPeer::SetTaskRunner(factory_.get(), runner_.get());

  EXPECT_FALSE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get()));

  MockQuicData socket_data;
  socket_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data.AddSocketDataToFactory(&socket_factory_);

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

  EXPECT_TRUE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get()));

  // Verify that QUIC is fully disabled after a TCP job succeeds.
  factory_->OnTcpJobCompleted(/*succeeded=*/true);
  EXPECT_TRUE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get()));

  // Verify that QUIC stays disabled after a TCP job succeeds.
  factory_->OnTcpJobCompleted(/*succeeded=*/false);
  EXPECT_TRUE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get()));

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest,
       DisableQuicWhenTimeoutsWithOpenStreamsExponentialBackoff) {
  disable_disk_cache_ = true;
  disable_quic_on_timeout_with_open_streams_ = true;
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  QuicStreamFactoryPeer::SetTaskRunner(factory_.get(), runner_.get());

  EXPECT_FALSE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get()));

  MockQuicData socket_data;
  socket_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data.AddSocketDataToFactory(&socket_factory_);

  MockQuicData socket_data2;
  socket_data2.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data2.AddSocketDataToFactory(&socket_factory_);

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
  EXPECT_TRUE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get()));

  ASSERT_EQ(1u, runner_->GetPostedTasks().size());
  ASSERT_EQ(clock_->NowInTicks() + base::TimeDelta::FromMinutes(5),
            runner_->GetPostedTasks()[0].GetTimeToRun());
  runner_->RunNextTask();

  // Need to spin the loop now to ensure that
  // QuicStreamFactory::OnSessionClosed() runs.
  base::RunLoop run_loop;
  run_loop.RunUntilIdle();

  EXPECT_FALSE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get()));

  ASSERT_TRUE(runner_->GetPostedTasks().empty());

  // Create a new session which will cause a task to be posted to
  // clear the exponential backoff.
  QuicStreamRequest request2(factory_.get());
  EXPECT_EQ(OK, request2.Request(host_port_pair_, privacy_mode_,
                                 /*cert_verify_flags=*/0, url_, "GET", net_log_,
                                 callback_.callback()));
  QuicChromiumClientSession* session2 = GetActiveSession(host_port_pair_);
  std::unique_ptr<QuicHttpStream> stream2 = request2.CreateStream();
  EXPECT_TRUE(stream2.get());
  HttpRequestInfo request_info2;
  EXPECT_EQ(OK, stream2->InitializeStream(&request_info2, DEFAULT_PRIORITY,
                                          net_log_, CompletionCallback()));

  // Check that the clear task has been posted.
  ASSERT_EQ(1u, runner_->GetPostedTasks().size());
  ASSERT_EQ(clock_->NowInTicks() + base::TimeDelta::FromMinutes(5),
            runner_->GetPostedTasks()[0].GetTimeToRun());

  session2->connection()->CloseConnection(
      QUIC_NETWORK_IDLE_TIMEOUT, "test", ConnectionCloseBehavior::SILENT_CLOSE);
  EXPECT_TRUE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get()));

  ASSERT_EQ(2u, runner_->GetPostedTasks().size());
  ASSERT_EQ(clock_->NowInTicks() + base::TimeDelta::FromMinutes(10),
            runner_->GetPostedTasks()[1].GetTimeToRun());
  runner_->RunNextTask();

  EXPECT_TRUE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get()));

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest,
       DisableQuicWhenTimeoutsWithOpenStreamsExponentialBackoffReset) {
  disable_disk_cache_ = true;
  disable_quic_on_timeout_with_open_streams_ = true;
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  QuicStreamFactoryPeer::SetTaskRunner(factory_.get(), runner_.get());

  EXPECT_FALSE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get()));

  MockQuicData socket_data;
  socket_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data.AddSocketDataToFactory(&socket_factory_);

  MockQuicData socket_data2;
  socket_data2.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data2.AddSocketDataToFactory(&socket_factory_);

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
  EXPECT_TRUE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get()));

  ASSERT_EQ(1u, runner_->GetPostedTasks().size());
  ASSERT_EQ(clock_->NowInTicks() + base::TimeDelta::FromMinutes(5),
            runner_->GetPostedTasks()[0].GetTimeToRun());
  runner_->RunNextTask();

  // Need to spin the loop now to ensure that
  // QuicStreamFactory::OnSessionClosed() runs.
  base::RunLoop run_loop;
  run_loop.RunUntilIdle();

  EXPECT_FALSE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get()));

  ASSERT_TRUE(runner_->GetPostedTasks().empty());

  // Create a new session which will cause a task to be posted to
  // clear the exponential backoff.
  QuicStreamRequest request2(factory_.get());
  EXPECT_EQ(OK, request2.Request(host_port_pair_, privacy_mode_,
                                 /*cert_verify_flags=*/0, url_, "GET", net_log_,
                                 callback_.callback()));
  QuicChromiumClientSession* session2 = GetActiveSession(host_port_pair_);
  std::unique_ptr<QuicHttpStream> stream2 = request2.CreateStream();
  EXPECT_TRUE(stream2.get());
  HttpRequestInfo request_info2;
  EXPECT_EQ(OK, stream2->InitializeStream(&request_info2, DEFAULT_PRIORITY,
                                          net_log_, CompletionCallback()));

  // Run the clear task and verify that the next disabling is
  // back to the default timeout.
  runner_->RunNextTask();

  // QUIC should still be enabled.
  EXPECT_FALSE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get()));

  session2->connection()->CloseConnection(
      QUIC_NETWORK_IDLE_TIMEOUT, "test", ConnectionCloseBehavior::SILENT_CLOSE);
  EXPECT_TRUE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get()));

  ASSERT_EQ(1u, runner_->GetPostedTasks().size());
  ASSERT_EQ(clock_->NowInTicks() + base::TimeDelta::FromMinutes(5),
            runner_->GetPostedTasks()[0].GetTimeToRun());
  runner_->RunNextTask();

  EXPECT_FALSE(QuicStreamFactoryPeer::IsQuicDisabled(factory_.get()));

  EXPECT_TRUE(socket_data.AllReadDataConsumed());
  EXPECT_TRUE(socket_data.AllWriteDataConsumed());
}

TEST_P(QuicStreamFactoryTest, EnableDelayTcpRace) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  bool delay_tcp_race = QuicStreamFactoryPeer::GetDelayTcpRace(factory_.get());
  QuicStreamFactoryPeer::SetDelayTcpRace(factory_.get(), false);
  MockQuicData socket_data;
  socket_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data.AddSocketDataToFactory(&socket_factory_);

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

// Verifies that the QUIC stream factory is initialized correctly.
TEST_P(QuicStreamFactoryTest, MaybeInitialize) {
  VerifyInitialization(false);
}

// Verifies that the alternative proxy server provided by the proxy delegate
// is added to the list of supported QUIC proxy servers, and the QUIC stream
// factory is initialized correctly.
TEST_P(QuicStreamFactoryTest, MaybeInitializeAlternativeProxyServer) {
  VerifyInitialization(true);
}

TEST_P(QuicStreamFactoryTest, StartCertVerifyJob) {
  Initialize();

  MockQuicData socket_data;
  socket_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data.AddSocketDataToFactory(&socket_factory_);

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

  MockQuicData socket_data;
  socket_data.AddSynchronousRead(ConstructClientConnectionClosePacket(0));
  socket_data.AddRead(ASYNC, OK);
  socket_data.AddSocketDataToFactory(&socket_factory_);

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

  MockQuicData socket_data;
  socket_data.AddSynchronousRead(ConstructClientConnectionClosePacket(0));
  socket_data.AddRead(ASYNC, OK);
  socket_data.AddSocketDataToFactory(&socket_factory_);

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

  MockQuicData socket_data;
  socket_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data.AddSocketDataToFactory(&socket_factory_);

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

  MockQuicData socket_data1;
  socket_data1.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data1.AddWrite(client_maker_.MakeRstPacket(
      1, true, kServerDataStreamId1, QUIC_STREAM_CANCELLED));
  socket_data1.AddSocketDataToFactory(&socket_factory_);

  MockQuicData socket_data2;
  socket_data2.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data2.AddSocketDataToFactory(&socket_factory_);

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

  MockQuicData socket_data;
  socket_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data.AddSocketDataToFactory(&socket_factory_);

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

  MockQuicData socket_data;
  socket_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  socket_data.AddSocketDataToFactory(&socket_factory_);

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
  std::vector<std::unique_ptr<SequencedSocketData>>
      sequenced_socket_data_vector_;
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
      std::vector<string> certs(1);
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
  factory_->ClearCachedStatesInCryptoConfig(base::Bind(
      static_cast<bool (*)(const GURL&, const GURL&)>(::operator==), origin));
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
