// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_stream_factory_impl.h"

#include <stdint.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "base/compiler_specific.h"
#include "base/macros.h"
#include "base/memory/ptr_util.h"
#include "base/message_loop/message_loop.h"
#include "base/run_loop.h"
#include "base/test/histogram_tester.h"
#include "net/base/port_util.h"
#include "net/base/privacy_mode.h"
#include "net/base/test_completion_callback.h"
#include "net/base/test_proxy_delegate.h"
#include "net/cert/ct_policy_enforcer.h"
#include "net/cert/mock_cert_verifier.h"
#include "net/cert/multi_log_ct_verifier.h"
#include "net/dns/mock_host_resolver.h"
#include "net/http/bidirectional_stream_impl.h"
#include "net/http/bidirectional_stream_request_info.h"
#include "net/http/http_auth_handler_factory.h"
#include "net/http/http_network_session.h"
#include "net/http/http_network_session_peer.h"
#include "net/http/http_network_transaction.h"
#include "net/http/http_request_info.h"
#include "net/http/http_server_properties.h"
#include "net/http/http_server_properties_impl.h"
#include "net/http/http_stream.h"
#include "net/http/transport_security_state.h"
#include "net/log/net_log_with_source.h"
#include "net/proxy/proxy_info.h"
#include "net/proxy/proxy_server.h"
#include "net/proxy/proxy_service.h"
#include "net/quic/chromium/mock_crypto_client_stream_factory.h"
#include "net/quic/chromium/quic_http_utils.h"
#include "net/quic/chromium/quic_stream_factory_peer.h"
#include "net/quic/chromium/quic_test_packet_maker.h"
#include "net/quic/core/quic_server_id.h"
#include "net/quic/test_tools/crypto_test_utils.h"
#include "net/quic/test_tools/mock_random.h"
#include "net/quic/test_tools/quic_test_utils.h"
#include "net/socket/client_socket_handle.h"
#include "net/socket/mock_client_socket_pool_manager.h"
#include "net/socket/next_proto.h"
#include "net/socket/socket_test_util.h"
#include "net/spdy/chromium/spdy_session.h"
#include "net/spdy/chromium/spdy_session_pool.h"
#include "net/spdy/chromium/spdy_test_util_common.h"
#include "net/ssl/ssl_config_service.h"
#include "net/ssl/ssl_config_service_defaults.h"
#include "net/test/cert_test_util.h"
#include "net/test/gtest_util.h"
#include "net/test/test_data_directory.h"

// This file can be included from net/http even though
// it is in net/websockets because it doesn't
// introduce any link dependency to net/websockets.
#include "net/websockets/websocket_handshake_stream_base.h"

#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using net::test::IsError;
using net::test::IsOk;

namespace base {
class Value;
class DictionaryValue;
}  // namespace base

namespace net {

class BidirectionalStreamImpl;

namespace {

class MockWebSocketHandshakeStream : public WebSocketHandshakeStreamBase {
 public:
  enum StreamType {
    kStreamTypeBasic,
    kStreamTypeSpdy,
  };

  explicit MockWebSocketHandshakeStream(StreamType type) : type_(type) {}

  ~MockWebSocketHandshakeStream() override {}

  StreamType type() const {
    return type_;
  }

  // HttpStream methods
  int InitializeStream(const HttpRequestInfo* request_info,
                       RequestPriority priority,
                       const NetLogWithSource& net_log,
                       const CompletionCallback& callback) override {
    return ERR_IO_PENDING;
  }
  int SendRequest(const HttpRequestHeaders& request_headers,
                  HttpResponseInfo* response,
                  const CompletionCallback& callback) override {
    return ERR_IO_PENDING;
  }
  int ReadResponseHeaders(const CompletionCallback& callback) override {
    return ERR_IO_PENDING;
  }
  int ReadResponseBody(IOBuffer* buf,
                       int buf_len,
                       const CompletionCallback& callback) override {
    return ERR_IO_PENDING;
  }
  void Close(bool not_reusable) override {}
  bool IsResponseBodyComplete() const override { return false; }
  bool IsConnectionReused() const override { return false; }
  void SetConnectionReused() override {}
  bool CanReuseConnection() const override { return false; }
  int64_t GetTotalReceivedBytes() const override { return 0; }
  int64_t GetTotalSentBytes() const override { return 0; }
  bool GetLoadTimingInfo(LoadTimingInfo* load_timing_info) const override {
    return false;
  }
  bool GetAlternativeService(
      AlternativeService* alternative_service) const override {
    return false;
  }
  void GetSSLInfo(SSLInfo* ssl_info) override {}
  void GetSSLCertRequestInfo(SSLCertRequestInfo* cert_request_info) override {}
  bool GetRemoteEndpoint(IPEndPoint* endpoint) override { return false; }
  Error GetTokenBindingSignature(crypto::ECPrivateKey* key,
                                 TokenBindingType tb_type,
                                 std::vector<uint8_t>* out) override {
    ADD_FAILURE();
    return ERR_NOT_IMPLEMENTED;
  }
  void Drain(HttpNetworkSession* session) override {}
  void PopulateNetErrorDetails(NetErrorDetails* details) override { return; }
  void SetPriority(RequestPriority priority) override {}
  HttpStream* RenewStreamForAuth() override { return nullptr; }

  std::unique_ptr<WebSocketStream> Upgrade() override {
    return std::unique_ptr<WebSocketStream>();
  }

 private:
  const StreamType type_;
};

// HttpStreamFactoryImpl subclass that can wait until a preconnect is complete.
class MockHttpStreamFactoryImplForPreconnect : public HttpStreamFactoryImpl {
 public:
  explicit MockHttpStreamFactoryImplForPreconnect(HttpNetworkSession* session)
      : HttpStreamFactoryImpl(session, false),
        preconnect_done_(false),
        waiting_for_preconnect_(false) {}

  void WaitForPreconnects() {
    while (!preconnect_done_) {
      waiting_for_preconnect_ = true;
      base::RunLoop().Run();
      waiting_for_preconnect_ = false;
    }
  }

 private:
  // HttpStreamFactoryImpl methods.
  void OnPreconnectsCompleteInternal() override {
    preconnect_done_ = true;
    if (waiting_for_preconnect_)
      base::MessageLoop::current()->QuitWhenIdle();
  }

  bool preconnect_done_;
  bool waiting_for_preconnect_;
};

class StreamRequestWaiter : public HttpStreamRequest::Delegate {
 public:
  StreamRequestWaiter()
      : waiting_for_stream_(false), stream_done_(false), error_status_(OK) {}

  // HttpStreamRequest::Delegate

  void OnStreamReady(const SSLConfig& used_ssl_config,
                     const ProxyInfo& used_proxy_info,
                     HttpStream* stream) override {
    stream_done_ = true;
    if (waiting_for_stream_)
      loop_.Quit();
    stream_.reset(stream);
    used_ssl_config_ = used_ssl_config;
    used_proxy_info_ = used_proxy_info;
  }

  void OnWebSocketHandshakeStreamReady(
      const SSLConfig& used_ssl_config,
      const ProxyInfo& used_proxy_info,
      WebSocketHandshakeStreamBase* stream) override {
    stream_done_ = true;
    if (waiting_for_stream_)
      loop_.Quit();
    websocket_stream_.reset(stream);
    used_ssl_config_ = used_ssl_config;
    used_proxy_info_ = used_proxy_info;
  }

  void OnBidirectionalStreamImplReady(
      const SSLConfig& used_ssl_config,
      const ProxyInfo& used_proxy_info,
      BidirectionalStreamImpl* stream) override {
    stream_done_ = true;
    if (waiting_for_stream_)
      loop_.Quit();
    bidirectional_stream_impl_.reset(stream);
    used_ssl_config_ = used_ssl_config;
    used_proxy_info_ = used_proxy_info;
  }

  void OnStreamFailed(int status, const SSLConfig& used_ssl_config) override {
    stream_done_ = true;
    if (waiting_for_stream_)
      loop_.Quit();
    used_ssl_config_ = used_ssl_config;
    error_status_ = status;
  }

  void OnCertificateError(int status,
                          const SSLConfig& used_ssl_config,
                          const SSLInfo& ssl_info) override {}

  void OnNeedsProxyAuth(const HttpResponseInfo& proxy_response,
                        const SSLConfig& used_ssl_config,
                        const ProxyInfo& used_proxy_info,
                        HttpAuthController* auth_controller) override {}

  void OnNeedsClientAuth(const SSLConfig& used_ssl_config,
                         SSLCertRequestInfo* cert_info) override {}

  void OnHttpsProxyTunnelResponse(const HttpResponseInfo& response_info,
                                  const SSLConfig& used_ssl_config,
                                  const ProxyInfo& used_proxy_info,
                                  std::unique_ptr<HttpStream> stream) override {
  }

  void OnQuicBroken() override {}

  void WaitForStream() {
    while (!stream_done_) {
      waiting_for_stream_ = true;
      loop_.Run();
      waiting_for_stream_ = false;
    }
  }

  const SSLConfig& used_ssl_config() const {
    return used_ssl_config_;
  }

  const ProxyInfo& used_proxy_info() const {
    return used_proxy_info_;
  }

  HttpStream* stream() {
    return stream_.get();
  }

  MockWebSocketHandshakeStream* websocket_stream() {
    return static_cast<MockWebSocketHandshakeStream*>(websocket_stream_.get());
  }

  BidirectionalStreamImpl* bidirectional_stream_impl() {
    return bidirectional_stream_impl_.get();
  }

  bool stream_done() const { return stream_done_; }
  int error_status() const { return error_status_; }

 private:
  bool waiting_for_stream_;
  bool stream_done_;
  base::RunLoop loop_;
  std::unique_ptr<HttpStream> stream_;
  std::unique_ptr<WebSocketHandshakeStreamBase> websocket_stream_;
  std::unique_ptr<BidirectionalStreamImpl> bidirectional_stream_impl_;
  SSLConfig used_ssl_config_;
  ProxyInfo used_proxy_info_;
  int error_status_;

  DISALLOW_COPY_AND_ASSIGN(StreamRequestWaiter);
};

class WebSocketBasicHandshakeStream : public MockWebSocketHandshakeStream {
 public:
  explicit WebSocketBasicHandshakeStream(
      std::unique_ptr<ClientSocketHandle> connection)
      : MockWebSocketHandshakeStream(kStreamTypeBasic),
        connection_(std::move(connection)) {}

  ~WebSocketBasicHandshakeStream() override {
    connection_->socket()->Disconnect();
  }

  ClientSocketHandle* connection() { return connection_.get(); }

 private:
  std::unique_ptr<ClientSocketHandle> connection_;
};

class WebSocketStreamCreateHelper
    : public WebSocketHandshakeStreamBase::CreateHelper {
 public:
  ~WebSocketStreamCreateHelper() override {}

  std::unique_ptr<WebSocketHandshakeStreamBase> CreateBasicStream(
      std::unique_ptr<ClientSocketHandle> connection,
      bool using_proxy) override {
    return base::MakeUnique<WebSocketBasicHandshakeStream>(
        std::move(connection));
  }
};

struct TestCase {
  int num_streams;
  bool ssl;
};

TestCase kTests[] = {
  { 1, false },
  { 2, false },
  { 1, true},
  { 2, true},
};

void PreconnectHelperForURL(int num_streams,
                            const GURL& url,
                            HttpNetworkSession* session) {
  HttpNetworkSessionPeer peer(session);
  MockHttpStreamFactoryImplForPreconnect* mock_factory =
      new MockHttpStreamFactoryImplForPreconnect(session);
  peer.SetHttpStreamFactory(std::unique_ptr<HttpStreamFactory>(mock_factory));

  HttpRequestInfo request;
  request.method = "GET";
  request.url = url;
  request.load_flags = 0;

  session->http_stream_factory()->PreconnectStreams(num_streams, request);
  mock_factory->WaitForPreconnects();
}

void PreconnectHelper(const TestCase& test,
                      HttpNetworkSession* session) {
  GURL url = test.ssl ? GURL("https://www.google.com") :
      GURL("http://www.google.com");
  PreconnectHelperForURL(test.num_streams, url, session);
}

template<typename ParentPool>
class CapturePreconnectsSocketPool : public ParentPool {
 public:
  CapturePreconnectsSocketPool(HostResolver* host_resolver,
                               CertVerifier* cert_verifier,
                               TransportSecurityState* transport_security_state,
                               CTVerifier* cert_transparency_verifier,
                               CTPolicyEnforcer* ct_policy_enforcer);

  int last_num_streams() const {
    return last_num_streams_;
  }

  // Resets |last_num_streams_| to its default value.
  void reset_last_num_streams() { last_num_streams_ = -1; }

  int RequestSocket(const std::string& group_name,
                    const void* socket_params,
                    RequestPriority priority,
                    ClientSocketPool::RespectLimits respect_limits,
                    ClientSocketHandle* handle,
                    const CompletionCallback& callback,
                    const NetLogWithSource& net_log) override {
    ADD_FAILURE();
    return ERR_UNEXPECTED;
  }

  void RequestSockets(const std::string& group_name,
                      const void* socket_params,
                      int num_sockets,
                      const NetLogWithSource& net_log) override {
    last_num_streams_ = num_sockets;
  }

  void CancelRequest(const std::string& group_name,
                     ClientSocketHandle* handle) override {
    ADD_FAILURE();
  }
  void ReleaseSocket(const std::string& group_name,
                     std::unique_ptr<StreamSocket> socket,
                     int id) override {
    ADD_FAILURE();
  }
  void CloseIdleSockets() override { ADD_FAILURE(); }
  int IdleSocketCount() const override {
    ADD_FAILURE();
    return 0;
  }
  int IdleSocketCountInGroup(const std::string& group_name) const override {
    ADD_FAILURE();
    return 0;
  }
  LoadState GetLoadState(const std::string& group_name,
                         const ClientSocketHandle* handle) const override {
    ADD_FAILURE();
    return LOAD_STATE_IDLE;
  }
  base::TimeDelta ConnectionTimeout() const override {
    return base::TimeDelta();
  }

 private:
  int last_num_streams_;
};

typedef CapturePreconnectsSocketPool<TransportClientSocketPool>
CapturePreconnectsTransportSocketPool;
typedef CapturePreconnectsSocketPool<HttpProxyClientSocketPool>
CapturePreconnectsHttpProxySocketPool;
typedef CapturePreconnectsSocketPool<SOCKSClientSocketPool>
CapturePreconnectsSOCKSSocketPool;
typedef CapturePreconnectsSocketPool<SSLClientSocketPool>
CapturePreconnectsSSLSocketPool;

template <typename ParentPool>
CapturePreconnectsSocketPool<ParentPool>::CapturePreconnectsSocketPool(
    HostResolver* host_resolver,
    CertVerifier*,
    TransportSecurityState*,
    CTVerifier*,
    CTPolicyEnforcer*)
    : ParentPool(0, 0, host_resolver, nullptr, nullptr, nullptr),
      last_num_streams_(-1) {}

template <>
CapturePreconnectsHttpProxySocketPool::CapturePreconnectsSocketPool(
    HostResolver*,
    CertVerifier*,
    TransportSecurityState*,
    CTVerifier*,
    CTPolicyEnforcer*)
    : HttpProxyClientSocketPool(0, 0, nullptr, nullptr, nullptr),
      last_num_streams_(-1) {}

template <>
CapturePreconnectsSSLSocketPool::CapturePreconnectsSocketPool(
    HostResolver* /* host_resolver */,
    CertVerifier* cert_verifier,
    TransportSecurityState* transport_security_state,
    CTVerifier* cert_transparency_verifier,
    CTPolicyEnforcer* ct_policy_enforcer)
    : SSLClientSocketPool(0,
                          0,
                          cert_verifier,
                          nullptr,  // channel_id_store
                          transport_security_state,
                          cert_transparency_verifier,
                          ct_policy_enforcer,
                          std::string(),  // ssl_session_cache_shard
                          nullptr,        // deterministic_socket_factory
                          nullptr,        // transport_socket_pool
                          nullptr,
                          nullptr,
                          nullptr,   // ssl_config_service
                          nullptr),  // net_log
      last_num_streams_(-1) {}

class HttpStreamFactoryTest : public ::testing::Test,
                              public ::testing::WithParamInterface<NextProto> {
};

TEST_F(HttpStreamFactoryTest, PreconnectDirect) {
  for (size_t i = 0; i < arraysize(kTests); ++i) {
    SpdySessionDependencies session_deps(ProxyService::CreateDirect());
    std::unique_ptr<HttpNetworkSession> session(
        SpdySessionDependencies::SpdyCreateSession(&session_deps));
    HttpNetworkSessionPeer peer(session.get());
    CapturePreconnectsTransportSocketPool* transport_conn_pool =
        new CapturePreconnectsTransportSocketPool(
            session_deps.host_resolver.get(), session_deps.cert_verifier.get(),
            session_deps.transport_security_state.get(),
            session_deps.cert_transparency_verifier.get(),
            session_deps.ct_policy_enforcer.get());
    CapturePreconnectsSSLSocketPool* ssl_conn_pool =
        new CapturePreconnectsSSLSocketPool(
            session_deps.host_resolver.get(), session_deps.cert_verifier.get(),
            session_deps.transport_security_state.get(),
            session_deps.cert_transparency_verifier.get(),
            session_deps.ct_policy_enforcer.get());
    std::unique_ptr<MockClientSocketPoolManager> mock_pool_manager(
        new MockClientSocketPoolManager);
    mock_pool_manager->SetTransportSocketPool(transport_conn_pool);
    mock_pool_manager->SetSSLSocketPool(ssl_conn_pool);
    peer.SetClientSocketPoolManager(std::move(mock_pool_manager));
    PreconnectHelper(kTests[i], session.get());
    if (kTests[i].ssl)
      EXPECT_EQ(kTests[i].num_streams, ssl_conn_pool->last_num_streams());
    else
      EXPECT_EQ(kTests[i].num_streams, transport_conn_pool->last_num_streams());
  }
}

TEST_F(HttpStreamFactoryTest, PreconnectHttpProxy) {
  for (size_t i = 0; i < arraysize(kTests); ++i) {
    SpdySessionDependencies session_deps(
        ProxyService::CreateFixed("http_proxy"));
    std::unique_ptr<HttpNetworkSession> session(
        SpdySessionDependencies::SpdyCreateSession(&session_deps));
    HttpNetworkSessionPeer peer(session.get());
    HostPortPair proxy_host("http_proxy", 80);
    CapturePreconnectsHttpProxySocketPool* http_proxy_pool =
        new CapturePreconnectsHttpProxySocketPool(
            session_deps.host_resolver.get(), session_deps.cert_verifier.get(),
            session_deps.transport_security_state.get(),
            session_deps.cert_transparency_verifier.get(),
            session_deps.ct_policy_enforcer.get());
    CapturePreconnectsSSLSocketPool* ssl_conn_pool =
        new CapturePreconnectsSSLSocketPool(
            session_deps.host_resolver.get(), session_deps.cert_verifier.get(),
            session_deps.transport_security_state.get(),
            session_deps.cert_transparency_verifier.get(),
            session_deps.ct_policy_enforcer.get());
    std::unique_ptr<MockClientSocketPoolManager> mock_pool_manager(
        new MockClientSocketPoolManager);
    mock_pool_manager->SetSocketPoolForHTTPProxy(
        proxy_host, base::WrapUnique(http_proxy_pool));
    mock_pool_manager->SetSocketPoolForSSLWithProxy(
        proxy_host, base::WrapUnique(ssl_conn_pool));
    peer.SetClientSocketPoolManager(std::move(mock_pool_manager));
    PreconnectHelper(kTests[i], session.get());
    if (kTests[i].ssl)
      EXPECT_EQ(kTests[i].num_streams, ssl_conn_pool->last_num_streams());
    else
      EXPECT_EQ(kTests[i].num_streams, http_proxy_pool->last_num_streams());
  }
}

TEST_F(HttpStreamFactoryTest, PreconnectSocksProxy) {
  for (size_t i = 0; i < arraysize(kTests); ++i) {
    SpdySessionDependencies session_deps(
        ProxyService::CreateFixed("socks4://socks_proxy:1080"));
    std::unique_ptr<HttpNetworkSession> session(
        SpdySessionDependencies::SpdyCreateSession(&session_deps));
    HttpNetworkSessionPeer peer(session.get());
    HostPortPair proxy_host("socks_proxy", 1080);
    CapturePreconnectsSOCKSSocketPool* socks_proxy_pool =
        new CapturePreconnectsSOCKSSocketPool(
            session_deps.host_resolver.get(), session_deps.cert_verifier.get(),
            session_deps.transport_security_state.get(),
            session_deps.cert_transparency_verifier.get(),
            session_deps.ct_policy_enforcer.get());
    CapturePreconnectsSSLSocketPool* ssl_conn_pool =
        new CapturePreconnectsSSLSocketPool(
            session_deps.host_resolver.get(), session_deps.cert_verifier.get(),
            session_deps.transport_security_state.get(),
            session_deps.cert_transparency_verifier.get(),
            session_deps.ct_policy_enforcer.get());
    std::unique_ptr<MockClientSocketPoolManager> mock_pool_manager(
        new MockClientSocketPoolManager);
    mock_pool_manager->SetSocketPoolForSOCKSProxy(
        proxy_host, base::WrapUnique(socks_proxy_pool));
    mock_pool_manager->SetSocketPoolForSSLWithProxy(
        proxy_host, base::WrapUnique(ssl_conn_pool));
    peer.SetClientSocketPoolManager(std::move(mock_pool_manager));
    PreconnectHelper(kTests[i], session.get());
    if (kTests[i].ssl)
      EXPECT_EQ(kTests[i].num_streams, ssl_conn_pool->last_num_streams());
    else
      EXPECT_EQ(kTests[i].num_streams, socks_proxy_pool->last_num_streams());
  }
}

TEST_F(HttpStreamFactoryTest, PreconnectDirectWithExistingSpdySession) {
  for (size_t i = 0; i < arraysize(kTests); ++i) {
    SpdySessionDependencies session_deps(ProxyService::CreateDirect());
    std::unique_ptr<HttpNetworkSession> session(
        SpdySessionDependencies::SpdyCreateSession(&session_deps));
    HttpNetworkSessionPeer peer(session.get());

    // Put a SpdySession in the pool.
    HostPortPair host_port_pair("www.google.com", 443);
    SpdySessionKey key(host_port_pair, ProxyServer::Direct(),
                       PRIVACY_MODE_DISABLED);
    ignore_result(CreateFakeSpdySession(session->spdy_session_pool(), key));

    CapturePreconnectsTransportSocketPool* transport_conn_pool =
        new CapturePreconnectsTransportSocketPool(
            session_deps.host_resolver.get(), session_deps.cert_verifier.get(),
            session_deps.transport_security_state.get(),
            session_deps.cert_transparency_verifier.get(),
            session_deps.ct_policy_enforcer.get());
    CapturePreconnectsSSLSocketPool* ssl_conn_pool =
        new CapturePreconnectsSSLSocketPool(
            session_deps.host_resolver.get(), session_deps.cert_verifier.get(),
            session_deps.transport_security_state.get(),
            session_deps.cert_transparency_verifier.get(),
            session_deps.ct_policy_enforcer.get());
    std::unique_ptr<MockClientSocketPoolManager> mock_pool_manager(
        new MockClientSocketPoolManager);
    mock_pool_manager->SetTransportSocketPool(transport_conn_pool);
    mock_pool_manager->SetSSLSocketPool(ssl_conn_pool);
    peer.SetClientSocketPoolManager(std::move(mock_pool_manager));
    PreconnectHelper(kTests[i], session.get());
    // We shouldn't be preconnecting if we have an existing session, which is
    // the case for https://www.google.com.
    if (kTests[i].ssl)
      EXPECT_EQ(-1, ssl_conn_pool->last_num_streams());
    else
      EXPECT_EQ(kTests[i].num_streams,
                transport_conn_pool->last_num_streams());
  }
}

// Verify that preconnects to unsafe ports are cancelled before they reach
// the SocketPool.
TEST_F(HttpStreamFactoryTest, PreconnectUnsafePort) {
  ASSERT_FALSE(IsPortAllowedForScheme(7, "http"));

  SpdySessionDependencies session_deps(ProxyService::CreateDirect());
  std::unique_ptr<HttpNetworkSession> session(
      SpdySessionDependencies::SpdyCreateSession(&session_deps));
  HttpNetworkSessionPeer peer(session.get());
  CapturePreconnectsTransportSocketPool* transport_conn_pool =
      new CapturePreconnectsTransportSocketPool(
          session_deps.host_resolver.get(), session_deps.cert_verifier.get(),
          session_deps.transport_security_state.get(),
          session_deps.cert_transparency_verifier.get(),
          session_deps.ct_policy_enforcer.get());
  std::unique_ptr<MockClientSocketPoolManager> mock_pool_manager(
      new MockClientSocketPoolManager);
  mock_pool_manager->SetTransportSocketPool(transport_conn_pool);
  peer.SetClientSocketPoolManager(std::move(mock_pool_manager));

  PreconnectHelperForURL(1, GURL("http://www.google.com:7"), session.get());
  EXPECT_EQ(-1, transport_conn_pool->last_num_streams());
}

TEST_F(HttpStreamFactoryTest, JobNotifiesProxy) {
  const char* kProxyString = "PROXY bad:99; PROXY maybe:80; DIRECT";
  SpdySessionDependencies session_deps(
      ProxyService::CreateFixedFromPacResult(kProxyString));

  // First connection attempt fails
  StaticSocketDataProvider socket_data1;
  socket_data1.set_connect_data(MockConnect(ASYNC, ERR_ADDRESS_UNREACHABLE));
  session_deps.socket_factory->AddSocketDataProvider(&socket_data1);

  // Second connection attempt succeeds
  StaticSocketDataProvider socket_data2;
  socket_data2.set_connect_data(MockConnect(ASYNC, OK));
  session_deps.socket_factory->AddSocketDataProvider(&socket_data2);

  std::unique_ptr<HttpNetworkSession> session(
      SpdySessionDependencies::SpdyCreateSession(&session_deps));

  // Now request a stream. It should succeed using the second proxy in the
  // list.
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("http://www.google.com");

  SSLConfig ssl_config;
  StreamRequestWaiter waiter;
  std::unique_ptr<HttpStreamRequest> request(
      session->http_stream_factory()->RequestStream(
          request_info, DEFAULT_PRIORITY, ssl_config, ssl_config, &waiter,
          /* enable_ip_based_pooling = */ true,
          /* enable_alternative_services = */ true, NetLogWithSource()));
  waiter.WaitForStream();

  // The proxy that failed should now be known to the proxy_service as bad.
  const ProxyRetryInfoMap& retry_info =
      session->proxy_service()->proxy_retry_info();
  EXPECT_EQ(1u, retry_info.size());
  ProxyRetryInfoMap::const_iterator iter = retry_info.find("bad:99");
  EXPECT_TRUE(iter != retry_info.end());
}

// List of errors that are used in the tests related to QUIC proxy.
const int quic_proxy_test_mock_errors[] = {
    ERR_PROXY_CONNECTION_FAILED,
    ERR_NAME_NOT_RESOLVED,
    ERR_ADDRESS_UNREACHABLE,
    ERR_CONNECTION_CLOSED,
    ERR_CONNECTION_TIMED_OUT,
    ERR_CONNECTION_RESET,
    ERR_CONNECTION_REFUSED,
    ERR_CONNECTION_ABORTED,
    ERR_TIMED_OUT,
    ERR_TUNNEL_CONNECTION_FAILED,
    ERR_SOCKS_CONNECTION_FAILED,
    ERR_PROXY_CERTIFICATE_INVALID,
    ERR_QUIC_PROTOCOL_ERROR,
    ERR_QUIC_HANDSHAKE_FAILED,
    ERR_SSL_PROTOCOL_ERROR,
    ERR_MSG_TOO_BIG,
};

// Tests that a bad QUIC proxy is added to the list of bad proxies.
TEST_F(HttpStreamFactoryTest, QuicProxyMarkedAsBad) {
  for (size_t i = 0; i < arraysize(quic_proxy_test_mock_errors); ++i) {
    std::unique_ptr<ProxyService> proxy_service;
    proxy_service =
        ProxyService::CreateFixedFromPacResult("QUIC bad:99; DIRECT");

    HttpNetworkSession::Params params;
    params.enable_quic = true;
    scoped_refptr<SSLConfigServiceDefaults> ssl_config_service(
        new SSLConfigServiceDefaults);
    HttpServerPropertiesImpl http_server_properties;
    MockClientSocketFactory socket_factory;
    params.client_socket_factory = &socket_factory;
    MockHostResolver host_resolver;
    params.host_resolver = &host_resolver;
    MockCertVerifier cert_verifier;
    params.cert_verifier = &cert_verifier;
    TransportSecurityState transport_security_state;
    params.transport_security_state = &transport_security_state;
    MultiLogCTVerifier ct_verifier;
    params.cert_transparency_verifier = &ct_verifier;
    CTPolicyEnforcer ct_policy_enforcer;
    params.ct_policy_enforcer = &ct_policy_enforcer;
    params.proxy_service = proxy_service.get();
    params.ssl_config_service = ssl_config_service.get();
    params.http_server_properties = &http_server_properties;

    std::unique_ptr<HttpNetworkSession> session(new HttpNetworkSession(params));
    session->quic_stream_factory()->set_require_confirmation(false);

    StaticSocketDataProvider socket_data1;
    socket_data1.set_connect_data(
        MockConnect(ASYNC, quic_proxy_test_mock_errors[i]));
    socket_factory.AddSocketDataProvider(&socket_data1);

    // Second connection attempt succeeds.
    StaticSocketDataProvider socket_data2;
    socket_data2.set_connect_data(MockConnect(ASYNC, OK));
    socket_factory.AddSocketDataProvider(&socket_data2);

    // Now request a stream. It should succeed using the second proxy in the
    // list.
    HttpRequestInfo request_info;
    request_info.method = "GET";
    request_info.url = GURL("http://www.google.com");

    SSLConfig ssl_config;
    StreamRequestWaiter waiter;
    std::unique_ptr<HttpStreamRequest> request(
        session->http_stream_factory()->RequestStream(
            request_info, DEFAULT_PRIORITY, ssl_config, ssl_config, &waiter,
            /* enable_ip_based_pooling = */ true,
            /* enable_alternative_services = */ true, NetLogWithSource()));
    waiter.WaitForStream();

    // The proxy that failed should now be known to the proxy_service as bad.
    const ProxyRetryInfoMap& retry_info =
        session->proxy_service()->proxy_retry_info();
    EXPECT_EQ(1u, retry_info.size()) << quic_proxy_test_mock_errors[i];
    EXPECT_TRUE(waiter.used_proxy_info().is_direct());

    ProxyRetryInfoMap::const_iterator iter = retry_info.find("quic://bad:99");
    EXPECT_TRUE(iter != retry_info.end()) << quic_proxy_test_mock_errors[i];
  }
}

// BidirectionalStreamImpl::Delegate to wait until response headers are
// received.
class TestBidirectionalDelegate : public BidirectionalStreamImpl::Delegate {
 public:
  void WaitUntilDone() { loop_.Run(); }

  const SpdyHeaderBlock& response_headers() const { return response_headers_; }

 private:
  void OnStreamReady(bool request_headers_sent) override {}
  void OnHeadersReceived(const SpdyHeaderBlock& response_headers) override {
    response_headers_ = response_headers.Clone();
    loop_.Quit();
  }
  void OnDataRead(int bytes_read) override { NOTREACHED(); }
  void OnDataSent() override { NOTREACHED(); }
  void OnTrailersReceived(const SpdyHeaderBlock& trailers) override {
    NOTREACHED();
  }
  void OnFailed(int error) override { NOTREACHED(); }
  base::RunLoop loop_;
  SpdyHeaderBlock response_headers_;
};

// Helper class to encapsulate MockReads and MockWrites for QUIC.
// Simplify ownership issues and the interaction with the MockSocketFactory.
class MockQuicData {
 public:
  MockQuicData() : packet_number_(0) {}

  ~MockQuicData() {}

  void AddRead(std::unique_ptr<QuicEncryptedPacket> packet) {
    reads_.push_back(
        MockRead(ASYNC, packet->data(), packet->length(), packet_number_++));
    packets_.push_back(std::move(packet));
  }

  void AddRead(IoMode mode, int rv) {
    reads_.push_back(MockRead(mode, rv, packet_number_++));
  }

  void AddWrite(std::unique_ptr<QuicEncryptedPacket> packet) {
    writes_.push_back(MockWrite(SYNCHRONOUS, packet->data(), packet->length(),
                                packet_number_++));
    packets_.push_back(std::move(packet));
  }

  void AddSocketDataToFactory(MockClientSocketFactory* factory) {
    MockRead* reads = reads_.empty() ? nullptr : &reads_[0];
    MockWrite* writes = writes_.empty() ? nullptr : &writes_[0];
    socket_data_.reset(
        new SequencedSocketData(reads, reads_.size(), writes, writes_.size()));
    factory->AddSocketDataProvider(socket_data_.get());
  }

 private:
  std::vector<std::unique_ptr<QuicEncryptedPacket>> packets_;
  std::vector<MockWrite> writes_;
  std::vector<MockRead> reads_;
  size_t packet_number_;
  std::unique_ptr<SequencedSocketData> socket_data_;
};

void SetupForQuicAlternativeProxyTest(
    HttpNetworkSession::Params* params,
    MockClientSocketFactory* socket_factory,
    ProxyService* proxy_service,
    TestProxyDelegate* test_proxy_delegate,
    HttpServerPropertiesImpl* http_server_properties,
    MockCertVerifier* cert_verifier,
    CTPolicyEnforcer* ct_policy_enforcer,
    MultiLogCTVerifier* ct_verifier,
    SSLConfigServiceDefaults* ssl_config_service,
    MockHostResolver* host_resolver,
    TransportSecurityState* transport_security_state,
    bool set_alternative_proxy_server) {
  params->enable_quic = true;
  params->client_socket_factory = socket_factory;
  params->host_resolver = host_resolver;
  params->transport_security_state = transport_security_state;
  params->proxy_service = proxy_service;
  params->ssl_config_service = ssl_config_service;
  params->http_server_properties = http_server_properties;
  params->cert_verifier = cert_verifier;
  params->ct_policy_enforcer = ct_policy_enforcer;
  params->cert_transparency_verifier = ct_verifier;

  if (set_alternative_proxy_server) {
    test_proxy_delegate->set_alternative_proxy_server(
        ProxyServer::FromPacString("QUIC badproxy:99"));
  }
  params->proxy_delegate = test_proxy_delegate;
}

}  // namespace

// Tests that a HTTPS proxy that supports QUIC alternative proxy server is
// marked as bad if connecting to both the default proxy and the alternative
// proxy is unsuccessful.
TEST_F(HttpStreamFactoryTest, WithQUICAlternativeProxyMarkedAsBad) {
  const bool set_alternative_proxy_server_values[] = {
      false, true,
  };

  for (auto mock_error : quic_proxy_test_mock_errors) {
    for (auto set_alternative_proxy_server :
         set_alternative_proxy_server_values) {
      HttpNetworkSession::Params params;
      MockClientSocketFactory socket_factory;
      std::unique_ptr<ProxyService> proxy_service =
          ProxyService::CreateFixedFromPacResult(
              "HTTPS badproxy:99; HTTPS badfallbackproxy:98; DIRECT");
      TestProxyDelegate test_proxy_delegate;
      HttpServerPropertiesImpl http_server_properties;
      MockCertVerifier cert_verifier;
      CTPolicyEnforcer ct_policy_enforcer;
      MultiLogCTVerifier ct_verifier;
      scoped_refptr<SSLConfigServiceDefaults> ssl_config_service(
          new SSLConfigServiceDefaults);
      MockHostResolver host_resolver;
      TransportSecurityState transport_security_state;
      SetupForQuicAlternativeProxyTest(
          &params, &socket_factory, proxy_service.get(), &test_proxy_delegate,
          &http_server_properties, &cert_verifier, &ct_policy_enforcer,
          &ct_verifier, ssl_config_service.get(), &host_resolver,
          &transport_security_state, set_alternative_proxy_server);

      std::unique_ptr<HttpNetworkSession> session(
          new HttpNetworkSession(params));

      // Before starting the test, verify that there are no proxies marked as
      // bad.
      ASSERT_TRUE(session->proxy_service()->proxy_retry_info().empty())
          << mock_error;

      StaticSocketDataProvider socket_data_proxy_main_job;
      socket_data_proxy_main_job.set_connect_data(
          MockConnect(ASYNC, mock_error));
      socket_factory.AddSocketDataProvider(&socket_data_proxy_main_job);

      StaticSocketDataProvider socket_data_proxy_alternate_job;
      if (set_alternative_proxy_server) {
        // Mock socket used by the QUIC job.
        socket_data_proxy_alternate_job.set_connect_data(
            MockConnect(ASYNC, mock_error));
        socket_factory.AddSocketDataProvider(&socket_data_proxy_alternate_job);
      }

      // When retrying the job using the second proxy (badFallback:98),
      // alternative job must not be created. So, socket data for only the
      // main job is needed.
      StaticSocketDataProvider socket_data_proxy_main_job_2;
      socket_data_proxy_main_job_2.set_connect_data(
          MockConnect(ASYNC, mock_error));
      socket_factory.AddSocketDataProvider(&socket_data_proxy_main_job_2);

      SSLSocketDataProvider ssl_data(ASYNC, OK);

      // First request would use DIRECT, and succeed.
      StaticSocketDataProvider socket_data_direct_first_request;
      socket_data_direct_first_request.set_connect_data(MockConnect(ASYNC, OK));
      socket_factory.AddSocketDataProvider(&socket_data_direct_first_request);
      socket_factory.AddSSLSocketDataProvider(&ssl_data);

      // Second request would use DIRECT, and succeed.
      StaticSocketDataProvider socket_data_direct_second_request;
      socket_data_direct_second_request.set_connect_data(
          MockConnect(ASYNC, OK));
      socket_factory.AddSocketDataProvider(&socket_data_direct_second_request);
      socket_factory.AddSSLSocketDataProvider(&ssl_data);

      // Now request a stream. It should succeed using the DIRECT.
      HttpRequestInfo request_info;
      request_info.method = "GET";
      request_info.url = GURL("http://www.google.com");

      SSLConfig ssl_config;
      StreamRequestWaiter waiter;

      EXPECT_EQ(set_alternative_proxy_server,
                test_proxy_delegate.alternative_proxy_server().is_quic());

      // Start two requests. The first request should consume data from
      // |socket_data_proxy_main_job|,
      // |socket_data_proxy_alternate_job| and
      // |socket_data_direct_first_request|. The second request should consume
      // data from |socket_data_direct_second_request|.
      for (size_t i = 0; i < 2; ++i) {
        std::unique_ptr<HttpStreamRequest> request(
            session->http_stream_factory()->RequestStream(
                request_info, DEFAULT_PRIORITY, ssl_config, ssl_config, &waiter,
                /* enable_ip_based_pooling = */ true,
                /* enable_alternative_services = */ true, NetLogWithSource()));
        waiter.WaitForStream();

        // The proxy that failed should now be known to the proxy_service as
        // bad.
        const ProxyRetryInfoMap retry_info =
            session->proxy_service()->proxy_retry_info();
        EXPECT_EQ(2u, retry_info.size()) << mock_error;

        // Verify that request was fetched without proxy.
        EXPECT_TRUE(waiter.used_proxy_info().is_direct());

        EXPECT_NE(retry_info.end(), retry_info.find("https://badproxy:99"));
        EXPECT_NE(retry_info.end(),
                  retry_info.find("https://badfallbackproxy:98"));

        // If alternative proxy server was specified, it should have been marked
        // as invalid so that it is not used for subsequent requests.
        EXPECT_FALSE(test_proxy_delegate.alternative_proxy_server().is_valid());

        if (set_alternative_proxy_server) {
          // GetAlternativeProxy should be called only once for the first
          // request.
          EXPECT_EQ(1, test_proxy_delegate.get_alternative_proxy_invocations());
        } else {
          // Alternative proxy server job is never started. So, ProxyDelegate is
          // queried once per request.
          EXPECT_EQ(2, test_proxy_delegate.get_alternative_proxy_invocations());
        }
      }
    }
  }
}

// Tests that a HTTPS proxy that supports QUIC alternative proxy server is
// not marked as bad if only the alternative proxy server job fails.
TEST_F(HttpStreamFactoryTest, WithQUICAlternativeProxyNotMarkedAsBad) {
  for (auto mock_error : quic_proxy_test_mock_errors) {
    HttpNetworkSession::Params params;
    MockClientSocketFactory socket_factory;
    std::unique_ptr<ProxyService> proxy_service =
        ProxyService::CreateFixedFromPacResult("HTTPS badproxy:99; DIRECT");
    TestProxyDelegate test_proxy_delegate;
    HttpServerPropertiesImpl http_server_properties;
    MockCertVerifier cert_verifier;
    CTPolicyEnforcer ct_policy_enforcer;
    MultiLogCTVerifier ct_verifier;

    scoped_refptr<SSLConfigServiceDefaults> ssl_config_service(
        new SSLConfigServiceDefaults);
    MockHostResolver host_resolver;
    TransportSecurityState transport_security_state;

    SetupForQuicAlternativeProxyTest(
        &params, &socket_factory, proxy_service.get(), &test_proxy_delegate,
        &http_server_properties, &cert_verifier, &ct_policy_enforcer,
        &ct_verifier, ssl_config_service.get(), &host_resolver,
        &transport_security_state, true);

    HostPortPair host_port_pair("badproxy", 99);
    std::unique_ptr<HttpNetworkSession> session(new HttpNetworkSession(params));

    // Before starting the test, verify that there are no proxies marked as
    // bad.
    ASSERT_TRUE(session->proxy_service()->proxy_retry_info().empty())
        << mock_error;

    StaticSocketDataProvider socket_data_proxy_main_job;
    socket_data_proxy_main_job.set_connect_data(MockConnect(ASYNC, mock_error));
    socket_factory.AddSocketDataProvider(&socket_data_proxy_main_job);

    SSLSocketDataProvider ssl_data(ASYNC, OK);

    // Next connection attempt would use HTTPS proxy, and succeed.
    StaticSocketDataProvider socket_data_https_first;
    socket_data_https_first.set_connect_data(MockConnect(ASYNC, OK));
    socket_factory.AddSocketDataProvider(&socket_data_https_first);
    socket_factory.AddSSLSocketDataProvider(&ssl_data);

    // Next connection attempt would use HTTPS proxy, and succeed.
    StaticSocketDataProvider socket_data_https_second;
    socket_data_https_second.set_connect_data(MockConnect(ASYNC, OK));
    socket_factory.AddSocketDataProvider(&socket_data_https_second);
    socket_factory.AddSSLSocketDataProvider(&ssl_data);

    // Now request a stream. It should succeed using the second proxy in the
    // list.
    HttpRequestInfo request_info;
    request_info.method = "GET";
    request_info.url = GURL("http://www.google.com");

    SSLConfig ssl_config;
    StreamRequestWaiter waiter;

    EXPECT_TRUE(test_proxy_delegate.alternative_proxy_server().is_quic());

    // Start two requests. The first request should consume data from
    // |socket_data_proxy_main_job| and |socket_data_https_first|.
    // The second request should consume data from |socket_data_https_second|.
    for (size_t i = 0; i < 2; ++i) {
      std::unique_ptr<HttpStreamRequest> request(
          session->http_stream_factory()->RequestStream(
              request_info, DEFAULT_PRIORITY, ssl_config, ssl_config, &waiter,
              /* enable_ip_based_pooling = */ true,
              /* enable_alternative_services = */ true, NetLogWithSource()));
      waiter.WaitForStream();

      // The proxy that failed should now be known to the proxy_service as
      // bad.
      const ProxyRetryInfoMap retry_info =
          session->proxy_service()->proxy_retry_info();
      // Proxy should not be marked as bad.
      EXPECT_EQ(0u, retry_info.size()) << mock_error;
      // Verify that request was fetched using proxy.
      EXPECT_TRUE(waiter.used_proxy_info().is_https());
      EXPECT_TRUE(host_port_pair.Equals(
          waiter.used_proxy_info().proxy_server().host_port_pair()));
      net::ProxyServer proxy_server;

      // Alternative proxy server should be marked as invalid so that it is
      // not used for subsequent requests.
      EXPECT_FALSE(test_proxy_delegate.alternative_proxy_server().is_quic());

      // GetAlternativeProxy should be called only once per request.
      EXPECT_EQ(static_cast<int>(i + 1),
                test_proxy_delegate.get_alternative_proxy_invocations());
    }
  }
}

TEST_F(HttpStreamFactoryTest, UsePreConnectIfNoZeroRTT) {
  for (int num_streams = 1; num_streams < 3; ++num_streams) {
    GURL url = GURL("https://www.google.com");

    // Set up QUIC as alternative_service.
    HttpServerPropertiesImpl http_server_properties;
    const AlternativeService alternative_service(kProtoQUIC, url.host().c_str(),
                                                 url.IntPort());
    AlternativeServiceInfoVector alternative_service_info_vector;
    base::Time expiration = base::Time::Now() + base::TimeDelta::FromDays(1);
    alternative_service_info_vector.push_back(
        AlternativeServiceInfo(alternative_service, expiration));
    HostPortPair host_port_pair(alternative_service.host_port_pair());
    url::SchemeHostPort server("https", host_port_pair.host(),
                               host_port_pair.port());
    http_server_properties.SetAlternativeServices(
        server, alternative_service_info_vector);

    SpdySessionDependencies session_deps(
        ProxyService::CreateFixed("http_proxy"));

    // Setup params to disable preconnect, but QUIC doesn't 0RTT.
    HttpNetworkSession::Params params =
        SpdySessionDependencies::CreateSessionParams(&session_deps);
    params.enable_quic = true;
    params.http_server_properties = &http_server_properties;

    std::unique_ptr<HttpNetworkSession> session(new HttpNetworkSession(params));
    HttpNetworkSessionPeer peer(session.get());
    HostPortPair proxy_host("http_proxy", 80);
    CapturePreconnectsHttpProxySocketPool* http_proxy_pool =
        new CapturePreconnectsHttpProxySocketPool(
            session_deps.host_resolver.get(), session_deps.cert_verifier.get(),
            session_deps.transport_security_state.get(),
            session_deps.cert_transparency_verifier.get(),
            session_deps.ct_policy_enforcer.get());
    CapturePreconnectsSSLSocketPool* ssl_conn_pool =
        new CapturePreconnectsSSLSocketPool(
            session_deps.host_resolver.get(), session_deps.cert_verifier.get(),
            session_deps.transport_security_state.get(),
            session_deps.cert_transparency_verifier.get(),
            session_deps.ct_policy_enforcer.get());
    std::unique_ptr<MockClientSocketPoolManager> mock_pool_manager(
        new MockClientSocketPoolManager);
    mock_pool_manager->SetSocketPoolForHTTPProxy(
        proxy_host, base::WrapUnique(http_proxy_pool));
    mock_pool_manager->SetSocketPoolForSSLWithProxy(
        proxy_host, base::WrapUnique(ssl_conn_pool));
    peer.SetClientSocketPoolManager(std::move(mock_pool_manager));
    PreconnectHelperForURL(num_streams, url, session.get());
    EXPECT_EQ(num_streams, ssl_conn_pool->last_num_streams());
  }
}

// Verify that only one preconnect job succeeds to a proxy server that supports
// request priorities.
TEST_F(HttpStreamFactoryTest, OnlyOnePreconnectToProxyServer) {
  for (bool set_http_server_properties : {false, true}) {
    for (int num_streams = 1; num_streams < 3; ++num_streams) {
      base::HistogramTester histogram_tester;
      GURL url = GURL("http://www.google.com");
      std::unique_ptr<ProxyService> proxy_service =
          ProxyService::CreateFixedFromPacResult("HTTPS myproxy.org:443");

      // Set up the proxy server as a server that supports request priorities.
      HttpServerPropertiesImpl http_server_properties;
      if (set_http_server_properties) {
        url::SchemeHostPort spdy_server("https", "myproxy.org", 443);
        http_server_properties.SetSupportsSpdy(spdy_server, true);
      }

      SpdySessionDependencies session_deps;
      HttpNetworkSession::Params params =
          SpdySessionDependencies::CreateSessionParams(&session_deps);
      params.enable_quic = true;
      params.proxy_service = proxy_service.get();
      params.http_server_properties = &http_server_properties;

      std::unique_ptr<HttpNetworkSession> session(
          new HttpNetworkSession(params));

      HttpNetworkSessionPeer peer(session.get());
      HostPortPair proxy_host("myproxy.org", 443);

      for (int preconnect_request = 0; preconnect_request < 2;
           ++preconnect_request) {
        CapturePreconnectsHttpProxySocketPool* http_proxy_pool =
            new CapturePreconnectsHttpProxySocketPool(
                session_deps.host_resolver.get(),
                session_deps.cert_verifier.get(),
                session_deps.transport_security_state.get(),
                session_deps.cert_transparency_verifier.get(),
                session_deps.ct_policy_enforcer.get());
        CapturePreconnectsSSLSocketPool* ssl_conn_pool =
            new CapturePreconnectsSSLSocketPool(
                session_deps.host_resolver.get(),
                session_deps.cert_verifier.get(),
                session_deps.transport_security_state.get(),
                session_deps.cert_transparency_verifier.get(),
                session_deps.ct_policy_enforcer.get());

        std::unique_ptr<MockClientSocketPoolManager> mock_pool_manager(
            new MockClientSocketPoolManager);
        mock_pool_manager->SetSocketPoolForHTTPProxy(
            proxy_host, base::WrapUnique(http_proxy_pool));
        mock_pool_manager->SetSocketPoolForSSLWithProxy(
            proxy_host, base::WrapUnique(ssl_conn_pool));
        peer.SetClientSocketPoolManager(std::move(mock_pool_manager));

        HttpRequestInfo request;
        request.method = "GET";
        request.url = url;
        request.load_flags = 0;

        if (preconnect_request == 0) {
          // First preconnect job should succeed.
          session->http_stream_factory()->PreconnectStreams(num_streams,
                                                            request);
          EXPECT_EQ(-1, ssl_conn_pool->last_num_streams());
          EXPECT_EQ(num_streams, http_proxy_pool->last_num_streams());
        } else {
          // Second preconnect job should not succeed.
          session->http_stream_factory()->PreconnectStreams(num_streams,
                                                            request);
          EXPECT_EQ(-1, ssl_conn_pool->last_num_streams());
          if (set_http_server_properties) {
            EXPECT_EQ(-1, http_proxy_pool->last_num_streams());
          } else {
            EXPECT_EQ(num_streams, http_proxy_pool->last_num_streams());
          }
        }
      }
      // Preconnects should be skipped only to proxy servers that support
      // request priorities.
      if (set_http_server_properties) {
        histogram_tester.ExpectUniqueSample(
            "Net.PreconnectSkippedToProxyServers", 1, 1);
      } else {
        histogram_tester.ExpectTotalCount("Net.PreconnectSkippedToProxyServers",
                                          0);
      }
    }
  }
}

// Verify that preconnect to a HTTP2 proxy server with a privacy mode different
// than that of the in-flight preconnect job succeeds.
TEST_F(HttpStreamFactoryTest, ProxyServerPreconnectDifferentPrivacyModes) {
  int num_streams = 1;
  base::HistogramTester histogram_tester;
  GURL url = GURL("http://www.google.com");
  std::unique_ptr<ProxyService> proxy_service =
      ProxyService::CreateFixedFromPacResult("HTTPS myproxy.org:443");

  // Set up the proxy server as a server that supports request priorities.
  HttpServerPropertiesImpl http_server_properties;

  url::SchemeHostPort spdy_server("https", "myproxy.org", 443);
  http_server_properties.SetSupportsSpdy(spdy_server, true);

  SpdySessionDependencies session_deps;
  HttpNetworkSession::Params params =
      SpdySessionDependencies::CreateSessionParams(&session_deps);
  params.enable_quic = true;
  params.proxy_service = proxy_service.get();
  params.http_server_properties = &http_server_properties;

  std::unique_ptr<HttpNetworkSession> session(new HttpNetworkSession(params));

  HttpNetworkSessionPeer peer(session.get());
  HostPortPair proxy_host("myproxy.org", 443);

  CapturePreconnectsHttpProxySocketPool* http_proxy_pool =
      new CapturePreconnectsHttpProxySocketPool(
          session_deps.host_resolver.get(), session_deps.cert_verifier.get(),
          session_deps.transport_security_state.get(),
          session_deps.cert_transparency_verifier.get(),
          session_deps.ct_policy_enforcer.get());
  CapturePreconnectsSSLSocketPool* ssl_conn_pool =
      new CapturePreconnectsSSLSocketPool(
          session_deps.host_resolver.get(), session_deps.cert_verifier.get(),
          session_deps.transport_security_state.get(),
          session_deps.cert_transparency_verifier.get(),
          session_deps.ct_policy_enforcer.get());

  std::unique_ptr<MockClientSocketPoolManager> mock_pool_manager(
      new MockClientSocketPoolManager);
  mock_pool_manager->SetSocketPoolForHTTPProxy(
      proxy_host, base::WrapUnique(http_proxy_pool));
  mock_pool_manager->SetSocketPoolForSSLWithProxy(
      proxy_host, base::WrapUnique(ssl_conn_pool));
  peer.SetClientSocketPoolManager(std::move(mock_pool_manager));

  HttpRequestInfo request_privacy_mode_disabled;
  request_privacy_mode_disabled.method = "GET";
  request_privacy_mode_disabled.url = url;
  request_privacy_mode_disabled.load_flags = 0;

  // First preconnect job should succeed.
  session->http_stream_factory()->PreconnectStreams(
      num_streams, request_privacy_mode_disabled);
  EXPECT_EQ(-1, ssl_conn_pool->last_num_streams());
  EXPECT_EQ(num_streams, http_proxy_pool->last_num_streams());
  http_proxy_pool->reset_last_num_streams();

  // Second preconnect job with same privacy mode should not succeed.
  session->http_stream_factory()->PreconnectStreams(
      num_streams + 1, request_privacy_mode_disabled);
  EXPECT_EQ(-1, ssl_conn_pool->last_num_streams());
  EXPECT_EQ(-1, http_proxy_pool->last_num_streams());

  // Next request with a different privacy mode should succeed.
  HttpRequestInfo request_privacy_mode_enabled;
  request_privacy_mode_enabled.method = "GET";
  request_privacy_mode_enabled.url = url;
  request_privacy_mode_enabled.load_flags = 0;
  request_privacy_mode_enabled.privacy_mode = PRIVACY_MODE_ENABLED;

  // Request with a different privacy mode should succeed.
  session->http_stream_factory()->PreconnectStreams(
      num_streams, request_privacy_mode_enabled);
  EXPECT_EQ(-1, ssl_conn_pool->last_num_streams());
  EXPECT_EQ(num_streams, http_proxy_pool->last_num_streams());
}

namespace {

TEST_F(HttpStreamFactoryTest, PrivacyModeDisablesChannelId) {
  SpdySessionDependencies session_deps(ProxyService::CreateDirect());

  StaticSocketDataProvider socket_data;
  socket_data.set_connect_data(MockConnect(ASYNC, OK));
  session_deps.socket_factory->AddSocketDataProvider(&socket_data);

  SSLSocketDataProvider ssl(ASYNC, OK);
  session_deps.socket_factory->AddSSLSocketDataProvider(&ssl);

  std::unique_ptr<HttpNetworkSession> session(
      SpdySessionDependencies::SpdyCreateSession(&session_deps));

  // Set an existing SpdySession in the pool.
  HostPortPair host_port_pair("www.google.com", 443);
  SpdySessionKey key(host_port_pair, ProxyServer::Direct(),
                     PRIVACY_MODE_ENABLED);

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");
  request_info.load_flags = 0;
  request_info.privacy_mode = PRIVACY_MODE_DISABLED;

  SSLConfig ssl_config;
  StreamRequestWaiter waiter;
  std::unique_ptr<HttpStreamRequest> request(
      session->http_stream_factory()->RequestStream(
          request_info, DEFAULT_PRIORITY, ssl_config, ssl_config, &waiter,
          /* enable_ip_based_pooling = */ true,
          /* enable_alternative_services = */ true, NetLogWithSource()));
  waiter.WaitForStream();

  // The stream shouldn't come from spdy as we are using different privacy mode
  EXPECT_FALSE(request->using_spdy());

  SSLConfig used_ssl_config = waiter.used_ssl_config();
  EXPECT_EQ(used_ssl_config.channel_id_enabled, ssl_config.channel_id_enabled);
}

namespace {

// Return count of distinct groups in given socket pool.
int GetSocketPoolGroupCount(ClientSocketPool* pool) {
  int count = 0;
  std::unique_ptr<base::DictionaryValue> dict(
      pool->GetInfoAsValue("", "", false));
  EXPECT_TRUE(dict != nullptr);
  base::DictionaryValue* groups = nullptr;
  if (dict->GetDictionary("groups", &groups) && (groups != nullptr)) {
    count = static_cast<int>(groups->size());
  }
  return count;
}

// Return count of distinct spdy sessions.
int GetSpdySessionCount(HttpNetworkSession* session) {
  std::unique_ptr<base::Value> value(
      session->spdy_session_pool()->SpdySessionPoolInfoToValue());
  base::ListValue* session_list;
  if (!value || !value->GetAsList(&session_list))
    return -1;
  return session_list->GetSize();
}

}  // namespace

TEST_F(HttpStreamFactoryTest, PrivacyModeUsesDifferentSocketPoolGroup) {
  SpdySessionDependencies session_deps(ProxyService::CreateDirect());

  StaticSocketDataProvider socket_data_1;
  socket_data_1.set_connect_data(MockConnect(ASYNC, OK));
  session_deps.socket_factory->AddSocketDataProvider(&socket_data_1);
  StaticSocketDataProvider socket_data_2;
  socket_data_2.set_connect_data(MockConnect(ASYNC, OK));
  session_deps.socket_factory->AddSocketDataProvider(&socket_data_2);
  StaticSocketDataProvider socket_data_3;
  socket_data_3.set_connect_data(MockConnect(ASYNC, OK));
  session_deps.socket_factory->AddSocketDataProvider(&socket_data_3);

  SSLSocketDataProvider ssl_1(ASYNC, OK);
  session_deps.socket_factory->AddSSLSocketDataProvider(&ssl_1);
  SSLSocketDataProvider ssl_2(ASYNC, OK);
  session_deps.socket_factory->AddSSLSocketDataProvider(&ssl_2);
  SSLSocketDataProvider ssl_3(ASYNC, OK);
  session_deps.socket_factory->AddSSLSocketDataProvider(&ssl_3);

  std::unique_ptr<HttpNetworkSession> session(
      SpdySessionDependencies::SpdyCreateSession(&session_deps));
  SSLClientSocketPool* ssl_pool = session->GetSSLSocketPool(
      HttpNetworkSession::NORMAL_SOCKET_POOL);

  EXPECT_EQ(GetSocketPoolGroupCount(ssl_pool), 0);

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");
  request_info.load_flags = 0;
  request_info.privacy_mode = PRIVACY_MODE_DISABLED;

  SSLConfig ssl_config;
  StreamRequestWaiter waiter;

  std::unique_ptr<HttpStreamRequest> request1(
      session->http_stream_factory()->RequestStream(
          request_info, DEFAULT_PRIORITY, ssl_config, ssl_config, &waiter,
          /* enable_ip_based_pooling = */ true,
          /* enable_alternative_services = */ true, NetLogWithSource()));
  waiter.WaitForStream();

  EXPECT_EQ(GetSocketPoolGroupCount(ssl_pool), 1);

  std::unique_ptr<HttpStreamRequest> request2(
      session->http_stream_factory()->RequestStream(
          request_info, DEFAULT_PRIORITY, ssl_config, ssl_config, &waiter,
          /* enable_ip_based_pooling = */ true,
          /* enable_alternative_services = */ true, NetLogWithSource()));
  waiter.WaitForStream();

  EXPECT_EQ(GetSocketPoolGroupCount(ssl_pool), 1);

  request_info.privacy_mode = PRIVACY_MODE_ENABLED;
  std::unique_ptr<HttpStreamRequest> request3(
      session->http_stream_factory()->RequestStream(
          request_info, DEFAULT_PRIORITY, ssl_config, ssl_config, &waiter,
          /* enable_ip_based_pooling = */ true,
          /* enable_alternative_services = */ true, NetLogWithSource()));
  waiter.WaitForStream();

  EXPECT_EQ(GetSocketPoolGroupCount(ssl_pool), 2);
}

TEST_F(HttpStreamFactoryTest, GetLoadState) {
  SpdySessionDependencies session_deps(ProxyService::CreateDirect());

  // Force asynchronous host resolutions, so that the LoadState will be
  // resolving the host.
  session_deps.host_resolver->set_synchronous_mode(false);

  StaticSocketDataProvider socket_data;
  socket_data.set_connect_data(MockConnect(ASYNC, OK));
  session_deps.socket_factory->AddSocketDataProvider(&socket_data);

  std::unique_ptr<HttpNetworkSession> session(
      SpdySessionDependencies::SpdyCreateSession(&session_deps));

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("http://www.google.com");

  SSLConfig ssl_config;
  StreamRequestWaiter waiter;
  std::unique_ptr<HttpStreamRequest> request(
      session->http_stream_factory()->RequestStream(
          request_info, DEFAULT_PRIORITY, ssl_config, ssl_config, &waiter,
          /* enable_ip_based_pooling = */ true,
          /* enable_alternative_services = */ true, NetLogWithSource()));

  EXPECT_EQ(LOAD_STATE_RESOLVING_HOST, request->GetLoadState());

  waiter.WaitForStream();
}

TEST_F(HttpStreamFactoryTest, RequestHttpStream) {
  SpdySessionDependencies session_deps(ProxyService::CreateDirect());

  StaticSocketDataProvider socket_data;
  socket_data.set_connect_data(MockConnect(ASYNC, OK));
  session_deps.socket_factory->AddSocketDataProvider(&socket_data);

  std::unique_ptr<HttpNetworkSession> session(
      SpdySessionDependencies::SpdyCreateSession(&session_deps));

  // Now request a stream.  It should succeed using the second proxy in the
  // list.
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("http://www.google.com");
  request_info.load_flags = 0;

  SSLConfig ssl_config;
  StreamRequestWaiter waiter;
  std::unique_ptr<HttpStreamRequest> request(
      session->http_stream_factory()->RequestStream(
          request_info, DEFAULT_PRIORITY, ssl_config, ssl_config, &waiter,
          /* enable_ip_based_pooling = */ true,
          /* enable_alternative_services = */ true, NetLogWithSource()));
  waiter.WaitForStream();
  EXPECT_TRUE(waiter.stream_done());
  ASSERT_TRUE(nullptr != waiter.stream());
  EXPECT_TRUE(nullptr == waiter.websocket_stream());

  EXPECT_EQ(0, GetSpdySessionCount(session.get()));
  EXPECT_EQ(1, GetSocketPoolGroupCount(
      session->GetTransportSocketPool(HttpNetworkSession::NORMAL_SOCKET_POOL)));
  EXPECT_EQ(0, GetSocketPoolGroupCount(session->GetSSLSocketPool(
      HttpNetworkSession::NORMAL_SOCKET_POOL)));
  EXPECT_EQ(0, GetSocketPoolGroupCount(
      session->GetTransportSocketPool(
          HttpNetworkSession::WEBSOCKET_SOCKET_POOL)));
  EXPECT_EQ(0, GetSocketPoolGroupCount(session->GetSSLSocketPool(
      HttpNetworkSession::WEBSOCKET_SOCKET_POOL)));
  EXPECT_TRUE(waiter.used_proxy_info().is_direct());
}

// Test the race of SetPriority versus stream completion where SetPriority
// may be called on an HttpStreamFactoryImpl::Job after the stream
// has been created by the job.
TEST_F(HttpStreamFactoryTest, ReprioritizeAfterStreamReceived) {
  SpdySessionDependencies session_deps(ProxyService::CreateDirect());

  MockRead mock_read(SYNCHRONOUS, ERR_IO_PENDING);
  StaticSocketDataProvider socket_data(&mock_read, 1, nullptr, 0);
  socket_data.set_connect_data(MockConnect(SYNCHRONOUS, OK));
  session_deps.socket_factory->AddSocketDataProvider(&socket_data);

  SSLSocketDataProvider ssl_socket_data(SYNCHRONOUS, OK);
  ssl_socket_data.next_proto = kProtoHTTP2;
  session_deps.socket_factory->AddSSLSocketDataProvider(&ssl_socket_data);

  std::unique_ptr<HttpNetworkSession> session(
      SpdySessionDependencies::SpdyCreateSession(&session_deps));

  // Now request a stream.
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");
  request_info.load_flags = 0;

  SSLConfig ssl_config;
  StreamRequestWaiter waiter;
  EXPECT_EQ(0, GetSpdySessionCount(session.get()));
  std::unique_ptr<HttpStreamRequest> request(
      session->http_stream_factory()->RequestStream(
          request_info, LOWEST, ssl_config, ssl_config, &waiter,
          /* enable_ip_based_pooling = */ true,
          /* enable_alternative_services = */ true, NetLogWithSource()));
  EXPECT_FALSE(waiter.stream_done());

  // Confirm a stream has been created by asserting that a new session
  // has been created.  (The stream is only created at the SPDY level on
  // first write, which happens after the request has returned a stream).
  ASSERT_EQ(1, GetSpdySessionCount(session.get()));

  // Test to confirm that a SetPriority received after the stream is created
  // but before the request returns it does not crash.
  request->SetPriority(HIGHEST);

  waiter.WaitForStream();
  EXPECT_TRUE(waiter.stream_done());
  ASSERT_TRUE(waiter.stream());
  EXPECT_FALSE(waiter.websocket_stream());
}

TEST_F(HttpStreamFactoryTest, RequestHttpStreamOverSSL) {
  SpdySessionDependencies session_deps(ProxyService::CreateDirect());

  MockRead mock_read(ASYNC, OK);
  StaticSocketDataProvider socket_data(&mock_read, 1, nullptr, 0);
  socket_data.set_connect_data(MockConnect(ASYNC, OK));
  session_deps.socket_factory->AddSocketDataProvider(&socket_data);

  SSLSocketDataProvider ssl_socket_data(ASYNC, OK);
  session_deps.socket_factory->AddSSLSocketDataProvider(&ssl_socket_data);

  std::unique_ptr<HttpNetworkSession> session(
      SpdySessionDependencies::SpdyCreateSession(&session_deps));

  // Now request a stream.
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");
  request_info.load_flags = 0;

  SSLConfig ssl_config;
  StreamRequestWaiter waiter;
  std::unique_ptr<HttpStreamRequest> request(
      session->http_stream_factory()->RequestStream(
          request_info, DEFAULT_PRIORITY, ssl_config, ssl_config, &waiter,
          /* enable_ip_based_pooling = */ true,
          /* enable_alternative_services = */ true, NetLogWithSource()));
  waiter.WaitForStream();
  EXPECT_TRUE(waiter.stream_done());
  ASSERT_TRUE(nullptr != waiter.stream());
  EXPECT_TRUE(nullptr == waiter.websocket_stream());

  EXPECT_EQ(0, GetSpdySessionCount(session.get()));
  EXPECT_EQ(1, GetSocketPoolGroupCount(
      session->GetTransportSocketPool(HttpNetworkSession::NORMAL_SOCKET_POOL)));
  EXPECT_EQ(1, GetSocketPoolGroupCount(
      session->GetSSLSocketPool(HttpNetworkSession::NORMAL_SOCKET_POOL)));
  EXPECT_EQ(0, GetSocketPoolGroupCount(
      session->GetTransportSocketPool(
          HttpNetworkSession::WEBSOCKET_SOCKET_POOL)));
  EXPECT_EQ(0, GetSocketPoolGroupCount(session->GetSSLSocketPool(
      HttpNetworkSession::WEBSOCKET_SOCKET_POOL)));
  EXPECT_TRUE(waiter.used_proxy_info().is_direct());
}

TEST_F(HttpStreamFactoryTest, RequestHttpStreamOverProxy) {
  SpdySessionDependencies session_deps(
      ProxyService::CreateFixed("myproxy:8888"));

  StaticSocketDataProvider socket_data;
  socket_data.set_connect_data(MockConnect(ASYNC, OK));
  session_deps.socket_factory->AddSocketDataProvider(&socket_data);

  std::unique_ptr<HttpNetworkSession> session(
      SpdySessionDependencies::SpdyCreateSession(&session_deps));

  // Now request a stream.  It should succeed using the second proxy in the
  // list.
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("http://www.google.com");
  request_info.load_flags = 0;

  SSLConfig ssl_config;
  StreamRequestWaiter waiter;
  std::unique_ptr<HttpStreamRequest> request(
      session->http_stream_factory()->RequestStream(
          request_info, DEFAULT_PRIORITY, ssl_config, ssl_config, &waiter,
          /* enable_ip_based_pooling = */ true,
          /* enable_alternative_services = */ true, NetLogWithSource()));
  waiter.WaitForStream();
  EXPECT_TRUE(waiter.stream_done());
  ASSERT_TRUE(nullptr != waiter.stream());
  EXPECT_TRUE(nullptr == waiter.websocket_stream());

  EXPECT_EQ(0, GetSpdySessionCount(session.get()));
  EXPECT_EQ(0, GetSocketPoolGroupCount(
      session->GetTransportSocketPool(HttpNetworkSession::NORMAL_SOCKET_POOL)));
  EXPECT_EQ(0, GetSocketPoolGroupCount(
      session->GetSSLSocketPool(HttpNetworkSession::NORMAL_SOCKET_POOL)));
  EXPECT_EQ(1, GetSocketPoolGroupCount(session->GetSocketPoolForHTTPProxy(
      HttpNetworkSession::NORMAL_SOCKET_POOL,
      HostPortPair("myproxy", 8888))));
  EXPECT_EQ(0, GetSocketPoolGroupCount(session->GetSocketPoolForSSLWithProxy(
      HttpNetworkSession::NORMAL_SOCKET_POOL,
      HostPortPair("myproxy", 8888))));
  EXPECT_EQ(0, GetSocketPoolGroupCount(session->GetSocketPoolForHTTPProxy(
      HttpNetworkSession::WEBSOCKET_SOCKET_POOL,
      HostPortPair("myproxy", 8888))));
  EXPECT_EQ(0, GetSocketPoolGroupCount(session->GetSocketPoolForSSLWithProxy(
      HttpNetworkSession::WEBSOCKET_SOCKET_POOL,
      HostPortPair("myproxy", 8888))));
  EXPECT_FALSE(waiter.used_proxy_info().is_direct());
}

// Verifies that once a stream has been created to a proxy server (that supports
// request priorities) the next preconnect job can again open new sockets.
TEST_F(HttpStreamFactoryTest, RequestHttpStreamOverProxyWithPreconnects) {
  SpdySessionDependencies session_deps(
      ProxyService::CreateFixed("https://myproxy.org:443"));

  // Set up the proxy server as a server that supports request priorities.
  std::unique_ptr<HttpServerPropertiesImpl> http_server_properties(
      new HttpServerPropertiesImpl());
  url::SchemeHostPort spdy_server("https", "myproxy.org", 443);
  http_server_properties->SetSupportsSpdy(spdy_server, true);
  session_deps.http_server_properties = std::move(http_server_properties);

  StaticSocketDataProvider socket_data;
  socket_data.set_connect_data(MockConnect(ASYNC, OK));
  session_deps.socket_factory->AddSocketDataProvider(&socket_data);

  SSLSocketDataProvider ssl_data(ASYNC, OK);
  session_deps.socket_factory->AddSSLSocketDataProvider(&ssl_data);

  std::unique_ptr<HttpNetworkSession> session(
      SpdySessionDependencies::SpdyCreateSession(&session_deps));

  // Now preconnect a request. Only the first preconnect should succeed.
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("http://www.google.com");
  request_info.load_flags = 0;

  base::HistogramTester histogram_tester;
  const int num_preconnects = 5;

  // First preconnect would be successful. The next |num_preconnects-1| would be
  // skipped.
  for (int preconnect_request = 1; preconnect_request <= num_preconnects;
       ++preconnect_request) {
    session->http_stream_factory()->PreconnectStreams(1, request_info);
    base::RunLoop().RunUntilIdle();
    while (GetSocketPoolGroupCount(session->GetSocketPoolForHTTPProxy(
               HttpNetworkSession::NORMAL_SOCKET_POOL,
               HostPortPair("myproxy.org", 443))) == 0) {
      base::RunLoop().RunUntilIdle();
    }
  }

  histogram_tester.ExpectUniqueSample("Net.PreconnectSkippedToProxyServers", 1,
                                      num_preconnects - 1);

  // Start a request. This should cause subsequent preconnect to proxy server to
  // succeed.
  SSLConfig ssl_config;
  StreamRequestWaiter waiter;
  std::unique_ptr<HttpStreamRequest> request(
      session->http_stream_factory()->RequestStream(
          request_info, DEFAULT_PRIORITY, ssl_config, ssl_config, &waiter,
          /* enable_ip_based_pooling = */ true,
          /* enable_alternative_services = */ true, NetLogWithSource()));
  waiter.WaitForStream();
  EXPECT_TRUE(waiter.stream_done());
  ASSERT_TRUE(nullptr != waiter.stream());
  EXPECT_TRUE(nullptr == waiter.websocket_stream());

  EXPECT_EQ(1, GetSocketPoolGroupCount(session->GetSocketPoolForHTTPProxy(
                   HttpNetworkSession::NORMAL_SOCKET_POOL,
                   HostPortPair("myproxy.org", 443))));
  EXPECT_FALSE(waiter.used_proxy_info().is_direct());

  for (int preconnect_request = 1; preconnect_request <= num_preconnects;
       ++preconnect_request) {
    session->http_stream_factory()->PreconnectStreams(1, request_info);
    base::RunLoop().RunUntilIdle();
    EXPECT_EQ(1, GetSocketPoolGroupCount(session->GetSocketPoolForHTTPProxy(
                     HttpNetworkSession::NORMAL_SOCKET_POOL,
                     HostPortPair("myproxy.org", 443))));
  }

  // First preconnect would be successful since the stream to the proxy server
  // has suceeded. The next |num_preconnects-1| would be skipped.
  histogram_tester.ExpectUniqueSample("Net.PreconnectSkippedToProxyServers", 1,
                                      2 * (num_preconnects - 1));
}

TEST_F(HttpStreamFactoryTest, RequestWebSocketBasicHandshakeStream) {
  SpdySessionDependencies session_deps(ProxyService::CreateDirect());

  StaticSocketDataProvider socket_data;
  socket_data.set_connect_data(MockConnect(ASYNC, OK));
  session_deps.socket_factory->AddSocketDataProvider(&socket_data);

  std::unique_ptr<HttpNetworkSession> session(
      SpdySessionDependencies::SpdyCreateSession(&session_deps));

  // Now request a stream.
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("ws://www.google.com");
  request_info.load_flags = 0;

  SSLConfig ssl_config;
  StreamRequestWaiter waiter;
  WebSocketStreamCreateHelper create_helper;
  std::unique_ptr<HttpStreamRequest> request(
      session->http_stream_factory_for_websocket()
          ->RequestWebSocketHandshakeStream(
              request_info, DEFAULT_PRIORITY, ssl_config, ssl_config, &waiter,
              &create_helper,
              /* enable_ip_based_pooling = */ true,
              /* enable_alternative_services = */ true, NetLogWithSource()));
  waiter.WaitForStream();
  EXPECT_TRUE(waiter.stream_done());
  EXPECT_TRUE(nullptr == waiter.stream());
  ASSERT_TRUE(nullptr != waiter.websocket_stream());
  EXPECT_EQ(MockWebSocketHandshakeStream::kStreamTypeBasic,
            waiter.websocket_stream()->type());
  EXPECT_EQ(0, GetSocketPoolGroupCount(
      session->GetTransportSocketPool(HttpNetworkSession::NORMAL_SOCKET_POOL)));
  EXPECT_EQ(0, GetSocketPoolGroupCount(
      session->GetSSLSocketPool(HttpNetworkSession::NORMAL_SOCKET_POOL)));
  EXPECT_EQ(0, GetSocketPoolGroupCount(
      session->GetSSLSocketPool(HttpNetworkSession::WEBSOCKET_SOCKET_POOL)));
  EXPECT_TRUE(waiter.used_proxy_info().is_direct());
}

TEST_F(HttpStreamFactoryTest, RequestWebSocketBasicHandshakeStreamOverSSL) {
  SpdySessionDependencies session_deps(ProxyService::CreateDirect());

  MockRead mock_read(ASYNC, OK);
  StaticSocketDataProvider socket_data(&mock_read, 1, nullptr, 0);
  socket_data.set_connect_data(MockConnect(ASYNC, OK));
  session_deps.socket_factory->AddSocketDataProvider(&socket_data);

  SSLSocketDataProvider ssl_socket_data(ASYNC, OK);
  session_deps.socket_factory->AddSSLSocketDataProvider(&ssl_socket_data);

  std::unique_ptr<HttpNetworkSession> session(
      SpdySessionDependencies::SpdyCreateSession(&session_deps));

  // Now request a stream.
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("wss://www.google.com");
  request_info.load_flags = 0;

  SSLConfig ssl_config;
  StreamRequestWaiter waiter;
  WebSocketStreamCreateHelper create_helper;
  std::unique_ptr<HttpStreamRequest> request(
      session->http_stream_factory_for_websocket()
          ->RequestWebSocketHandshakeStream(
              request_info, DEFAULT_PRIORITY, ssl_config, ssl_config, &waiter,
              &create_helper,
              /* enable_ip_based_pooling = */ true,
              /* enable_alternative_services = */ true, NetLogWithSource()));
  waiter.WaitForStream();
  EXPECT_TRUE(waiter.stream_done());
  EXPECT_TRUE(nullptr == waiter.stream());
  ASSERT_TRUE(nullptr != waiter.websocket_stream());
  EXPECT_EQ(MockWebSocketHandshakeStream::kStreamTypeBasic,
            waiter.websocket_stream()->type());
  EXPECT_EQ(0, GetSocketPoolGroupCount(
      session->GetTransportSocketPool(HttpNetworkSession::NORMAL_SOCKET_POOL)));
  EXPECT_EQ(0, GetSocketPoolGroupCount(
      session->GetSSLSocketPool(HttpNetworkSession::NORMAL_SOCKET_POOL)));
  EXPECT_EQ(1, GetSocketPoolGroupCount(
      session->GetSSLSocketPool(HttpNetworkSession::WEBSOCKET_SOCKET_POOL)));
  EXPECT_TRUE(waiter.used_proxy_info().is_direct());
}

TEST_F(HttpStreamFactoryTest, RequestWebSocketBasicHandshakeStreamOverProxy) {
  SpdySessionDependencies session_deps(
      ProxyService::CreateFixed("myproxy:8888"));

  MockRead read(SYNCHRONOUS, "HTTP/1.0 200 Connection established\r\n\r\n");
  StaticSocketDataProvider socket_data(&read, 1, 0, 0);
  socket_data.set_connect_data(MockConnect(ASYNC, OK));
  session_deps.socket_factory->AddSocketDataProvider(&socket_data);

  std::unique_ptr<HttpNetworkSession> session(
      SpdySessionDependencies::SpdyCreateSession(&session_deps));

  // Now request a stream.
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("ws://www.google.com");
  request_info.load_flags = 0;

  SSLConfig ssl_config;
  StreamRequestWaiter waiter;
  WebSocketStreamCreateHelper create_helper;
  std::unique_ptr<HttpStreamRequest> request(
      session->http_stream_factory_for_websocket()
          ->RequestWebSocketHandshakeStream(
              request_info, DEFAULT_PRIORITY, ssl_config, ssl_config, &waiter,
              &create_helper,
              /* enable_ip_based_pooling = */ true,
              /* enable_alternative_services = */ true, NetLogWithSource()));
  waiter.WaitForStream();
  EXPECT_TRUE(waiter.stream_done());
  EXPECT_TRUE(nullptr == waiter.stream());
  ASSERT_TRUE(nullptr != waiter.websocket_stream());
  EXPECT_EQ(MockWebSocketHandshakeStream::kStreamTypeBasic,
            waiter.websocket_stream()->type());
  EXPECT_EQ(0, GetSocketPoolGroupCount(
      session->GetTransportSocketPool(
          HttpNetworkSession::WEBSOCKET_SOCKET_POOL)));
  EXPECT_EQ(0, GetSocketPoolGroupCount(
      session->GetSSLSocketPool(HttpNetworkSession::WEBSOCKET_SOCKET_POOL)));
  EXPECT_EQ(0, GetSocketPoolGroupCount(session->GetSocketPoolForHTTPProxy(
      HttpNetworkSession::NORMAL_SOCKET_POOL,
      HostPortPair("myproxy", 8888))));
  EXPECT_EQ(0, GetSocketPoolGroupCount(session->GetSocketPoolForSSLWithProxy(
      HttpNetworkSession::NORMAL_SOCKET_POOL,
      HostPortPair("myproxy", 8888))));
  EXPECT_EQ(1, GetSocketPoolGroupCount(session->GetSocketPoolForHTTPProxy(
      HttpNetworkSession::WEBSOCKET_SOCKET_POOL,
      HostPortPair("myproxy", 8888))));
  EXPECT_EQ(0, GetSocketPoolGroupCount(session->GetSocketPoolForSSLWithProxy(
      HttpNetworkSession::WEBSOCKET_SOCKET_POOL,
      HostPortPair("myproxy", 8888))));
  EXPECT_FALSE(waiter.used_proxy_info().is_direct());
}

TEST_F(HttpStreamFactoryTest, RequestSpdyHttpStreamHttpsURL) {
  SpdySessionDependencies session_deps(ProxyService::CreateDirect());

  MockRead mock_read(SYNCHRONOUS, ERR_IO_PENDING);
  SequencedSocketData socket_data(&mock_read, 1, nullptr, 0);
  socket_data.set_connect_data(MockConnect(ASYNC, OK));
  session_deps.socket_factory->AddSocketDataProvider(&socket_data);

  SSLSocketDataProvider ssl_socket_data(ASYNC, OK);
  ssl_socket_data.next_proto = kProtoHTTP2;
  session_deps.socket_factory->AddSSLSocketDataProvider(&ssl_socket_data);

  HostPortPair host_port_pair("www.google.com", 443);
  std::unique_ptr<HttpNetworkSession> session(
      SpdySessionDependencies::SpdyCreateSession(&session_deps));

  // Now request a stream.
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");
  request_info.load_flags = 0;

  SSLConfig ssl_config;
  StreamRequestWaiter waiter;
  std::unique_ptr<HttpStreamRequest> request(
      session->http_stream_factory()->RequestStream(
          request_info, DEFAULT_PRIORITY, ssl_config, ssl_config, &waiter,
          /* enable_ip_based_pooling = */ true,
          /* enable_alternative_services = */ true, NetLogWithSource()));
  waiter.WaitForStream();
  EXPECT_TRUE(waiter.stream_done());
  EXPECT_TRUE(nullptr == waiter.websocket_stream());
  ASSERT_TRUE(nullptr != waiter.stream());

  EXPECT_EQ(1, GetSpdySessionCount(session.get()));
  EXPECT_EQ(1, GetSocketPoolGroupCount(
      session->GetTransportSocketPool(HttpNetworkSession::NORMAL_SOCKET_POOL)));
  EXPECT_EQ(1, GetSocketPoolGroupCount(
      session->GetSSLSocketPool(HttpNetworkSession::NORMAL_SOCKET_POOL)));
  EXPECT_EQ(0, GetSocketPoolGroupCount(
      session->GetTransportSocketPool(
          HttpNetworkSession::WEBSOCKET_SOCKET_POOL)));
  EXPECT_EQ(0, GetSocketPoolGroupCount(
      session->GetSSLSocketPool(HttpNetworkSession::WEBSOCKET_SOCKET_POOL)));
  EXPECT_TRUE(waiter.used_proxy_info().is_direct());
}

TEST_F(HttpStreamFactoryTest, RequestSpdyHttpStreamHttpURL) {
  url::SchemeHostPort scheme_host_port("http", "myproxy.org", 443);
  auto session_deps = base::MakeUnique<SpdySessionDependencies>(
      ProxyService::CreateFixedFromPacResult("HTTPS myproxy.org:443"));
  std::unique_ptr<ProxyService> proxy_service =
      ProxyService::CreateFixedFromPacResult("HTTPS myproxy.org:443");

  MockRead mock_read(SYNCHRONOUS, ERR_IO_PENDING);
  SequencedSocketData socket_data(&mock_read, 1, nullptr, 0);
  socket_data.set_connect_data(MockConnect(ASYNC, OK));
  session_deps->socket_factory->AddSocketDataProvider(&socket_data);

  SSLSocketDataProvider ssl_socket_data(ASYNC, OK);
  ssl_socket_data.next_proto = kProtoHTTP2;
  session_deps->socket_factory->AddSSLSocketDataProvider(&ssl_socket_data);
  session_deps->proxy_service = std::move(proxy_service);

  std::unique_ptr<HttpNetworkSession> session(
      SpdySessionDependencies::SpdyCreateSession(session_deps.get()));

  HttpServerProperties* http_server_properties =
      session->spdy_session_pool()->http_server_properties();
  EXPECT_FALSE(http_server_properties->GetSupportsSpdy(scheme_host_port));

  // Now request a stream.
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("http://www.google.com");
  request_info.load_flags = 0;

  SSLConfig ssl_config;
  StreamRequestWaiter waiter;
  std::unique_ptr<HttpStreamRequest> request(
      session->http_stream_factory()->RequestStream(
          request_info, DEFAULT_PRIORITY, ssl_config, ssl_config, &waiter,
          /* enable_ip_based_pooling = */ true,
          /* enable_alternative_services = */ true, NetLogWithSource()));
  waiter.WaitForStream();
  EXPECT_TRUE(waiter.stream_done());
  EXPECT_TRUE(nullptr == waiter.websocket_stream());
  ASSERT_TRUE(nullptr != waiter.stream());

  EXPECT_EQ(1, GetSpdySessionCount(session.get()));
  EXPECT_EQ(0, GetSocketPoolGroupCount(session->GetTransportSocketPool(
                   HttpNetworkSession::NORMAL_SOCKET_POOL)));
  EXPECT_EQ(0, GetSocketPoolGroupCount(session->GetSSLSocketPool(
                   HttpNetworkSession::NORMAL_SOCKET_POOL)));
  EXPECT_EQ(0, GetSocketPoolGroupCount(session->GetTransportSocketPool(
                   HttpNetworkSession::WEBSOCKET_SOCKET_POOL)));
  EXPECT_EQ(0, GetSocketPoolGroupCount(session->GetSSLSocketPool(
                   HttpNetworkSession::WEBSOCKET_SOCKET_POOL)));
  EXPECT_FALSE(waiter.used_proxy_info().is_direct());
  EXPECT_TRUE(http_server_properties->GetSupportsSpdy(scheme_host_port));
}

// Tests that when a new SpdySession is established, duplicated idle H2 sockets
// to the same server are closed.
TEST_F(HttpStreamFactoryTest, NewSpdySessionCloseIdleH2Sockets) {
  SpdySessionDependencies session_deps(ProxyService::CreateDirect());

  const int kNumIdleSockets = 4;
  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING)};
  std::vector<std::unique_ptr<SequencedSocketData>> providers;
  SSLSocketDataProvider ssl_socket_data(ASYNC, OK);
  ssl_socket_data.next_proto = kProtoHTTP2;
  for (int i = 0; i < kNumIdleSockets; i++) {
    auto provider = base::MakeUnique<SequencedSocketData>(
        reads, arraysize(reads), nullptr, 0);
    provider->set_connect_data(MockConnect(ASYNC, OK));
    session_deps.socket_factory->AddSocketDataProvider(provider.get());
    providers.push_back(std::move(provider));
    session_deps.socket_factory->AddSSLSocketDataProvider(&ssl_socket_data);
  }

  std::unique_ptr<HttpNetworkSession> session(
      SpdySessionDependencies::SpdyCreateSession(&session_deps));

  HostPortPair host_port_pair("www.google.com", 443);

  // Create some HTTP/2 sockets.
  std::vector<std::unique_ptr<ClientSocketHandle>> handles;
  for (size_t i = 0; i < kNumIdleSockets; i++) {
    scoped_refptr<TransportSocketParams> transport_params(
        new TransportSocketParams(
            host_port_pair, false, OnHostResolutionCallback(),
            TransportSocketParams::COMBINE_CONNECT_AND_WRITE_DEFAULT));

    auto connection = base::MakeUnique<ClientSocketHandle>();
    TestCompletionCallback callback;

    SSLConfig ssl_config;
    scoped_refptr<SSLSocketParams> ssl_params(
        new SSLSocketParams(transport_params, nullptr, nullptr, host_port_pair,
                            ssl_config, PRIVACY_MODE_DISABLED, 0, false));
    std::string group_name = "ssl/" + host_port_pair.ToString();
    int rv = connection->Init(
        group_name, ssl_params, MEDIUM,
        ClientSocketPool::RespectLimits::ENABLED, callback.callback(),
        session->GetSSLSocketPool(HttpNetworkSession::NORMAL_SOCKET_POOL),
        NetLogWithSource());
    rv = callback.GetResult(rv);
    handles.push_back(std::move(connection));
  }

  // Releases handles now, and these sockets should go into the socket pool.
  handles.clear();
  EXPECT_EQ(kNumIdleSockets,
            session->GetSSLSocketPool(HttpNetworkSession::NORMAL_SOCKET_POOL)
                ->IdleSocketCount());

  // Request two streams at once and make sure they use the same connection.
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");
  request_info.load_flags = 0;

  SSLConfig ssl_config;
  StreamRequestWaiter waiter1;
  StreamRequestWaiter waiter2;
  std::unique_ptr<HttpStreamRequest> request1(
      session->http_stream_factory()->RequestStream(
          request_info, DEFAULT_PRIORITY, ssl_config, ssl_config, &waiter1,
          /* enable_ip_based_pooling = */ true,
          /* enable_alternative_services = */ true, NetLogWithSource()));
  std::unique_ptr<HttpStreamRequest> request2(
      session->http_stream_factory()->RequestStream(
          request_info, DEFAULT_PRIORITY, ssl_config, ssl_config, &waiter2,
          /* enable_ip_based_pooling = */ true,
          /* enable_alternative_services = */ true, NetLogWithSource()));
  waiter1.WaitForStream();
  waiter2.WaitForStream();
  EXPECT_TRUE(waiter1.stream_done());
  EXPECT_TRUE(waiter2.stream_done());
  ASSERT_NE(nullptr, waiter1.stream());
  ASSERT_NE(nullptr, waiter2.stream());
  ASSERT_NE(waiter1.stream(), waiter2.stream());

  // Establishing the SpdySession will close idle H2 sockets.
  EXPECT_EQ(0, session->GetSSLSocketPool(HttpNetworkSession::NORMAL_SOCKET_POOL)
                   ->IdleSocketCount());
  EXPECT_EQ(1, GetSpdySessionCount(session.get()));
}

TEST_F(HttpStreamFactoryTest, RequestBidirectionalStreamImpl) {
  SpdySessionDependencies session_deps(ProxyService::CreateDirect());

  MockRead mock_read(ASYNC, OK);
  SequencedSocketData socket_data(&mock_read, 1, nullptr, 0);
  socket_data.set_connect_data(MockConnect(ASYNC, OK));
  session_deps.socket_factory->AddSocketDataProvider(&socket_data);

  SSLSocketDataProvider ssl_socket_data(ASYNC, OK);
  ssl_socket_data.next_proto = kProtoHTTP2;
  session_deps.socket_factory->AddSSLSocketDataProvider(&ssl_socket_data);

  HostPortPair host_port_pair("www.google.com", 443);
  std::unique_ptr<HttpNetworkSession> session(
      SpdySessionDependencies::SpdyCreateSession(&session_deps));

  // Now request a stream.
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");
  request_info.load_flags = 0;

  SSLConfig ssl_config;
  StreamRequestWaiter waiter;
  std::unique_ptr<HttpStreamRequest> request(
      session->http_stream_factory()->RequestBidirectionalStreamImpl(
          request_info, DEFAULT_PRIORITY, ssl_config, ssl_config, &waiter,
          /* enable_ip_based_pooling = */ true,
          /* enable_alternative_services = */ true, NetLogWithSource()));
  waiter.WaitForStream();
  EXPECT_TRUE(waiter.stream_done());
  EXPECT_FALSE(waiter.websocket_stream());
  ASSERT_FALSE(waiter.stream());
  ASSERT_TRUE(waiter.bidirectional_stream_impl());
  EXPECT_EQ(1, GetSocketPoolGroupCount(session->GetTransportSocketPool(
                   HttpNetworkSession::NORMAL_SOCKET_POOL)));
  EXPECT_EQ(1, GetSocketPoolGroupCount(session->GetSSLSocketPool(
                   HttpNetworkSession::NORMAL_SOCKET_POOL)));
  EXPECT_EQ(0, GetSocketPoolGroupCount(session->GetTransportSocketPool(
                   HttpNetworkSession::WEBSOCKET_SOCKET_POOL)));
  EXPECT_EQ(0, GetSocketPoolGroupCount(session->GetSSLSocketPool(
                   HttpNetworkSession::WEBSOCKET_SOCKET_POOL)));
  EXPECT_TRUE(waiter.used_proxy_info().is_direct());
}

class HttpStreamFactoryBidirectionalQuicTest
    : public ::testing::Test,
      public ::testing::WithParamInterface<QuicVersion> {
 protected:
  HttpStreamFactoryBidirectionalQuicTest()
      : default_url_(kDefaultUrl),
        client_packet_maker_(GetParam(),
                             0,
                             &clock_,
                             "www.example.org",
                             Perspective::IS_CLIENT),
        server_packet_maker_(GetParam(),
                             0,
                             &clock_,
                             "www.example.org",
                             Perspective::IS_SERVER),
        random_generator_(0),
        proxy_service_(ProxyService::CreateDirect()),
        ssl_config_service_(new SSLConfigServiceDefaults) {
    clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(20));
  }

  void TearDown() override { session_.reset(); }

  // Disable bidirectional stream over QUIC. This should be invoked before
  // Initialize().
  void DisableQuicBidirectionalStream() {
    params_.quic_disable_bidirectional_streams = true;
  }

  void Initialize() {
    params_.enable_quic = true;
    params_.http_server_properties = &http_server_properties_;
    params_.quic_random = &random_generator_;
    params_.quic_clock = &clock_;

    // Load a certificate that is valid for *.example.org
    scoped_refptr<X509Certificate> test_cert(
        ImportCertFromFile(GetTestCertsDirectory(), "wildcard.pem"));
    EXPECT_TRUE(test_cert.get());
    verify_details_.cert_verify_result.verified_cert = test_cert;
    verify_details_.cert_verify_result.is_issued_by_known_root = true;
    crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details_);
    crypto_client_stream_factory_.set_handshake_mode(
        MockCryptoClientStream::CONFIRM_HANDSHAKE);
    params_.cert_verifier = &cert_verifier_;
    params_.quic_crypto_client_stream_factory = &crypto_client_stream_factory_;
    params_.quic_supported_versions = test::SupportedVersions(GetParam());
    params_.transport_security_state = &transport_security_state_;
    params_.cert_transparency_verifier = &ct_verifier_;
    params_.ct_policy_enforcer = &ct_policy_enforcer_;
    params_.host_resolver = &host_resolver_;
    params_.proxy_service = proxy_service_.get();
    params_.ssl_config_service = ssl_config_service_.get();
    params_.client_socket_factory = &socket_factory_;
    session_.reset(new HttpNetworkSession(params_));
    session_->quic_stream_factory()->set_require_confirmation(false);
  }

  void AddQuicAlternativeService() {
    const AlternativeService alternative_service(kProtoQUIC, "www.example.org",
                                                 443);
    AlternativeServiceInfoVector alternative_service_info_vector;
    base::Time expiration = base::Time::Now() + base::TimeDelta::FromDays(1);
    alternative_service_info_vector.push_back(
        AlternativeServiceInfo(alternative_service, expiration));
    http_server_properties_.SetAlternativeServices(
        url::SchemeHostPort(default_url_), alternative_service_info_vector);
  }

  test::QuicTestPacketMaker& client_packet_maker() {
    return client_packet_maker_;
  }
  test::QuicTestPacketMaker& server_packet_maker() {
    return server_packet_maker_;
  }

  MockClientSocketFactory& socket_factory() { return socket_factory_; }

  HttpNetworkSession* session() { return session_.get(); }

  const GURL default_url_;

  QuicStreamId GetNthClientInitiatedStreamId(int n) {
    return test::GetNthClientInitiatedStreamId(GetParam(), n);
  }

 private:
  MockClock clock_;
  test::QuicTestPacketMaker client_packet_maker_;
  test::QuicTestPacketMaker server_packet_maker_;
  MockClientSocketFactory socket_factory_;
  std::unique_ptr<HttpNetworkSession> session_;
  test::MockRandom random_generator_;
  MockCertVerifier cert_verifier_;
  ProofVerifyDetailsChromium verify_details_;
  MockCryptoClientStreamFactory crypto_client_stream_factory_;
  HttpServerPropertiesImpl http_server_properties_;
  TransportSecurityState transport_security_state_;
  MultiLogCTVerifier ct_verifier_;
  CTPolicyEnforcer ct_policy_enforcer_;
  MockHostResolver host_resolver_;
  std::unique_ptr<ProxyService> proxy_service_;
  scoped_refptr<SSLConfigServiceDefaults> ssl_config_service_;
  HttpNetworkSession::Params params_;
};

INSTANTIATE_TEST_CASE_P(Version,
                        HttpStreamFactoryBidirectionalQuicTest,
                        ::testing::ValuesIn(AllSupportedVersions()));

TEST_P(HttpStreamFactoryBidirectionalQuicTest,
       RequestBidirectionalStreamImplQuicAlternative) {
  MockQuicData mock_quic_data;
  SpdyPriority priority =
      ConvertRequestPriorityToQuicPriority(DEFAULT_PRIORITY);
  size_t spdy_headers_frame_length;
  QuicStreamOffset header_stream_offset = 0;
  mock_quic_data.AddWrite(client_packet_maker().MakeInitialSettingsPacket(
      1, &header_stream_offset));
  mock_quic_data.AddWrite(client_packet_maker().MakeRequestHeadersPacket(
      2, GetNthClientInitiatedStreamId(0), /*should_include_version=*/true,
      /*fin=*/true, priority,
      client_packet_maker().GetRequestHeaders("GET", "https", "/"),
      &spdy_headers_frame_length, &header_stream_offset));
  size_t spdy_response_headers_frame_length;
  mock_quic_data.AddRead(server_packet_maker().MakeResponseHeadersPacket(
      1, GetNthClientInitiatedStreamId(0), /*should_include_version=*/false,
      /*fin=*/true, server_packet_maker().GetResponseHeaders("200"),
      &spdy_response_headers_frame_length));
  mock_quic_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);  // No more read data.
  mock_quic_data.AddSocketDataToFactory(&socket_factory());

  // Add hanging data for http job.
  std::unique_ptr<StaticSocketDataProvider> hanging_data;
  hanging_data.reset(new StaticSocketDataProvider());
  MockConnect hanging_connect(SYNCHRONOUS, ERR_IO_PENDING);
  hanging_data->set_connect_data(hanging_connect);
  socket_factory().AddSocketDataProvider(hanging_data.get());
  SSLSocketDataProvider ssl_data(ASYNC, OK);
  socket_factory().AddSSLSocketDataProvider(&ssl_data);

  // Set up QUIC as alternative_service.
  AddQuicAlternativeService();
  Initialize();

  // Now request a stream.
  SSLConfig ssl_config;
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = default_url_;
  request_info.load_flags = 0;

  StreamRequestWaiter waiter;
  std::unique_ptr<HttpStreamRequest> request(
      session()->http_stream_factory()->RequestBidirectionalStreamImpl(
          request_info, DEFAULT_PRIORITY, ssl_config, ssl_config, &waiter,
          /* enable_ip_based_pooling = */ true,
          /* enable_alternative_services = */ true, NetLogWithSource()));

  waiter.WaitForStream();
  EXPECT_TRUE(waiter.stream_done());
  EXPECT_FALSE(waiter.websocket_stream());
  ASSERT_FALSE(waiter.stream());
  ASSERT_TRUE(waiter.bidirectional_stream_impl());
  BidirectionalStreamImpl* stream_impl = waiter.bidirectional_stream_impl();

  BidirectionalStreamRequestInfo bidi_request_info;
  bidi_request_info.method = "GET";
  bidi_request_info.url = default_url_;
  bidi_request_info.end_stream_on_headers = true;
  bidi_request_info.priority = LOWEST;

  TestBidirectionalDelegate delegate;
  stream_impl->Start(&bidi_request_info, NetLogWithSource(),
                     /*send_request_headers_automatically=*/true, &delegate,
                     nullptr);
  delegate.WaitUntilDone();

  scoped_refptr<IOBuffer> buffer = new net::IOBuffer(1);
  EXPECT_THAT(stream_impl->ReadData(buffer.get(), 1), IsOk());
  EXPECT_EQ(kProtoQUIC, stream_impl->GetProtocol());
  EXPECT_EQ("200", delegate.response_headers().find(":status")->second);
  EXPECT_EQ(0, GetSocketPoolGroupCount(session()->GetTransportSocketPool(
                   HttpNetworkSession::NORMAL_SOCKET_POOL)));
  EXPECT_EQ(0, GetSocketPoolGroupCount(session()->GetSSLSocketPool(
                   HttpNetworkSession::NORMAL_SOCKET_POOL)));
  EXPECT_EQ(0, GetSocketPoolGroupCount(session()->GetTransportSocketPool(
                   HttpNetworkSession::WEBSOCKET_SOCKET_POOL)));
  EXPECT_EQ(0, GetSocketPoolGroupCount(session()->GetSSLSocketPool(
                   HttpNetworkSession::WEBSOCKET_SOCKET_POOL)));
  EXPECT_TRUE(waiter.used_proxy_info().is_direct());
}

// Tests that when QUIC is not enabled for bidirectional streaming, HTTP/2 is
// used instead.
TEST_P(HttpStreamFactoryBidirectionalQuicTest,
       RequestBidirectionalStreamImplQuicNotEnabled) {
  // Make the http job fail.
  std::unique_ptr<StaticSocketDataProvider> http_job_data;
  http_job_data.reset(new StaticSocketDataProvider());
  MockConnect failed_connect(ASYNC, ERR_CONNECTION_REFUSED);
  http_job_data->set_connect_data(failed_connect);
  socket_factory().AddSocketDataProvider(http_job_data.get());
  SSLSocketDataProvider ssl_data(ASYNC, OK);
  socket_factory().AddSSLSocketDataProvider(&ssl_data);

  // Set up QUIC as alternative_service.
  AddQuicAlternativeService();
  DisableQuicBidirectionalStream();
  Initialize();

  // Now request a stream.
  SSLConfig ssl_config;
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = default_url_;
  request_info.load_flags = 0;

  StreamRequestWaiter waiter;
  std::unique_ptr<HttpStreamRequest> request(
      session()->http_stream_factory()->RequestBidirectionalStreamImpl(
          request_info, DEFAULT_PRIORITY, ssl_config, ssl_config, &waiter,
          /* enable_ip_based_pooling = */ true,
          /* enable_alternative_services = */ true, NetLogWithSource()));

  waiter.WaitForStream();
  EXPECT_TRUE(waiter.stream_done());
  EXPECT_FALSE(waiter.websocket_stream());
  ASSERT_FALSE(waiter.stream());
  ASSERT_FALSE(waiter.bidirectional_stream_impl());
  // Since the alternative service job is not started, we will get the error
  // from the http job.
  ASSERT_THAT(waiter.error_status(), IsError(ERR_CONNECTION_REFUSED));
}

// Tests that if Http job fails, but Quic job succeeds, we return
// BidirectionalStreamQuicImpl.
TEST_P(HttpStreamFactoryBidirectionalQuicTest,
       RequestBidirectionalStreamImplHttpJobFailsQuicJobSucceeds) {
  // Set up Quic data.
  MockQuicData mock_quic_data;
  SpdyPriority priority =
      ConvertRequestPriorityToQuicPriority(DEFAULT_PRIORITY);
  size_t spdy_headers_frame_length;
  QuicStreamOffset header_stream_offset = 0;
  mock_quic_data.AddWrite(client_packet_maker().MakeInitialSettingsPacket(
      1, &header_stream_offset));
  mock_quic_data.AddWrite(client_packet_maker().MakeRequestHeadersPacket(
      2, GetNthClientInitiatedStreamId(0), /*should_include_version=*/true,
      /*fin=*/true, priority,
      client_packet_maker().GetRequestHeaders("GET", "https", "/"),
      &spdy_headers_frame_length, &header_stream_offset));
  size_t spdy_response_headers_frame_length;
  mock_quic_data.AddRead(server_packet_maker().MakeResponseHeadersPacket(
      1, GetNthClientInitiatedStreamId(0), /*should_include_version=*/false,
      /*fin=*/true, server_packet_maker().GetResponseHeaders("200"),
      &spdy_response_headers_frame_length));
  mock_quic_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);  // No more read data.
  mock_quic_data.AddSocketDataToFactory(&socket_factory());

  // Make the http job fail.
  std::unique_ptr<StaticSocketDataProvider> http_job_data;
  http_job_data.reset(new StaticSocketDataProvider());
  MockConnect failed_connect(ASYNC, ERR_CONNECTION_REFUSED);
  http_job_data->set_connect_data(failed_connect);
  socket_factory().AddSocketDataProvider(http_job_data.get());
  SSLSocketDataProvider ssl_data(ASYNC, OK);
  socket_factory().AddSSLSocketDataProvider(&ssl_data);

  // Set up QUIC as alternative_service.
  AddQuicAlternativeService();
  Initialize();

  // Now request a stream.
  SSLConfig ssl_config;
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = default_url_;
  request_info.load_flags = 0;

  StreamRequestWaiter waiter;
  std::unique_ptr<HttpStreamRequest> request(
      session()->http_stream_factory()->RequestBidirectionalStreamImpl(
          request_info, DEFAULT_PRIORITY, ssl_config, ssl_config, &waiter,
          /* enable_ip_based_pooling = */ true,
          /* enable_alternative_services = */ true, NetLogWithSource()));

  waiter.WaitForStream();
  EXPECT_TRUE(waiter.stream_done());
  EXPECT_FALSE(waiter.websocket_stream());
  ASSERT_FALSE(waiter.stream());
  ASSERT_TRUE(waiter.bidirectional_stream_impl());
  BidirectionalStreamImpl* stream_impl = waiter.bidirectional_stream_impl();

  BidirectionalStreamRequestInfo bidi_request_info;
  bidi_request_info.method = "GET";
  bidi_request_info.url = default_url_;
  bidi_request_info.end_stream_on_headers = true;
  bidi_request_info.priority = LOWEST;

  TestBidirectionalDelegate delegate;
  stream_impl->Start(&bidi_request_info, NetLogWithSource(),
                     /*send_request_headers_automatically=*/true, &delegate,
                     nullptr);
  delegate.WaitUntilDone();

  // Make sure the BidirectionalStream negotiated goes through QUIC.
  scoped_refptr<IOBuffer> buffer = new net::IOBuffer(1);
  EXPECT_THAT(stream_impl->ReadData(buffer.get(), 1), IsOk());
  EXPECT_EQ(kProtoQUIC, stream_impl->GetProtocol());
  EXPECT_EQ("200", delegate.response_headers().find(":status")->second);
  // There is no Http2 socket pool.
  EXPECT_EQ(0, GetSocketPoolGroupCount(session()->GetTransportSocketPool(
                   HttpNetworkSession::NORMAL_SOCKET_POOL)));
  EXPECT_EQ(0, GetSocketPoolGroupCount(session()->GetSSLSocketPool(
                   HttpNetworkSession::NORMAL_SOCKET_POOL)));
  EXPECT_EQ(0, GetSocketPoolGroupCount(session()->GetTransportSocketPool(
                   HttpNetworkSession::WEBSOCKET_SOCKET_POOL)));
  EXPECT_EQ(0, GetSocketPoolGroupCount(session()->GetSSLSocketPool(
                   HttpNetworkSession::WEBSOCKET_SOCKET_POOL)));
  EXPECT_TRUE(waiter.used_proxy_info().is_direct());
}

TEST_F(HttpStreamFactoryTest, RequestBidirectionalStreamImplFailure) {
  SpdySessionDependencies session_deps(ProxyService::CreateDirect());

  MockRead mock_read(ASYNC, OK);
  SequencedSocketData socket_data(&mock_read, 1, nullptr, 0);
  socket_data.set_connect_data(MockConnect(ASYNC, OK));
  session_deps.socket_factory->AddSocketDataProvider(&socket_data);

  SSLSocketDataProvider ssl_socket_data(ASYNC, OK);

  // If HTTP/1 is used, BidirectionalStreamImpl should not be obtained.
  ssl_socket_data.next_proto = kProtoHTTP11;
  session_deps.socket_factory->AddSSLSocketDataProvider(&ssl_socket_data);

  HostPortPair host_port_pair("www.google.com", 443);
  std::unique_ptr<HttpNetworkSession> session(
      SpdySessionDependencies::SpdyCreateSession(&session_deps));

  // Now request a stream.
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");
  request_info.load_flags = 0;

  SSLConfig ssl_config;
  StreamRequestWaiter waiter;
  std::unique_ptr<HttpStreamRequest> request(
      session->http_stream_factory()->RequestBidirectionalStreamImpl(
          request_info, DEFAULT_PRIORITY, ssl_config, ssl_config, &waiter,
          /* enable_ip_based_pooling = */ true,
          /* enable_alternative_services = */ true, NetLogWithSource()));
  waiter.WaitForStream();
  EXPECT_TRUE(waiter.stream_done());
  ASSERT_THAT(waiter.error_status(), IsError(ERR_FAILED));
  EXPECT_FALSE(waiter.websocket_stream());
  ASSERT_FALSE(waiter.stream());
  ASSERT_FALSE(waiter.bidirectional_stream_impl());
  EXPECT_EQ(1, GetSocketPoolGroupCount(session->GetTransportSocketPool(
                   HttpNetworkSession::NORMAL_SOCKET_POOL)));
  EXPECT_EQ(1, GetSocketPoolGroupCount(session->GetSSLSocketPool(
                   HttpNetworkSession::NORMAL_SOCKET_POOL)));
  EXPECT_EQ(0, GetSocketPoolGroupCount(session->GetTransportSocketPool(
                   HttpNetworkSession::WEBSOCKET_SOCKET_POOL)));
  EXPECT_EQ(0, GetSocketPoolGroupCount(session->GetSSLSocketPool(
                   HttpNetworkSession::WEBSOCKET_SOCKET_POOL)));
}

}  // namespace

}  // namespace net
