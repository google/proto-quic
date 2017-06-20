// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_stream_factory_impl_job_controller.h"

#include <string>
#include <utility>
#include <vector>

#include "base/memory/ptr_util.h"
#include "base/run_loop.h"
#include "base/strings/stringprintf.h"
#include "base/test/histogram_tester.h"
#include "base/test/scoped_feature_list.h"
#include "base/test/scoped_mock_time_message_loop_task_runner.h"
#include "base/threading/platform_thread.h"
#include "net/base/test_proxy_delegate.h"
#include "net/dns/mock_host_resolver.h"
#include "net/http/http_basic_stream.h"
#include "net/http/http_stream_factory_impl.h"
#include "net/http/http_stream_factory_impl_job.h"
#include "net/http/http_stream_factory_impl_request.h"
#include "net/http/http_stream_factory_test_util.h"
#include "net/log/net_log_with_source.h"
#include "net/log/test_net_log.h"
#include "net/log/test_net_log_entry.h"
#include "net/log/test_net_log_util.h"
#include "net/proxy/mock_proxy_resolver.h"
#include "net/proxy/proxy_config_service_fixed.h"
#include "net/proxy/proxy_info.h"
#include "net/proxy/proxy_service.h"
#include "net/quic/chromium/mock_crypto_client_stream_factory.h"
#include "net/quic/chromium/mock_quic_data.h"
#include "net/quic/chromium/quic_stream_factory.h"
#include "net/quic/chromium/quic_stream_factory_peer.h"
#include "net/quic/chromium/quic_test_packet_maker.h"
#include "net/quic/test_tools/mock_random.h"
#include "net/socket/socket_test_util.h"
#include "net/spdy/chromium/spdy_test_util_common.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gmock_mutant.h"
#include "testing/gtest/include/gtest/gtest.h"

using ::testing::_;
using ::testing::Invoke;

namespace net {

namespace test {

namespace {

const char kServerHostname[] = "www.example.com";

// List of errors that are used in the proxy resolution tests.
const int proxy_test_mock_errors[] = {
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

class FailingProxyResolverFactory : public ProxyResolverFactory {
 public:
  FailingProxyResolverFactory() : ProxyResolverFactory(false) {}

  // ProxyResolverFactory override.
  int CreateProxyResolver(
      const scoped_refptr<ProxyResolverScriptData>& script_data,
      std::unique_ptr<ProxyResolver>* result,
      const CompletionCallback& callback,
      std::unique_ptr<Request>* request) override {
    return ERR_PAC_SCRIPT_FAILED;
  }
};

class FailingHostResolver : public MockHostResolverBase {
 public:
  FailingHostResolver() : MockHostResolverBase(false /*use_caching*/) {}
  ~FailingHostResolver() override {}

  int Resolve(const RequestInfo& info,
              RequestPriority priority,
              AddressList* addresses,
              const CompletionCallback& callback,
              std::unique_ptr<Request>* out_req,
              const NetLogWithSource& net_log) override {
    return ERR_NAME_NOT_RESOLVED;
  }
};

// TODO(xunjieli): This should just use HangingHostResolver from
// mock_host_resolver.h
class HangingResolver : public MockHostResolverBase {
 public:
  HangingResolver() : MockHostResolverBase(false /*use_caching*/) {}
  ~HangingResolver() override {}

  int Resolve(const RequestInfo& info,
              RequestPriority priority,
              AddressList* addresses,
              const CompletionCallback& callback,
              std::unique_ptr<Request>* out_req,
              const NetLogWithSource& net_log) override {
    return ERR_IO_PENDING;
  }
};

// A mock HttpServerProperties that always returns false for IsInitialized().
class MockHttpServerProperties : public HttpServerPropertiesImpl {
 public:
  MockHttpServerProperties() {}
  ~MockHttpServerProperties() override {}
  bool IsInitialized() const override { return false; }
};

}  // anonymous namespace

class HttpStreamFactoryImplJobPeer {
 public:
  static void Start(HttpStreamFactoryImpl::Job* job,
                    HttpStreamRequest::StreamType stream_type) {
    // Start() is mocked for MockHttpStreamFactoryImplJob.
    // This is the alternative method to invoke real Start() method on Job.
    job->stream_type_ = stream_type;
    job->StartInternal();
  }

  // Returns |num_streams_| of |job|. It should be 0 for non-preconnect Jobs.
  static int GetNumStreams(const HttpStreamFactoryImpl::Job* job) {
    return job->num_streams_;
  }

  // Return SpdySessionKey of |job|.
  static const SpdySessionKey GetSpdySessionKey(
      const HttpStreamFactoryImpl::Job* job) {
    return job->spdy_session_key_;
  }
};

class JobControllerPeer {
 public:
  static bool main_job_is_blocked(
      HttpStreamFactoryImpl::JobController* job_controller) {
    return job_controller->main_job_is_blocked_;
  }
  static bool main_job_is_resumed(
      HttpStreamFactoryImpl::JobController* job_controller) {
    return job_controller->main_job_is_resumed_;
  }
};

class HttpStreamFactoryImplJobControllerTest : public ::testing::Test {
 public:
  HttpStreamFactoryImplJobControllerTest() { session_deps_.enable_quic = true; }

  void UseAlternativeProxy() {
    ASSERT_FALSE(test_proxy_delegate_);
    use_alternative_proxy_ = true;
  }

  void SetPreconnect() {
    ASSERT_FALSE(test_proxy_delegate_);
    is_preconnect_ = true;
  }

  void DisableIPBasedPooling() {
    ASSERT_FALSE(test_proxy_delegate_);
    enable_ip_based_pooling_ = false;
  }

  void DisableAlternativeServices() {
    ASSERT_FALSE(test_proxy_delegate_);
    enable_alternative_services_ = false;
  }

  void SkipCreatingJobController() {
    ASSERT_FALSE(job_controller_);
    create_job_controller_ = false;
  }

  void Initialize(const HttpRequestInfo& request_info) {
    ASSERT_FALSE(test_proxy_delegate_);
    auto test_proxy_delegate = base::MakeUnique<TestProxyDelegate>();
    test_proxy_delegate_ = test_proxy_delegate.get();

    test_proxy_delegate->set_alternative_proxy_server(
        ProxyServer::FromPacString("QUIC myproxy.org:443"));
    EXPECT_TRUE(test_proxy_delegate->alternative_proxy_server().is_quic());
    session_deps_.proxy_delegate = std::move(test_proxy_delegate);

    if (quic_data_)
      quic_data_->AddSocketDataToFactory(session_deps_.socket_factory.get());
    if (tcp_data_)
      session_deps_.socket_factory->AddSocketDataProvider(tcp_data_.get());

    if (use_alternative_proxy_) {
      std::unique_ptr<ProxyService> proxy_service =
          ProxyService::CreateFixedFromPacResult("HTTPS myproxy.org:443");
      session_deps_.proxy_service = std::move(proxy_service);
    }
    session_deps_.net_log = net_log_.bound().net_log();
    HttpNetworkSession::Params params =
        SpdySessionDependencies::CreateSessionParams(&session_deps_);
    HttpNetworkSession::Context session_context =
        SpdySessionDependencies::CreateSessionContext(&session_deps_);

    session_context.quic_crypto_client_stream_factory =
        &crypto_client_stream_factory_;
    session_context.quic_random = &random_generator_;
    session_ = base::MakeUnique<HttpNetworkSession>(params, session_context);
    factory_ =
        static_cast<HttpStreamFactoryImpl*>(session_->http_stream_factory());
    if (create_job_controller_) {
      job_controller_ = new HttpStreamFactoryImpl::JobController(
          factory_, &request_delegate_, session_.get(), &job_factory_,
          request_info, is_preconnect_, enable_ip_based_pooling_,
          enable_alternative_services_, SSLConfig(), SSLConfig());
      HttpStreamFactoryImplPeer::AddJobController(factory_, job_controller_);
    }
  }

  TestProxyDelegate* test_proxy_delegate() const {
    return test_proxy_delegate_;
  }

  ~HttpStreamFactoryImplJobControllerTest() override {
    if (quic_data_) {
      EXPECT_TRUE(quic_data_->AllReadDataConsumed());
      EXPECT_TRUE(quic_data_->AllWriteDataConsumed());
    }
    if (tcp_data_) {
      EXPECT_TRUE(tcp_data_->AllReadDataConsumed());
      EXPECT_TRUE(tcp_data_->AllWriteDataConsumed());
    }
  }

  void SetAlternativeService(const HttpRequestInfo& request_info,
                             AlternativeService alternative_service) {
    HostPortPair host_port_pair = HostPortPair::FromURL(request_info.url);
    url::SchemeHostPort server(request_info.url);
    base::Time expiration = base::Time::Now() + base::TimeDelta::FromDays(1);
    session_->http_server_properties()->SetAlternativeService(
        server, alternative_service, expiration);
  }

  void VerifyBrokenAlternateProtocolMapping(const HttpRequestInfo& request_info,
                                            bool should_mark_broken) {
    const url::SchemeHostPort server(request_info.url);
    const AlternativeServiceInfoVector alternative_service_info_vector =
        session_->http_server_properties()->GetAlternativeServiceInfos(server);
    EXPECT_EQ(1u, alternative_service_info_vector.size());
    EXPECT_EQ(should_mark_broken,
              session_->http_server_properties()->IsAlternativeServiceBroken(
                  alternative_service_info_vector[0].alternative_service()));
  }

  TestJobFactory job_factory_;
  MockHttpStreamRequestDelegate request_delegate_;
  SpdySessionDependencies session_deps_{ProxyService::CreateDirect()};
  std::unique_ptr<HttpNetworkSession> session_;
  HttpStreamFactoryImpl* factory_ = nullptr;
  HttpStreamFactoryImpl::JobController* job_controller_ = nullptr;
  std::unique_ptr<HttpStreamFactoryImpl::Request> request_;
  std::unique_ptr<SequencedSocketData> tcp_data_;
  std::unique_ptr<MockQuicData> quic_data_;
  MockCryptoClientStreamFactory crypto_client_stream_factory_;
  MockClock clock_;
  MockRandom random_generator_{0};
  QuicTestPacketMaker client_maker_{
      HttpNetworkSession::Params().quic_supported_versions[0], 0, &clock_,
      kServerHostname, Perspective::IS_CLIENT};

 protected:
  BoundTestNetLog net_log_;
  bool use_alternative_proxy_ = false;
  bool is_preconnect_ = false;
  bool enable_ip_based_pooling_ = true;
  bool enable_alternative_services_ = true;

 private:
  // Not owned by |this|.
  TestProxyDelegate* test_proxy_delegate_ = nullptr;
  bool create_job_controller_ = true;

  DISALLOW_COPY_AND_ASSIGN(HttpStreamFactoryImplJobControllerTest);
};

TEST_F(HttpStreamFactoryImplJobControllerTest, ProxyResolutionFailsSync) {
  ProxyConfig proxy_config;
  proxy_config.set_pac_url(GURL("http://fooproxyurl"));
  proxy_config.set_pac_mandatory(true);
  session_deps_.proxy_service.reset(new ProxyService(
      base::MakeUnique<ProxyConfigServiceFixed>(proxy_config),
      base::WrapUnique(new FailingProxyResolverFactory), nullptr));
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("http://www.google.com");

  Initialize(request_info);

  EXPECT_CALL(request_delegate_,
              OnStreamFailed(ERR_MANDATORY_PROXY_CONFIGURATION_FAILED, _))
      .Times(1);
  request_ =
      job_controller_->Start(&request_delegate_, nullptr, net_log_.bound(),
                             HttpStreamRequest::HTTP_STREAM, DEFAULT_PRIORITY);

  EXPECT_FALSE(job_controller_->main_job());
  EXPECT_FALSE(job_controller_->alternative_job());

  // Make sure calling GetLoadState() when before job creation does not crash.
  // Regression test for crbug.com/723920.
  EXPECT_EQ(LOAD_STATE_IDLE, job_controller_->GetLoadState());

  base::RunLoop().RunUntilIdle();
  request_.reset();
  EXPECT_TRUE(HttpStreamFactoryImplPeer::IsJobControllerDeleted(factory_));
}

TEST_F(HttpStreamFactoryImplJobControllerTest, ProxyResolutionFailsAsync) {
  ProxyConfig proxy_config;
  proxy_config.set_pac_url(GURL("http://fooproxyurl"));
  proxy_config.set_pac_mandatory(true);
  MockAsyncProxyResolverFactory* proxy_resolver_factory =
      new MockAsyncProxyResolverFactory(false);
  MockAsyncProxyResolver resolver;
  session_deps_.proxy_service.reset(
      new ProxyService(base::MakeUnique<ProxyConfigServiceFixed>(proxy_config),
                       base::WrapUnique(proxy_resolver_factory), nullptr));
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("http://www.google.com");

  Initialize(request_info);

  request_ =
      job_controller_->Start(&request_delegate_, nullptr, net_log_.bound(),
                             HttpStreamRequest::HTTP_STREAM, DEFAULT_PRIORITY);

  EXPECT_FALSE(job_controller_->main_job());
  EXPECT_FALSE(job_controller_->alternative_job());

  EXPECT_EQ(LOAD_STATE_RESOLVING_PROXY_FOR_URL,
            job_controller_->GetLoadState());

  EXPECT_CALL(request_delegate_,
              OnStreamFailed(ERR_MANDATORY_PROXY_CONFIGURATION_FAILED, _))
      .Times(1);
  proxy_resolver_factory->pending_requests()[0]->CompleteNowWithForwarder(
      ERR_FAILED, &resolver);
  base::RunLoop().RunUntilIdle();
  request_.reset();
  EXPECT_TRUE(HttpStreamFactoryImplPeer::IsJobControllerDeleted(factory_));
}

TEST_F(HttpStreamFactoryImplJobControllerTest, NoSupportedProxies) {
  session_deps_.proxy_service =
      ProxyService::CreateFixedFromPacResult("QUIC myproxy.org:443");
  session_deps_.enable_quic = false;
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("http://www.google.com");

  Initialize(request_info);

  EXPECT_CALL(request_delegate_, OnStreamFailed(ERR_NO_SUPPORTED_PROXIES, _))
      .Times(1);
  request_ =
      job_controller_->Start(&request_delegate_, nullptr, net_log_.bound(),
                             HttpStreamRequest::HTTP_STREAM, DEFAULT_PRIORITY);

  EXPECT_FALSE(job_controller_->main_job());
  EXPECT_FALSE(job_controller_->alternative_job());

  base::RunLoop().RunUntilIdle();
  request_.reset();
  EXPECT_TRUE(HttpStreamFactoryImplPeer::IsJobControllerDeleted(factory_));
}

class JobControllerReconsiderProxyAfterErrorTest
    : public HttpStreamFactoryImplJobControllerTest,
      public ::testing::WithParamInterface<::testing::tuple<bool, int>> {
 public:
  void Initialize(std::unique_ptr<ProxyService> proxy_service,
                  std::unique_ptr<ProxyDelegate> proxy_delegate) {
    session_deps_.proxy_delegate = std::move(proxy_delegate);
    session_deps_.proxy_service = std::move(proxy_service);
    session_ = base::MakeUnique<HttpNetworkSession>(
        SpdySessionDependencies::CreateSessionParams(&session_deps_),
        SpdySessionDependencies::CreateSessionContext(&session_deps_));
    factory_ =
        static_cast<HttpStreamFactoryImpl*>(session_->http_stream_factory());
  }

  std::unique_ptr<HttpStreamRequest> CreateJobController(
      const HttpRequestInfo& request_info) {
    HttpStreamFactoryImpl::JobController* job_controller =
        new HttpStreamFactoryImpl::JobController(
            factory_, &request_delegate_, session_.get(), &default_job_factory_,
            request_info, is_preconnect_, enable_ip_based_pooling_,
            enable_alternative_services_, SSLConfig(), SSLConfig());
    HttpStreamFactoryImplPeer::AddJobController(factory_, job_controller);
    return job_controller->Start(&request_delegate_, nullptr, net_log_.bound(),
                                 HttpStreamRequest::HTTP_STREAM,
                                 DEFAULT_PRIORITY);
  }

 private:
  // Use real Jobs so that Job::Resume() is not mocked out. When main job is
  // resumed it will use mock socket data.
  HttpStreamFactoryImpl::JobFactory default_job_factory_;
};

INSTANTIATE_TEST_CASE_P(
    /* no prefix */,
    JobControllerReconsiderProxyAfterErrorTest,
    ::testing::Combine(::testing::Bool(),
                       testing::ValuesIn(proxy_test_mock_errors)));

TEST_P(JobControllerReconsiderProxyAfterErrorTest, ReconsiderProxyAfterError) {
  const bool set_alternative_proxy_server = ::testing::get<0>(GetParam());
  const int mock_error = ::testing::get<1>(GetParam());
  std::unique_ptr<ProxyService> proxy_service =
      ProxyService::CreateFixedFromPacResult(
          "HTTPS badproxy:99; HTTPS badfallbackproxy:98; DIRECT");
  auto test_proxy_delegate = base::MakeUnique<TestProxyDelegate>();
  TestProxyDelegate* test_proxy_delegate_raw = test_proxy_delegate.get();

  // Before starting the test, verify that there are no proxies marked as bad.
  ASSERT_TRUE(proxy_service->proxy_retry_info().empty()) << mock_error;

  StaticSocketDataProvider socket_data_proxy_main_job;
  socket_data_proxy_main_job.set_connect_data(MockConnect(ASYNC, mock_error));
  session_deps_.socket_factory->AddSocketDataProvider(
      &socket_data_proxy_main_job);

  StaticSocketDataProvider socket_data_proxy_alternate_job;
  if (set_alternative_proxy_server) {
    // Mock socket used by the QUIC job.
    socket_data_proxy_alternate_job.set_connect_data(
        MockConnect(ASYNC, mock_error));
    session_deps_.socket_factory->AddSocketDataProvider(
        &socket_data_proxy_alternate_job);
    test_proxy_delegate->set_alternative_proxy_server(
        ProxyServer::FromPacString("QUIC badproxy:99"));
  }

  SSLSocketDataProvider ssl_data(ASYNC, OK);

  // When retrying the job using the second proxy (badFallback:98),
  // alternative job must not be created. So, socket data for only the
  // main job is needed.
  StaticSocketDataProvider socket_data_proxy_main_job_2;
  socket_data_proxy_main_job_2.set_connect_data(MockConnect(ASYNC, mock_error));
  session_deps_.socket_factory->AddSocketDataProvider(
      &socket_data_proxy_main_job_2);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data);

  // First request would use DIRECT, and succeed.
  StaticSocketDataProvider socket_data_direct_first_request;
  socket_data_direct_first_request.set_connect_data(MockConnect(ASYNC, OK));
  session_deps_.socket_factory->AddSocketDataProvider(
      &socket_data_direct_first_request);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data);

  // Second request would use DIRECT, and succeed.
  StaticSocketDataProvider socket_data_direct_second_request;
  socket_data_direct_second_request.set_connect_data(MockConnect(ASYNC, OK));
  session_deps_.socket_factory->AddSocketDataProvider(
      &socket_data_direct_second_request);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data);

  // Now request a stream. It should succeed using the DIRECT.
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("http://www.example.com");

  Initialize(std::move(proxy_service), std::move(test_proxy_delegate));
  EXPECT_EQ(set_alternative_proxy_server,
            test_proxy_delegate_raw->alternative_proxy_server().is_quic());

  // Start two requests. The first request should consume data from
  // |socket_data_proxy_main_job|,
  // |socket_data_proxy_alternate_job| and
  // |socket_data_direct_first_request|. The second request should consume
  // data from |socket_data_direct_second_request|.

  for (size_t i = 0; i < 2; ++i) {
    ProxyInfo used_proxy_info;
    EXPECT_CALL(request_delegate_, OnStreamReadyImpl(_, _, _))
        .Times(1)
        .WillOnce(::testing::SaveArg<1>(&used_proxy_info));

    std::unique_ptr<HttpStreamRequest> request =
        CreateJobController(request_info);

    base::RunLoop().RunUntilIdle();
    // The proxy that failed should now be known to the proxy_service as
    // bad.
    const ProxyRetryInfoMap retry_info =
        session_->proxy_service()->proxy_retry_info();
    EXPECT_EQ(2u, retry_info.size()) << mock_error;
    EXPECT_NE(retry_info.end(), retry_info.find("https://badproxy:99"));
    EXPECT_NE(retry_info.end(), retry_info.find("https://badfallbackproxy:98"));

    // Verify that request was fetched without proxy.
    EXPECT_TRUE(used_proxy_info.is_direct());

    // If alternative proxy server was specified, it should have been marked
    // as invalid so that it is not used for subsequent requests.
    EXPECT_FALSE(
        test_proxy_delegate_raw->alternative_proxy_server().is_valid());

    if (set_alternative_proxy_server) {
      // GetAlternativeProxy should be called only once for the first
      // request.
      EXPECT_EQ(1,
                test_proxy_delegate_raw->get_alternative_proxy_invocations());
    } else {
      // Alternative proxy server job is never started. So, ProxyDelegate is
      // queried once per request.
      EXPECT_EQ(2,
                test_proxy_delegate_raw->get_alternative_proxy_invocations());
    }
  }
  EXPECT_TRUE(HttpStreamFactoryImplPeer::IsJobControllerDeleted(factory_));
}

// Regression test for crbug.com/723589.
TEST_P(JobControllerReconsiderProxyAfterErrorTest,
       ProxyResolutionSucceedsOnReconsiderAsync) {
  const int mock_error = ::testing::get<1>(GetParam());
  StaticSocketDataProvider failed_main_job;
  failed_main_job.set_connect_data(MockConnect(ASYNC, mock_error));
  session_deps_.socket_factory->AddSocketDataProvider(&failed_main_job);

  StaticSocketDataProvider successful_fallback;
  successful_fallback.set_connect_data(MockConnect(SYNCHRONOUS, OK));
  session_deps_.socket_factory->AddSocketDataProvider(&successful_fallback);

  ProxyConfig proxy_config;
  GURL pac_url("http://fooproxyurl/old.pac");
  proxy_config.set_pac_url(pac_url);
  proxy_config.set_pac_mandatory(true);
  MockAsyncProxyResolverFactory* proxy_resolver_factory =
      new MockAsyncProxyResolverFactory(false);
  ProxyService* proxy_service =
      new ProxyService(base::MakeUnique<ProxyConfigServiceFixed>(proxy_config),
                       base::WrapUnique(proxy_resolver_factory), nullptr);
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("http://www.example.com");

  Initialize(base::WrapUnique<ProxyService>(proxy_service), nullptr);
  std::unique_ptr<HttpStreamRequest> request =
      CreateJobController(request_info);
  ASSERT_EQ(1u, proxy_resolver_factory->pending_requests().size());

  EXPECT_CALL(request_delegate_, OnStreamFailed(_, _)).Times(0);
  EXPECT_EQ(
      pac_url,
      proxy_resolver_factory->pending_requests()[0]->script_data()->url());
  MockAsyncProxyResolver resolver;
  proxy_resolver_factory->pending_requests()[0]->CompleteNowWithForwarder(
      OK, &resolver);
  ASSERT_EQ(1u, resolver.pending_jobs().size());
  EXPECT_EQ(request_info.url, resolver.pending_jobs()[0]->url());
  resolver.pending_jobs()[0]->results()->UsePacString("PROXY badproxy:10");
  resolver.pending_jobs()[0]->CompleteNow(OK);
  ASSERT_EQ(0u, proxy_resolver_factory->pending_requests().size());

  ProxyConfig new_proxy_config;
  GURL new_pac_url("http://fooproxyurl/new.pac");
  new_proxy_config.set_pac_url(new_pac_url);
  new_proxy_config.set_pac_mandatory(true);
  auto new_proxy_config_service =
      base::MakeUnique<ProxyConfigServiceFixed>(new_proxy_config);
  proxy_service->ResetConfigService(std::move(new_proxy_config_service));
  base::RunLoop().RunUntilIdle();
  ASSERT_EQ(1u, proxy_resolver_factory->pending_requests().size());
  EXPECT_EQ(
      new_pac_url,
      proxy_resolver_factory->pending_requests()[0]->script_data()->url());
  proxy_resolver_factory->pending_requests()[0]->CompleteNowWithForwarder(
      OK, &resolver);
  ASSERT_EQ(1u, resolver.pending_jobs().size());
  EXPECT_EQ(request_info.url, resolver.pending_jobs()[0]->url());
  resolver.pending_jobs()[0]->results()->UsePacString(
      "PROXY goodfallbackproxy:80");
  resolver.pending_jobs()[0]->CompleteNow(OK);

  EXPECT_CALL(request_delegate_, OnStreamReadyImpl(_, _, _));
  base::RunLoop().RunUntilIdle();
  request.reset();
  EXPECT_TRUE(HttpStreamFactoryImplPeer::IsJobControllerDeleted(factory_));
}

TEST_F(HttpStreamFactoryImplJobControllerTest,
       OnStreamFailedWithNoAlternativeJob) {
  tcp_data_ = base::MakeUnique<SequencedSocketData>(nullptr, 0, nullptr, 0);
  tcp_data_->set_connect_data(MockConnect(ASYNC, ERR_FAILED));

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("http://www.google.com");

  Initialize(request_info);

  request_ =
      job_controller_->Start(&request_delegate_, nullptr, net_log_.bound(),
                             HttpStreamRequest::HTTP_STREAM, DEFAULT_PRIORITY);

  EXPECT_TRUE(job_controller_->main_job());
  EXPECT_FALSE(job_controller_->alternative_job());

  // There's no other alternative job. Thus when stream failed, it should
  // notify Request of the stream failure.
  EXPECT_CALL(request_delegate_, OnStreamFailed(ERR_FAILED, _)).Times(1);
  base::RunLoop().RunUntilIdle();
}

TEST_F(HttpStreamFactoryImplJobControllerTest,
       OnStreamReadyWithNoAlternativeJob) {
  tcp_data_ = base::MakeUnique<SequencedSocketData>(nullptr, 0, nullptr, 0);
  tcp_data_->set_connect_data(MockConnect(ASYNC, OK));

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("http://www.google.com");

  Initialize(request_info);

  request_ =
      job_controller_->Start(&request_delegate_, nullptr, net_log_.bound(),
                             HttpStreamRequest::HTTP_STREAM, DEFAULT_PRIORITY);

  // There's no other alternative job. Thus when a stream is ready, it should
  // notify Request.
  EXPECT_TRUE(job_controller_->main_job());

  EXPECT_CALL(request_delegate_, OnStreamReadyImpl(_, _, _));
  base::RunLoop().RunUntilIdle();
}

// Test we cancel Jobs correctly when the Request is explicitly canceled
// before any Job is bound to Request.
TEST_F(HttpStreamFactoryImplJobControllerTest, CancelJobsBeforeBinding) {
  // Use COLD_START to make the alt job pending.
  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::COLD_START);
  quic_data_ = base::MakeUnique<MockQuicData>();
  quic_data_->AddRead(SYNCHRONOUS, OK);

  tcp_data_ = base::MakeUnique<SequencedSocketData>(nullptr, 0, nullptr, 0);
  tcp_data_->set_connect_data(MockConnect(ASYNC, OK));
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");

  Initialize(request_info);
  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(kProtoQUIC, server.host(), 443);
  SetAlternativeService(request_info, alternative_service);

  request_ =
      job_controller_->Start(&request_delegate_, nullptr, net_log_.bound(),
                             HttpStreamRequest::HTTP_STREAM, DEFAULT_PRIORITY);
  EXPECT_TRUE(job_controller_->main_job());
  EXPECT_TRUE(job_controller_->alternative_job());

  // Reset the Request will cancel all the Jobs since there's no Job determined
  // to serve Request yet and JobController will notify the factory to delete
  // itself upon completion.
  request_.reset();
  VerifyBrokenAlternateProtocolMapping(request_info, false);
  EXPECT_TRUE(HttpStreamFactoryImplPeer::IsJobControllerDeleted(factory_));
}

TEST_F(HttpStreamFactoryImplJobControllerTest, OnStreamFailedForBothJobs) {
  quic_data_ = base::MakeUnique<MockQuicData>();
  quic_data_->AddConnect(ASYNC, ERR_FAILED);
  tcp_data_ = base::MakeUnique<SequencedSocketData>(nullptr, 0, nullptr, 0);
  tcp_data_->set_connect_data(MockConnect(ASYNC, ERR_FAILED));

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");

  Initialize(request_info);
  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(kProtoQUIC, server.host(), 443);
  SetAlternativeService(request_info, alternative_service);

  request_ =
      job_controller_->Start(&request_delegate_, nullptr, net_log_.bound(),
                             HttpStreamRequest::HTTP_STREAM, DEFAULT_PRIORITY);
  EXPECT_TRUE(job_controller_->main_job());
  EXPECT_TRUE(job_controller_->alternative_job());

  // The failure of second Job should be reported to Request as there's no more
  // pending Job to serve the Request.
  EXPECT_CALL(request_delegate_, OnStreamFailed(_, _)).Times(1);
  base::RunLoop().RunUntilIdle();
  VerifyBrokenAlternateProtocolMapping(request_info, false);
  request_.reset();
  EXPECT_TRUE(HttpStreamFactoryImplPeer::IsJobControllerDeleted(factory_));
}

TEST_F(HttpStreamFactoryImplJobControllerTest,
       AltJobFailsAfterMainJobSucceeds) {
  quic_data_ = base::MakeUnique<MockQuicData>();
  quic_data_->AddRead(ASYNC, ERR_FAILED);
  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::COLD_START);

  tcp_data_ = base::MakeUnique<SequencedSocketData>(nullptr, 0, nullptr, 0);
  tcp_data_->set_connect_data(MockConnect(SYNCHRONOUS, OK));
  SSLSocketDataProvider ssl_data(SYNCHRONOUS, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data);

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");

  Initialize(request_info);
  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(kProtoQUIC, server.host(), 443);
  SetAlternativeService(request_info, alternative_service);

  request_ =
      job_controller_->Start(&request_delegate_, nullptr, net_log_.bound(),
                             HttpStreamRequest::HTTP_STREAM, DEFAULT_PRIORITY);
  EXPECT_TRUE(job_controller_->main_job());
  EXPECT_TRUE(job_controller_->alternative_job());

  // Main job succeeds, starts serving Request and it should report status
  // to Request. The alternative job will mark the main job complete and gets
  // orphaned.
  EXPECT_CALL(request_delegate_, OnStreamReadyImpl(_, _, _));
  // JobController shouldn't report the status of second job as request
  // is already successfully served.
  EXPECT_CALL(request_delegate_, OnStreamFailed(_, _)).Times(0);

  base::RunLoop().RunUntilIdle();

  VerifyBrokenAlternateProtocolMapping(request_info, true);
  // Reset the request as it's been successfully served.
  request_.reset();
  EXPECT_TRUE(HttpStreamFactoryImplPeer::IsJobControllerDeleted(factory_));
}

// Tests that if alt job succeeds and main job is blocked, main job should be
// cancelled immediately. |request_| completion will clean up the JobController.
// Regression test for crbug.com/678768.
TEST_F(HttpStreamFactoryImplJobControllerTest,
       AltJobSucceedsMainJobBlockedControllerDestroyed) {
  quic_data_ = base::MakeUnique<MockQuicData>();
  quic_data_->AddWrite(client_maker_.MakeInitialSettingsPacket(1, nullptr));
  quic_data_->AddRead(ASYNC, OK);

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");

  Initialize(request_info);

  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(kProtoQUIC, server.host(), 443);
  SetAlternativeService(request_info, alternative_service);
  request_ =
      job_controller_->Start(&request_delegate_, nullptr, net_log_.bound(),
                             HttpStreamRequest::HTTP_STREAM, DEFAULT_PRIORITY);
  EXPECT_TRUE(job_controller_->main_job());
  EXPECT_TRUE(job_controller_->alternative_job());
  EXPECT_TRUE(JobControllerPeer::main_job_is_blocked(job_controller_));

  // |alternative_job| succeeds and should report status to |request_delegate_|.
  EXPECT_CALL(request_delegate_, OnStreamReadyImpl(_, _, _));

  base::RunLoop().RunUntilIdle();

  EXPECT_FALSE(job_controller_->main_job());
  EXPECT_TRUE(job_controller_->alternative_job());

  // Invoke OnRequestComplete() which should delete |job_controller_| from
  // |factory_|.
  request_.reset();
  VerifyBrokenAlternateProtocolMapping(request_info, false);
  // This fails without the fix for crbug.com/678768.
  EXPECT_TRUE(HttpStreamFactoryImplPeer::IsJobControllerDeleted(factory_));
}

TEST_F(HttpStreamFactoryImplJobControllerTest,
       SpdySessionKeyHasOriginHostPortPair) {
  session_deps_.enable_http2_alternative_service = true;

  const char origin_host[] = "www.example.org";
  const uint16_t origin_port = 443;
  const char alternative_host[] = "mail.example.org";
  const uint16_t alternative_port = 123;

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url =
      GURL(base::StringPrintf("https://%s:%u", origin_host, origin_port));
  Initialize(request_info);

  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(kProtoHTTP2, alternative_host,
                                         alternative_port);
  SetAlternativeService(request_info, alternative_service);

  request_ =
      job_controller_->Start(&request_delegate_, nullptr, net_log_.bound(),
                             HttpStreamRequest::HTTP_STREAM, DEFAULT_PRIORITY);

  HostPortPair main_host_port_pair =
      HttpStreamFactoryImplJobPeer::GetSpdySessionKey(
          job_controller_->main_job())
          .host_port_pair();
  EXPECT_EQ(origin_host, main_host_port_pair.host());
  EXPECT_EQ(origin_port, main_host_port_pair.port());

  HostPortPair alternative_host_port_pair =
      HttpStreamFactoryImplJobPeer::GetSpdySessionKey(
          job_controller_->alternative_job())
          .host_port_pair();
  EXPECT_EQ(origin_host, alternative_host_port_pair.host());
  EXPECT_EQ(origin_port, alternative_host_port_pair.port());
}

// Tests that if an orphaned job completes after |request_| is gone,
// JobController will be cleaned up.
TEST_F(HttpStreamFactoryImplJobControllerTest,
       OrphanedJobCompletesControllerDestroyed) {
  quic_data_ = base::MakeUnique<MockQuicData>();
  quic_data_->AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  // Use cold start and complete alt job manually.
  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::COLD_START);

  tcp_data_ = base::MakeUnique<SequencedSocketData>(nullptr, 0, nullptr, 0);
  tcp_data_->set_connect_data(MockConnect(SYNCHRONOUS, OK));
  SSLSocketDataProvider ssl_data(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data);

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");

  Initialize(request_info);

  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(kProtoQUIC, server.host(), 443);
  SetAlternativeService(request_info, alternative_service);

  request_ =
      job_controller_->Start(&request_delegate_, nullptr, net_log_.bound(),
                             HttpStreamRequest::HTTP_STREAM, DEFAULT_PRIORITY);
  EXPECT_TRUE(job_controller_->main_job());
  EXPECT_TRUE(job_controller_->alternative_job());
  // main job should not be blocked because alt job returned ERR_IO_PENDING.
  EXPECT_FALSE(JobControllerPeer::main_job_is_blocked(job_controller_));

  EXPECT_CALL(request_delegate_, OnStreamReadyImpl(_, _, _));

  // Complete main job now.
  base::RunLoop().RunUntilIdle();

  // Invoke OnRequestComplete() which should not delete |job_controller_| from
  // |factory_| because alt job is yet to finish.
  request_.reset();
  ASSERT_FALSE(HttpStreamFactoryImplPeer::IsJobControllerDeleted(factory_));
  EXPECT_FALSE(job_controller_->main_job());
  EXPECT_TRUE(job_controller_->alternative_job());

  // Make |alternative_job| succeed.
  HttpStream* http_stream =
      new HttpBasicStream(base::MakeUnique<ClientSocketHandle>(), false, false);
  job_factory_.alternative_job()->SetStream(http_stream);
  // This should not call request_delegate_::OnStreamReady.
  job_controller_->OnStreamReady(job_factory_.alternative_job(), SSLConfig());
  // Make sure that controller does not leak.
  EXPECT_TRUE(HttpStreamFactoryImplPeer::IsJobControllerDeleted(factory_));
}

TEST_F(HttpStreamFactoryImplJobControllerTest,
       AltJobSucceedsAfterMainJobFailed) {
  quic_data_ = base::MakeUnique<MockQuicData>();
  quic_data_->AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  // Use cold start and complete alt job manually.
  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::COLD_START);

  // One failed TCP connect.
  tcp_data_ = base::MakeUnique<SequencedSocketData>(nullptr, 0, nullptr, 0);
  tcp_data_->set_connect_data(MockConnect(SYNCHRONOUS, ERR_FAILED));

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");

  Initialize(request_info);

  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(kProtoQUIC, server.host(), 443);
  SetAlternativeService(request_info, alternative_service);

  // |main_job| fails but should not report status to Request.
  EXPECT_CALL(request_delegate_, OnStreamFailed(_, _)).Times(0);

  request_ =
      job_controller_->Start(&request_delegate_, nullptr, net_log_.bound(),
                             HttpStreamRequest::HTTP_STREAM, DEFAULT_PRIORITY);
  EXPECT_TRUE(job_controller_->main_job());
  EXPECT_TRUE(job_controller_->alternative_job());

  base::RunLoop().RunUntilIdle();

  // Make |alternative_job| succeed.
  HttpStream* http_stream =
      new HttpBasicStream(base::MakeUnique<ClientSocketHandle>(), false, false);

  EXPECT_CALL(request_delegate_, OnStreamReadyImpl(_, _, http_stream));

  job_factory_.alternative_job()->SetStream(http_stream);
  job_controller_->OnStreamReady(job_factory_.alternative_job(), SSLConfig());

  // |alternative_job| succeeds and should report status to Request.
  VerifyBrokenAlternateProtocolMapping(request_info, false);
  request_.reset();
  EXPECT_TRUE(HttpStreamFactoryImplPeer::IsJobControllerDeleted(factory_));
}

TEST_F(HttpStreamFactoryImplJobControllerTest,
       MainJobSucceedsAfterAltJobFailed) {
  quic_data_ = base::MakeUnique<MockQuicData>();
  quic_data_->AddConnect(SYNCHRONOUS, ERR_FAILED);

  tcp_data_ = base::MakeUnique<SequencedSocketData>(nullptr, 0, nullptr, 0);
  tcp_data_->set_connect_data(MockConnect(SYNCHRONOUS, OK));
  SSLSocketDataProvider ssl_data(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data);

  base::HistogramTester histogram_tester;
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");

  Initialize(request_info);

  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(kProtoQUIC, server.host(), 443);
  SetAlternativeService(request_info, alternative_service);

  request_ =
      job_controller_->Start(&request_delegate_, nullptr, net_log_.bound(),
                             HttpStreamRequest::HTTP_STREAM, DEFAULT_PRIORITY);
  EXPECT_TRUE(job_controller_->main_job());
  EXPECT_TRUE(job_controller_->alternative_job());

  // |alternative_job| fails but should not report status to Request.
  EXPECT_CALL(request_delegate_, OnStreamFailed(_, _)).Times(0);
  // |main_job| succeeds and should report status to Request.
  EXPECT_CALL(request_delegate_, OnStreamReadyImpl(_, _, _));

  base::RunLoop().RunUntilIdle();

  // Verify that the alternate protocol is marked as broken.
  VerifyBrokenAlternateProtocolMapping(request_info, true);
  histogram_tester.ExpectUniqueSample("Net.AlternateServiceFailed", -ERR_FAILED,
                                      1);
  request_.reset();
  EXPECT_TRUE(HttpStreamFactoryImplPeer::IsJobControllerDeleted(factory_));
}

// Verifies that if the alternative job fails due to a connection change event,
// then the alternative service is not marked as broken.
TEST_F(HttpStreamFactoryImplJobControllerTest,
       MainJobSucceedsAfterConnectionChanged) {
  quic_data_ = base::MakeUnique<MockQuicData>();
  quic_data_->AddConnect(SYNCHRONOUS, ERR_NETWORK_CHANGED);
  tcp_data_ = base::MakeUnique<SequencedSocketData>(nullptr, 0, nullptr, 0);
  tcp_data_->set_connect_data(MockConnect(SYNCHRONOUS, OK));
  SSLSocketDataProvider ssl_data(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data);

  base::HistogramTester histogram_tester;

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");
  Initialize(request_info);

  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(kProtoQUIC, server.host(), 443);
  SetAlternativeService(request_info, alternative_service);

  request_ =
      job_controller_->Start(&request_delegate_, nullptr, net_log_.bound(),
                             HttpStreamRequest::HTTP_STREAM, DEFAULT_PRIORITY);
  EXPECT_TRUE(job_controller_->main_job());
  EXPECT_TRUE(job_controller_->alternative_job());

  // |alternative_job| fails but should not report status to Request.
  EXPECT_CALL(request_delegate_, OnStreamFailed(_, _)).Times(0);
  // |main_job| succeeds and should report status to Request.
  EXPECT_CALL(request_delegate_, OnStreamReadyImpl(_, _, _));
  base::RunLoop().RunUntilIdle();

  // Verify that the alternate protocol is not marked as broken.
  VerifyBrokenAlternateProtocolMapping(request_info, false);
  histogram_tester.ExpectUniqueSample("Net.AlternateServiceFailed",
                                      -ERR_NETWORK_CHANGED, 1);
  request_.reset();
  EXPECT_TRUE(HttpStreamFactoryImplPeer::IsJobControllerDeleted(factory_));
}

// Regression test for crbug/621069.
// Get load state after main job fails and before alternative job succeeds.
TEST_F(HttpStreamFactoryImplJobControllerTest, GetLoadStateAfterMainJobFailed) {
  // Use COLD_START to complete alt job manually.
  quic_data_ = base::MakeUnique<MockQuicData>();
  quic_data_->AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::COLD_START);

  tcp_data_ = base::MakeUnique<SequencedSocketData>(nullptr, 0, nullptr, 0);
  tcp_data_->set_connect_data(MockConnect(ASYNC, ERR_FAILED));

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");

  Initialize(request_info);
  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(kProtoQUIC, server.host(), 443);
  SetAlternativeService(request_info, alternative_service);

  request_ =
      job_controller_->Start(&request_delegate_, nullptr, net_log_.bound(),
                             HttpStreamRequest::HTTP_STREAM, DEFAULT_PRIORITY);
  EXPECT_TRUE(job_controller_->main_job());
  EXPECT_TRUE(job_controller_->alternative_job());

  // |main_job| fails but should not report status to Request.
  // The alternative job will mark the main job complete.
  EXPECT_CALL(request_delegate_, OnStreamFailed(_, _)).Times(0);

  base::RunLoop().RunUntilIdle();

  // Controller should use alternative job to get load state.
  job_controller_->GetLoadState();

  // |alternative_job| succeeds and should report status to Request.
  HttpStream* http_stream =
      new HttpBasicStream(base::MakeUnique<ClientSocketHandle>(), false, false);
  job_factory_.alternative_job()->SetStream(http_stream);

  EXPECT_CALL(request_delegate_, OnStreamReadyImpl(_, _, http_stream));
  job_controller_->OnStreamReady(job_factory_.alternative_job(), SSLConfig());
  request_.reset();
  EXPECT_TRUE(HttpStreamFactoryImplPeer::IsJobControllerDeleted(factory_));
}

TEST_F(HttpStreamFactoryImplJobControllerTest, ResumeMainJobWhenAltJobStalls) {
  // Use COLD_START to stall alt job.
  quic_data_ = base::MakeUnique<MockQuicData>();
  quic_data_->AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::COLD_START);

  tcp_data_ = base::MakeUnique<SequencedSocketData>(nullptr, 0, nullptr, 0);
  tcp_data_->set_connect_data(MockConnect(SYNCHRONOUS, OK));
  SSLSocketDataProvider ssl_data(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data);

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");

  Initialize(request_info);
  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(kProtoQUIC, server.host(), 443);
  SetAlternativeService(request_info, alternative_service);

  request_ =
      job_controller_->Start(&request_delegate_, nullptr, net_log_.bound(),
                             HttpStreamRequest::HTTP_STREAM, DEFAULT_PRIORITY);
  EXPECT_TRUE(job_controller_->main_job());
  EXPECT_TRUE(job_controller_->alternative_job());

  // Alt job is stalled and main job should complete successfully.
  EXPECT_CALL(request_delegate_, OnStreamReadyImpl(_, _, _));

  base::RunLoop().RunUntilIdle();
}

TEST_F(HttpStreamFactoryImplJobControllerTest, InvalidPortForQuic) {
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");

  // Using a restricted port 101 for QUIC should fail and the alternative job
  // should post OnStreamFailedCall on the controller to resume the main job.
  Initialize(request_info);

  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(kProtoQUIC, server.host(), 101);
  SetAlternativeService(request_info, alternative_service);

  request_ =
      job_controller_->Start(&request_delegate_, nullptr, net_log_.bound(),
                             HttpStreamRequest::HTTP_STREAM, DEFAULT_PRIORITY);

  EXPECT_TRUE(job_factory_.main_job()->is_waiting());

  // Wait until OnStreamFailedCallback is executed on the alternative job.
  EXPECT_CALL(*job_factory_.main_job(), Resume()).Times(1);
  base::RunLoop().RunUntilIdle();
}

TEST_F(HttpStreamFactoryImplJobControllerTest, DelayedTCP) {
  base::ScopedMockTimeMessageLoopTaskRunner test_task_runner;
  auto failing_resolver = base::MakeUnique<MockHostResolver>();
  failing_resolver->set_ondemand_mode(true);
  failing_resolver->rules()->AddSimulatedFailure("*google.com");
  session_deps_.host_resolver = std::move(failing_resolver);

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");

  Initialize(request_info);

  // Enable delayed TCP and set time delay for waiting job.
  QuicStreamFactory* quic_stream_factory = session_->quic_stream_factory();
  quic_stream_factory->set_require_confirmation(false);
  ServerNetworkStats stats1;
  stats1.srtt = base::TimeDelta::FromMicroseconds(10);
  session_->http_server_properties()->SetServerNetworkStats(
      url::SchemeHostPort(GURL("https://www.google.com")), stats1);

  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(kProtoQUIC, server.host(), 443);
  SetAlternativeService(request_info, alternative_service);

  request_ =
      job_controller_->Start(&request_delegate_, nullptr, net_log_.bound(),
                             HttpStreamRequest::HTTP_STREAM, DEFAULT_PRIORITY);
  EXPECT_TRUE(job_controller_->main_job());
  EXPECT_TRUE(job_controller_->alternative_job());
  EXPECT_TRUE(job_controller_->main_job()->is_waiting());

  // The alternative job stalls as host resolution hangs when creating the QUIC
  // request and controller should resume the main job after delay.
  EXPECT_TRUE(test_task_runner->HasPendingTask());
  EXPECT_EQ(1u, test_task_runner->GetPendingTaskCount());
  EXPECT_CALL(*job_factory_.main_job(), Resume()).Times(1);
  test_task_runner->FastForwardBy(base::TimeDelta::FromMicroseconds(15));
  EXPECT_FALSE(test_task_runner->HasPendingTask());

  EXPECT_TRUE(job_controller_->main_job());
  EXPECT_TRUE(job_controller_->alternative_job());

  // |alternative_job| fails but should not report status to Request.
  EXPECT_CALL(request_delegate_, OnStreamFailed(_, _)).Times(0);

  EXPECT_FALSE(JobControllerPeer::main_job_is_blocked(job_controller_));
  // OnStreamFailed will post a task to resume the main job immediately but
  // won't call Resume() on the main job since it's been resumed already.
  EXPECT_CALL(*job_factory_.main_job(), Resume()).Times(0);
  // Now unblock Resolver so that alternate job (and QuicStreamFactory::Job) can
  // be cleaned up.
  session_deps_.host_resolver->ResolveAllPending();
  EXPECT_EQ(1u, test_task_runner->GetPendingTaskCount());
  test_task_runner->FastForwardUntilNoTasksRemain();
  EXPECT_FALSE(job_controller_->alternative_job());
}

// Test that main job is blocked for kMaxDelayTimeForMainJob(3s) if
// http_server_properties cached an inappropriate large srtt for the server,
// which would potentially delay the main job for a extremely long time in
// delayed tcp case.
TEST_F(HttpStreamFactoryImplJobControllerTest, DelayedTCPWithLargeSrtt) {
  // Overrides the main thread's message loop with a mock tick clock so that we
  // could verify the main job is resumed with appropriate delay.
  base::ScopedMockTimeMessageLoopTaskRunner test_task_runner;
  // The max delay time should be in sync with .cc file.
  base::TimeDelta kMaxDelayTimeForMainJob = base::TimeDelta::FromSeconds(3);
  auto failing_resolver = base::MakeUnique<MockHostResolver>();
  failing_resolver->set_ondemand_mode(true);
  failing_resolver->rules()->AddSimulatedFailure("*google.com");
  session_deps_.host_resolver = std::move(failing_resolver);

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");

  Initialize(request_info);

  // Enable delayed TCP and set a extremely large time delay for waiting job.
  QuicStreamFactory* quic_stream_factory = session_->quic_stream_factory();
  quic_stream_factory->set_require_confirmation(false);
  ServerNetworkStats stats1;
  stats1.srtt = base::TimeDelta::FromSeconds(100);
  session_->http_server_properties()->SetServerNetworkStats(
      url::SchemeHostPort(GURL("https://www.google.com")), stats1);

  // Set a SPDY alternative service for the server.
  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(kProtoQUIC, server.host(), 443);
  SetAlternativeService(request_info, alternative_service);

  request_ =
      job_controller_->Start(&request_delegate_, nullptr, net_log_.bound(),
                             HttpStreamRequest::HTTP_STREAM, DEFAULT_PRIORITY);
  EXPECT_TRUE(job_controller_->main_job());
  EXPECT_TRUE(job_controller_->alternative_job());
  EXPECT_TRUE(job_controller_->main_job()->is_waiting());

  // The alternative job stalls as host resolution hangs when creating the QUIC
  // request and controller should resume the main job after delay.
  EXPECT_TRUE(test_task_runner->HasPendingTask());
  EXPECT_EQ(1u, test_task_runner->GetPendingTaskCount());

  EXPECT_CALL(*job_factory_.main_job(), Resume()).Times(1);
  // Move forward the task runner with kMaxDelayTimeForMainJob and verify the
  // main job is resumed.
  test_task_runner->FastForwardBy(kMaxDelayTimeForMainJob);
  EXPECT_FALSE(test_task_runner->HasPendingTask());

  // Now unblock Resolver so that alternate job (and QuicStreamFactory::Job) can
  // be cleaned up.
  session_deps_.host_resolver->ResolveAllPending();
  EXPECT_EQ(1u, test_task_runner->GetPendingTaskCount());
  test_task_runner->FastForwardUntilNoTasksRemain();
  EXPECT_FALSE(job_controller_->alternative_job());
}

TEST_F(HttpStreamFactoryImplJobControllerTest,
       ResumeMainJobImmediatelyOnStreamFailed) {
  // Overrides the main thread's message loop with a mock tick clock so that we
  // could verify the main job is resumed with appropriate delay.
  base::ScopedMockTimeMessageLoopTaskRunner test_task_runner;

  auto failing_resolver = base::MakeUnique<MockHostResolver>();
  failing_resolver->set_ondemand_mode(true);
  failing_resolver->rules()->AddSimulatedFailure("*google.com");
  session_deps_.host_resolver = std::move(failing_resolver);

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");

  Initialize(request_info);

  // Enable delayed TCP and set time delay for waiting job.
  QuicStreamFactory* quic_stream_factory = session_->quic_stream_factory();
  quic_stream_factory->set_require_confirmation(false);
  ServerNetworkStats stats1;
  stats1.srtt = base::TimeDelta::FromMicroseconds(10);
  session_->http_server_properties()->SetServerNetworkStats(
      url::SchemeHostPort(GURL("https://www.google.com")), stats1);

  // Set a SPDY alternative service for the server.
  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(kProtoQUIC, server.host(), 443);
  SetAlternativeService(request_info, alternative_service);

  // The alternative job stalls as host resolution hangs when creating the QUIC
  // request and controller should resume the main job with delay.
  // OnStreamFailed should resume the main job immediately.
  request_ =
      job_controller_->Start(&request_delegate_, nullptr, net_log_.bound(),
                             HttpStreamRequest::HTTP_STREAM, DEFAULT_PRIORITY);
  EXPECT_TRUE(job_controller_->main_job());
  EXPECT_TRUE(job_controller_->alternative_job());
  EXPECT_TRUE(job_controller_->main_job()->is_waiting());

  EXPECT_TRUE(test_task_runner->HasPendingTask());
  EXPECT_EQ(1u, test_task_runner->GetPendingTaskCount());

  // |alternative_job| fails but should not report status to Request.
  EXPECT_CALL(request_delegate_, OnStreamFailed(_, _)).Times(0);
  // Now unblock Resolver to fail the alternate job.
  session_deps_.host_resolver->ResolveAllPending();
  EXPECT_EQ(2u, test_task_runner->GetPendingTaskCount());

  // Verify the main job will be resumed immediately.
  EXPECT_CALL(*job_factory_.main_job(), Resume()).Times(1);
  // Execute tasks that have no remaining delay. Tasks with nonzero delay will
  // remain queued.
  test_task_runner->RunUntilIdle();

  // Verify there is another task to resume main job with delay but should
  // not call Resume() on the main job as main job has been resumed.
  EXPECT_TRUE(test_task_runner->HasPendingTask());
  EXPECT_EQ(1u, test_task_runner->GetPendingTaskCount());
  EXPECT_CALL(*job_factory_.main_job(), Resume()).Times(0);
  test_task_runner->FastForwardBy(base::TimeDelta::FromMicroseconds(15));
  EXPECT_FALSE(test_task_runner->HasPendingTask());
  EXPECT_FALSE(job_controller_->alternative_job());
}

// Verifies that the alternative proxy server job is not created if the URL
// scheme is HTTPS.
TEST_F(HttpStreamFactoryImplJobControllerTest, HttpsURL) {
  // Using hanging resolver will cause the alternative job to hang indefinitely.
  session_deps_.host_resolver = base::MakeUnique<HangingResolver>();

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://mail.example.org/");
  Initialize(request_info);
  EXPECT_TRUE(test_proxy_delegate()->alternative_proxy_server().is_quic());

  request_ =
      job_controller_->Start(&request_delegate_, nullptr, net_log_.bound(),
                             HttpStreamRequest::HTTP_STREAM, DEFAULT_PRIORITY);
  EXPECT_TRUE(job_controller_->main_job());
  EXPECT_FALSE(job_controller_->main_job()->is_waiting());
  EXPECT_FALSE(job_controller_->alternative_job());

  EXPECT_CALL(*job_factory_.main_job(), Resume()).Times(0);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(0, test_proxy_delegate()->get_alternative_proxy_invocations());
}

// Verifies that the alternative proxy server job is not created if the main job
// does not fetch the resource through a proxy.
TEST_F(HttpStreamFactoryImplJobControllerTest, HttpURLWithNoProxy) {
  // Using hanging resolver will cause the alternative job to hang indefinitely.
  session_deps_.host_resolver = base::MakeUnique<HangingResolver>();

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("http://mail.example.org/");

  Initialize(request_info);
  EXPECT_TRUE(test_proxy_delegate()->alternative_proxy_server().is_quic());

  request_ =
      job_controller_->Start(&request_delegate_, nullptr, net_log_.bound(),
                             HttpStreamRequest::HTTP_STREAM, DEFAULT_PRIORITY);
  EXPECT_TRUE(job_controller_->main_job());
  EXPECT_FALSE(job_controller_->main_job()->is_waiting());
  EXPECT_FALSE(job_controller_->alternative_job());

  EXPECT_CALL(*job_factory_.main_job(), Resume()).Times(0);
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(0, test_proxy_delegate()->get_alternative_proxy_invocations());
}

// Verifies that the main job is resumed properly after a delay when the
// alternative proxy server job hangs.
TEST_F(HttpStreamFactoryImplJobControllerTest, DelayedTCPAlternativeProxy) {
  // Overrides the main thread's message loop with a mock tick clock so that we
  // could verify the main job is resumed with appropriate delay.
  base::ScopedMockTimeMessageLoopTaskRunner test_task_runner;

  auto failing_resolver = base::MakeUnique<MockHostResolver>();
  failing_resolver->set_ondemand_mode(true);
  failing_resolver->rules()->AddSimulatedFailure("*myproxy.org");
  session_deps_.host_resolver = std::move(failing_resolver);

  UseAlternativeProxy();

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("http://mail.example.org/");
  Initialize(request_info);

  EXPECT_TRUE(test_proxy_delegate()->alternative_proxy_server().is_quic());

  // Enable delayed TCP and set time delay for waiting job.
  QuicStreamFactory* quic_stream_factory = session_->quic_stream_factory();
  quic_stream_factory->set_require_confirmation(false);
  ServerNetworkStats stats1;
  stats1.srtt = base::TimeDelta::FromMicroseconds(10);
  session_->http_server_properties()->SetServerNetworkStats(
      url::SchemeHostPort(GURL("https://myproxy.org")), stats1);

  request_ =
      job_controller_->Start(&request_delegate_, nullptr, net_log_.bound(),
                             HttpStreamRequest::HTTP_STREAM, DEFAULT_PRIORITY);
  EXPECT_TRUE(job_controller_->main_job());
  EXPECT_TRUE(job_controller_->main_job()->is_waiting());
  EXPECT_TRUE(job_controller_->alternative_job());
  // The main job is unblocked but is resumed one message loop iteration later.
  EXPECT_FALSE(JobControllerPeer::main_job_is_blocked(job_controller_));
  EXPECT_FALSE(JobControllerPeer::main_job_is_resumed(job_controller_));
  EXPECT_EQ(1u, test_task_runner->GetPendingTaskCount());

  // Move forward the delay and verify the main job is resumed.
  EXPECT_CALL(*job_factory_.main_job(), Resume()).Times(1);
  test_task_runner->FastForwardBy(base::TimeDelta::FromMicroseconds(15));
  EXPECT_FALSE(JobControllerPeer::main_job_is_blocked(job_controller_));
  EXPECT_TRUE(JobControllerPeer::main_job_is_resumed(job_controller_));

  test_task_runner->RunUntilIdle();
  EXPECT_TRUE(test_proxy_delegate()->alternative_proxy_server().is_valid());
  EXPECT_EQ(1, test_proxy_delegate()->get_alternative_proxy_invocations());
  EXPECT_FALSE(test_task_runner->HasPendingTask());

  // Now unblock Resolver so that alternate job (and QuicStreamFactory::Job) can
  // be cleaned up.
  session_deps_.host_resolver->ResolveAllPending();
  EXPECT_EQ(1u, test_task_runner->GetPendingTaskCount());
  test_task_runner->FastForwardUntilNoTasksRemain();
  EXPECT_FALSE(job_controller_->alternative_job());
}

// Verifies that if the alternative proxy server job fails immediately, the
// main job is not blocked.
TEST_F(HttpStreamFactoryImplJobControllerTest, FailAlternativeProxy) {
  quic_data_ = base::MakeUnique<MockQuicData>();
  quic_data_->AddConnect(SYNCHRONOUS, ERR_FAILED);
  tcp_data_ = base::MakeUnique<SequencedSocketData>(nullptr, 0, nullptr, 0);
  tcp_data_->set_connect_data(MockConnect(SYNCHRONOUS, OK));
  SSLSocketDataProvider ssl_data(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data);

  UseAlternativeProxy();

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("http://mail.example.org/");
  Initialize(request_info);
  EXPECT_TRUE(test_proxy_delegate()->alternative_proxy_server().is_quic());

  // Enable delayed TCP and set time delay for waiting job.
  QuicStreamFactory* quic_stream_factory = session_->quic_stream_factory();
  quic_stream_factory->set_require_confirmation(false);
  ServerNetworkStats stats1;
  stats1.srtt = base::TimeDelta::FromMicroseconds(300 * 1000);
  session_->http_server_properties()->SetServerNetworkStats(
      url::SchemeHostPort(GURL("https://myproxy.org")), stats1);

  request_ =
      job_controller_->Start(&request_delegate_, nullptr, net_log_.bound(),
                             HttpStreamRequest::HTTP_STREAM, DEFAULT_PRIORITY);
  EXPECT_TRUE(job_controller_->main_job());
  EXPECT_TRUE(job_controller_->alternative_job());

  EXPECT_CALL(request_delegate_, OnStreamReadyImpl(_, _, _));

  base::RunLoop().RunUntilIdle();

  EXPECT_FALSE(job_controller_->alternative_job());
  EXPECT_TRUE(job_controller_->main_job());

  // The alternative proxy server should be marked as bad.
  EXPECT_FALSE(test_proxy_delegate()->alternative_proxy_server().is_valid());
  EXPECT_EQ(1, test_proxy_delegate()->get_alternative_proxy_invocations());
  request_.reset();
  EXPECT_TRUE(HttpStreamFactoryImplPeer::IsJobControllerDeleted(factory_));
}

TEST_F(HttpStreamFactoryImplJobControllerTest,
       AlternativeProxyServerJobFailsAfterMainJobSucceeds) {
  base::HistogramTester histogram_tester;

  // Use COLD_START to make the alt job pending.
  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::COLD_START);
  quic_data_ = base::MakeUnique<MockQuicData>();
  quic_data_->AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  tcp_data_ = base::MakeUnique<SequencedSocketData>(nullptr, 0, nullptr, 0);
  tcp_data_->set_connect_data(MockConnect(SYNCHRONOUS, OK));
  SSLSocketDataProvider ssl_data(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data);

  UseAlternativeProxy();

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("http://www.google.com");
  Initialize(request_info);

  url::SchemeHostPort server(request_info.url);

  request_ =
      job_controller_->Start(&request_delegate_, nullptr, net_log_.bound(),
                             HttpStreamRequest::HTTP_STREAM, DEFAULT_PRIORITY);
  EXPECT_TRUE(job_controller_->main_job());
  EXPECT_TRUE(job_controller_->alternative_job());

  // Main job succeeds, starts serving Request and it should report status
  // to Request. The alternative job will mark the main job complete and gets
  // orphaned.
  EXPECT_CALL(request_delegate_, OnStreamReadyImpl(_, _, _));

  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(job_controller_->main_job());
  EXPECT_TRUE(job_controller_->alternative_job());

  // JobController shouldn't report the status of alternative server job as
  // request is already successfully served.
  EXPECT_CALL(request_delegate_, OnStreamFailed(_, _)).Times(0);
  job_controller_->OnStreamFailed(job_factory_.alternative_job(), ERR_FAILED,
                                  SSLConfig());

  // Reset the request as it's been successfully served.
  request_.reset();
  EXPECT_TRUE(HttpStreamFactoryImplPeer::IsJobControllerDeleted(factory_));

  histogram_tester.ExpectUniqueSample("Net.QuicAlternativeProxy.Usage",
                                      2 /* ALTERNATIVE_PROXY_USAGE_LOST_RACE */,
                                      1);
}

TEST_F(HttpStreamFactoryImplJobControllerTest,
       PreconnectToHostWithValidAltSvc) {
  quic_data_ = base::MakeUnique<MockQuicData>();
  quic_data_->AddWrite(client_maker_.MakeInitialSettingsPacket(1, nullptr));
  quic_data_->AddRead(ASYNC, OK);

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.example.com");
  SetPreconnect();

  Initialize(request_info);

  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(kProtoQUIC, server.host(), 443);
  SetAlternativeService(request_info, alternative_service);

  job_controller_->Preconnect(1);
  EXPECT_TRUE(job_controller_->main_job());
  EXPECT_EQ(HttpStreamFactoryImpl::PRECONNECT,
            job_controller_->main_job()->job_type());
  EXPECT_FALSE(job_controller_->alternative_job());

  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(HttpStreamFactoryImplPeer::IsJobControllerDeleted(factory_));
}

// When preconnect to a H2 supported server, only 1 connection is opened.
TEST_F(HttpStreamFactoryImplJobControllerTest,
       PreconnectMultipleStreamsToH2Server) {
  tcp_data_ = base::MakeUnique<SequencedSocketData>(nullptr, 0, nullptr, 0);
  tcp_data_->set_connect_data(MockConnect(ASYNC, OK));
  SetPreconnect();

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("http://www.example.com");
  Initialize(request_info);

  // Sets server support HTTP/2.
  url::SchemeHostPort server(request_info.url);
  session_->http_server_properties()->SetSupportsSpdy(server, true);

  job_controller_->Preconnect(/*num_streams=*/5);
  // Only one job is started.
  EXPECT_TRUE(job_controller_->main_job());
  EXPECT_FALSE(job_controller_->alternative_job());
  EXPECT_EQ(HttpStreamFactoryImpl::PRECONNECT,
            job_controller_->main_job()->job_type());
  // There is only 1 connect even though multiple streams were requested.
  EXPECT_EQ(1, HttpStreamFactoryImplJobPeer::GetNumStreams(
                   job_controller_->main_job()));

  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(HttpStreamFactoryImplPeer::IsJobControllerDeleted(factory_));
}

class JobControllerLimitMultipleH2Requests
    : public HttpStreamFactoryImplJobControllerTest {
 protected:
  const int kNumRequests = 5;
  void SetUp() override { SkipCreatingJobController(); }
};

TEST_F(JobControllerLimitMultipleH2Requests, MultipleRequests) {
  // Make sure there is only one socket connect.
  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING)};
  tcp_data_ = base::MakeUnique<SequencedSocketData>(reads, arraysize(reads),
                                                    nullptr, 0);
  tcp_data_->set_connect_data(MockConnect(ASYNC, OK));
  SSLSocketDataProvider ssl_data(ASYNC, OK);
  ssl_data.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data);
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.example.com");
  Initialize(request_info);
  SpdySessionPoolPeer pool_peer(session_->spdy_session_pool());
  pool_peer.SetEnableSendingInitialData(false);

  // Sets server support HTTP/2.
  url::SchemeHostPort server(request_info.url);
  session_->http_server_properties()->SetSupportsSpdy(server, true);

  std::vector<std::unique_ptr<MockHttpStreamRequestDelegate>> request_delegates;
  std::vector<std::unique_ptr<HttpStreamRequest>> requests;
  for (int i = 0; i < kNumRequests; ++i) {
    request_delegates.emplace_back(
        base::MakeUnique<MockHttpStreamRequestDelegate>());
    HttpStreamFactoryImpl::JobController* job_controller =
        new HttpStreamFactoryImpl::JobController(
            factory_, request_delegates[i].get(), session_.get(), &job_factory_,
            request_info, is_preconnect_, enable_ip_based_pooling_,
            enable_alternative_services_, SSLConfig(), SSLConfig());
    HttpStreamFactoryImplPeer::AddJobController(factory_, job_controller);
    auto request = job_controller->Start(
        request_delegates[i].get(), nullptr, net_log_.bound(),
        HttpStreamRequest::HTTP_STREAM, DEFAULT_PRIORITY);
    EXPECT_TRUE(job_controller->main_job());
    EXPECT_FALSE(job_controller->alternative_job());
    requests.push_back(std::move(request));
  }

  for (int i = 0; i < kNumRequests; ++i) {
    // When a request is completed, delete it. This is needed because
    // otherwise request will be completed twice. See crbug.com/706974.
    EXPECT_CALL(*request_delegates[i].get(), OnStreamReadyImpl(_, _, _))
        .WillOnce(testing::InvokeWithoutArgs(
            [this, &requests, i]() { requests[i].reset(); }));
  }

  base::RunLoop().RunUntilIdle();
  requests.clear();
  EXPECT_TRUE(HttpStreamFactoryImplPeer::IsJobControllerDeleted(factory_));
  TestNetLogEntry::List entries;
  size_t log_position = 0;
  for (int i = 0; i < kNumRequests - 1; ++i) {
    net_log_.GetEntries(&entries);
    log_position = ExpectLogContainsSomewhereAfter(
        entries, log_position, NetLogEventType::HTTP_STREAM_JOB_THROTTLED,
        NetLogEventPhase::NONE);
  }
}

TEST_F(JobControllerLimitMultipleH2Requests, MultipleRequestsFirstRequestHang) {
  base::ScopedMockTimeMessageLoopTaskRunner test_task_runner;
  // First socket connect hang.
  SequencedSocketData hangdata(nullptr, 0, nullptr, 0);
  hangdata.set_connect_data(MockConnect(SYNCHRONOUS, ERR_IO_PENDING));
  session_deps_.socket_factory->AddSocketDataProvider(&hangdata);
  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING)};
  std::list<SequencedSocketData> socket_data;
  std::list<SSLSocketDataProvider> ssl_socket_data;
  // kNumRequests - 1 will resume themselves after a delay. There will be
  // kNumRequests - 1 sockets opened.
  for (int i = 0; i < kNumRequests - 1; i++) {
    // Only the first one needs a MockRead because subsequent sockets are
    // not used to establish a SpdySession.
    if (i == 0) {
      socket_data.emplace_back(reads, arraysize(reads), nullptr, 0);
    } else {
      socket_data.emplace_back(nullptr, 0, nullptr, 0);
    }
    socket_data.back().set_connect_data(MockConnect(ASYNC, OK));
    session_deps_.socket_factory->AddSocketDataProvider(&socket_data.back());
    ssl_socket_data.emplace_back(ASYNC, OK);
    ssl_socket_data.back().next_proto = kProtoHTTP2;
    session_deps_.socket_factory->AddSSLSocketDataProvider(
        &ssl_socket_data.back());
  }
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.example.com");
  Initialize(request_info);
  SpdySessionPoolPeer pool_peer(session_->spdy_session_pool());
  pool_peer.SetEnableSendingInitialData(false);

  // Sets server support HTTP/2.
  url::SchemeHostPort server(request_info.url);
  session_->http_server_properties()->SetSupportsSpdy(server, true);

  std::vector<std::unique_ptr<MockHttpStreamRequestDelegate>> request_delegates;
  std::vector<std::unique_ptr<HttpStreamRequest>> requests;
  for (int i = 0; i < kNumRequests; ++i) {
    request_delegates.push_back(
        base::MakeUnique<MockHttpStreamRequestDelegate>());
    HttpStreamFactoryImpl::JobController* job_controller =
        new HttpStreamFactoryImpl::JobController(
            factory_, request_delegates[i].get(), session_.get(), &job_factory_,
            request_info, is_preconnect_, enable_ip_based_pooling_,
            enable_alternative_services_, SSLConfig(), SSLConfig());
    HttpStreamFactoryImplPeer::AddJobController(factory_, job_controller);
    auto request = job_controller->Start(
        request_delegates[i].get(), nullptr, net_log_.bound(),
        HttpStreamRequest::HTTP_STREAM, DEFAULT_PRIORITY);
    EXPECT_TRUE(job_controller->main_job());
    EXPECT_FALSE(job_controller->alternative_job());
    requests.push_back(std::move(request));
  }

  for (int i = 0; i < kNumRequests; ++i) {
    // When a request is completed, delete it. This is needed because
    // otherwise request will be completed twice. See crbug.com/706974.
    EXPECT_CALL(*request_delegates[i].get(), OnStreamReadyImpl(_, _, _))
        .WillOnce(testing::InvokeWithoutArgs(
            [this, &requests, i]() { requests[i].reset(); }));
  }

  EXPECT_TRUE(test_task_runner->HasPendingTask());
  test_task_runner->FastForwardBy(base::TimeDelta::FromMilliseconds(
      HttpStreamFactoryImpl::Job::kHTTP2ThrottleMs));
  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(HttpStreamFactoryImplPeer::IsJobControllerDeleted(factory_));
  EXPECT_TRUE(hangdata.AllReadDataConsumed());
  for (const auto& data : socket_data) {
    EXPECT_TRUE(data.AllReadDataConsumed());
    EXPECT_TRUE(data.AllWriteDataConsumed());
  }
}

TEST_F(JobControllerLimitMultipleH2Requests,
       MultipleRequestsFirstRequestCanceled) {
  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING)};
  SequencedSocketData first_socket(reads, arraysize(reads), nullptr, 0);
  first_socket.set_connect_data(MockConnect(ASYNC, OK));
  SSLSocketDataProvider first_ssl_data(ASYNC, OK);
  first_ssl_data.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSocketDataProvider(&first_socket);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&first_ssl_data);
  std::list<SequencedSocketData> socket_data;
  std::list<SSLSocketDataProvider> ssl_socket_data;
  // kNumRequests - 1 will be resumed when the first request is canceled.
  for (int i = 0; i < kNumRequests - 1; i++) {
    socket_data.emplace_back(nullptr, 0, nullptr, 0);
    socket_data.back().set_connect_data(MockConnect(ASYNC, OK));
    session_deps_.socket_factory->AddSocketDataProvider(&socket_data.back());
    ssl_socket_data.emplace_back(ASYNC, OK);
    ssl_socket_data.back().next_proto = kProtoHTTP2;
    session_deps_.socket_factory->AddSSLSocketDataProvider(
        &ssl_socket_data.back());
  }

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.example.com");
  Initialize(request_info);
  SpdySessionPoolPeer pool_peer(session_->spdy_session_pool());
  pool_peer.SetEnableSendingInitialData(false);

  // Sets server support HTTP/2.
  url::SchemeHostPort server(request_info.url);
  session_->http_server_properties()->SetSupportsSpdy(server, true);

  std::vector<std::unique_ptr<MockHttpStreamRequestDelegate>> request_delegates;
  std::vector<std::unique_ptr<HttpStreamRequest>> requests;
  for (int i = 0; i < kNumRequests; ++i) {
    request_delegates.emplace_back(
        base::MakeUnique<MockHttpStreamRequestDelegate>());
    HttpStreamFactoryImpl::JobController* job_controller =
        new HttpStreamFactoryImpl::JobController(
            factory_, request_delegates[i].get(), session_.get(), &job_factory_,
            request_info, is_preconnect_, enable_ip_based_pooling_,
            enable_alternative_services_, SSLConfig(), SSLConfig());
    HttpStreamFactoryImplPeer::AddJobController(factory_, job_controller);
    auto request = job_controller->Start(
        request_delegates[i].get(), nullptr, net_log_.bound(),
        HttpStreamRequest::HTTP_STREAM, DEFAULT_PRIORITY);
    EXPECT_TRUE(job_controller->main_job());
    EXPECT_FALSE(job_controller->alternative_job());
    requests.push_back(std::move(request));
  }
  // Cancel the first one.
  requests[0].reset();

  for (int i = 1; i < kNumRequests; ++i) {
    // When a request is completed, delete it. This is needed because
    // otherwise request will be completed twice. See crbug.com/706974.
    EXPECT_CALL(*request_delegates[i].get(), OnStreamReadyImpl(_, _, _))
        .WillOnce(testing::InvokeWithoutArgs(
            [this, &requests, i]() { requests[i].reset(); }));
  }
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(HttpStreamFactoryImplPeer::IsJobControllerDeleted(factory_));
  EXPECT_TRUE(first_socket.AllReadDataConsumed());
  for (const auto& data : socket_data) {
    EXPECT_TRUE(data.AllReadDataConsumed());
    EXPECT_TRUE(data.AllWriteDataConsumed());
  }
}

TEST_F(JobControllerLimitMultipleH2Requests, MultiplePreconnects) {
  // Make sure there is only one socket connect.
  tcp_data_ = base::MakeUnique<SequencedSocketData>(nullptr, 0, nullptr, 0);
  tcp_data_->set_connect_data(MockConnect(ASYNC, OK));
  SSLSocketDataProvider ssl_data(ASYNC, OK);
  ssl_data.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data);
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.example.com");
  SetPreconnect();
  Initialize(request_info);

  // Sets server support HTTP/2.
  url::SchemeHostPort server(request_info.url);
  session_->http_server_properties()->SetSupportsSpdy(server, true);

  std::vector<std::unique_ptr<MockHttpStreamRequestDelegate>> request_delegates;
  for (int i = 0; i < kNumRequests; ++i) {
    request_delegates.emplace_back(
        base::MakeUnique<MockHttpStreamRequestDelegate>());
    HttpStreamFactoryImpl::JobController* job_controller =
        new HttpStreamFactoryImpl::JobController(
            factory_, request_delegates[i].get(), session_.get(), &job_factory_,
            request_info, is_preconnect_, enable_ip_based_pooling_,
            enable_alternative_services_, SSLConfig(), SSLConfig());
    HttpStreamFactoryImplPeer::AddJobController(factory_, job_controller);
    job_controller->Preconnect(1);
    EXPECT_TRUE(job_controller->main_job());
    EXPECT_FALSE(job_controller->alternative_job());
  }
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(HttpStreamFactoryImplPeer::IsJobControllerDeleted(factory_));
}

TEST_F(JobControllerLimitMultipleH2Requests, H1NegotiatedForFirstRequest) {
  // First socket is an HTTP/1.1 socket.
  SequencedSocketData first_socket(nullptr, 0, nullptr, 0);
  first_socket.set_connect_data(MockConnect(ASYNC, OK));
  SSLSocketDataProvider ssl_data(ASYNC, OK);
  session_deps_.socket_factory->AddSocketDataProvider(&first_socket);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data);
  // Second socket is an HTTP/2 socket.
  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING)};
  SequencedSocketData second_socket(reads, arraysize(reads), nullptr, 0);
  second_socket.set_connect_data(MockConnect(ASYNC, OK));
  session_deps_.socket_factory->AddSocketDataProvider(&second_socket);
  SSLSocketDataProvider second_ssl_data(ASYNC, OK);
  second_ssl_data.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&second_ssl_data);

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.example.com");
  Initialize(request_info);
  SpdySessionPoolPeer pool_peer(session_->spdy_session_pool());
  pool_peer.SetEnableSendingInitialData(false);

  // Sets server support HTTP/2.
  url::SchemeHostPort server(request_info.url);
  session_->http_server_properties()->SetSupportsSpdy(server, true);

  std::vector<std::unique_ptr<MockHttpStreamRequestDelegate>> request_delegates;
  std::vector<std::unique_ptr<HttpStreamRequest>> requests;
  for (int i = 0; i < 2; ++i) {
    request_delegates.emplace_back(
        base::MakeUnique<MockHttpStreamRequestDelegate>());
    HttpStreamFactoryImpl::JobController* job_controller =
        new HttpStreamFactoryImpl::JobController(
            factory_, request_delegates[i].get(), session_.get(), &job_factory_,
            request_info, is_preconnect_, enable_ip_based_pooling_,
            enable_alternative_services_, SSLConfig(), SSLConfig());
    HttpStreamFactoryImplPeer::AddJobController(factory_, job_controller);
    auto request = job_controller->Start(
        request_delegates[i].get(), nullptr, net_log_.bound(),
        HttpStreamRequest::HTTP_STREAM, DEFAULT_PRIORITY);
    EXPECT_TRUE(job_controller->main_job());
    EXPECT_FALSE(job_controller->alternative_job());
    requests.push_back(std::move(request));
  }

  for (int i = 0; i < 2; ++i) {
    // When a request is completed, delete it. This is needed because
    // otherwise request will be completed twice. See crbug.com/706974.
    EXPECT_CALL(*request_delegates[i].get(), OnStreamReadyImpl(_, _, _))
        .WillOnce(testing::InvokeWithoutArgs(
            [this, &requests, i]() { requests[i].reset(); }));
  }
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(HttpStreamFactoryImplPeer::IsJobControllerDeleted(factory_));
  EXPECT_TRUE(first_socket.AllReadDataConsumed());
  EXPECT_FALSE(second_socket.AllReadDataConsumed());
}

// Tests that HTTP/2 throttling logic only applies to non-QUIC jobs.
TEST_F(JobControllerLimitMultipleH2Requests, QuicJobNotThrottled) {
  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::COLD_START);
  quic_data_ = base::MakeUnique<MockQuicData>();
  quic_data_->AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING)};
  tcp_data_ = base::MakeUnique<SequencedSocketData>(reads, arraysize(reads),
                                                    nullptr, 0);

  tcp_data_->set_connect_data(MockConnect(ASYNC, OK));
  SSLSocketDataProvider ssl_data(ASYNC, OK);
  ssl_data.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data);

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");

  Initialize(request_info);
  SpdySessionPoolPeer pool_peer(session_->spdy_session_pool());
  pool_peer.SetEnableSendingInitialData(false);

  url::SchemeHostPort server(request_info.url);
  // Sets server supports QUIC.
  AlternativeService alternative_service(kProtoQUIC, server.host(), 443);
  SetAlternativeService(request_info, alternative_service);

  // Sets server support HTTP/2.
  session_->http_server_properties()->SetSupportsSpdy(server, true);

  // Use default job factory so that Resume() is not mocked out.
  HttpStreamFactoryImpl::JobFactory default_job_factory;
  HttpStreamFactoryImpl::JobController* job_controller =
      new HttpStreamFactoryImpl::JobController(
          factory_, &request_delegate_, session_.get(), &default_job_factory,
          request_info, is_preconnect_, enable_ip_based_pooling_,
          enable_alternative_services_, SSLConfig(), SSLConfig());
  HttpStreamFactoryImplPeer::AddJobController(factory_, job_controller);
  request_ =
      job_controller->Start(&request_delegate_, nullptr, net_log_.bound(),
                            HttpStreamRequest::HTTP_STREAM, DEFAULT_PRIORITY);

  EXPECT_TRUE(job_controller->main_job());
  EXPECT_TRUE(job_controller->alternative_job());
  EXPECT_CALL(request_delegate_, OnStreamReadyImpl(_, _, _));
  base::RunLoop().RunUntilIdle();
  TestNetLogEntry::List entries;
  net_log_.GetEntries(&entries);
  for (auto entry : entries) {
    ASSERT_NE(NetLogEventType::HTTP_STREAM_JOB_THROTTLED, entry.type);
  }
}

class HttpStreamFactoryImplJobControllerMisdirectedRequestRetry
    : public HttpStreamFactoryImplJobControllerTest,
      public ::testing::WithParamInterface<::testing::tuple<bool, bool>> {};

INSTANTIATE_TEST_CASE_P(
    /* no prefix */,
    HttpStreamFactoryImplJobControllerMisdirectedRequestRetry,
    ::testing::Combine(::testing::Bool(), ::testing::Bool()));

TEST_P(HttpStreamFactoryImplJobControllerMisdirectedRequestRetry,
       DisableIPBasedPoolingAndAlternativeServices) {
  const bool enable_ip_based_pooling = ::testing::get<0>(GetParam());
  const bool enable_alternative_services = ::testing::get<1>(GetParam());
  if (enable_alternative_services) {
    quic_data_ = base::MakeUnique<MockQuicData>();
    quic_data_->AddConnect(SYNCHRONOUS, OK);
    quic_data_->AddWrite(client_maker_.MakeInitialSettingsPacket(1, nullptr));
    quic_data_->AddRead(ASYNC, OK);
  }
  tcp_data_ = base::MakeUnique<SequencedSocketData>(nullptr, 0, nullptr, 0);
  tcp_data_->set_connect_data(MockConnect(SYNCHRONOUS, OK));
  SSLSocketDataProvider ssl_data(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data);

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");

  if (!enable_ip_based_pooling)
    DisableIPBasedPooling();
  if (!enable_alternative_services)
    DisableAlternativeServices();

  Initialize(request_info);

  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(kProtoQUIC, server.host(), 443);
  SetAlternativeService(request_info, alternative_service);

  request_ =
      job_controller_->Start(&request_delegate_, nullptr, net_log_.bound(),
                             HttpStreamRequest::HTTP_STREAM, DEFAULT_PRIORITY);
  EXPECT_TRUE(job_controller_->main_job());
  if (enable_alternative_services) {
    EXPECT_TRUE(job_controller_->alternative_job());
  } else {
    EXPECT_FALSE(job_controller_->alternative_job());
  }

  // |main_job| succeeds and should report status to Request.
  EXPECT_CALL(request_delegate_, OnStreamReadyImpl(_, _, _));
  base::RunLoop().RunUntilIdle();
}

class HttpStreamFactoryImplJobControllerPreconnectTest
    : public HttpStreamFactoryImplJobControllerTest,
      public ::testing::WithParamInterface<bool> {
 protected:
  void SetUp() override {
    if (GetParam()) {
      scoped_feature_list_.InitFromCommandLine("LimitEarlyPreconnects",
                                               std::string());
    }
  }

  void Initialize() {
    session_deps_.http_server_properties =
        base::MakeUnique<MockHttpServerProperties>();
    session_ = SpdySessionDependencies::SpdyCreateSession(&session_deps_);
    factory_ =
        static_cast<HttpStreamFactoryImpl*>(session_->http_stream_factory());
    request_info_.method = "GET";
    request_info_.url = GURL("https://www.example.com");
    job_controller_ = new HttpStreamFactoryImpl::JobController(
        factory_, &request_delegate_, session_.get(), &job_factory_,
        request_info_, /* is_preconnect = */ true,
        /* enable_ip_based_pooling = */ true,
        /* enable_alternative_services = */ true, SSLConfig(), SSLConfig());
    HttpStreamFactoryImplPeer::AddJobController(factory_, job_controller_);
  }

 protected:
  void Preconnect(int num_streams) {
    job_controller_->Preconnect(num_streams);
    // Only one job is started.
    EXPECT_TRUE(job_controller_->main_job());
    EXPECT_FALSE(job_controller_->alternative_job());
  }

 private:
  base::test::ScopedFeatureList scoped_feature_list_;
  HttpRequestInfo request_info_;
};

INSTANTIATE_TEST_CASE_P(
    /* no prefix */,
    HttpStreamFactoryImplJobControllerPreconnectTest,
    ::testing::Bool());

TEST_P(HttpStreamFactoryImplJobControllerPreconnectTest,
       LimitEarlyPreconnects) {
  std::list<SequencedSocketData> providers;
  std::list<SSLSocketDataProvider> ssl_providers;
  const int kNumPreconects = 5;
  MockRead reads[] = {MockRead(ASYNC, OK)};
  // If experiment is not enabled, there are 5 socket connects.
  const size_t actual_num_connects = GetParam() ? 1 : kNumPreconects;
  for (size_t i = 0; i < actual_num_connects; ++i) {
    providers.emplace_back(reads, arraysize(reads), nullptr, 0);
    session_deps_.socket_factory->AddSocketDataProvider(&providers.back());
    ssl_providers.emplace_back(ASYNC, OK);
    session_deps_.socket_factory->AddSSLSocketDataProvider(
        &ssl_providers.back());
  }
  Initialize();
  Preconnect(kNumPreconects);
  // If experiment is enabled, only 1 stream is requested.
  EXPECT_EQ(
      (int)actual_num_connects,
      HttpStreamFactoryImplJobPeer::GetNumStreams(job_controller_->main_job()));
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(HttpStreamFactoryImplPeer::IsJobControllerDeleted(factory_));
}

}  // namespace test

}  // namespace net
