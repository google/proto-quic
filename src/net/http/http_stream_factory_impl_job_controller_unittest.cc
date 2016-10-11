// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_stream_factory_impl_job_controller.h"

#include <memory>

#include "base/memory/ptr_util.h"
#include "base/run_loop.h"
#include "base/test/histogram_tester.h"
#include "base/threading/platform_thread.h"
#include "net/base/test_proxy_delegate.h"
#include "net/dns/mock_host_resolver.h"
#include "net/http/http_basic_stream.h"
#include "net/http/http_stream_factory_impl_request.h"
#include "net/http/http_stream_factory_test_util.h"
#include "net/log/net_log_with_source.h"
#include "net/proxy/mock_proxy_resolver.h"
#include "net/proxy/proxy_config_service_fixed.h"
#include "net/proxy/proxy_info.h"
#include "net/proxy/proxy_service.h"
#include "net/quic/test_tools/quic_stream_factory_peer.h"
#include "net/spdy/spdy_test_util_common.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gmock_mutant.h"
#include "testing/gtest/include/gtest/gtest.h"

using ::testing::_;
using ::testing::Invoke;

namespace net {

namespace {

void DeleteHttpStreamPointer(const SSLConfig& used_ssl_config,
                             const ProxyInfo& used_proxy_info,
                             HttpStream* stream) {
  delete stream;
}

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
};

class JobControllerPeer {
 public:
  static void VerifyWaitingTimeForMainJob(
      HttpStreamFactoryImpl::JobController* job_controller,
      const base::TimeDelta& delay) {
    EXPECT_EQ(delay, job_controller->main_job_wait_time_);
  }

  static bool main_job_is_blocked(
      HttpStreamFactoryImpl::JobController* job_controller) {
    return job_controller->main_job_is_blocked_;
  }
};

class HttpStreamFactoryImplJobControllerTest
    : public ::testing::Test,
      public ::testing::WithParamInterface<NextProto> {
 public:
  HttpStreamFactoryImplJobControllerTest()
      : session_deps_(ProxyService::CreateDirect()) {
    session_deps_.enable_quic = true;
  }

  void Initialize(bool use_alternative_proxy) {
    std::unique_ptr<TestProxyDelegate> test_proxy_delegate(
        new TestProxyDelegate());
    test_proxy_delegate_ = test_proxy_delegate.get();

    test_proxy_delegate->set_alternative_proxy_server(
        ProxyServer::FromPacString("QUIC myproxy.org:443"));
    EXPECT_TRUE(test_proxy_delegate->alternative_proxy_server().is_quic());
    session_deps_.proxy_delegate.reset(test_proxy_delegate.release());

    if (use_alternative_proxy) {
      std::unique_ptr<ProxyService> proxy_service =
          ProxyService::CreateFixedFromPacResult("HTTPS myproxy.org:443");
      session_deps_.proxy_service.reset(proxy_service.release());
    }
    session_ = SpdySessionDependencies::SpdyCreateSession(&session_deps_);
    factory_ =
        static_cast<HttpStreamFactoryImpl*>(session_->http_stream_factory());
    job_controller_ = new HttpStreamFactoryImpl::JobController(
        factory_, &request_delegate_, session_.get(), &job_factory_);
    HttpStreamFactoryImplPeer::AddJobController(factory_, job_controller_);
  }

  TestProxyDelegate* test_proxy_delegate() const {
    return test_proxy_delegate_;
  }

  ~HttpStreamFactoryImplJobControllerTest() {}

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
    const AlternativeServiceVector alternative_service_vector =
        session_->http_server_properties()->GetAlternativeServices(server);
    EXPECT_EQ(1u, alternative_service_vector.size());
    EXPECT_EQ(should_mark_broken,
              session_->http_server_properties()->IsAlternativeServiceBroken(
                  alternative_service_vector[0]));
  }

  // Not owned by |this|.
  TestProxyDelegate* test_proxy_delegate_;
  TestJobFactory job_factory_;
  MockHttpStreamRequestDelegate request_delegate_;
  SpdySessionDependencies session_deps_;
  std::unique_ptr<HttpNetworkSession> session_;
  HttpStreamFactoryImpl* factory_;
  HttpStreamFactoryImpl::JobController* job_controller_;
  std::unique_ptr<HttpStreamFactoryImpl::Request> request_;

  DISALLOW_COPY_AND_ASSIGN(HttpStreamFactoryImplJobControllerTest);
};

TEST_F(HttpStreamFactoryImplJobControllerTest,
       OnStreamFailedWithNoAlternativeJob) {
  ProxyConfig proxy_config;
  proxy_config.set_auto_detect(true);
  // Use asynchronous proxy resolver.
  MockAsyncProxyResolverFactory* proxy_resolver_factory =
      new MockAsyncProxyResolverFactory(false);
  session_deps_.proxy_service.reset(
      new ProxyService(base::MakeUnique<ProxyConfigServiceFixed>(proxy_config),
                       base::WrapUnique(proxy_resolver_factory), nullptr));
  Initialize(false);

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("http://www.google.com");

  request_.reset(
      job_controller_->Start(request_info, &request_delegate_, nullptr,
                             NetLogWithSource(), HttpStreamRequest::HTTP_STREAM,
                             DEFAULT_PRIORITY, SSLConfig(), SSLConfig()));

  EXPECT_TRUE(job_controller_->main_job());

  // There's no other alternative job. Thus when stream failed, it should
  // notify Request of the stream failure.
  EXPECT_CALL(request_delegate_, OnStreamFailed(ERR_FAILED, _)).Times(1);
  job_controller_->OnStreamFailed(job_factory_.main_job(), ERR_FAILED,
                                  SSLConfig());
}

TEST_F(HttpStreamFactoryImplJobControllerTest,
       OnStreamReadyWithNoAlternativeJob) {
  ProxyConfig proxy_config;
  proxy_config.set_auto_detect(true);
  // Use asynchronous proxy resolver.
  MockAsyncProxyResolverFactory* proxy_resolver_factory =
      new MockAsyncProxyResolverFactory(false);
  session_deps_.proxy_service.reset(
      new ProxyService(base::MakeUnique<ProxyConfigServiceFixed>(proxy_config),
                       base::WrapUnique(proxy_resolver_factory), nullptr));
  Initialize(false);

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("http://www.google.com");

  request_.reset(
      job_controller_->Start(request_info, &request_delegate_, nullptr,
                             NetLogWithSource(), HttpStreamRequest::HTTP_STREAM,
                             DEFAULT_PRIORITY, SSLConfig(), SSLConfig()));

  // There's no other alternative job. Thus when a stream is ready, it should
  // notify Request.
  HttpStream* http_stream =
      new HttpBasicStream(base::MakeUnique<ClientSocketHandle>(), false, false);
  job_factory_.main_job()->SetStream(http_stream);

  EXPECT_CALL(request_delegate_, OnStreamReady(_, _, http_stream))
      .WillOnce(Invoke(DeleteHttpStreamPointer));
  job_controller_->OnStreamReady(job_factory_.main_job(), SSLConfig(),
                                 ProxyInfo());
}

// Test we cancel Jobs correctly when the Request is explicitly canceled
// before any Job is bound to Request.
TEST_F(HttpStreamFactoryImplJobControllerTest, CancelJobsBeforeBinding) {
  ProxyConfig proxy_config;
  proxy_config.set_auto_detect(true);
  // Use asynchronous proxy resolver.
  MockAsyncProxyResolverFactory* proxy_resolver_factory =
      new MockAsyncProxyResolverFactory(false);
  session_deps_.proxy_service.reset(new ProxyService(
      base::WrapUnique(new ProxyConfigServiceFixed(proxy_config)),
      base::WrapUnique(proxy_resolver_factory), nullptr));
  Initialize(false);

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");

  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(QUIC, server.host(), 443);
  SetAlternativeService(request_info, alternative_service);

  request_.reset(
      job_controller_->Start(request_info, &request_delegate_, nullptr,
                             NetLogWithSource(), HttpStreamRequest::HTTP_STREAM,
                             DEFAULT_PRIORITY, SSLConfig(), SSLConfig()));
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
  ProxyConfig proxy_config;
  proxy_config.set_auto_detect(true);
  // Use asynchronous proxy resolver.
  MockAsyncProxyResolverFactory* proxy_resolver_factory =
      new MockAsyncProxyResolverFactory(false);
  session_deps_.proxy_service.reset(
      new ProxyService(base::MakeUnique<ProxyConfigServiceFixed>(proxy_config),
                       base::WrapUnique(proxy_resolver_factory), nullptr));
  Initialize(false);

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");

  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(QUIC, server.host(), 443);
  SetAlternativeService(request_info, alternative_service);

  request_.reset(
      job_controller_->Start(request_info, &request_delegate_, nullptr,
                             NetLogWithSource(), HttpStreamRequest::HTTP_STREAM,
                             DEFAULT_PRIORITY, SSLConfig(), SSLConfig()));
  EXPECT_TRUE(job_controller_->main_job());
  EXPECT_TRUE(job_controller_->alternative_job());

  // We have the main job with unknown status when the alternative job is failed
  // thus should not notify Request of the alternative job's failure. But should
  // notify the main job to mark the alternative job failed.
  EXPECT_CALL(request_delegate_, OnStreamFailed(_, _)).Times(0);
  job_controller_->OnStreamFailed(job_factory_.alternative_job(), ERR_FAILED,
                                  SSLConfig());
  EXPECT_TRUE(!job_controller_->alternative_job());
  EXPECT_TRUE(job_controller_->main_job());

  // The failure of second Job should be reported to Request as there's no more
  // pending Job to serve the Request.
  EXPECT_CALL(request_delegate_, OnStreamFailed(_, _)).Times(1);
  job_controller_->OnStreamFailed(job_factory_.main_job(), ERR_FAILED,
                                  SSLConfig());
  VerifyBrokenAlternateProtocolMapping(request_info, false);
}

TEST_F(HttpStreamFactoryImplJobControllerTest,
       AltJobFailsAfterMainJobSucceeds) {
  ProxyConfig proxy_config;
  proxy_config.set_auto_detect(true);
  // Use asynchronous proxy resolver.
  MockAsyncProxyResolverFactory* proxy_resolver_factory =
      new MockAsyncProxyResolverFactory(false);
  session_deps_.proxy_service.reset(
      new ProxyService(base::MakeUnique<ProxyConfigServiceFixed>(proxy_config),
                       base::WrapUnique(proxy_resolver_factory), nullptr));
  Initialize(false);

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");

  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(QUIC, server.host(), 443);
  SetAlternativeService(request_info, alternative_service);

  request_.reset(
      job_controller_->Start(request_info, &request_delegate_, nullptr,
                             NetLogWithSource(), HttpStreamRequest::HTTP_STREAM,
                             DEFAULT_PRIORITY, SSLConfig(), SSLConfig()));
  EXPECT_TRUE(job_controller_->main_job());
  EXPECT_TRUE(job_controller_->alternative_job());

  // Main job succeeds, starts serving Request and it should report status
  // to Request. The alternative job will mark the main job complete and gets
  // orphaned.
  HttpStream* http_stream =
      new HttpBasicStream(base::MakeUnique<ClientSocketHandle>(), false, false);
  job_factory_.main_job()->SetStream(http_stream);

  EXPECT_CALL(request_delegate_, OnStreamReady(_, _, http_stream))
      .WillOnce(Invoke(DeleteHttpStreamPointer));
  job_controller_->OnStreamReady(job_factory_.main_job(), SSLConfig(),
                                 ProxyInfo());

  // JobController shouldn't report the status of second job as request
  // is already successfully served.
  EXPECT_CALL(request_delegate_, OnStreamFailed(_, _)).Times(0);
  job_controller_->OnStreamFailed(job_factory_.alternative_job(), ERR_FAILED,
                                  SSLConfig());

  VerifyBrokenAlternateProtocolMapping(request_info, true);
  // Reset the request as it's been successfully served.
  request_.reset();
  EXPECT_TRUE(HttpStreamFactoryImplPeer::IsJobControllerDeleted(factory_));
}

TEST_F(HttpStreamFactoryImplJobControllerTest,
       AltJobSucceedsAfterMainJobFailed) {
  ProxyConfig proxy_config;
  proxy_config.set_auto_detect(true);
  // Use asynchronous proxy resolver.
  MockAsyncProxyResolverFactory* proxy_resolver_factory =
      new MockAsyncProxyResolverFactory(false);
  session_deps_.proxy_service.reset(
      new ProxyService(base::MakeUnique<ProxyConfigServiceFixed>(proxy_config),
                       base::WrapUnique(proxy_resolver_factory), nullptr));
  Initialize(false);

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");

  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(QUIC, server.host(), 443);
  SetAlternativeService(request_info, alternative_service);

  request_.reset(
      job_controller_->Start(request_info, &request_delegate_, nullptr,
                             NetLogWithSource(), HttpStreamRequest::HTTP_STREAM,
                             DEFAULT_PRIORITY, SSLConfig(), SSLConfig()));
  EXPECT_TRUE(job_controller_->main_job());
  EXPECT_TRUE(job_controller_->alternative_job());

  // |main_job| fails but should not report status to Request.
  EXPECT_CALL(request_delegate_, OnStreamFailed(_, _)).Times(0);

  job_controller_->OnStreamFailed(job_factory_.main_job(), ERR_FAILED,
                                  SSLConfig());

  // |alternative_job| succeeds and should report status to Request.
  HttpStream* http_stream =
      new HttpBasicStream(base::MakeUnique<ClientSocketHandle>(), false, false);
  job_factory_.alternative_job()->SetStream(http_stream);

  EXPECT_CALL(request_delegate_, OnStreamReady(_, _, http_stream))
      .WillOnce(Invoke(DeleteHttpStreamPointer));
  job_controller_->OnStreamReady(job_factory_.alternative_job(), SSLConfig(),
                                 ProxyInfo());
  VerifyBrokenAlternateProtocolMapping(request_info, false);
}

TEST_F(HttpStreamFactoryImplJobControllerTest,
       MainJobSucceedsAfterAltJobFailed) {
  ProxyConfig proxy_config;
  proxy_config.set_auto_detect(true);
  // Use asynchronous proxy resolver.
  MockAsyncProxyResolverFactory* proxy_resolver_factory =
      new MockAsyncProxyResolverFactory(false);
  session_deps_.proxy_service.reset(
      new ProxyService(base::MakeUnique<ProxyConfigServiceFixed>(proxy_config),
                       base::WrapUnique(proxy_resolver_factory), nullptr));
  Initialize(false);

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");

  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(QUIC, server.host(), 443);
  SetAlternativeService(request_info, alternative_service);

  request_.reset(
      job_controller_->Start(request_info, &request_delegate_, nullptr,
                             NetLogWithSource(), HttpStreamRequest::HTTP_STREAM,
                             DEFAULT_PRIORITY, SSLConfig(), SSLConfig()));
  EXPECT_TRUE(job_controller_->main_job());
  EXPECT_TRUE(job_controller_->alternative_job());

  // |alternative_job| fails but should not report status to Request.
  EXPECT_CALL(request_delegate_, OnStreamFailed(_, _)).Times(0);

  job_controller_->OnStreamFailed(job_factory_.alternative_job(), ERR_FAILED,
                                  SSLConfig());

  // |main_job| succeeds and should report status to Request.
  HttpStream* http_stream =
      new HttpBasicStream(base::MakeUnique<ClientSocketHandle>(), false, false);
  job_factory_.main_job()->SetStream(http_stream);

  EXPECT_CALL(request_delegate_, OnStreamReady(_, _, http_stream))
      .WillOnce(Invoke(DeleteHttpStreamPointer));
  job_controller_->OnStreamReady(job_factory_.main_job(), SSLConfig(),
                                 ProxyInfo());

  VerifyBrokenAlternateProtocolMapping(request_info, true);
}

// Regression test for crbug/621069.
// Get load state after main job fails and before alternative job succeeds.
TEST_F(HttpStreamFactoryImplJobControllerTest, GetLoadStateAfterMainJobFailed) {
  ProxyConfig proxy_config;
  proxy_config.set_auto_detect(true);
  // Use asynchronous proxy resolver.
  MockAsyncProxyResolverFactory* proxy_resolver_factory =
      new MockAsyncProxyResolverFactory(false);
  session_deps_.proxy_service.reset(new ProxyService(
      base::WrapUnique(new ProxyConfigServiceFixed(proxy_config)),
      base::WrapUnique(proxy_resolver_factory), nullptr));
  Initialize(false);

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");

  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(QUIC, server.host(), 443);
  SetAlternativeService(request_info, alternative_service);

  request_.reset(
      job_controller_->Start(request_info, &request_delegate_, nullptr,
                             NetLogWithSource(), HttpStreamRequest::HTTP_STREAM,
                             DEFAULT_PRIORITY, SSLConfig(), SSLConfig()));
  EXPECT_TRUE(job_controller_->main_job());
  EXPECT_TRUE(job_controller_->alternative_job());

  // |main_job| fails but should not report status to Request.
  // The alternative job will mark the main job complete.
  EXPECT_CALL(request_delegate_, OnStreamFailed(_, _)).Times(0);

  job_controller_->OnStreamFailed(job_factory_.main_job(), ERR_FAILED,
                                  SSLConfig());

  // Controller should use alternative job to get load state.
  job_controller_->GetLoadState();

  // |alternative_job| succeeds and should report status to Request.
  HttpStream* http_stream =
      new HttpBasicStream(base::MakeUnique<ClientSocketHandle>(), false, false);
  job_factory_.alternative_job()->SetStream(http_stream);

  EXPECT_CALL(request_delegate_, OnStreamReady(_, _, http_stream))
      .WillOnce(Invoke(DeleteHttpStreamPointer));
  job_controller_->OnStreamReady(job_factory_.alternative_job(), SSLConfig(),
                                 ProxyInfo());
}

TEST_F(HttpStreamFactoryImplJobControllerTest, DoNotResumeMainJobBeforeWait) {
  // Use failing ProxyResolverFactory which is unable to create ProxyResolver
  // to stall the alternative job and report to controller to maybe resume the
  // main job.
  ProxyConfig proxy_config;
  proxy_config.set_auto_detect(true);
  proxy_config.set_pac_mandatory(true);
  session_deps_.proxy_service.reset(new ProxyService(
      base::MakeUnique<ProxyConfigServiceFixed>(proxy_config),
      base::WrapUnique(new FailingProxyResolverFactory), nullptr));

  Initialize(false);

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");

  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(QUIC, server.host(), 443);
  SetAlternativeService(request_info, alternative_service);

  request_.reset(
      job_controller_->Start(request_info, &request_delegate_, nullptr,
                             NetLogWithSource(), HttpStreamRequest::HTTP_STREAM,
                             DEFAULT_PRIORITY, SSLConfig(), SSLConfig()));
  EXPECT_TRUE(job_controller_->main_job());
  EXPECT_TRUE(job_controller_->alternative_job());

  // Wait until OnStreamFailedCallback is executed on the alternative job.
  EXPECT_CALL(request_delegate_, OnStreamFailed(_, _)).Times(1);
  base::RunLoop().RunUntilIdle();
}

TEST_F(HttpStreamFactoryImplJobControllerTest, InvalidPortForQuic) {
  // Using a restricted port 101 for QUIC should fail and the alternative job
  // should post OnStreamFailedCall on the controller to resume the main job.
  Initialize(false);

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");

  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(QUIC, server.host(), 101);
  SetAlternativeService(request_info, alternative_service);

  request_.reset(
      job_controller_->Start(request_info, &request_delegate_, nullptr,
                             NetLogWithSource(), HttpStreamRequest::HTTP_STREAM,
                             DEFAULT_PRIORITY, SSLConfig(), SSLConfig()));

  EXPECT_TRUE(job_factory_.main_job()->is_waiting());

  // Wait until OnStreamFailedCallback is executed on the alternative job.
  EXPECT_CALL(*job_factory_.main_job(), Resume()).Times(1);
  base::RunLoop().RunUntilIdle();
}

TEST_F(HttpStreamFactoryImplJobControllerTest,
       NoAvailableSpdySessionToResumeMainJob) {
  // Test the alternative job is not resumed when the alternative job is
  // IO_PENDING for proxy resolution. Once all the proxy resolution succeeds,
  // the latter part of this test tests controller resumes the main job
  // when there's no SPDY session for the alternative job.
  ProxyConfig proxy_config;
  proxy_config.set_auto_detect(true);
  // Use asynchronous proxy resolver.
  MockAsyncProxyResolverFactory* proxy_resolver_factory =
      new MockAsyncProxyResolverFactory(false);
  session_deps_.proxy_service.reset(
      new ProxyService(base::MakeUnique<ProxyConfigServiceFixed>(proxy_config),
                       base::WrapUnique(proxy_resolver_factory), nullptr));

  HangingResolver* host_resolver = new HangingResolver();
  session_deps_.host_resolver.reset(host_resolver);
  session_deps_.host_resolver->set_synchronous_mode(false);

  Initialize(false);

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");

  // Set a SPDY alternative service for the server.
  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(QUIC, server.host(), 443);
  SetAlternativeService(request_info, alternative_service);
  // Hack to use different URL for the main job to help differentiate the proxy
  // requests.
  job_factory_.UseDifferentURLForMainJob(GURL("http://www.google.com"));

  request_.reset(
      job_controller_->Start(request_info, &request_delegate_, nullptr,
                             NetLogWithSource(), HttpStreamRequest::HTTP_STREAM,
                             DEFAULT_PRIORITY, SSLConfig(), SSLConfig()));
  // Both jobs should be created but stalled as proxy resolution not completed.
  EXPECT_TRUE(job_controller_->main_job());
  EXPECT_TRUE(job_controller_->alternative_job());

  MockAsyncProxyResolver resolver;
  proxy_resolver_factory->pending_requests()[0]->CompleteNowWithForwarder(
      net::OK, &resolver);

  // Resolve proxy for the main job which then proceed to wait for the
  // alternative job which is IO_PENDING.
  int main_job_request_id =
      resolver.pending_requests()[0]->url().SchemeIs("http") ? 0 : 1;

  resolver.pending_requests()[main_job_request_id]->results()->UseNamedProxy(
      "result1:80");
  resolver.pending_requests()[main_job_request_id]->CompleteNow(net::OK);
  EXPECT_TRUE(job_controller_->main_job()->is_waiting());

  // Resolve proxy for the alternative job to proceed to create a connection.
  // Use hanging HostResolver to fail creation of a SPDY session for the
  // alternative job. The alternative job will be IO_PENDING thus should resume
  // the main job.
  resolver.pending_requests()[0]->CompleteNow(net::OK);
  EXPECT_CALL(request_delegate_, OnStreamFailed(_, _)).Times(0);
  EXPECT_CALL(*job_factory_.main_job(), Resume()).Times(1);

  base::RunLoop().RunUntilIdle();
}

TEST_F(HttpStreamFactoryImplJobControllerTest,
       NoAvailableQuicSessionToResumeMainJob) {
  // Use failing HostResolver which is unable to resolve the host name for QUIC.
  // No QUIC session is created and thus should resume the main job.
  FailingHostResolver* host_resolver = new FailingHostResolver();
  session_deps_.host_resolver.reset(host_resolver);

  ProxyConfig proxy_config;
  proxy_config.set_auto_detect(true);
  // Use asynchronous proxy resolver.
  MockAsyncProxyResolverFactory* proxy_resolver_factory =
      new MockAsyncProxyResolverFactory(false);
  session_deps_.proxy_service.reset(
      new ProxyService(base::MakeUnique<ProxyConfigServiceFixed>(proxy_config),
                       base::WrapUnique(proxy_resolver_factory), nullptr));

  Initialize(false);

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");

  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(QUIC, server.host(), 443);
  SetAlternativeService(request_info, alternative_service);
  // Hack to use different URL for the main job to help differentiate the proxy
  // requests.
  job_factory_.UseDifferentURLForMainJob(GURL("http://www.google.com"));

  request_.reset(
      job_controller_->Start(request_info, &request_delegate_, nullptr,
                             NetLogWithSource(), HttpStreamRequest::HTTP_STREAM,
                             DEFAULT_PRIORITY, SSLConfig(), SSLConfig()));
  EXPECT_TRUE(job_controller_->main_job());
  EXPECT_TRUE(job_controller_->alternative_job());

  MockAsyncProxyResolver resolver;
  proxy_resolver_factory->pending_requests()[0]->CompleteNowWithForwarder(
      net::OK, &resolver);

  // Resolve proxy for the main job which then proceed to wait for the
  // alternative job which is IO_PENDING.
  int main_job_request_id =
      resolver.pending_requests()[0]->url().SchemeIs("http") ? 0 : 1;

  resolver.pending_requests()[main_job_request_id]->results()->UseNamedProxy(
      "result1:80");
  resolver.pending_requests()[main_job_request_id]->CompleteNow(net::OK);
  EXPECT_TRUE(job_controller_->main_job()->is_waiting());

  // Resolve proxy for the alternative job to proceed to create a connection.
  // Use failing HostResolver to fail creation of a QUIC session for the
  // alternative job. The alternative job will thus resume the main job.
  resolver.pending_requests()[0]->results()->UseNamedProxy("result1:80");
  resolver.pending_requests()[0]->CompleteNow(net::OK);

  // Wait until OnStreamFailedCallback is executed on the alternative job.
  // Request shouldn't be notified as the main job is still pending status.
  EXPECT_CALL(request_delegate_, OnStreamFailed(_, _)).Times(0);
  EXPECT_CALL(*job_factory_.main_job(), Resume()).Times(1);

  base::RunLoop().RunUntilIdle();
}

TEST_F(HttpStreamFactoryImplJobControllerTest, DelayedTCP) {
  HangingResolver* resolver = new HangingResolver();
  session_deps_.host_resolver.reset(resolver);

  Initialize(false);

  // Enable delayed TCP and set time delay for waiting job.
  QuicStreamFactory* quic_stream_factory = session_->quic_stream_factory();
  test::QuicStreamFactoryPeer::SetDelayTcpRace(quic_stream_factory, true);
  quic_stream_factory->set_require_confirmation(false);
  ServerNetworkStats stats1;
  stats1.srtt = base::TimeDelta::FromMicroseconds(10);
  session_->http_server_properties()->SetServerNetworkStats(
      url::SchemeHostPort(GURL("https://www.google.com")), stats1);

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");

  // Set a SPDY alternative service for the server.
  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(QUIC, server.host(), 443);
  SetAlternativeService(request_info, alternative_service);

  request_.reset(
      job_controller_->Start(request_info, &request_delegate_, nullptr,
                             NetLogWithSource(), HttpStreamRequest::HTTP_STREAM,
                             DEFAULT_PRIORITY, SSLConfig(), SSLConfig()));
  EXPECT_TRUE(job_controller_->main_job());
  EXPECT_TRUE(job_controller_->alternative_job());

  // The alternative job stalls as host resolution hangs when creating the QUIC
  // request and controller should resume the main job after delay.
  // Verify the waiting time for delayed main job.
  EXPECT_CALL(*job_factory_.main_job(), Resume())
      .WillOnce(Invoke(testing::CreateFunctor(
          &JobControllerPeer::VerifyWaitingTimeForMainJob, job_controller_,
          base::TimeDelta::FromMicroseconds(15))));

  base::RunLoop().RunUntilIdle();
}

// Verifies that the alternative proxy server job is not created if the URL
// scheme is HTTPS.
TEST_F(HttpStreamFactoryImplJobControllerTest, HttpsURL) {
  // Using hanging resolver will cause the alternative job to hang indefinitely.
  HangingResolver* resolver = new HangingResolver();
  session_deps_.host_resolver.reset(resolver);

  Initialize(true);
  EXPECT_TRUE(test_proxy_delegate()->alternative_proxy_server().is_quic());

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://mail.example.org/");

  request_.reset(
      job_controller_->Start(request_info, &request_delegate_, nullptr,
                             NetLogWithSource(), HttpStreamRequest::HTTP_STREAM,
                             DEFAULT_PRIORITY, SSLConfig(), SSLConfig()));
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
  HangingResolver* resolver = new HangingResolver();
  session_deps_.host_resolver.reset(resolver);

  Initialize(false);
  EXPECT_TRUE(test_proxy_delegate()->alternative_proxy_server().is_quic());

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("http://mail.example.org/");

  request_.reset(
      job_controller_->Start(request_info, &request_delegate_, nullptr,
                             NetLogWithSource(), HttpStreamRequest::HTTP_STREAM,
                             DEFAULT_PRIORITY, SSLConfig(), SSLConfig()));
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
  // Using hanging resolver will cause the alternative job to hang indefinitely.
  HangingResolver* resolver = new HangingResolver();
  session_deps_.host_resolver.reset(resolver);

  Initialize(true);
  EXPECT_TRUE(test_proxy_delegate()->alternative_proxy_server().is_quic());

  // Enable delayed TCP and set time delay for waiting job.
  QuicStreamFactory* quic_stream_factory = session_->quic_stream_factory();
  test::QuicStreamFactoryPeer::SetDelayTcpRace(quic_stream_factory, true);
  quic_stream_factory->set_require_confirmation(false);
  ServerNetworkStats stats1;
  stats1.srtt = base::TimeDelta::FromMicroseconds(10);
  session_->http_server_properties()->SetServerNetworkStats(
      url::SchemeHostPort(GURL("https://myproxy.org")), stats1);

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("http://mail.example.org/");

  request_.reset(
      job_controller_->Start(request_info, &request_delegate_, nullptr,
                             NetLogWithSource(), HttpStreamRequest::HTTP_STREAM,
                             DEFAULT_PRIORITY, SSLConfig(), SSLConfig()));
  EXPECT_TRUE(job_controller_->main_job());
  EXPECT_TRUE(job_controller_->main_job()->is_waiting());
  EXPECT_TRUE(job_controller_->alternative_job());
  EXPECT_TRUE(JobControllerPeer::main_job_is_blocked(job_controller_));

  // The alternative proxy server job stalls when connecting to the alternative
  // proxy server, and controller should resume the main job after delay.
  // Verify the waiting time for delayed main job.
  EXPECT_CALL(*job_factory_.main_job(), Resume())
      .WillOnce(Invoke(testing::CreateFunctor(
          &JobControllerPeer::VerifyWaitingTimeForMainJob, job_controller_,
          base::TimeDelta::FromMicroseconds(15))));

  // This message loop should cause the alternative proxy server job to start,
  // and schedule resumption of the main job.
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(JobControllerPeer::main_job_is_blocked(job_controller_));

  // Wait for the Resume to post.
  base::PlatformThread::Sleep(base::TimeDelta::FromSeconds(1));

  // This message loop should cause the main job to resume.
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(JobControllerPeer::main_job_is_blocked(job_controller_));

  JobControllerPeer::VerifyWaitingTimeForMainJob(
      job_controller_, base::TimeDelta::FromMicroseconds(0));

  // Since the main job did not complete successfully, the alternative proxy
  // server should not be marked as bad.
  EXPECT_TRUE(test_proxy_delegate()->alternative_proxy_server().is_valid());
  EXPECT_EQ(1, test_proxy_delegate()->get_alternative_proxy_invocations());
}

// Verifies that the alternative proxy server job fails immediately, and the
// main job is not blocked.
TEST_F(HttpStreamFactoryImplJobControllerTest, FailAlternativeProxy) {
  // Using failing resolver will cause the alternative job to fail.
  FailingHostResolver* resolver = new FailingHostResolver();
  session_deps_.host_resolver.reset(resolver);

  Initialize(true);
  EXPECT_TRUE(test_proxy_delegate()->alternative_proxy_server().is_quic());

  // Enable delayed TCP and set time delay for waiting job.
  QuicStreamFactory* quic_stream_factory = session_->quic_stream_factory();
  test::QuicStreamFactoryPeer::SetDelayTcpRace(quic_stream_factory, true);
  quic_stream_factory->set_require_confirmation(false);
  ServerNetworkStats stats1;
  stats1.srtt = base::TimeDelta::FromMicroseconds(300 * 1000);
  session_->http_server_properties()->SetServerNetworkStats(
      url::SchemeHostPort(GURL("https://myproxy.org")), stats1);

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("http://mail.example.org/");

  request_.reset(
      job_controller_->Start(request_info, &request_delegate_, nullptr,
                             NetLogWithSource(), HttpStreamRequest::HTTP_STREAM,
                             DEFAULT_PRIORITY, SSLConfig(), SSLConfig()));
  EXPECT_TRUE(job_controller_->main_job()->is_waiting());
  EXPECT_TRUE(job_controller_->alternative_job());

  EXPECT_CALL(request_delegate_, OnStreamReady(_, _, _)).Times(0);

  // Since the alternative proxy server job is started in the next message loop,
  // the main job would remain blocked until the alternative proxy starts, and
  // fails.
  EXPECT_CALL(*job_factory_.main_job(), Resume())
      .WillOnce(Invoke(testing::CreateFunctor(
          &JobControllerPeer::VerifyWaitingTimeForMainJob, job_controller_,
          base::TimeDelta::FromMicroseconds(0))));

  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(job_controller_->alternative_job());
  EXPECT_TRUE(job_controller_->main_job()->is_waiting());
  // Since the main job did not complete successfully, the alternative proxy
  // server should not be marked as bad.
  EXPECT_TRUE(test_proxy_delegate()->alternative_proxy_server().is_valid());
  EXPECT_EQ(1, test_proxy_delegate()->get_alternative_proxy_invocations());
}

TEST_F(HttpStreamFactoryImplJobControllerTest,
       AlternativeProxyServerJobFailsAfterMainJobSucceeds) {
  base::HistogramTester histogram_tester;
  Initialize(true);

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("http://www.google.com");

  url::SchemeHostPort server(request_info.url);

  request_.reset(
      job_controller_->Start(request_info, &request_delegate_, nullptr,
                             NetLogWithSource(), HttpStreamRequest::HTTP_STREAM,
                             DEFAULT_PRIORITY, SSLConfig(), SSLConfig()));
  EXPECT_TRUE(job_controller_->main_job());
  EXPECT_TRUE(job_controller_->alternative_job());

  // Main job succeeds, starts serving Request and it should report status
  // to Request. The alternative job will mark the main job complete and gets
  // orphaned.
  HttpStream* http_stream =
      new HttpBasicStream(base::MakeUnique<ClientSocketHandle>(), false, false);
  job_factory_.main_job()->SetStream(http_stream);

  EXPECT_CALL(request_delegate_, OnStreamReady(_, _, http_stream))
      .WillOnce(Invoke(DeleteHttpStreamPointer));
  job_controller_->OnStreamReady(job_factory_.main_job(), SSLConfig(),
                                 ProxyInfo());

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

}  // namespace net
