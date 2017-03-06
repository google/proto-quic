// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_stream_factory_impl_job_controller.h"

#include <memory>
#include <vector>

#include "base/memory/ptr_util.h"
#include "base/run_loop.h"
#include "base/test/histogram_tester.h"
#include "base/test/scoped_feature_list.h"
#include "base/test/scoped_mock_time_message_loop_task_runner.h"
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
#include "net/socket/socket_test_util.h"
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
};

class JobControllerPeer {
 public:
  static bool main_job_is_blocked(
      HttpStreamFactoryImpl::JobController* job_controller) {
    return job_controller->main_job_is_blocked_;
  }
};

class HttpStreamFactoryImplJobControllerTest : public ::testing::Test {
 public:
  HttpStreamFactoryImplJobControllerTest()
      : session_deps_(ProxyService::CreateDirect()) {
    session_deps_.enable_quic = true;
  }

  void Initialize(const HttpRequestInfo& request_info,
                  bool use_alternative_proxy,
                  bool is_preconnect) {
    std::unique_ptr<TestProxyDelegate> test_proxy_delegate(
        new TestProxyDelegate());
    test_proxy_delegate_ = test_proxy_delegate.get();

    test_proxy_delegate->set_alternative_proxy_server(
        ProxyServer::FromPacString("QUIC myproxy.org:443"));
    EXPECT_TRUE(test_proxy_delegate->alternative_proxy_server().is_quic());
    session_deps_.proxy_delegate = std::move(test_proxy_delegate);

    if (use_alternative_proxy) {
      std::unique_ptr<ProxyService> proxy_service =
          ProxyService::CreateFixedFromPacResult("HTTPS myproxy.org:443");
      session_deps_.proxy_service = std::move(proxy_service);
    }
    session_ = SpdySessionDependencies::SpdyCreateSession(&session_deps_);
    factory_ =
        static_cast<HttpStreamFactoryImpl*>(session_->http_stream_factory());
    job_controller_ = new HttpStreamFactoryImpl::JobController(
        factory_, &request_delegate_, session_.get(), &job_factory_,
        request_info, is_preconnect);
    HttpStreamFactoryImplPeer::AddJobController(factory_, job_controller_);
  }

  TestProxyDelegate* test_proxy_delegate() const {
    return test_proxy_delegate_;
  }

  ~HttpStreamFactoryImplJobControllerTest() override {}

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

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("http://www.google.com");

  Initialize(request_info, false, false);

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
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("http://www.google.com");

  Initialize(request_info, false, false);

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
  job_controller_->OnStreamReady(job_factory_.main_job(), SSLConfig());
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

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");

  Initialize(request_info, false, false);
  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(kProtoQUIC, server.host(), 443);
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

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");

  Initialize(request_info, false, false);
  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(kProtoQUIC, server.host(), 443);
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

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");

  Initialize(request_info, false, false);
  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(kProtoQUIC, server.host(), 443);
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
  job_controller_->OnStreamReady(job_factory_.main_job(), SSLConfig());

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

// Tests that if alt job succeeds and main job is blocked, main job should be
// cancelled immediately. |request_| completion will clean up the JobController.
// Regression test for crbug.com/678768.
TEST_F(HttpStreamFactoryImplJobControllerTest,
       AltJobSucceedsMainJobBlockedControllerDestroyed) {
  ProxyConfig proxy_config;
  proxy_config.set_auto_detect(true);
  MockAsyncProxyResolverFactory* proxy_resolver_factory =
      new MockAsyncProxyResolverFactory(false);
  session_deps_.proxy_service.reset(
      new ProxyService(base::MakeUnique<ProxyConfigServiceFixed>(proxy_config),
                       base::WrapUnique(proxy_resolver_factory), nullptr));
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");

  Initialize(request_info, false, false);

  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(kProtoQUIC, server.host(), 443);
  SetAlternativeService(request_info, alternative_service);
  request_.reset(
      job_controller_->Start(request_info, &request_delegate_, nullptr,
                             NetLogWithSource(), HttpStreamRequest::HTTP_STREAM,
                             DEFAULT_PRIORITY, SSLConfig(), SSLConfig()));
  EXPECT_TRUE(job_controller_->main_job());
  EXPECT_TRUE(job_controller_->alternative_job());
  EXPECT_TRUE(JobControllerPeer::main_job_is_blocked(job_controller_));

  // |alternative_job| succeeds and should report status to Request.
  HttpStream* http_stream =
      new HttpBasicStream(base::MakeUnique<ClientSocketHandle>(), false, false);
  job_factory_.alternative_job()->SetStream(http_stream);
  EXPECT_CALL(request_delegate_, OnStreamReady(_, _, http_stream))
      .WillOnce(Invoke(DeleteHttpStreamPointer));
  job_controller_->OnStreamReady(job_factory_.alternative_job(), SSLConfig());

  EXPECT_FALSE(job_controller_->main_job());
  EXPECT_TRUE(job_controller_->alternative_job());

  // Invoke OnRequestComplete() which should delete |job_controller_| from
  // |factory_|.
  request_.reset();
  VerifyBrokenAlternateProtocolMapping(request_info, false);
  // This fails without the fix for crbug.com/678768.
  EXPECT_TRUE(HttpStreamFactoryImplPeer::IsJobControllerDeleted(factory_));
}

// Tests that if an orphaned job completes after |request_| is gone,
// JobController will be cleaned up.
TEST_F(HttpStreamFactoryImplJobControllerTest,
       OrphanedJobCompletesControllerDestroyed) {
  ProxyConfig proxy_config;
  proxy_config.set_auto_detect(true);
  MockAsyncProxyResolverFactory* proxy_resolver_factory =
      new MockAsyncProxyResolverFactory(false);
  session_deps_.proxy_service.reset(
      new ProxyService(base::MakeUnique<ProxyConfigServiceFixed>(proxy_config),
                       base::WrapUnique(proxy_resolver_factory), nullptr));
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");

  Initialize(request_info, false, false);

  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(kProtoQUIC, server.host(), 443);
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
  EXPECT_TRUE(JobControllerPeer::main_job_is_blocked(job_controller_));

  // Complete main job now.
  MockAsyncProxyResolver resolver;
  proxy_resolver_factory->pending_requests()[0]->CompleteNowWithForwarder(
      net::OK, &resolver);
  int main_job_request_id =
      resolver.pending_jobs()[0]->url().SchemeIs("http") ? 0 : 1;

  resolver.pending_jobs()[main_job_request_id]->results()->UseNamedProxy(
      "result1:80");
  resolver.pending_jobs()[main_job_request_id]->CompleteNow(net::OK);

  HttpStream* http_stream =
      new HttpBasicStream(base::MakeUnique<ClientSocketHandle>(), false, false);
  job_factory_.main_job()->SetStream(http_stream);

  EXPECT_CALL(request_delegate_, OnStreamReady(_, _, http_stream))
      .WillOnce(Invoke(DeleteHttpStreamPointer));
  job_controller_->OnStreamReady(job_factory_.main_job(), SSLConfig());
  // Invoke OnRequestComplete() which should not delete |job_controller_| from
  // |factory_| because alt job is yet to finish.
  request_.reset();
  ASSERT_FALSE(HttpStreamFactoryImplPeer::IsJobControllerDeleted(factory_));
  EXPECT_FALSE(job_controller_->main_job());
  EXPECT_TRUE(job_controller_->alternative_job());

  // Make |alternative_job| succeed.
  resolver.pending_jobs()[0]->results()->UseNamedProxy("result1:80");
  resolver.pending_jobs()[0]->CompleteNow(net::OK);
  HttpStream* http_stream2 =
      new HttpBasicStream(base::MakeUnique<ClientSocketHandle>(), false, false);
  job_factory_.alternative_job()->SetStream(http_stream2);
  // This should not call request_delegate_::OnStreamReady.
  job_controller_->OnStreamReady(job_factory_.alternative_job(), SSLConfig());
  // Make sure that controller does not leak.
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
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");

  Initialize(request_info, false, false);

  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(kProtoQUIC, server.host(), 443);
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
  job_controller_->OnStreamReady(job_factory_.alternative_job(), SSLConfig());
  VerifyBrokenAlternateProtocolMapping(request_info, false);
}

TEST_F(HttpStreamFactoryImplJobControllerTest,
       MainJobSucceedsAfterAltJobFailed) {
  base::HistogramTester histogram_tester;
  ProxyConfig proxy_config;
  proxy_config.set_auto_detect(true);
  // Use asynchronous proxy resolver.
  MockAsyncProxyResolverFactory* proxy_resolver_factory =
      new MockAsyncProxyResolverFactory(false);
  session_deps_.proxy_service.reset(
      new ProxyService(base::MakeUnique<ProxyConfigServiceFixed>(proxy_config),
                       base::WrapUnique(proxy_resolver_factory), nullptr));
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");

  Initialize(request_info, false, false);

  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(kProtoQUIC, server.host(), 443);
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
  job_controller_->OnStreamReady(job_factory_.main_job(), SSLConfig());

  // Verify that the alternate protocol is marked as broken.
  VerifyBrokenAlternateProtocolMapping(request_info, true);
  histogram_tester.ExpectUniqueSample("Net.AlternateServiceFailed", -ERR_FAILED,
                                      1);
}

// Verifies that if the alternative job fails due to a connection change event,
// then the alternative service is not marked as broken.
TEST_F(HttpStreamFactoryImplJobControllerTest,
       MainJobSucceedsAfterConnectionChanged) {
  base::HistogramTester histogram_tester;
  ProxyConfig proxy_config;
  proxy_config.set_auto_detect(true);
  // Use asynchronous proxy resolver.
  MockAsyncProxyResolverFactory* proxy_resolver_factory =
      new MockAsyncProxyResolverFactory(false);
  session_deps_.proxy_service.reset(
      new ProxyService(base::MakeUnique<ProxyConfigServiceFixed>(proxy_config),
                       base::WrapUnique(proxy_resolver_factory), nullptr));
  session_deps_.quic_do_not_mark_as_broken_on_network_change = true;

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");
  Initialize(request_info, false, false);

  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(kProtoQUIC, server.host(), 443);
  SetAlternativeService(request_info, alternative_service);

  request_.reset(
      job_controller_->Start(request_info, &request_delegate_, nullptr,
                             NetLogWithSource(), HttpStreamRequest::HTTP_STREAM,
                             DEFAULT_PRIORITY, SSLConfig(), SSLConfig()));
  EXPECT_TRUE(job_controller_->main_job());
  EXPECT_TRUE(job_controller_->alternative_job());

  // |alternative_job| fails but should not report status to Request.
  EXPECT_CALL(request_delegate_, OnStreamFailed(_, _)).Times(0);

  job_controller_->OnStreamFailed(job_factory_.alternative_job(),
                                  ERR_NETWORK_CHANGED, SSLConfig());

  // |main_job| succeeds and should report status to Request.
  HttpStream* http_stream =
      new HttpBasicStream(base::MakeUnique<ClientSocketHandle>(), false, false);
  job_factory_.main_job()->SetStream(http_stream);

  EXPECT_CALL(request_delegate_, OnStreamReady(_, _, http_stream))
      .WillOnce(Invoke(DeleteHttpStreamPointer));
  job_controller_->OnStreamReady(job_factory_.main_job(), SSLConfig());

  // Verify that the alternate protocol is not marked as broken.
  VerifyBrokenAlternateProtocolMapping(request_info, false);
  histogram_tester.ExpectUniqueSample("Net.AlternateServiceFailed",
                                      -ERR_NETWORK_CHANGED, 1);
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

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");

  Initialize(request_info, false, false);
  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(kProtoQUIC, server.host(), 443);
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
  job_controller_->OnStreamReady(job_factory_.alternative_job(), SSLConfig());
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

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");

  Initialize(request_info, false, false);
  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(kProtoQUIC, server.host(), 443);
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
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");

  // Using a restricted port 101 for QUIC should fail and the alternative job
  // should post OnStreamFailedCall on the controller to resume the main job.
  Initialize(request_info, false, false);

  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(kProtoQUIC, server.host(), 101);
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

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");

  Initialize(request_info, false, false);

  // Set a SPDY alternative service for the server.
  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(kProtoQUIC, server.host(), 443);
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
      resolver.pending_jobs()[0]->url().SchemeIs("http") ? 0 : 1;

  resolver.pending_jobs()[main_job_request_id]->results()->UseNamedProxy(
      "result1:80");
  resolver.pending_jobs()[main_job_request_id]->CompleteNow(net::OK);
  EXPECT_TRUE(job_controller_->main_job()->is_waiting());

  // Resolve proxy for the alternative job to proceed to create a connection.
  // Use hanging HostResolver to fail creation of a SPDY session for the
  // alternative job. The alternative job will be IO_PENDING thus should resume
  // the main job.
  resolver.pending_jobs()[0]->CompleteNow(net::OK);
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

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");

  Initialize(request_info, false, false);
  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(kProtoQUIC, server.host(), 443);
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
      resolver.pending_jobs()[0]->url().SchemeIs("http") ? 0 : 1;

  resolver.pending_jobs()[main_job_request_id]->results()->UseNamedProxy(
      "result1:80");
  resolver.pending_jobs()[main_job_request_id]->CompleteNow(net::OK);
  EXPECT_TRUE(job_controller_->main_job()->is_waiting());

  // Resolve proxy for the alternative job to proceed to create a connection.
  // Use failing HostResolver to fail creation of a QUIC session for the
  // alternative job. The alternative job will thus resume the main job.
  resolver.pending_jobs()[0]->results()->UseNamedProxy("result1:80");
  resolver.pending_jobs()[0]->CompleteNow(net::OK);

  // Wait until OnStreamFailedCallback is executed on the alternative job.
  // Request shouldn't be notified as the main job is still pending status.
  EXPECT_CALL(request_delegate_, OnStreamFailed(_, _)).Times(0);
  EXPECT_CALL(*job_factory_.main_job(), Resume()).Times(1);

  base::RunLoop().RunUntilIdle();
}

TEST_F(HttpStreamFactoryImplJobControllerTest, DelayedTCP) {
  base::ScopedMockTimeMessageLoopTaskRunner test_task_runner;
  HangingResolver* resolver = new HangingResolver();
  session_deps_.host_resolver.reset(resolver);

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");

  Initialize(request_info, false, false);

  // Enable delayed TCP and set time delay for waiting job.
  QuicStreamFactory* quic_stream_factory = session_->quic_stream_factory();
  test::QuicStreamFactoryPeer::SetDelayTcpRace(quic_stream_factory, true);
  quic_stream_factory->set_require_confirmation(false);
  ServerNetworkStats stats1;
  stats1.srtt = base::TimeDelta::FromMicroseconds(10);
  session_->http_server_properties()->SetServerNetworkStats(
      url::SchemeHostPort(GURL("https://www.google.com")), stats1);

  // Set a SPDY alternative service for the server.
  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(kProtoQUIC, server.host(), 443);
  SetAlternativeService(request_info, alternative_service);

  request_.reset(
      job_controller_->Start(request_info, &request_delegate_, nullptr,
                             NetLogWithSource(), HttpStreamRequest::HTTP_STREAM,
                             DEFAULT_PRIORITY, SSLConfig(), SSLConfig()));
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
  job_controller_->OnStreamFailed(job_factory_.alternative_job(),
                                  ERR_NETWORK_CHANGED, SSLConfig());
  EXPECT_EQ(1u, test_task_runner->GetPendingTaskCount());
  test_task_runner->FastForwardUntilNoTasksRemain();
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
  HangingResolver* resolver = new HangingResolver();
  session_deps_.host_resolver.reset(resolver);

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");

  Initialize(request_info, false, false);

  // Enable delayed TCP and set a extremely large time delay for waiting job.
  QuicStreamFactory* quic_stream_factory = session_->quic_stream_factory();
  test::QuicStreamFactoryPeer::SetDelayTcpRace(quic_stream_factory, true);
  quic_stream_factory->set_require_confirmation(false);
  ServerNetworkStats stats1;
  stats1.srtt = base::TimeDelta::FromSeconds(100);
  session_->http_server_properties()->SetServerNetworkStats(
      url::SchemeHostPort(GURL("https://www.google.com")), stats1);

  // Set a SPDY alternative service for the server.
  url::SchemeHostPort server(request_info.url);
  AlternativeService alternative_service(kProtoQUIC, server.host(), 443);
  SetAlternativeService(request_info, alternative_service);

  request_.reset(
      job_controller_->Start(request_info, &request_delegate_, nullptr,
                             NetLogWithSource(), HttpStreamRequest::HTTP_STREAM,
                             DEFAULT_PRIORITY, SSLConfig(), SSLConfig()));
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
}

TEST_F(HttpStreamFactoryImplJobControllerTest,
       ResumeMainJobImmediatelyOnStreamFailed) {
  // Overrides the main thread's message loop with a mock tick clock so that we
  // could verify the main job is resumed with appropriate delay.
  base::ScopedMockTimeMessageLoopTaskRunner test_task_runner;

  HangingResolver* resolver = new HangingResolver();
  session_deps_.host_resolver.reset(resolver);

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");

  Initialize(request_info, false, false);

  // Enable delayed TCP and set time delay for waiting job.
  QuicStreamFactory* quic_stream_factory = session_->quic_stream_factory();
  test::QuicStreamFactoryPeer::SetDelayTcpRace(quic_stream_factory, true);
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
  request_.reset(
      job_controller_->Start(request_info, &request_delegate_, nullptr,
                             NetLogWithSource(), HttpStreamRequest::HTTP_STREAM,
                             DEFAULT_PRIORITY, SSLConfig(), SSLConfig()));
  EXPECT_TRUE(job_controller_->main_job());
  EXPECT_TRUE(job_controller_->alternative_job());
  EXPECT_TRUE(job_controller_->main_job()->is_waiting());

  EXPECT_TRUE(test_task_runner->HasPendingTask());
  EXPECT_EQ(1u, test_task_runner->GetPendingTaskCount());

  // |alternative_job| fails but should not report status to Request.
  EXPECT_CALL(request_delegate_, OnStreamFailed(_, _)).Times(0);
  job_controller_->OnStreamFailed(job_factory_.alternative_job(),
                                  ERR_NETWORK_CHANGED, SSLConfig());
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
}

// Verifies that the alternative proxy server job is not created if the URL
// scheme is HTTPS.
TEST_F(HttpStreamFactoryImplJobControllerTest, HttpsURL) {
  // Using hanging resolver will cause the alternative job to hang indefinitely.
  HangingResolver* resolver = new HangingResolver();
  session_deps_.host_resolver.reset(resolver);

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://mail.example.org/");
  Initialize(request_info, false, false);
  EXPECT_TRUE(test_proxy_delegate()->alternative_proxy_server().is_quic());

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

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("http://mail.example.org/");

  Initialize(request_info, false, false);
  EXPECT_TRUE(test_proxy_delegate()->alternative_proxy_server().is_quic());

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
  // Overrides the main thread's message loop with a mock tick clock so that we
  // could verify the main job is resumed with appropriate delay.
  base::ScopedMockTimeMessageLoopTaskRunner test_task_runner;

  // Using hanging resolver will cause the alternative job to hang indefinitely.
  HangingResolver* resolver = new HangingResolver();
  session_deps_.host_resolver.reset(resolver);

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("http://mail.example.org/");
  Initialize(request_info, true, false);

  EXPECT_TRUE(test_proxy_delegate()->alternative_proxy_server().is_quic());

  // Enable delayed TCP and set time delay for waiting job.
  QuicStreamFactory* quic_stream_factory = session_->quic_stream_factory();
  test::QuicStreamFactoryPeer::SetDelayTcpRace(quic_stream_factory, true);
  quic_stream_factory->set_require_confirmation(false);
  ServerNetworkStats stats1;
  stats1.srtt = base::TimeDelta::FromMicroseconds(10);
  session_->http_server_properties()->SetServerNetworkStats(
      url::SchemeHostPort(GURL("https://myproxy.org")), stats1);

  request_.reset(
      job_controller_->Start(request_info, &request_delegate_, nullptr,
                             NetLogWithSource(), HttpStreamRequest::HTTP_STREAM,
                             DEFAULT_PRIORITY, SSLConfig(), SSLConfig()));
  EXPECT_TRUE(job_controller_->main_job());
  EXPECT_TRUE(job_controller_->main_job()->is_waiting());
  EXPECT_TRUE(job_controller_->alternative_job());
  EXPECT_TRUE(JobControllerPeer::main_job_is_blocked(job_controller_));

  // Alternative proxy server job will start in the next message loop.
  EXPECT_EQ(1u, test_task_runner->GetPendingTaskCount());

  EXPECT_CALL(*job_factory_.main_job(), Resume()).Times(0);
  // Run tasks with no remaining delay, this will start the alternative proxy
  // server job. The alternative proxy server job stalls when connecting to the
  // alternative proxy server, and should schedule a task to resume the main job
  // after delay. That task will be queued.
  test_task_runner->RunUntilIdle();
  EXPECT_EQ(1u, test_task_runner->GetPendingTaskCount());

  // Move forward the delay and verify the main job is resumed.
  EXPECT_CALL(*job_factory_.main_job(), Resume()).Times(1);
  test_task_runner->FastForwardBy(base::TimeDelta::FromMicroseconds(15));
  EXPECT_FALSE(JobControllerPeer::main_job_is_blocked(job_controller_));

  test_task_runner->RunUntilIdle();
  EXPECT_TRUE(test_proxy_delegate()->alternative_proxy_server().is_valid());
  EXPECT_EQ(1, test_proxy_delegate()->get_alternative_proxy_invocations());
  EXPECT_FALSE(test_task_runner->HasPendingTask());
}

// Verifies that the alternative proxy server job fails immediately, and the
// main job is not blocked.
TEST_F(HttpStreamFactoryImplJobControllerTest, FailAlternativeProxy) {
  base::ScopedMockTimeMessageLoopTaskRunner test_task_runner;
  // Using failing resolver will cause the alternative job to fail.
  FailingHostResolver* resolver = new FailingHostResolver();
  session_deps_.host_resolver.reset(resolver);

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("http://mail.example.org/");
  Initialize(request_info, true, false);
  EXPECT_TRUE(test_proxy_delegate()->alternative_proxy_server().is_quic());

  // Enable delayed TCP and set time delay for waiting job.
  QuicStreamFactory* quic_stream_factory = session_->quic_stream_factory();
  test::QuicStreamFactoryPeer::SetDelayTcpRace(quic_stream_factory, true);
  quic_stream_factory->set_require_confirmation(false);
  ServerNetworkStats stats1;
  stats1.srtt = base::TimeDelta::FromMicroseconds(300 * 1000);
  session_->http_server_properties()->SetServerNetworkStats(
      url::SchemeHostPort(GURL("https://myproxy.org")), stats1);

  request_.reset(
      job_controller_->Start(request_info, &request_delegate_, nullptr,
                             NetLogWithSource(), HttpStreamRequest::HTTP_STREAM,
                             DEFAULT_PRIORITY, SSLConfig(), SSLConfig()));
  EXPECT_TRUE(job_controller_->main_job()->is_waiting());
  EXPECT_TRUE(job_controller_->alternative_job());

  EXPECT_EQ(1u, test_task_runner->GetPendingTaskCount());

  EXPECT_CALL(request_delegate_, OnStreamReady(_, _, _)).Times(0);

  // Since the alternative proxy server job is started in the next message loop,
  // the main job would remain blocked until the alternative proxy starts, and
  // fails.
  EXPECT_CALL(*job_factory_.main_job(), Resume()).Times(1);

  // Run tasks with no remaining delay.
  test_task_runner->RunUntilIdle();

  EXPECT_FALSE(job_controller_->alternative_job());
  EXPECT_TRUE(job_controller_->main_job()->is_waiting());
  // Since the main job did not complete successfully, the alternative proxy
  // server should not be marked as bad.
  EXPECT_TRUE(test_proxy_delegate()->alternative_proxy_server().is_valid());
  EXPECT_EQ(1, test_proxy_delegate()->get_alternative_proxy_invocations());
  EXPECT_FALSE(test_task_runner->HasPendingTask());
}

TEST_F(HttpStreamFactoryImplJobControllerTest,
       AlternativeProxyServerJobFailsAfterMainJobSucceeds) {
  base::HistogramTester histogram_tester;
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("http://www.google.com");
  Initialize(request_info, true, false);

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
  job_controller_->OnStreamReady(job_factory_.main_job(), SSLConfig());

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

// When preconnect to a H2 supported server, only 1 connection is opened.
TEST_F(HttpStreamFactoryImplJobControllerTest,
       PreconnectMultipleStreamsToH2Server) {
  MockRead reads[] = {MockRead(ASYNC, OK)};
  SequencedSocketData data(reads, arraysize(reads), nullptr, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("http://www.example.com");
  Initialize(request_info, false, /*is_preconnect=*/true);

  url::SchemeHostPort server(request_info.url);

  // Sets server support Http/2.
  session_->http_server_properties()->SetSupportsSpdy(server, true);

  job_controller_->Preconnect(/*num_streams=*/5, request_info, SSLConfig(),
                              SSLConfig());
  // Only one job is started.
  EXPECT_TRUE(job_controller_->main_job());
  EXPECT_FALSE(job_controller_->alternative_job());
  // There is only 1 connect even though multiple streams were requested.
  EXPECT_EQ(1, HttpStreamFactoryImplJobPeer::GetNumStreams(
                   job_controller_->main_job()));

  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(HttpStreamFactoryImplPeer::IsJobControllerDeleted(factory_));
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
        request_info_, true);
    HttpStreamFactoryImplPeer::AddJobController(factory_, job_controller_);
  }

 protected:
  void Preconnect(int num_streams) {
    job_controller_->Preconnect(num_streams, request_info_, SSLConfig(),
                                SSLConfig());
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
  std::vector<std::unique_ptr<SequencedSocketData>> providers;
  std::vector<std::unique_ptr<SSLSocketDataProvider>> ssl_providers;
  const int kNumPreconects = 5;
  MockRead reads[] = {MockRead(ASYNC, OK)};
  // If experiment is not enabled, there are 5 socket connects.
  const size_t actual_num_connects = GetParam() ? 1 : kNumPreconects;
  for (size_t i = 0; i < actual_num_connects; ++i) {
    auto data = base::MakeUnique<SequencedSocketData>(reads, arraysize(reads),
                                                      nullptr, 0);
    auto ssl_data = base::MakeUnique<SSLSocketDataProvider>(ASYNC, OK);
    session_deps_.socket_factory->AddSocketDataProvider(data.get());
    session_deps_.socket_factory->AddSSLSocketDataProvider(ssl_data.get());
    providers.push_back(std::move(data));
    ssl_providers.push_back(std::move(ssl_data));
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

}  // namespace net
