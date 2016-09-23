// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_HTTP_HTTP_STREAM_FACTORY_TEST_UTIL_H_
#define NET_HTTP_HTTP_STREAM_FACTORY_TEST_UTIL_H_

#include "base/memory/ptr_util.h"
#include "net/http/http_stream.h"
#include "net/http/http_stream_factory.h"
#include "net/http/http_stream_factory_impl.h"
#include "net/http/http_stream_factory_impl_job.h"
#include "net/http/http_stream_factory_impl_job_controller.h"
#include "net/proxy/proxy_info.h"
#include "net/proxy/proxy_server.h"
#include "testing/gmock/include/gmock/gmock.h"

using testing::_;
using testing::Invoke;

namespace net {

class HttpStreamFactoryImplPeer {
 public:
  static void AddJobController(
      HttpStreamFactoryImpl* factory,
      HttpStreamFactoryImpl::JobController* job_controller) {
    factory->job_controller_set_.insert(base::WrapUnique(job_controller));
  }

  static bool IsJobControllerDeleted(HttpStreamFactoryImpl* factory) {
    return factory->job_controller_set_.empty();
  }

  static HttpStreamFactoryImpl::JobFactory* GetDefaultJobFactory(
      HttpStreamFactoryImpl* factory) {
    return factory->job_factory_.get();
  }
};

// This delegate does nothing when called.
class MockHttpStreamRequestDelegate : public HttpStreamRequest::Delegate {
 public:
  MockHttpStreamRequestDelegate();

  ~MockHttpStreamRequestDelegate() override;

  MOCK_METHOD3(OnStreamReady,
               void(const SSLConfig& used_ssl_config,
                    const ProxyInfo& used_proxy_info,
                    HttpStream* stream));

  MOCK_METHOD3(OnBidirectionalStreamImplReady,
               void(const SSLConfig& used_ssl_config,
                    const ProxyInfo& used_proxy_info,
                    BidirectionalStreamImpl* stream));

  MOCK_METHOD3(OnWebSocketHandshakeStreamReady,
               void(const SSLConfig& used_ssl_config,
                    const ProxyInfo& used_proxy_info,
                    WebSocketHandshakeStreamBase* stream));

  MOCK_METHOD2(OnStreamFailed,
               void(int status, const SSLConfig& used_ssl_config));

  MOCK_METHOD3(OnCertificateError,
               void(int status,
                    const SSLConfig& used_ssl_config,
                    const SSLInfo& ssl_info));

  MOCK_METHOD4(OnNeedsProxyAuth,
               void(const HttpResponseInfo& proxy_response,
                    const SSLConfig& used_ssl_config,
                    const ProxyInfo& used_proxy_info,
                    HttpAuthController* auth_controller));

  MOCK_METHOD2(OnNeedsClientAuth,
               void(const SSLConfig& used_ssl_config,
                    SSLCertRequestInfo* cert_info));

  MOCK_METHOD4(OnHttpsProxyTunnelResponse,
               void(const HttpResponseInfo& response_info,
                    const SSLConfig& used_ssl_config,
                    const ProxyInfo& used_proxy_info,
                    HttpStream* stream));

  MOCK_METHOD0(OnQuicBroken, void());

 private:
  DISALLOW_COPY_AND_ASSIGN(MockHttpStreamRequestDelegate);
};

class MockHttpStreamFactoryImplJob : public HttpStreamFactoryImpl::Job {
 public:
  MockHttpStreamFactoryImplJob(HttpStreamFactoryImpl::Job::Delegate* delegate,
                               HttpStreamFactoryImpl::JobType job_type,
                               HttpNetworkSession* session,
                               const HttpRequestInfo& request_info,
                               RequestPriority priority,
                               const SSLConfig& server_ssl_config,
                               const SSLConfig& proxy_ssl_config,
                               HostPortPair destination,
                               GURL origin_url,
                               NetLog* net_log);

  MockHttpStreamFactoryImplJob(HttpStreamFactoryImpl::Job::Delegate* delegate,
                               HttpStreamFactoryImpl::JobType job_type,
                               HttpNetworkSession* session,
                               const HttpRequestInfo& request_info,
                               RequestPriority priority,
                               const SSLConfig& server_ssl_config,
                               const SSLConfig& proxy_ssl_config,
                               HostPortPair destination,
                               GURL origin_url,
                               AlternativeService alternative_service,
                               const ProxyServer& alternative_proxy_server,
                               NetLog* net_log);

  ~MockHttpStreamFactoryImplJob() override;

  MOCK_METHOD0(Resume, void());

  MOCK_METHOD0(Orphan, void());
};

// JobFactory for creating MockHttpStreamFactoryImplJobs.
class TestJobFactory : public HttpStreamFactoryImpl::JobFactory {
 public:
  TestJobFactory();
  ~TestJobFactory() override;

  HttpStreamFactoryImpl::Job* CreateJob(
      HttpStreamFactoryImpl::Job::Delegate* delegate,
      HttpStreamFactoryImpl::JobType job_type,
      HttpNetworkSession* session,
      const HttpRequestInfo& request_info,
      RequestPriority priority,
      const SSLConfig& server_ssl_config,
      const SSLConfig& proxy_ssl_config,
      HostPortPair destination,
      GURL origin_url,
      NetLog* net_log) override;

  HttpStreamFactoryImpl::Job* CreateJob(
      HttpStreamFactoryImpl::Job::Delegate* delegate,
      HttpStreamFactoryImpl::JobType job_type,
      HttpNetworkSession* session,
      const HttpRequestInfo& request_info,
      RequestPriority priority,
      const SSLConfig& server_ssl_config,
      const SSLConfig& proxy_ssl_config,
      HostPortPair destination,
      GURL origin_url,
      AlternativeService alternative_service,
      NetLog* net_log) override;

  HttpStreamFactoryImpl::Job* CreateJob(
      HttpStreamFactoryImpl::Job::Delegate* delegate,
      HttpStreamFactoryImpl::JobType job_type,
      HttpNetworkSession* session,
      const HttpRequestInfo& request_info,
      RequestPriority priority,
      const SSLConfig& server_ssl_config,
      const SSLConfig& proxy_ssl_config,
      HostPortPair destination,
      GURL origin_url,
      const ProxyServer& alternative_proxy_server,
      NetLog* net_log) override;

  MockHttpStreamFactoryImplJob* main_job() const { return main_job_; }
  MockHttpStreamFactoryImplJob* alternative_job() const {
    return alternative_job_;
  }

  void UseDifferentURLForMainJob(GURL url) {
    override_main_job_url_ = true;
    main_job_alternative_url_ = url;
  }

 private:
  MockHttpStreamFactoryImplJob* main_job_;
  MockHttpStreamFactoryImplJob* alternative_job_;
  bool override_main_job_url_;
  GURL main_job_alternative_url_;
};

}  // namespace net

#endif  // NET_HTTP_HTTP_STREAM_FACTORY_TEST_UTIL_H_
