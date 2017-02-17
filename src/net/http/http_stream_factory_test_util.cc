// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_stream_factory_test_util.h"

#include "net/proxy/proxy_info.h"

using ::testing::_;

namespace net {
MockHttpStreamRequestDelegate::MockHttpStreamRequestDelegate() {}

MockHttpStreamRequestDelegate::~MockHttpStreamRequestDelegate() {}

MockHttpStreamFactoryImplJob::MockHttpStreamFactoryImplJob(
    HttpStreamFactoryImpl::Job::Delegate* delegate,
    HttpStreamFactoryImpl::JobType job_type,
    HttpNetworkSession* session,
    const HttpRequestInfo& request_info,
    RequestPriority priority,
    const SSLConfig& server_ssl_config,
    const SSLConfig& proxy_ssl_config,
    HostPortPair destination,
    GURL origin_url,
    NetLog* net_log)
    : HttpStreamFactoryImpl::Job(delegate,
                                 job_type,
                                 session,
                                 request_info,
                                 priority,
                                 server_ssl_config,
                                 proxy_ssl_config,
                                 destination,
                                 origin_url,
                                 net_log) {
  DCHECK(!is_waiting());
}

MockHttpStreamFactoryImplJob::MockHttpStreamFactoryImplJob(
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
    const ProxyServer& alternative_proxy_server,
    NetLog* net_log)
    : HttpStreamFactoryImpl::Job(delegate,
                                 job_type,
                                 session,
                                 request_info,
                                 priority,
                                 server_ssl_config,
                                 proxy_ssl_config,
                                 destination,
                                 origin_url,
                                 alternative_service,
                                 alternative_proxy_server,
                                 net_log) {}

MockHttpStreamFactoryImplJob::~MockHttpStreamFactoryImplJob() {}

TestJobFactory::TestJobFactory()
    : main_job_(nullptr),
      alternative_job_(nullptr),
      override_main_job_url_(false) {}

TestJobFactory::~TestJobFactory() {}

HttpStreamFactoryImpl::Job* TestJobFactory::CreateJob(
    HttpStreamFactoryImpl::Job::Delegate* delegate,
    HttpStreamFactoryImpl::JobType job_type,
    HttpNetworkSession* session,
    const HttpRequestInfo& request_info,
    RequestPriority priority,
    const SSLConfig& server_ssl_config,
    const SSLConfig& proxy_ssl_config,
    HostPortPair destination,
    GURL origin_url,
    NetLog* net_log) {
  DCHECK(!main_job_);

  if (override_main_job_url_)
    origin_url = main_job_alternative_url_;

  main_job_ = new MockHttpStreamFactoryImplJob(
      delegate, job_type, session, request_info, priority, SSLConfig(),
      SSLConfig(), destination, origin_url, nullptr);

  return main_job_;
}

HttpStreamFactoryImpl::Job* TestJobFactory::CreateJob(
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
    NetLog* net_log) {
  DCHECK(!alternative_job_);
  alternative_job_ = new MockHttpStreamFactoryImplJob(
      delegate, job_type, session, request_info, priority, SSLConfig(),
      SSLConfig(), destination, origin_url, alternative_service, ProxyServer(),
      nullptr);

  return alternative_job_;
}

HttpStreamFactoryImpl::Job* TestJobFactory::CreateJob(
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
    NetLog* net_log) {
  DCHECK(!alternative_job_);
  alternative_job_ = new MockHttpStreamFactoryImplJob(
      delegate, job_type, session, request_info, priority, SSLConfig(),
      SSLConfig(), destination, origin_url, AlternativeService(),
      alternative_proxy_server, nullptr);

  return alternative_job_;
}

}  // namespace net
