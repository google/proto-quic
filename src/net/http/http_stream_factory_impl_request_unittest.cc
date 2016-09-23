// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_stream_factory_impl_request.h"

#include <memory>

#include "base/run_loop.h"
#include "net/http/http_stream_factory_impl.h"
#include "net/http/http_stream_factory_impl_job.h"
#include "net/http/http_stream_factory_impl_job_controller.h"
#include "net/http/http_stream_factory_test_util.h"
#include "net/proxy/proxy_info.h"
#include "net/proxy/proxy_service.h"
#include "net/spdy/spdy_test_util_common.h"
#include "testing/gtest/include/gtest/gtest.h"

using testing::_;

namespace net {

class HttpStreamFactoryImplRequestTest : public ::testing::Test {};

// Make sure that Request passes on its priority updates to its jobs.
TEST_F(HttpStreamFactoryImplRequestTest, SetPriority) {
  SpdySessionDependencies session_deps(ProxyService::CreateDirect());
  std::unique_ptr<HttpNetworkSession> session =
      SpdySessionDependencies::SpdyCreateSession(&session_deps);
  HttpStreamFactoryImpl* factory =
      static_cast<HttpStreamFactoryImpl*>(session->http_stream_factory());
  MockHttpStreamRequestDelegate request_delegate;
  TestJobFactory job_factory;
  HttpStreamFactoryImpl::JobController* job_controller =
      new HttpStreamFactoryImpl::JobController(factory, &request_delegate,
                                               session.get(), &job_factory);
  factory->job_controller_set_.insert(base::WrapUnique(job_controller));

  HttpRequestInfo request_info;
  std::unique_ptr<HttpStreamFactoryImpl::Request> request(
      job_controller->Start(request_info, &request_delegate, nullptr,
                            NetLogWithSource(), HttpStreamRequest::HTTP_STREAM,
                            DEFAULT_PRIORITY, SSLConfig(), SSLConfig()));
  EXPECT_TRUE(job_controller->main_job());
  EXPECT_EQ(DEFAULT_PRIORITY, job_controller->main_job()->priority());

  request->SetPriority(MEDIUM);
  EXPECT_EQ(MEDIUM, job_controller->main_job()->priority());

  EXPECT_CALL(request_delegate, OnStreamFailed(_, _)).Times(1);
  job_controller->OnStreamFailed(job_factory.main_job(), ERR_FAILED,
                                 SSLConfig());

  request->SetPriority(IDLE);
  EXPECT_EQ(IDLE, job_controller->main_job()->priority());
}
}  // namespace net
