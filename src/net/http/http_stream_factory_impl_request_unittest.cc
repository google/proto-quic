// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_stream_factory_impl_request.h"

#include <memory>

#include "base/memory/ptr_util.h"
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
  HttpRequestInfo request_info;
  auto job_controller = base::MakeUnique<HttpStreamFactoryImpl::JobController>(
      factory, &request_delegate, session.get(), &job_factory, request_info,
      /*is_preconnect=*/false);
  HttpStreamFactoryImpl::JobController* job_controller_raw_ptr =
      job_controller.get();
  factory->job_controller_set_.insert(std::move(job_controller));

  std::unique_ptr<HttpStreamFactoryImpl::Request> request(
      job_controller_raw_ptr->Start(
          request_info, &request_delegate, nullptr, NetLogWithSource(),
          HttpStreamRequest::HTTP_STREAM, DEFAULT_PRIORITY, SSLConfig(),
          SSLConfig()));
  EXPECT_TRUE(job_controller_raw_ptr->main_job());
  EXPECT_EQ(DEFAULT_PRIORITY, job_controller_raw_ptr->main_job()->priority());

  request->SetPriority(MEDIUM);
  EXPECT_EQ(MEDIUM, job_controller_raw_ptr->main_job()->priority());

  EXPECT_CALL(request_delegate, OnStreamFailed(_, _)).Times(1);
  job_controller_raw_ptr->OnStreamFailed(job_factory.main_job(), ERR_FAILED,
                                         SSLConfig());

  request->SetPriority(IDLE);
  EXPECT_EQ(IDLE, job_controller_raw_ptr->main_job()->priority());
}
}  // namespace net
