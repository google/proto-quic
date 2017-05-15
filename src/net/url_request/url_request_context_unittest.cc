// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/url_request/url_request_context.h"

#include <memory>
#include <utility>
#include <vector>

#include "base/memory/ptr_util.h"
#include "base/test/histogram_tester.h"
#include "base/trace_event/memory_dump_request_args.h"
#include "base/trace_event/process_memory_dump.h"
#include "net/proxy/proxy_config_service_fixed.h"
#include "net/test/url_request/url_request_failed_job.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "net/url_request/url_request_context_builder.h"
#include "net/url_request/url_request_filter.h"
#include "net/url_request/url_request_interceptor.h"
#include "net/url_request/url_request_test_util.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

class HangingRequestInterceptor : public URLRequestInterceptor {
 public:
  HangingRequestInterceptor() {}
  ~HangingRequestInterceptor() override {}

  URLRequestJob* MaybeInterceptRequest(
      URLRequest* request,
      NetworkDelegate* network_delegate) const override {
    return new URLRequestFailedJob(request, network_delegate, ERR_IO_PENDING);
  }
};

}  // namespace

class URLRequestContextMemoryDumpTest
    : public testing::TestWithParam<
          base::trace_event::MemoryDumpLevelOfDetail> {};

INSTANTIATE_TEST_CASE_P(
    /* no prefix */,
    URLRequestContextMemoryDumpTest,
    ::testing::Values(base::trace_event::MemoryDumpLevelOfDetail::DETAILED,
                      base::trace_event::MemoryDumpLevelOfDetail::BACKGROUND));

// Checks if the dump provider runs without crashing and dumps root objects.
TEST_P(URLRequestContextMemoryDumpTest, MemoryDumpProvider) {
  base::trace_event::MemoryDumpArgs dump_args = {GetParam()};
  std::unique_ptr<base::trace_event::ProcessMemoryDump> process_memory_dump(
      new base::trace_event::ProcessMemoryDump(nullptr, dump_args));
  URLRequestContextBuilder builder;
#if defined(OS_LINUX) || defined(OS_ANDROID)
  builder.set_proxy_config_service(
      base::MakeUnique<ProxyConfigServiceFixed>(ProxyConfig::CreateDirect()));
#endif  // defined(OS_LINUX) || defined(OS_ANDROID)
  std::unique_ptr<URLRequestContext> context(builder.Build());
  context->OnMemoryDump(dump_args, process_memory_dump.get());
  const base::trace_event::ProcessMemoryDump::AllocatorDumpsMap&
      allocator_dumps = process_memory_dump->allocator_dumps();

  bool did_dump_http_network_session = false;
  bool did_dump_ssl_client_session_cache = false;
  bool did_dump_url_request_context = false;
  bool did_dump_url_request_context_http_network_session = false;
  for (const auto& it : allocator_dumps) {
    const std::string& dump_name = it.first;
    if (dump_name.find("net/http_network_session") != std::string::npos)
      did_dump_http_network_session = true;
    if (dump_name.find("net/ssl_session_cache") != std::string::npos)
      did_dump_ssl_client_session_cache = true;
    if (dump_name.find("net/url_request_context") != std::string::npos) {
      // A sub allocator dump to take into account of the sharing relationship.
      if (dump_name.find("http_network_session") != std::string::npos) {
        did_dump_url_request_context_http_network_session = true;
      } else {
        did_dump_url_request_context = true;
      }
    }
  }
  ASSERT_TRUE(did_dump_http_network_session);
  ASSERT_TRUE(did_dump_ssl_client_session_cache);
  ASSERT_TRUE(did_dump_url_request_context);
  ASSERT_TRUE(did_dump_url_request_context_http_network_session);
}

// TODO(xunjieli): Add more granular tests on the MemoryDumpProvider.

// Tests that if many requests are outstanding, histogram is reported correctly.
TEST(URLRequestContextTest, TooManyRequests) {
  TestURLRequestContext context(false);
  base::HistogramTester histogram_tester;
  std::unique_ptr<URLRequestInterceptor> interceptor(
      new HangingRequestInterceptor());
  GURL url("http://www.example.com");
  URLRequestFilter::GetInstance()->AddUrlInterceptor(url,
                                                     std::move(interceptor));
  std::vector<std::unique_ptr<URLRequest>> outstanding_requests;
  const int kNumRequestLimit = 1000;
  // Make two more requests above the limit to test that AddToAddressMap() only
  // returns false once.
  const int kNumRequests = kNumRequestLimit + 2;
  const void* const dummy_address = &context;
  for (int i = 0; i < kNumRequests; ++i) {
    TestDelegate test_delegate;
    test_delegate.set_quit_on_complete(true);
    std::unique_ptr<URLRequest> request = context.CreateRequest(
        url, DEFAULT_PRIORITY, &test_delegate, TRAFFIC_ANNOTATION_FOR_TESTS);
    EXPECT_EQ(i != kNumRequestLimit, context.AddToAddressMap(dummy_address));
    request->Start();
    outstanding_requests.push_back(std::move(request));
  }

  histogram_tester.ExpectTotalCount("Net.URLRequestContext.OutstandingRequests",
                                    kNumRequests);
  for (int i = 0; i < kNumRequests; ++i) {
    context.RemoveFromAddressMap(dummy_address);
  }
}

}  // namespace net
