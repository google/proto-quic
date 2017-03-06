// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/url_request/url_request_http_job.h"

#include <stdint.h>

#include <cstddef>
#include <memory>

#include "base/compiler_specific.h"
#include "base/macros.h"
#include "base/memory/ptr_util.h"
#include "base/memory/ref_counted.h"
#include "base/run_loop.h"
#include "base/strings/string_split.h"
#include "base/test/histogram_tester.h"
#include "net/base/auth.h"
#include "net/base/request_priority.h"
#include "net/base/sdch_observer.h"
#include "net/cookies/cookie_store_test_helpers.h"
#include "net/http/http_transaction_factory.h"
#include "net/http/http_transaction_test_util.h"
#include "net/log/net_log_event_type.h"
#include "net/log/test_net_log.h"
#include "net/log/test_net_log_entry.h"
#include "net/log/test_net_log_util.h"
#include "net/net_features.h"
#include "net/socket/socket_test_util.h"
#include "net/test/cert_test_util.h"
#include "net/test/gtest_util.h"
#include "net/test/test_data_directory.h"
#include "net/url_request/url_request.h"
#include "net/url_request/url_request_job_factory_impl.h"
#include "net/url_request/url_request_status.h"
#include "net/url_request/url_request_test_util.h"
#include "net/websockets/websocket_handshake_stream_base.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"
#include "url/url_constants.h"

#if defined(OS_ANDROID)
#include "base/android/build_info.h"
#include "base/android/jni_android.h"
#include "jni/AndroidNetworkLibraryTestUtil_jni.h"
#endif

using net::test::IsError;
using net::test::IsOk;

namespace net {

namespace {

using ::testing::Return;

const char kSimpleGetMockWrite[] =
    "GET / HTTP/1.1\r\n"
    "Host: www.example.com\r\n"
    "Connection: keep-alive\r\n"
    "User-Agent:\r\n"
    "Accept-Encoding: gzip, deflate\r\n"
    "Accept-Language: en-us,fr\r\n\r\n";

// Inherit from URLRequestHttpJob to expose the priority and some
// other hidden functions.
class TestURLRequestHttpJob : public URLRequestHttpJob {
 public:
  explicit TestURLRequestHttpJob(URLRequest* request)
      : URLRequestHttpJob(request,
                          request->context()->network_delegate(),
                          request->context()->http_user_agent_settings()),
        use_null_source_stream_(false) {}

  ~TestURLRequestHttpJob() override {}

  // URLRequestJob implementation:
  std::unique_ptr<SourceStream> SetUpSourceStream() override {
    if (use_null_source_stream_)
      return nullptr;
    return URLRequestHttpJob::SetUpSourceStream();
  }

  void set_use_null_source_stream(bool use_null_source_stream) {
    use_null_source_stream_ = use_null_source_stream;
  }

  using URLRequestHttpJob::SetPriority;
  using URLRequestHttpJob::Start;
  using URLRequestHttpJob::Kill;
  using URLRequestHttpJob::priority;

 private:
  bool use_null_source_stream_;

  DISALLOW_COPY_AND_ASSIGN(TestURLRequestHttpJob);
};

class URLRequestHttpJobSetUpSourceTest : public ::testing::Test {
 public:
  URLRequestHttpJobSetUpSourceTest() : context_(true) {
    test_job_interceptor_ = new TestJobInterceptor();
    EXPECT_TRUE(test_job_factory_.SetProtocolHandler(
        url::kHttpScheme, base::WrapUnique(test_job_interceptor_)));
    context_.set_job_factory(&test_job_factory_);
    context_.set_client_socket_factory(&socket_factory_);
    context_.Init();
  }

 protected:
  MockClientSocketFactory socket_factory_;
  // |test_job_interceptor_| is owned by |test_job_factory_|.
  TestJobInterceptor* test_job_interceptor_;
  URLRequestJobFactoryImpl test_job_factory_;

  TestURLRequestContext context_;
  TestDelegate delegate_;
};

// Tests that if SetUpSourceStream() returns nullptr, the request fails.
TEST_F(URLRequestHttpJobSetUpSourceTest, SetUpSourceFails) {
  MockWrite writes[] = {MockWrite(kSimpleGetMockWrite)};
  MockRead reads[] = {MockRead("HTTP/1.1 200 OK\r\n"
                               "Content-Length: 12\r\n\r\n"),
                      MockRead("Test Content")};

  StaticSocketDataProvider socket_data(reads, arraysize(reads), writes,
                                       arraysize(writes));
  socket_factory_.AddSocketDataProvider(&socket_data);

  std::unique_ptr<URLRequest> request = context_.CreateRequest(
      GURL("http://www.example.com"), DEFAULT_PRIORITY, &delegate_);
  std::unique_ptr<TestURLRequestHttpJob> job(
      new TestURLRequestHttpJob(request.get()));
  job->set_use_null_source_stream(true);
  test_job_interceptor_->set_main_intercept_job(std::move(job));
  request->Start();

  base::RunLoop().Run();
  EXPECT_EQ(ERR_CONTENT_DECODING_INIT_FAILED, delegate_.request_status());
}

// Tests that if there is an unknown content-encoding type, the raw response
// body is passed through.
TEST_F(URLRequestHttpJobSetUpSourceTest, UnknownEncoding) {
  MockWrite writes[] = {MockWrite(kSimpleGetMockWrite)};
  MockRead reads[] = {MockRead("HTTP/1.1 200 OK\r\n"
                               "Content-Encoding: foo, gzip\r\n"
                               "Content-Length: 12\r\n\r\n"),
                      MockRead("Test Content")};

  StaticSocketDataProvider socket_data(reads, arraysize(reads), writes,
                                       arraysize(writes));
  socket_factory_.AddSocketDataProvider(&socket_data);

  std::unique_ptr<URLRequest> request = context_.CreateRequest(
      GURL("http://www.example.com"), DEFAULT_PRIORITY, &delegate_);
  std::unique_ptr<TestURLRequestHttpJob> job(
      new TestURLRequestHttpJob(request.get()));
  test_job_interceptor_->set_main_intercept_job(std::move(job));
  request->Start();

  base::RunLoop().Run();
  EXPECT_EQ(OK, delegate_.request_status());
  EXPECT_EQ("Test Content", delegate_.data_received());
}

// Received a malformed SDCH encoded response when there is no SdchManager.
TEST_F(URLRequestHttpJobSetUpSourceTest, SdchNotAdvertisedGotSdchResponse) {
  MockWrite writes[] = {MockWrite(kSimpleGetMockWrite)};
  MockRead reads[] = {MockRead("HTTP/1.1 200 OK\r\n"
                               "Content-Encoding: sdch\r\n"
                               "Content-Length: 12\r\n\r\n"),
                      MockRead("Test Content")};

  StaticSocketDataProvider socket_data(reads, arraysize(reads), writes,
                                       arraysize(writes));
  socket_factory_.AddSocketDataProvider(&socket_data);

  // This test expects TestURLRequestContexts to have no SdchManager.
  DCHECK(!context_.sdch_manager());

  std::unique_ptr<URLRequest> request = context_.CreateRequest(
      GURL("http://www.example.com"), DEFAULT_PRIORITY, &delegate_);
  std::unique_ptr<TestURLRequestHttpJob> job(
      new TestURLRequestHttpJob(request.get()));
  test_job_interceptor_->set_main_intercept_job(std::move(job));
  request->Start();

  base::RunLoop().Run();
  // Pass through the raw response the same way as if received unknown encoding.
  EXPECT_EQ(OK, delegate_.request_status());
  EXPECT_EQ("Test Content", delegate_.data_received());
}

class URLRequestHttpJobTest : public ::testing::Test {
 protected:
  URLRequestHttpJobTest() : context_(true) {
    context_.set_http_transaction_factory(&network_layer_);

    // The |test_job_factory_| takes ownership of the interceptor.
    test_job_interceptor_ = new TestJobInterceptor();
    EXPECT_TRUE(test_job_factory_.SetProtocolHandler(
        url::kHttpScheme, base::WrapUnique(test_job_interceptor_)));
    context_.set_job_factory(&test_job_factory_);
    context_.set_net_log(&net_log_);
    context_.Init();

    req_ = context_.CreateRequest(GURL("http://www.example.com"),
                                  DEFAULT_PRIORITY, &delegate_);
  }

  bool TransactionAcceptsSdchEncoding() {
    base::WeakPtr<MockNetworkTransaction> transaction(
        network_layer_.last_transaction());
    EXPECT_TRUE(transaction);
    if (!transaction) return false;

    const HttpRequestInfo* request_info = transaction->request();
    EXPECT_TRUE(request_info);
    if (!request_info) return false;

    std::string encoding_headers;
    bool get_success = request_info->extra_headers.GetHeader(
        "Accept-Encoding", &encoding_headers);
    EXPECT_TRUE(get_success);
    if (!get_success) return false;

    // This check isn't wrapped with EXPECT* macros because different
    // results from this function may be expected in different tests.
    for (const std::string& token :
         base::SplitString(encoding_headers, ", ", base::KEEP_WHITESPACE,
                           base::SPLIT_WANT_NONEMPTY)) {
      if (base::EqualsCaseInsensitiveASCII(token, "sdch"))
        return true;
    }
    return false;
  }

  void EnableSdch() {
    context_.SetSdchManager(std::unique_ptr<SdchManager>(new SdchManager));
  }

  MockNetworkLayer network_layer_;

  // |test_job_interceptor_| is owned by |test_job_factory_|.
  TestJobInterceptor* test_job_interceptor_;
  URLRequestJobFactoryImpl test_job_factory_;

  TestURLRequestContext context_;
  TestDelegate delegate_;
  TestNetLog net_log_;
  std::unique_ptr<URLRequest> req_;
};

class URLRequestHttpJobWithMockSocketsTest : public ::testing::Test {
 protected:
  URLRequestHttpJobWithMockSocketsTest()
      : context_(new TestURLRequestContext(true)) {
    context_->set_client_socket_factory(&socket_factory_);
    context_->set_network_delegate(&network_delegate_);
    context_->Init();
  }

  MockClientSocketFactory socket_factory_;
  TestNetworkDelegate network_delegate_;
  std::unique_ptr<TestURLRequestContext> context_;
};

TEST_F(URLRequestHttpJobWithMockSocketsTest,
       TestContentLengthSuccessfulRequest) {
  MockWrite writes[] = {MockWrite(kSimpleGetMockWrite)};
  MockRead reads[] = {MockRead("HTTP/1.1 200 OK\r\n"
                               "Content-Length: 12\r\n\r\n"),
                      MockRead("Test Content")};

  StaticSocketDataProvider socket_data(reads, arraysize(reads), writes,
                                       arraysize(writes));
  socket_factory_.AddSocketDataProvider(&socket_data);

  TestDelegate delegate;
  std::unique_ptr<URLRequest> request = context_->CreateRequest(
      GURL("http://www.example.com"), DEFAULT_PRIORITY, &delegate);

  request->Start();
  ASSERT_TRUE(request->is_pending());
  base::RunLoop().Run();

  EXPECT_THAT(delegate.request_status(), IsOk());
  EXPECT_EQ(12, request->received_response_content_length());
  EXPECT_EQ(CountWriteBytes(writes, arraysize(writes)),
            request->GetTotalSentBytes());
  EXPECT_EQ(CountReadBytes(reads, arraysize(reads)),
            request->GetTotalReceivedBytes());
  EXPECT_EQ(CountWriteBytes(writes, arraysize(writes)),
            network_delegate_.total_network_bytes_sent());
  EXPECT_EQ(CountReadBytes(reads, arraysize(reads)),
            network_delegate_.total_network_bytes_received());
}

TEST_F(URLRequestHttpJobWithMockSocketsTest,
       TestContentLengthSuccessfulHttp09Request) {
  MockWrite writes[] = {MockWrite(kSimpleGetMockWrite)};
  MockRead reads[] = {MockRead("Test Content"),
                      MockRead(net::SYNCHRONOUS, net::OK)};

  StaticSocketDataProvider socket_data(reads, arraysize(reads), nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data);

  TestDelegate delegate;
  std::unique_ptr<URLRequest> request = context_->CreateRequest(
      GURL("http://www.example.com"), DEFAULT_PRIORITY, &delegate);

  request->Start();
  ASSERT_TRUE(request->is_pending());
  base::RunLoop().Run();

  EXPECT_THAT(delegate.request_status(), IsOk());
  EXPECT_EQ(12, request->received_response_content_length());
  EXPECT_EQ(CountWriteBytes(writes, arraysize(writes)),
            request->GetTotalSentBytes());
  EXPECT_EQ(CountReadBytes(reads, arraysize(reads)),
            request->GetTotalReceivedBytes());
  EXPECT_EQ(CountWriteBytes(writes, arraysize(writes)),
            network_delegate_.total_network_bytes_sent());
  EXPECT_EQ(CountReadBytes(reads, arraysize(reads)),
            network_delegate_.total_network_bytes_received());
}

TEST_F(URLRequestHttpJobWithMockSocketsTest, TestContentLengthFailedRequest) {
  MockWrite writes[] = {MockWrite(kSimpleGetMockWrite)};
  MockRead reads[] = {MockRead("HTTP/1.1 200 OK\r\n"
                               "Content-Length: 20\r\n\r\n"),
                      MockRead("Test Content"),
                      MockRead(net::SYNCHRONOUS, net::ERR_FAILED)};

  StaticSocketDataProvider socket_data(reads, arraysize(reads), writes,
                                       arraysize(writes));
  socket_factory_.AddSocketDataProvider(&socket_data);

  TestDelegate delegate;
  std::unique_ptr<URLRequest> request = context_->CreateRequest(
      GURL("http://www.example.com"), DEFAULT_PRIORITY, &delegate);

  request->Start();
  ASSERT_TRUE(request->is_pending());
  base::RunLoop().Run();

  EXPECT_THAT(delegate.request_status(), IsError(ERR_FAILED));
  EXPECT_EQ(12, request->received_response_content_length());
  EXPECT_EQ(CountWriteBytes(writes, arraysize(writes)),
            request->GetTotalSentBytes());
  EXPECT_EQ(CountReadBytes(reads, arraysize(reads)),
            request->GetTotalReceivedBytes());
  EXPECT_EQ(CountWriteBytes(writes, arraysize(writes)),
            network_delegate_.total_network_bytes_sent());
  EXPECT_EQ(CountReadBytes(reads, arraysize(reads)),
            network_delegate_.total_network_bytes_received());
}

TEST_F(URLRequestHttpJobWithMockSocketsTest,
       TestContentLengthCancelledRequest) {
  MockWrite writes[] = {MockWrite(kSimpleGetMockWrite)};
  MockRead reads[] = {MockRead("HTTP/1.1 200 OK\r\n"
                               "Content-Length: 20\r\n\r\n"),
                      MockRead("Test Content"),
                      MockRead(net::SYNCHRONOUS, net::ERR_IO_PENDING)};

  StaticSocketDataProvider socket_data(reads, arraysize(reads), writes,
                                       arraysize(writes));
  socket_factory_.AddSocketDataProvider(&socket_data);

  TestDelegate delegate;
  std::unique_ptr<URLRequest> request = context_->CreateRequest(
      GURL("http://www.example.com"), DEFAULT_PRIORITY, &delegate);

  delegate.set_cancel_in_received_data(true);
  request->Start();
  base::RunLoop().RunUntilIdle();

  EXPECT_THAT(delegate.request_status(), IsError(ERR_ABORTED));
  EXPECT_EQ(12, request->received_response_content_length());
  EXPECT_EQ(CountWriteBytes(writes, arraysize(writes)),
            request->GetTotalSentBytes());
  EXPECT_EQ(CountReadBytes(reads, arraysize(reads)),
            request->GetTotalReceivedBytes());
  EXPECT_EQ(CountWriteBytes(writes, arraysize(writes)),
            network_delegate_.total_network_bytes_sent());
  EXPECT_EQ(CountReadBytes(reads, arraysize(reads)),
            network_delegate_.total_network_bytes_received());
}

TEST_F(URLRequestHttpJobWithMockSocketsTest,
       TestRawHeaderSizeSuccessfullRequest) {
  MockWrite writes[] = {MockWrite(kSimpleGetMockWrite)};

  const std::string& response_header =
      "HTTP/1.1 200 OK\r\n"
      "Content-Length: 12\r\n\r\n";
  const std::string& content_data = "Test Content";

  MockRead reads[] = {MockRead(response_header.c_str()),
                      MockRead(content_data.c_str()),
                      MockRead(net::SYNCHRONOUS, net::OK)};

  StaticSocketDataProvider socket_data(reads, arraysize(reads), writes,
                                       arraysize(writes));
  socket_factory_.AddSocketDataProvider(&socket_data);

  TestDelegate delegate;
  std::unique_ptr<URLRequest> request = context_->CreateRequest(
      GURL("http://www.example.com"), DEFAULT_PRIORITY, &delegate);

  request->Start();
  ASSERT_TRUE(request->is_pending());
  base::RunLoop().Run();

  EXPECT_EQ(net::OK, request->status().error());
  EXPECT_EQ(static_cast<int>(content_data.size()),
            request->received_response_content_length());
  EXPECT_EQ(static_cast<int>(response_header.size()),
            request->raw_header_size());
  EXPECT_EQ(CountReadBytes(reads, arraysize(reads)),
            request->GetTotalReceivedBytes());
}

TEST_F(URLRequestHttpJobWithMockSocketsTest,
       TestRawHeaderSizeSuccessfull100ContinueRequest) {
  MockWrite writes[] = {MockWrite(kSimpleGetMockWrite)};

  const std::string& continue_header = "HTTP/1.1 100 Continue\r\n\r\n";
  const std::string& response_header =
      "HTTP/1.1 200 OK\r\n"
      "Content-Length: 12\r\n\r\n";
  const std::string& content_data = "Test Content";

  MockRead reads[] = {
      MockRead(continue_header.c_str()), MockRead(response_header.c_str()),
      MockRead(content_data.c_str()), MockRead(net::SYNCHRONOUS, net::OK)};

  StaticSocketDataProvider socket_data(reads, arraysize(reads), writes,
                                       arraysize(writes));
  socket_factory_.AddSocketDataProvider(&socket_data);

  TestDelegate delegate;
  std::unique_ptr<URLRequest> request = context_->CreateRequest(
      GURL("http://www.example.com"), DEFAULT_PRIORITY, &delegate);

  request->Start();
  ASSERT_TRUE(request->is_pending());
  base::RunLoop().Run();

  EXPECT_EQ(net::OK, request->status().error());
  EXPECT_EQ(static_cast<int>(content_data.size()),
            request->received_response_content_length());
  EXPECT_EQ(static_cast<int>(continue_header.size() + response_header.size()),
            request->raw_header_size());
  EXPECT_EQ(CountReadBytes(reads, arraysize(reads)),
            request->GetTotalReceivedBytes());
}

TEST_F(URLRequestHttpJobWithMockSocketsTest,
       TestRawHeaderSizeFailureTruncatedHeaders) {
  MockWrite writes[] = {MockWrite(kSimpleGetMockWrite)};
  MockRead reads[] = {MockRead("HTTP/1.0 200 OK\r\n"
                               "Content-Len"),
                      MockRead(net::SYNCHRONOUS, net::OK)};

  StaticSocketDataProvider socket_data(reads, arraysize(reads), writes,
                                       arraysize(writes));
  socket_factory_.AddSocketDataProvider(&socket_data);

  TestDelegate delegate;
  std::unique_ptr<URLRequest> request = context_->CreateRequest(
      GURL("http://www.example.com"), DEFAULT_PRIORITY, &delegate);

  delegate.set_cancel_in_response_started(true);
  request->Start();
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(ERR_ABORTED, request->status().error());
  EXPECT_EQ(0, request->received_response_content_length());
  EXPECT_EQ(28, request->raw_header_size());
  EXPECT_EQ(CountReadBytes(reads, arraysize(reads)),
            request->GetTotalReceivedBytes());
}

TEST_F(URLRequestHttpJobWithMockSocketsTest,
       TestRawHeaderSizeSuccessfullContinuiousRead) {
  MockWrite writes[] = {MockWrite(kSimpleGetMockWrite)};
  const std::string& header_data =
      "HTTP/1.1 200 OK\r\n"
      "Content-Length: 12\r\n\r\n";
  const std::string& content_data = "Test Content";
  std::string single_read_content = header_data;
  single_read_content.append(content_data);
  MockRead reads[] = {MockRead(single_read_content.c_str())};

  StaticSocketDataProvider socket_data(reads, arraysize(reads), writes,
                                       arraysize(writes));
  socket_factory_.AddSocketDataProvider(&socket_data);

  TestDelegate delegate;
  std::unique_ptr<URLRequest> request = context_->CreateRequest(
      GURL("http://www.example.com"), DEFAULT_PRIORITY, &delegate);

  request->Start();
  base::RunLoop().Run();

  EXPECT_EQ(net::OK, request->status().error());
  EXPECT_EQ(static_cast<int>(content_data.size()),
            request->received_response_content_length());
  EXPECT_EQ(static_cast<int>(header_data.size()), request->raw_header_size());
  EXPECT_EQ(CountReadBytes(reads, arraysize(reads)),
            request->GetTotalReceivedBytes());
}

TEST_F(URLRequestHttpJobWithMockSocketsTest,
       TestNetworkBytesRedirectedRequest) {
  MockWrite redirect_writes[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.redirect.com\r\n"
                "Connection: keep-alive\r\n"
                "User-Agent:\r\n"
                "Accept-Encoding: gzip, deflate\r\n"
                "Accept-Language: en-us,fr\r\n\r\n")};

  MockRead redirect_reads[] = {
      MockRead("HTTP/1.1 302 Found\r\n"
               "Location: http://www.example.com\r\n\r\n"),
  };
  StaticSocketDataProvider redirect_socket_data(
      redirect_reads, arraysize(redirect_reads), redirect_writes,
      arraysize(redirect_writes));
  socket_factory_.AddSocketDataProvider(&redirect_socket_data);

  MockWrite final_writes[] = {MockWrite(kSimpleGetMockWrite)};
  MockRead final_reads[] = {MockRead("HTTP/1.1 200 OK\r\n"
                                     "Content-Length: 12\r\n\r\n"),
                            MockRead("Test Content")};
  StaticSocketDataProvider final_socket_data(
      final_reads, arraysize(final_reads), final_writes,
      arraysize(final_writes));
  socket_factory_.AddSocketDataProvider(&final_socket_data);

  TestDelegate delegate;
  std::unique_ptr<URLRequest> request = context_->CreateRequest(
      GURL("http://www.redirect.com"), DEFAULT_PRIORITY, &delegate);

  request->Start();
  ASSERT_TRUE(request->is_pending());
  base::RunLoop().RunUntilIdle();

  EXPECT_THAT(delegate.request_status(), IsOk());
  EXPECT_EQ(12, request->received_response_content_length());
  // Should not include the redirect.
  EXPECT_EQ(CountWriteBytes(final_writes, arraysize(final_writes)),
            request->GetTotalSentBytes());
  EXPECT_EQ(CountReadBytes(final_reads, arraysize(final_reads)),
            request->GetTotalReceivedBytes());
  // Should include the redirect as well as the final response.
  EXPECT_EQ(CountWriteBytes(redirect_writes, arraysize(redirect_writes)) +
                CountWriteBytes(final_writes, arraysize(final_writes)),
            network_delegate_.total_network_bytes_sent());
  EXPECT_EQ(CountReadBytes(redirect_reads, arraysize(redirect_reads)) +
                CountReadBytes(final_reads, arraysize(final_reads)),
            network_delegate_.total_network_bytes_received());
}

TEST_F(URLRequestHttpJobWithMockSocketsTest,
       TestNetworkBytesCancelledAfterHeaders) {
  MockWrite writes[] = {MockWrite(kSimpleGetMockWrite)};
  MockRead reads[] = {MockRead("HTTP/1.1 200 OK\r\n\r\n")};
  StaticSocketDataProvider socket_data(reads, arraysize(reads), writes,
                                       arraysize(writes));
  socket_factory_.AddSocketDataProvider(&socket_data);

  TestDelegate delegate;
  std::unique_ptr<URLRequest> request = context_->CreateRequest(
      GURL("http://www.example.com"), DEFAULT_PRIORITY, &delegate);

  delegate.set_cancel_in_response_started(true);
  request->Start();
  base::RunLoop().RunUntilIdle();

  EXPECT_THAT(delegate.request_status(), IsError(ERR_ABORTED));
  EXPECT_EQ(0, request->received_response_content_length());
  EXPECT_EQ(CountWriteBytes(writes, arraysize(writes)),
            request->GetTotalSentBytes());
  EXPECT_EQ(CountReadBytes(reads, arraysize(reads)),
            request->GetTotalReceivedBytes());
  EXPECT_EQ(CountWriteBytes(writes, arraysize(writes)),
            network_delegate_.total_network_bytes_sent());
  EXPECT_EQ(CountReadBytes(reads, arraysize(reads)),
            network_delegate_.total_network_bytes_received());
}

TEST_F(URLRequestHttpJobWithMockSocketsTest,
       TestNetworkBytesCancelledImmediately) {
  StaticSocketDataProvider socket_data(nullptr, 0, nullptr, 0);
  socket_factory_.AddSocketDataProvider(&socket_data);

  TestDelegate delegate;
  std::unique_ptr<URLRequest> request = context_->CreateRequest(
      GURL("http://www.example.com"), DEFAULT_PRIORITY, &delegate);

  request->Start();
  request->Cancel();
  base::RunLoop().RunUntilIdle();

  EXPECT_THAT(delegate.request_status(), IsError(ERR_ABORTED));
  EXPECT_EQ(0, request->received_response_content_length());
  EXPECT_EQ(0, request->GetTotalSentBytes());
  EXPECT_EQ(0, request->GetTotalReceivedBytes());
  EXPECT_EQ(0, network_delegate_.total_network_bytes_received());
}

TEST_F(URLRequestHttpJobWithMockSocketsTest, TestHttpTimeToFirstByte) {
  base::HistogramTester histograms;
  MockWrite writes[] = {MockWrite(kSimpleGetMockWrite)};
  MockRead reads[] = {MockRead("HTTP/1.1 200 OK\r\n"
                               "Content-Length: 12\r\n\r\n"),
                      MockRead("Test Content")};

  StaticSocketDataProvider socket_data(reads, arraysize(reads), writes,
                                       arraysize(writes));
  socket_factory_.AddSocketDataProvider(&socket_data);

  TestDelegate delegate;
  std::unique_ptr<URLRequest> request = context_->CreateRequest(
      GURL("http://www.example.com"), DEFAULT_PRIORITY, &delegate);
  histograms.ExpectTotalCount("Net.HttpTimeToFirstByte", 0);

  request->Start();
  base::RunLoop().Run();

  EXPECT_THAT(delegate.request_status(), IsOk());
  histograms.ExpectTotalCount("Net.HttpTimeToFirstByte", 1);
}

TEST_F(URLRequestHttpJobWithMockSocketsTest,
       TestHttpTimeToFirstByteForCancelledTask) {
  base::HistogramTester histograms;
  MockWrite writes[] = {MockWrite(kSimpleGetMockWrite)};
  MockRead reads[] = {MockRead("HTTP/1.1 200 OK\r\n"
                               "Content-Length: 12\r\n\r\n"),
                      MockRead("Test Content")};

  StaticSocketDataProvider socket_data(reads, arraysize(reads), writes,
                                       arraysize(writes));
  socket_factory_.AddSocketDataProvider(&socket_data);

  TestDelegate delegate;
  std::unique_ptr<URLRequest> request = context_->CreateRequest(
      GURL("http://www.example.com"), DEFAULT_PRIORITY, &delegate);

  request->Start();
  request->Cancel();
  base::RunLoop().Run();

  EXPECT_THAT(delegate.request_status(), IsError(ERR_ABORTED));
  histograms.ExpectTotalCount("Net.HttpTimeToFirstByte", 0);
}

TEST_F(URLRequestHttpJobTest, TestCancelWhileReadingCookies) {
  DelayedCookieMonster cookie_monster;
  TestURLRequestContext context(true);
  context.set_cookie_store(&cookie_monster);
  context.Init();

  TestDelegate delegate;
  std::unique_ptr<URLRequest> request = context.CreateRequest(
      GURL("http://www.example.com"), DEFAULT_PRIORITY, &delegate);

  request->Start();
  request->Cancel();
  base::RunLoop().Run();

  EXPECT_THAT(delegate.request_status(), IsError(ERR_ABORTED));
}

// Make sure that SetPriority actually sets the URLRequestHttpJob's
// priority, before start.  Other tests handle the after start case.
TEST_F(URLRequestHttpJobTest, SetPriorityBasic) {
  std::unique_ptr<TestURLRequestHttpJob> job(
      new TestURLRequestHttpJob(req_.get()));
  EXPECT_EQ(DEFAULT_PRIORITY, job->priority());

  job->SetPriority(LOWEST);
  EXPECT_EQ(LOWEST, job->priority());

  job->SetPriority(LOW);
  EXPECT_EQ(LOW, job->priority());
}

// Make sure that URLRequestHttpJob passes on its priority to its
// transaction on start.
TEST_F(URLRequestHttpJobTest, SetTransactionPriorityOnStart) {
  test_job_interceptor_->set_main_intercept_job(
      base::WrapUnique(new TestURLRequestHttpJob(req_.get())));
  req_->SetPriority(LOW);

  EXPECT_FALSE(network_layer_.last_transaction());

  req_->Start();

  ASSERT_TRUE(network_layer_.last_transaction());
  EXPECT_EQ(LOW, network_layer_.last_transaction()->priority());
}

// Make sure that URLRequestHttpJob passes on its priority updates to
// its transaction.
TEST_F(URLRequestHttpJobTest, SetTransactionPriority) {
  test_job_interceptor_->set_main_intercept_job(
      base::WrapUnique(new TestURLRequestHttpJob(req_.get())));
  req_->SetPriority(LOW);
  req_->Start();
  ASSERT_TRUE(network_layer_.last_transaction());
  EXPECT_EQ(LOW, network_layer_.last_transaction()->priority());

  req_->SetPriority(HIGHEST);
  EXPECT_EQ(HIGHEST, network_layer_.last_transaction()->priority());
}

// Confirm we do advertise SDCH encoding in the case of a GET.
TEST_F(URLRequestHttpJobTest, SdchAdvertisementGet) {
  EnableSdch();
  req_->set_method("GET");  // Redundant with default.
  test_job_interceptor_->set_main_intercept_job(
      base::WrapUnique(new TestURLRequestHttpJob(req_.get())));
  req_->Start();
  EXPECT_TRUE(TransactionAcceptsSdchEncoding());
}

// Confirm we don't advertise SDCH encoding in the case of a POST.
TEST_F(URLRequestHttpJobTest, SdchAdvertisementPost) {
  EnableSdch();
  req_->set_method("POST");
  test_job_interceptor_->set_main_intercept_job(
      base::WrapUnique(new TestURLRequestHttpJob(req_.get())));
  req_->Start();
  EXPECT_FALSE(TransactionAcceptsSdchEncoding());
}

TEST_F(URLRequestHttpJobTest, HSTSInternalRedirectTest) {
  // Setup HSTS state.
  context_.transport_security_state()->AddHSTS(
      "upgrade.test", base::Time::Now() + base::TimeDelta::FromSeconds(10),
      true);
  ASSERT_TRUE(
      context_.transport_security_state()->ShouldUpgradeToSSL("upgrade.test"));
  ASSERT_FALSE(context_.transport_security_state()->ShouldUpgradeToSSL(
      "no-upgrade.test"));

  struct TestCase {
    const char* url;
    bool upgrade_expected;
    const char* url_expected;
  } cases[] = {
    {"http://upgrade.test/", true, "https://upgrade.test/"},
    {"http://upgrade.test:123/", true, "https://upgrade.test:123/"},
    {"http://no-upgrade.test/", false, "http://no-upgrade.test/"},
    {"http://no-upgrade.test:123/", false, "http://no-upgrade.test:123/"},
#if BUILDFLAG(ENABLE_WEBSOCKETS)
    {"ws://upgrade.test/", true, "wss://upgrade.test/"},
    {"ws://upgrade.test:123/", true, "wss://upgrade.test:123/"},
    {"ws://no-upgrade.test/", false, "ws://no-upgrade.test/"},
    {"ws://no-upgrade.test:123/", false, "ws://no-upgrade.test:123/"},
#endif  // BUILDFLAG(ENABLE_WEBSOCKETS)
  };

  for (const auto& test : cases) {
    SCOPED_TRACE(test.url);
    TestDelegate d;
    TestNetworkDelegate network_delegate;
    std::unique_ptr<URLRequest> r(
        context_.CreateRequest(GURL(test.url), DEFAULT_PRIORITY, &d));

    net_log_.Clear();
    r->Start();
    base::RunLoop().Run();

    if (test.upgrade_expected) {
      net::TestNetLogEntry::List entries;
      net_log_.GetEntries(&entries);
      int redirects = 0;
      for (const auto& entry : entries) {
        if (entry.type == net::NetLogEventType::URL_REQUEST_REDIRECT_JOB) {
          redirects++;
          std::string value;
          EXPECT_TRUE(entry.GetStringValue("reason", &value));
          EXPECT_EQ("HSTS", value);
        }
      }
      EXPECT_EQ(1, redirects);
      EXPECT_EQ(1, d.received_redirect_count());
      EXPECT_EQ(2u, r->url_chain().size());
    } else {
      EXPECT_EQ(0, d.received_redirect_count());
      EXPECT_EQ(1u, r->url_chain().size());
    }
    EXPECT_EQ(GURL(test.url_expected), r->url());
  }
}

class MockSdchObserver : public SdchObserver {
 public:
  MockSdchObserver() {}
  MOCK_METHOD2(OnDictionaryAdded,
               void(const GURL& request_url, const std::string& server_hash));
  MOCK_METHOD1(OnDictionaryRemoved, void(const std::string& server_hash));
  MOCK_METHOD1(OnDictionaryUsed, void(const std::string& server_hash));
  MOCK_METHOD2(OnGetDictionary,
               void(const GURL& request_url, const GURL& dictionary_url));
  MOCK_METHOD0(OnClearDictionaries, void());
};

class URLRequestHttpJobWithSdchSupportTest : public ::testing::Test {
 protected:
  URLRequestHttpJobWithSdchSupportTest() : context_(true) {
    std::unique_ptr<HttpNetworkSession::Params> params(
        new HttpNetworkSession::Params);
    context_.set_http_network_session_params(std::move(params));
    context_.set_client_socket_factory(&socket_factory_);
    context_.Init();
  }

  MockClientSocketFactory socket_factory_;
  TestURLRequestContext context_;
};

// Received a malformed SDCH encoded response that has no valid dictionary id.
TEST_F(URLRequestHttpJobWithSdchSupportTest,
       SdchAdvertisedGotMalformedSdchResponse) {
  MockWrite writes[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.com\r\n"
                "Connection: keep-alive\r\n"
                "User-Agent:\r\n"
                "Accept-Encoding: gzip, deflate, sdch\r\n"
                "Accept-Language: en-us,fr\r\n\r\n")};
  MockRead reads[] = {MockRead("HTTP/1.1 200 OK\r\n"
                               "Content-Encoding: sdch\r\n"
                               "Content-Length: 12\r\n\r\n"),
                      MockRead("Test Content")};

  StaticSocketDataProvider socket_data(reads, arraysize(reads), writes,
                                       arraysize(writes));
  socket_factory_.AddSocketDataProvider(&socket_data);

  MockSdchObserver sdch_observer;
  SdchManager sdch_manager;
  sdch_manager.AddObserver(&sdch_observer);
  context_.set_sdch_manager(&sdch_manager);
  TestDelegate delegate;
  std::unique_ptr<URLRequest> request = context_.CreateRequest(
      GURL("http://www.example.com"), DEFAULT_PRIORITY, &delegate);
  request->Start();

  base::RunLoop().Run();
  // SdchPolicyDelegate::OnDictionaryIdError() detects that the response is
  // malformed (missing dictionary), and will issue a pass-through of the raw
  // response.
  EXPECT_EQ(OK, delegate.request_status());
  EXPECT_EQ("Test Content", delegate.data_received());
  // Cleanup manager.
  sdch_manager.RemoveObserver(&sdch_observer);
}

TEST_F(URLRequestHttpJobWithSdchSupportTest, GetDictionary) {
  MockWrite writes[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: example.com\r\n"
                "Connection: keep-alive\r\n"
                "User-Agent:\r\n"
                "Accept-Encoding: gzip, deflate, sdch\r\n"
                "Accept-Language: en-us,fr\r\n\r\n")};

  MockRead reads[] = {MockRead("HTTP/1.1 200 OK\r\n"
                               "Get-Dictionary: /sdch.dict\r\n"
                               "Cache-Control: max-age=120\r\n"
                               "Content-Length: 12\r\n\r\n"),
                      MockRead("Test Content")};
  StaticSocketDataProvider socket_data(reads, arraysize(reads), writes,
                                       arraysize(writes));
  socket_factory_.AddSocketDataProvider(&socket_data);

  MockSdchObserver sdch_observer;
  SdchManager sdch_manager;
  sdch_manager.AddObserver(&sdch_observer);
  context_.set_sdch_manager(&sdch_manager);

  // First response will be "from network" and we should have OnGetDictionary
  // invoked.
  GURL url("http://example.com");
  EXPECT_CALL(sdch_observer,
              OnGetDictionary(url, GURL("http://example.com/sdch.dict")));
  TestDelegate delegate;
  std::unique_ptr<URLRequest> request =
      context_.CreateRequest(url, DEFAULT_PRIORITY, &delegate);
  request->Start();
  base::RunLoop().RunUntilIdle();

  EXPECT_THAT(delegate.request_status(), IsOk());

  // Second response should be from cache without notification of SdchObserver
  TestDelegate delegate2;
  std::unique_ptr<URLRequest> request2 =
      context_.CreateRequest(url, DEFAULT_PRIORITY, &delegate2);
  request2->Start();
  base::RunLoop().RunUntilIdle();

  EXPECT_THAT(delegate2.request_status(), IsOk());

  // Cleanup manager.
  sdch_manager.RemoveObserver(&sdch_observer);
}

class URLRequestHttpJobWithBrotliSupportTest : public ::testing::Test {
 protected:
  URLRequestHttpJobWithBrotliSupportTest()
      : context_(new TestURLRequestContext(true)) {
    std::unique_ptr<HttpNetworkSession::Params> params(
        new HttpNetworkSession::Params);
    context_->set_enable_brotli(true);
    context_->set_http_network_session_params(std::move(params));
    context_->set_client_socket_factory(&socket_factory_);
    context_->Init();
  }

  MockClientSocketFactory socket_factory_;
  std::unique_ptr<TestURLRequestContext> context_;
};

TEST_F(URLRequestHttpJobWithBrotliSupportTest, NoBrotliAdvertisementOverHttp) {
  MockWrite writes[] = {MockWrite(kSimpleGetMockWrite)};
  MockRead reads[] = {MockRead("HTTP/1.1 200 OK\r\n"
                               "Content-Length: 12\r\n\r\n"),
                      MockRead("Test Content")};
  StaticSocketDataProvider socket_data(reads, arraysize(reads), writes,
                                       arraysize(writes));
  socket_factory_.AddSocketDataProvider(&socket_data);

  TestDelegate delegate;
  std::unique_ptr<URLRequest> request = context_->CreateRequest(
      GURL("http://www.example.com"), DEFAULT_PRIORITY, &delegate);
  request->Start();
  base::RunLoop().RunUntilIdle();

  EXPECT_THAT(delegate.request_status(), IsOk());
  EXPECT_EQ(12, request->received_response_content_length());
  EXPECT_EQ(CountWriteBytes(writes, arraysize(writes)),
            request->GetTotalSentBytes());
  EXPECT_EQ(CountReadBytes(reads, arraysize(reads)),
            request->GetTotalReceivedBytes());
}

TEST_F(URLRequestHttpJobWithBrotliSupportTest, BrotliAdvertisement) {
  net::SSLSocketDataProvider ssl_socket_data_provider(net::ASYNC, net::OK);
  ssl_socket_data_provider.next_proto = kProtoHTTP11;
  ssl_socket_data_provider.cert =
      ImportCertFromFile(GetTestCertsDirectory(), "unittest.selfsigned.der");
  socket_factory_.AddSSLSocketDataProvider(&ssl_socket_data_provider);

  MockWrite writes[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.com\r\n"
                "Connection: keep-alive\r\n"
                "User-Agent:\r\n"
                "Accept-Encoding: gzip, deflate, br\r\n"
                "Accept-Language: en-us,fr\r\n\r\n")};
  MockRead reads[] = {MockRead("HTTP/1.1 200 OK\r\n"
                               "Content-Length: 12\r\n\r\n"),
                      MockRead("Test Content")};
  StaticSocketDataProvider socket_data(reads, arraysize(reads), writes,
                                       arraysize(writes));
  socket_factory_.AddSocketDataProvider(&socket_data);

  TestDelegate delegate;
  std::unique_ptr<URLRequest> request = context_->CreateRequest(
      GURL("https://www.example.com"), DEFAULT_PRIORITY, &delegate);
  request->Start();
  base::RunLoop().RunUntilIdle();

  EXPECT_THAT(delegate.request_status(), IsOk());
  EXPECT_EQ(12, request->received_response_content_length());
  EXPECT_EQ(CountWriteBytes(writes, arraysize(writes)),
            request->GetTotalSentBytes());
  EXPECT_EQ(CountReadBytes(reads, arraysize(reads)),
            request->GetTotalReceivedBytes());
}

#if defined(OS_ANDROID)
TEST_F(URLRequestHttpJobTest, AndroidCleartextPermittedTest) {
  context_.set_check_cleartext_permitted(true);

  struct TestCase {
    const char* url;
    bool cleartext_permitted;
    bool should_block;
  } cases[] = {
      {"http://blocked.test/", true, false},
      {"https://blocked.test/", true, false},
      {"http://blocked.test/", false, true},
      {"https://blocked.test/", false, false},
  };

  for (const TestCase& test : cases) {
    JNIEnv* env = base::android::AttachCurrentThread();
    Java_AndroidNetworkLibraryTestUtil_setUpSecurityPolicyForTesting(
        env, test.cleartext_permitted);

    TestDelegate delegate;
    std::unique_ptr<URLRequest> request =
        context_.CreateRequest(GURL(test.url), DEFAULT_PRIORITY, &delegate);
    request->Start();
    base::RunLoop().Run();

    int sdk_int = base::android::BuildInfo::GetInstance()->sdk_int();
    bool expect_blocked = (sdk_int >= base::android::SDK_VERSION_MARSHMALLOW &&
                           test.should_block);
    if (expect_blocked) {
      EXPECT_THAT(delegate.request_status(),
                  IsError(ERR_CLEARTEXT_NOT_PERMITTED));
    } else {
      // Should fail since there's no test server running
      EXPECT_THAT(delegate.request_status(), IsError(ERR_FAILED));
    }
  }
}
#endif

// This base class just serves to set up some things before the TestURLRequest
// constructor is called.
class URLRequestHttpJobWebSocketTestBase : public ::testing::Test {
 protected:
  URLRequestHttpJobWebSocketTestBase() : socket_data_(nullptr, 0, nullptr, 0),
                                         context_(true) {
    // A Network Delegate is required for the WebSocketHandshakeStreamBase
    // object to be passed on to the HttpNetworkTransaction.
    context_.set_network_delegate(&network_delegate_);

    // Attempting to create real ClientSocketHandles is not going to work out so
    // well. Set up a fake socket factory.
    socket_factory_.AddSocketDataProvider(&socket_data_);
    context_.set_client_socket_factory(&socket_factory_);
    context_.Init();
  }

  StaticSocketDataProvider socket_data_;
  TestNetworkDelegate network_delegate_;
  MockClientSocketFactory socket_factory_;
  TestURLRequestContext context_;
};

class URLRequestHttpJobWebSocketTest
    : public URLRequestHttpJobWebSocketTestBase {
 protected:
  URLRequestHttpJobWebSocketTest()
      : req_(context_.CreateRequest(GURL("ws://www.example.com"),
                                    DEFAULT_PRIORITY,
                                    &delegate_)) {
  }

  TestDelegate delegate_;
  std::unique_ptr<URLRequest> req_;
};

class MockCreateHelper : public WebSocketHandshakeStreamBase::CreateHelper {
 public:
  // GoogleMock does not appear to play nicely with move-only types like
  // std::unique_ptr, so this forwarding method acts as a workaround.
  WebSocketHandshakeStreamBase* CreateBasicStream(
      std::unique_ptr<ClientSocketHandle> connection,
      bool using_proxy) override {
    // Discard the arguments since we don't need them anyway.
    return CreateBasicStreamMock();
  }

  MOCK_METHOD0(CreateBasicStreamMock,
               WebSocketHandshakeStreamBase*());

  MOCK_METHOD2(CreateSpdyStream,
               WebSocketHandshakeStreamBase*(const base::WeakPtr<SpdySession>&,
                                             bool));
};

#if BUILDFLAG(ENABLE_WEBSOCKETS)

class FakeWebSocketHandshakeStream : public WebSocketHandshakeStreamBase {
 public:
  FakeWebSocketHandshakeStream() : initialize_stream_was_called_(false) {}

  bool initialize_stream_was_called() const {
    return initialize_stream_was_called_;
  }

  // Fake implementation of HttpStreamBase methods.
  int InitializeStream(const HttpRequestInfo* request_info,
                       RequestPriority priority,
                       const NetLogWithSource& net_log,
                       const CompletionCallback& callback) override {
    initialize_stream_was_called_ = true;
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

  // Fake implementation of WebSocketHandshakeStreamBase method(s)
  std::unique_ptr<WebSocketStream> Upgrade() override {
    return std::unique_ptr<WebSocketStream>();
  }

 private:
  bool initialize_stream_was_called_;
};

TEST_F(URLRequestHttpJobWebSocketTest, RejectedWithoutCreateHelper) {
  req_->Start();
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(delegate_.request_status(), IsError(ERR_DISALLOWED_URL_SCHEME));
}

TEST_F(URLRequestHttpJobWebSocketTest, CreateHelperPassedThrough) {
  std::unique_ptr<MockCreateHelper> create_helper(
      new ::testing::StrictMock<MockCreateHelper>());
  FakeWebSocketHandshakeStream* fake_handshake_stream(
      new FakeWebSocketHandshakeStream);
  // Ownership of fake_handshake_stream is transferred when CreateBasicStream()
  // is called.
  EXPECT_CALL(*create_helper, CreateBasicStreamMock())
      .WillOnce(Return(fake_handshake_stream));
  req_->SetUserData(WebSocketHandshakeStreamBase::CreateHelper::DataKey(),
                    create_helper.release());
  req_->SetLoadFlags(LOAD_DISABLE_CACHE);
  req_->Start();
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(delegate_.request_status(), IsError(ERR_IO_PENDING));
  EXPECT_TRUE(fake_handshake_stream->initialize_stream_was_called());
}

#endif  // BUILDFLAG(ENABLE_WEBSOCKETS)

}  // namespace

}  // namespace net
