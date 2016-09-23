// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert_net/cert_net_fetcher_impl.h"

#include <string>
#include <utility>

#include "base/compiler_specific.h"
#include "base/memory/ptr_util.h"
#include "base/run_loop.h"
#include "net/cert/ct_policy_enforcer.h"
#include "net/cert/mock_cert_verifier.h"
#include "net/cert/multi_log_ct_verifier.h"
#include "net/dns/mock_host_resolver.h"
#include "net/http/http_server_properties_impl.h"
#include "net/test/embedded_test_server/embedded_test_server.h"
#include "net/test/gtest_util.h"
#include "net/url_request/url_request_job_factory_impl.h"
#include "net/url_request/url_request_test_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "testing/platform_test.h"

using net::test::IsOk;

// TODO(eroman): Test that cookies aren't sent.

using base::ASCIIToUTF16;

namespace net {

namespace {

const base::FilePath::CharType kDocRoot[] =
    FILE_PATH_LITERAL("net/data/cert_net_fetcher_impl_unittest");

// A non-mock URLRequestContext which can access http:// urls.
class RequestContext : public URLRequestContext {
 public:
  RequestContext() : storage_(this) {
    ProxyConfig no_proxy;
    storage_.set_host_resolver(
        std::unique_ptr<HostResolver>(new MockHostResolver));
    storage_.set_cert_verifier(base::WrapUnique(new MockCertVerifier));
    storage_.set_transport_security_state(
        base::WrapUnique(new TransportSecurityState));
    storage_.set_cert_transparency_verifier(
        base::WrapUnique(new MultiLogCTVerifier));
    storage_.set_ct_policy_enforcer(base::WrapUnique(new CTPolicyEnforcer));
    storage_.set_proxy_service(ProxyService::CreateFixed(no_proxy));
    storage_.set_ssl_config_service(new SSLConfigServiceDefaults);
    storage_.set_http_server_properties(
        std::unique_ptr<HttpServerProperties>(new HttpServerPropertiesImpl()));

    HttpNetworkSession::Params params;
    params.host_resolver = host_resolver();
    params.cert_verifier = cert_verifier();
    params.transport_security_state = transport_security_state();
    params.cert_transparency_verifier = cert_transparency_verifier();
    params.ct_policy_enforcer = ct_policy_enforcer();
    params.proxy_service = proxy_service();
    params.ssl_config_service = ssl_config_service();
    params.http_server_properties = http_server_properties();
    storage_.set_http_network_session(
        base::MakeUnique<HttpNetworkSession>(params));
    storage_.set_http_transaction_factory(base::MakeUnique<HttpCache>(
        storage_.http_network_session(), HttpCache::DefaultBackend::InMemory(0),
        false /* set_up_quic_server_info */));
    storage_.set_job_factory(base::MakeUnique<URLRequestJobFactoryImpl>());
  }

  ~RequestContext() override { AssertNoURLRequests(); }

 private:
  URLRequestContextStorage storage_;
};

class FetchResult {
 public:
  FetchResult(Error net_error, const std::vector<uint8_t>& response_body)
      : net_error_(net_error), response_body_(response_body) {}

  void VerifySuccess(const std::string& expected_body) {
    EXPECT_THAT(net_error_, IsOk());
    EXPECT_EQ(expected_body,
              std::string(response_body_.begin(), response_body_.end()));
  }

  void VerifyFailure(Error expected_error) {
    EXPECT_EQ(expected_error, net_error_);
    EXPECT_EQ(0u, response_body_.size());
  }

 private:
  const Error net_error_;
  const std::vector<uint8_t> response_body_;
};

// Helper to synchronously wait for the fetch completion. This is similar to
// net's TestCompletionCallback, but built around FetchCallback.
class TestFetchCallback {
 public:
  TestFetchCallback()
      : callback_(base::Bind(&TestFetchCallback::OnCallback,
                             base::Unretained(this))) {}

  const CertNetFetcher::FetchCallback& callback() const { return callback_; }

  std::unique_ptr<FetchResult> WaitForResult() {
    DCHECK(quit_closure_.is_null());
    while (!HasResult()) {
      base::RunLoop run_loop;
      quit_closure_ = run_loop.QuitClosure();
      run_loop.Run();
      quit_closure_.Reset();
    }
    return std::move(result_);
  }

  bool HasResult() const { return result_.get(); }

  // Sets an extra action (in addition to recording the result) that is run when
  // the FetchCallback is invoked.
  void set_extra_closure(const base::Closure& closure) {
    extra_closure_ = closure;
  }

 private:
  void OnCallback(Error net_error, const std::vector<uint8_t>& response_body) {
    DCHECK(!HasResult());
    result_.reset(new FetchResult(net_error, response_body));

    if (!extra_closure_.is_null())
      extra_closure_.Run();

    if (!quit_closure_.is_null())
      quit_closure_.Run();
  }

  CertNetFetcher::FetchCallback callback_;
  std::unique_ptr<FetchResult> result_;
  base::Closure quit_closure_;
  base::Closure extra_closure_;
};

}  // namespace

class CertNetFetcherImplTest : public PlatformTest {
 public:
  CertNetFetcherImplTest() {
    test_server_.AddDefaultHandlers(base::FilePath(kDocRoot));
    context_.set_network_delegate(&network_delegate_);
  }

 protected:
  EmbeddedTestServer test_server_;
  TestNetworkDelegate network_delegate_;
  RequestContext context_;
};

// Helper to start an AIA fetch using default parameters.
WARN_UNUSED_RESULT std::unique_ptr<CertNetFetcher::Request> StartRequest(
    CertNetFetcher* fetcher,
    const GURL& url,
    const TestFetchCallback& callback) {
  return fetcher->FetchCaIssuers(url, CertNetFetcher::DEFAULT,
                                 CertNetFetcher::DEFAULT, callback.callback());
}

// Flaky on Android. See http://crbug.com/646147.
#if defined(OS_ANDROID)
#define MAYBE_ParallelFetchNoDuplicates DISABLED_ParallelFetchNoDuplicates
#else
#define MAYBE_ParallelFetchNoDuplicates ParallelFetchNoDuplicates
#endif
// Fetch a few unique URLs using GET in parallel. Each URL has a different body
// and Content-Type.
TEST_F(CertNetFetcherImplTest, MAYBE_ParallelFetchNoDuplicates) {
  ASSERT_TRUE(test_server_.Start());

  CertNetFetcherImpl fetcher(&context_);
  TestFetchCallback callback1;
  TestFetchCallback callback2;
  TestFetchCallback callback3;

  // Request a URL with Content-Type "application/pkix-cert"
  GURL url1 = test_server_.GetURL("/cert.crt");
  std::unique_ptr<CertNetFetcher::Request> request1 =
      StartRequest(&fetcher, url1, callback1);

  // Request a URL with Content-Type "application/pkix-crl"
  GURL url2 = test_server_.GetURL("/root.crl");
  std::unique_ptr<CertNetFetcher::Request> request2 =
      StartRequest(&fetcher, url2, callback2);

  // Request a URL with Content-Type "application/pkcs7-mime"
  GURL url3 = test_server_.GetURL("/certs.p7c");
  std::unique_ptr<CertNetFetcher::Request> request3 =
      StartRequest(&fetcher, url3, callback3);

  // Wait for all of the requests to complete.
  std::unique_ptr<FetchResult> result1 = callback1.WaitForResult();
  std::unique_ptr<FetchResult> result2 = callback2.WaitForResult();
  std::unique_ptr<FetchResult> result3 = callback3.WaitForResult();

  // Verify the fetch results.
  result1->VerifySuccess("-cert.crt-\n");
  result2->VerifySuccess("-root.crl-\n");
  result3->VerifySuccess("-certs.p7c-\n");

  EXPECT_EQ(3, network_delegate_.created_requests());
}

// Fetch a caIssuers URL which has an unexpected extension and Content-Type.
// The extension is .txt and the Content-Type is text/plain. Despite being
// unusual this succeeds as the extension and Content-Type are not required to
// be meaningful.
TEST_F(CertNetFetcherImplTest, ContentTypeDoesntMatter) {
  ASSERT_TRUE(test_server_.Start());

  CertNetFetcherImpl fetcher(&context_);

  TestFetchCallback callback;
  GURL url = test_server_.GetURL("/foo.txt");
  std::unique_ptr<CertNetFetcher::Request> request =
      StartRequest(&fetcher, url, callback);
  std::unique_ptr<FetchResult> result = callback.WaitForResult();
  result->VerifySuccess("-foo.txt-\n");
}

// Fetch a URLs whose HTTP response code is not 200. These are considered
// failures.
TEST_F(CertNetFetcherImplTest, HttpStatusCode) {
  ASSERT_TRUE(test_server_.Start());

  CertNetFetcherImpl fetcher(&context_);

  // Response was HTTP status 404.
  {
    TestFetchCallback callback;
    GURL url = test_server_.GetURL("/404.html");
    std::unique_ptr<CertNetFetcher::Request> request =
        StartRequest(&fetcher, url, callback);
    std::unique_ptr<FetchResult> result = callback.WaitForResult();
    result->VerifyFailure(ERR_FAILED);
  }

  // Response was HTTP status 500.
  {
    TestFetchCallback callback;
    GURL url = test_server_.GetURL("/500.html");
    std::unique_ptr<CertNetFetcher::Request> request =
        StartRequest(&fetcher, url, callback);
    std::unique_ptr<FetchResult> result = callback.WaitForResult();
    result->VerifyFailure(ERR_FAILED);
  }
}

// Fetching a URL with a Content-Disposition header should have no effect.
TEST_F(CertNetFetcherImplTest, ContentDisposition) {
  ASSERT_TRUE(test_server_.Start());

  CertNetFetcherImpl fetcher(&context_);

  TestFetchCallback callback;
  GURL url = test_server_.GetURL("/downloadable.js");
  std::unique_ptr<CertNetFetcher::Request> request =
      StartRequest(&fetcher, url, callback);
  std::unique_ptr<FetchResult> result = callback.WaitForResult();
  result->VerifySuccess("-downloadable.js-\n");
}

// Verifies that a cachable request will be served from the HTTP cache the
// second time it is requested.
TEST_F(CertNetFetcherImplTest, Cache) {
  ASSERT_TRUE(test_server_.Start());

  CertNetFetcherImpl fetcher(&context_);

  // Fetch a URL whose HTTP headers make it cacheable for 1 hour.
  GURL url(test_server_.GetURL("/cacheable_1hr.crt"));
  {
    TestFetchCallback callback;

    std::unique_ptr<CertNetFetcher::Request> request =
        StartRequest(&fetcher, url, callback);
    std::unique_ptr<FetchResult> result = callback.WaitForResult();
    result->VerifySuccess("-cacheable_1hr.crt-\n");
  }

  EXPECT_EQ(1, network_delegate_.created_requests());

  // Kill the HTTP server.
  ASSERT_TRUE(test_server_.ShutdownAndWaitUntilComplete());

  // Fetch again -- will fail unless served from cache.
  {
    TestFetchCallback callback;
    std::unique_ptr<CertNetFetcher::Request> request =
        StartRequest(&fetcher, url, callback);
    std::unique_ptr<FetchResult> result = callback.WaitForResult();
    result->VerifySuccess("-cacheable_1hr.crt-\n");
  }

  EXPECT_EQ(2, network_delegate_.created_requests());
}

// Verify that the maximum response body constraints are enforced by fetching a
// resource that is larger than the limit.
TEST_F(CertNetFetcherImplTest, TooLarge) {
  ASSERT_TRUE(test_server_.Start());

  CertNetFetcherImpl fetcher(&context_);

  // This file has a response body 12 bytes long. So setting the maximum to 11
  // bytes will cause it to fail.
  GURL url(test_server_.GetURL("/certs.p7c"));
  TestFetchCallback callback;
  std::unique_ptr<CertNetFetcher::Request> request = fetcher.FetchCaIssuers(
      url, CertNetFetcher::DEFAULT, 11, callback.callback());

  std::unique_ptr<FetchResult> result = callback.WaitForResult();
  result->VerifyFailure(ERR_FILE_TOO_BIG);
}

// Set the timeout to 10 milliseconds, and try fetching a URL that takes 5
// seconds to complete. It should fail due to a timeout.
TEST_F(CertNetFetcherImplTest, Hang) {
  ASSERT_TRUE(test_server_.Start());

  CertNetFetcherImpl fetcher(&context_);

  GURL url(test_server_.GetURL("/slow/certs.p7c?5"));
  TestFetchCallback callback;
  std::unique_ptr<CertNetFetcher::Request> request = fetcher.FetchCaIssuers(
      url, 10, CertNetFetcher::DEFAULT, callback.callback());
  std::unique_ptr<FetchResult> result = callback.WaitForResult();
  result->VerifyFailure(ERR_TIMED_OUT);
}

// Verify that if a response is gzip-encoded it gets inflated before being
// returned to the caller.
TEST_F(CertNetFetcherImplTest, Gzip) {
  ASSERT_TRUE(test_server_.Start());

  CertNetFetcherImpl fetcher(&context_);

  GURL url(test_server_.GetURL("/gzipped_crl"));
  TestFetchCallback callback;
  std::unique_ptr<CertNetFetcher::Request> request =
      StartRequest(&fetcher, url, callback);
  std::unique_ptr<FetchResult> result = callback.WaitForResult();
  result->VerifySuccess("-gzipped_crl-\n");
}

// Try fetching an unsupported URL scheme (https).
TEST_F(CertNetFetcherImplTest, HttpsNotAllowed) {
  ASSERT_TRUE(test_server_.Start());

  CertNetFetcherImpl fetcher(&context_);

  GURL url("https://foopy/foo.crt");
  TestFetchCallback callback;
  std::unique_ptr<CertNetFetcher::Request> request =
      StartRequest(&fetcher, url, callback);
  // Should NOT complete synchronously despite being a test that could be done
  // immediately.
  EXPECT_FALSE(callback.HasResult());
  std::unique_ptr<FetchResult> result = callback.WaitForResult();
  result->VerifyFailure(ERR_DISALLOWED_URL_SCHEME);

  // No request was created because the URL scheme was unsupported.
  EXPECT_EQ(0, network_delegate_.created_requests());
}

// Try fetching a URL which redirects to https.
TEST_F(CertNetFetcherImplTest, RedirectToHttpsNotAllowed) {
  ASSERT_TRUE(test_server_.Start());

  CertNetFetcherImpl fetcher(&context_);

  GURL url(test_server_.GetURL("/redirect_https"));
  TestFetchCallback callback;

  std::unique_ptr<CertNetFetcher::Request> request =
      StartRequest(&fetcher, url, callback);
  std::unique_ptr<FetchResult> result = callback.WaitForResult();
  result->VerifyFailure(ERR_DISALLOWED_URL_SCHEME);

  EXPECT_EQ(1, network_delegate_.created_requests());
}

// Try fetching an unsupported URL scheme (https) and then immediately
// cancelling. This is a bit special because this codepath needs to post a task.
TEST_F(CertNetFetcherImplTest, CancelHttpsNotAllowed) {
  ASSERT_TRUE(test_server_.Start());

  CertNetFetcherImpl fetcher(&context_);

  GURL url("https://foopy/foo.crt");
  TestFetchCallback callback;
  std::unique_ptr<CertNetFetcher::Request> request =
      StartRequest(&fetcher, url, callback);

  // Cancel the request.
  request.reset();

  // Spin the message loop to increase chance of catching a bug.
  base::RunLoop().RunUntilIdle();

  // Should NOT complete synchronously despite being a test that could be done
  // immediately.
  EXPECT_FALSE(callback.HasResult());

  EXPECT_EQ(0, network_delegate_.created_requests());
}

// Flaky on Android. See http://crbug.com/646147.
#if defined(OS_ANDROID)
#define MAYBE_CancelBeforeRunningMessageLoop \
  DISABLED_CancelBeforeRunningMessageLoop
#else
#define MAYBE_CancelBeforeRunningMessageLoop CancelBeforeRunningMessageLoop
#endif
// Start a few requests, and cancel one of them before running the message loop
// again.
TEST_F(CertNetFetcherImplTest, MAYBE_CancelBeforeRunningMessageLoop) {
  ASSERT_TRUE(test_server_.Start());

  CertNetFetcherImpl fetcher(&context_);
  TestFetchCallback callback1;
  TestFetchCallback callback2;
  TestFetchCallback callback3;

  GURL url1 = test_server_.GetURL("/cert.crt");
  std::unique_ptr<CertNetFetcher::Request> request1 =
      StartRequest(&fetcher, url1, callback1);

  GURL url2 = test_server_.GetURL("/root.crl");
  std::unique_ptr<CertNetFetcher::Request> request2 =
      StartRequest(&fetcher, url2, callback2);

  GURL url3 = test_server_.GetURL("/certs.p7c");

  std::unique_ptr<CertNetFetcher::Request> request3 =
      StartRequest(&fetcher, url3, callback3);

  EXPECT_EQ(3, network_delegate_.created_requests());
  EXPECT_FALSE(callback1.HasResult());
  EXPECT_FALSE(callback2.HasResult());
  EXPECT_FALSE(callback3.HasResult());

  // Cancel the second request.
  request2.reset();

  // Wait for the non-cancelled requests to complete.
  std::unique_ptr<FetchResult> result1 = callback1.WaitForResult();
  std::unique_ptr<FetchResult> result3 = callback3.WaitForResult();

  // Verify the fetch results.
  result1->VerifySuccess("-cert.crt-\n");
  result3->VerifySuccess("-certs.p7c-\n");

  EXPECT_FALSE(callback2.HasResult());
}

// Start several requests, and cancel one of them after the first has completed.
// NOTE: The python test server is single threaded and can only service one
// request at a time. After a socket is opened by the server it waits for it to
// be completed, and any subsequent request will hang until the first socket is
// closed.
// Cancelling the first request can therefore be problematic, since if
// cancellation is done after the socket is opened but before reading/writing,
// then the socket is re-cycled and things will be stalled until the cleanup
// timer (10 seconds) closes it.
// To work around this, the last request is cancelled, and hope that the
// requests are given opened sockets in a FIFO order.
// TODO(eroman): Make this more robust.
TEST_F(CertNetFetcherImplTest, CancelAfterRunningMessageLoop) {
  ASSERT_TRUE(test_server_.Start());

  CertNetFetcherImpl fetcher(&context_);
  TestFetchCallback callback1;
  TestFetchCallback callback2;
  TestFetchCallback callback3;

  GURL url1 = test_server_.GetURL("/cert.crt");

  std::unique_ptr<CertNetFetcher::Request> request1 =
      StartRequest(&fetcher, url1, callback1);

  GURL url2 = test_server_.GetURL("/certs.p7c");
  std::unique_ptr<CertNetFetcher::Request> request2 =
      StartRequest(&fetcher, url2, callback2);

  GURL url3("ftp://www.not.supported.com/foo");
  std::unique_ptr<CertNetFetcher::Request> request3 =
      StartRequest(&fetcher, url3, callback3);

  EXPECT_FALSE(callback1.HasResult());
  EXPECT_FALSE(callback2.HasResult());
  EXPECT_FALSE(callback3.HasResult());

  // Wait for the ftp request to complete (it should complete right away since
  // it doesn't even try to connect to the server).
  std::unique_ptr<FetchResult> result3 = callback3.WaitForResult();
  result3->VerifyFailure(ERR_DISALLOWED_URL_SCHEME);

  // Cancel the second outstanding request.
  request2.reset();

  // Wait for the first request to complete.
  std::unique_ptr<FetchResult> result2 = callback1.WaitForResult();

  // Verify the fetch results.
  result2->VerifySuccess("-cert.crt-\n");
}

// Delete a CertNetFetcherImpl with outstanding requests on it.
TEST_F(CertNetFetcherImplTest, DeleteCancels) {
  ASSERT_TRUE(test_server_.Start());

  std::unique_ptr<CertNetFetcherImpl> fetcher(
      new CertNetFetcherImpl(&context_));

  GURL url(test_server_.GetURL("/slow/certs.p7c?20"));
  TestFetchCallback callback;
  std::unique_ptr<CertNetFetcher::Request> request =
      StartRequest(fetcher.get(), url, callback);

  // Destroy the fetcher before the outstanding request.
  fetcher.reset();
}

// Flaky on Android. See http://crbug.com/646147.
#if defined(OS_ANDROID)
#define MAYBE_ParallelFetchDuplicates DISABLED_ParallelFetchDuplicates
#else
#define MAYBE_ParallelFetchDuplicates ParallelFetchDuplicates
#endif
// Fetch the same URLs in parallel and verify that only 1 request is made per
// URL.
TEST_F(CertNetFetcherImplTest, MAYBE_ParallelFetchDuplicates) {
  ASSERT_TRUE(test_server_.Start());

  CertNetFetcherImpl fetcher(&context_);

  GURL url1 = test_server_.GetURL("/cert.crt");
  GURL url2 = test_server_.GetURL("/root.crl");

  // Issue 3 requests for url1, and 3 requests for url2
  TestFetchCallback callback1;
  std::unique_ptr<CertNetFetcher::Request> request1 =
      StartRequest(&fetcher, url1, callback1);

  TestFetchCallback callback2;
  std::unique_ptr<CertNetFetcher::Request> request2 =
      StartRequest(&fetcher, url2, callback2);

  TestFetchCallback callback3;
  std::unique_ptr<CertNetFetcher::Request> request3 =
      StartRequest(&fetcher, url1, callback3);

  TestFetchCallback callback4;
  std::unique_ptr<CertNetFetcher::Request> request4 =
      StartRequest(&fetcher, url2, callback4);

  TestFetchCallback callback5;
  std::unique_ptr<CertNetFetcher::Request> request5 =
      StartRequest(&fetcher, url2, callback5);

  TestFetchCallback callback6;
  std::unique_ptr<CertNetFetcher::Request> request6 =
      StartRequest(&fetcher, url1, callback6);

  // Cancel all but one of the requests for url1.
  request1.reset();
  request3.reset();

  // Wait for the remaining requests to finish.
  std::unique_ptr<FetchResult> result2 = callback2.WaitForResult();
  std::unique_ptr<FetchResult> result4 = callback4.WaitForResult();
  std::unique_ptr<FetchResult> result5 = callback5.WaitForResult();
  std::unique_ptr<FetchResult> result6 = callback6.WaitForResult();

  // Verify that none of the cancelled requests for url1 completed (since they
  // were cancelled).
  EXPECT_FALSE(callback1.HasResult());
  EXPECT_FALSE(callback3.HasResult());

  // Verify the fetch results.
  result2->VerifySuccess("-root.crl-\n");
  result4->VerifySuccess("-root.crl-\n");
  result5->VerifySuccess("-root.crl-\n");
  result6->VerifySuccess("-cert.crt-\n");

  // Verify that only 2 URLRequests were started even though 6 requests were
  // issued.
  EXPECT_EQ(2, network_delegate_.created_requests());
}

// Flaky on Android. See http://crbug.com/646147.
#if defined(OS_ANDROID)
#define MAYBE_CancelThenStart DISABLED_CancelThenStart
#else
#define MAYBE_CancelThenStart CancelThenStart
#endif
// Cancel a request and then start another one for the same URL.
TEST_F(CertNetFetcherImplTest, MAYBE_CancelThenStart) {
  ASSERT_TRUE(test_server_.Start());

  CertNetFetcherImpl fetcher(&context_);
  TestFetchCallback callback1;
  TestFetchCallback callback2;
  TestFetchCallback callback3;

  GURL url = test_server_.GetURL("/cert.crt");

  std::unique_ptr<CertNetFetcher::Request> request1 =
      StartRequest(&fetcher, url, callback1);
  request1.reset();

  std::unique_ptr<CertNetFetcher::Request> request2 =
      StartRequest(&fetcher, url, callback2);

  std::unique_ptr<CertNetFetcher::Request> request3 =
      StartRequest(&fetcher, url, callback3);
  request3.reset();

  // All but |request2| were canceled.
  std::unique_ptr<FetchResult> result = callback2.WaitForResult();

  result->VerifySuccess("-cert.crt-\n");

  EXPECT_FALSE(callback1.HasResult());
  EXPECT_FALSE(callback3.HasResult());

  // One URLRequest that was cancelled, then another right afterwards.
  EXPECT_EQ(2, network_delegate_.created_requests());
}

// Start duplicate requests and then cancel all of them.
TEST_F(CertNetFetcherImplTest, CancelAll) {
  ASSERT_TRUE(test_server_.Start());

  CertNetFetcherImpl fetcher(&context_);
  TestFetchCallback callback[3];
  std::unique_ptr<CertNetFetcher::Request> request[3];

  GURL url = test_server_.GetURL("/cert.crt");

  for (size_t i = 0; i < arraysize(callback); ++i) {
    request[i] = StartRequest(&fetcher, url, callback[i]);
  }

  // Cancel all the requests.
  for (size_t i = 0; i < arraysize(request); ++i)
    request[i].reset();

  EXPECT_EQ(1, network_delegate_.created_requests());

  for (size_t i = 0; i < arraysize(request); ++i)
    EXPECT_FALSE(callback[i].HasResult());
}

void DeleteCertNetFetcher(CertNetFetcher* fetcher) {
  delete fetcher;
}

// Delete the CertNetFetcherImpl within a request callback.
TEST_F(CertNetFetcherImplTest, DeleteWithinCallback) {
  ASSERT_TRUE(test_server_.Start());

  // Deleted by callback2.
  CertNetFetcher* fetcher = new CertNetFetcherImpl(&context_);

  GURL url = test_server_.GetURL("/cert.crt");

  TestFetchCallback callback[4];
  std::unique_ptr<CertNetFetcher::Request> reqs[4];
  callback[1].set_extra_closure(base::Bind(DeleteCertNetFetcher, fetcher));

  for (size_t i = 0; i < arraysize(callback); ++i)
    reqs[i] = StartRequest(fetcher, url, callback[i]);

  EXPECT_EQ(1, network_delegate_.created_requests());

  callback[1].WaitForResult();

  // Assume requests for the same URL are executed in FIFO order.
  EXPECT_TRUE(callback[0].HasResult());
  EXPECT_FALSE(callback[2].HasResult());
  EXPECT_FALSE(callback[3].HasResult());
}

void FetchRequest(CertNetFetcher* fetcher,
                  const GURL& url,
                  TestFetchCallback* callback,
                  std::unique_ptr<CertNetFetcher::Request>* request) {
  *request = StartRequest(fetcher, url, *callback);
}

// Flaky on Android. See http://crbug.com/646147.
#if defined(OS_ANDROID)
#define MAYBE_FetchWithinCallback DISABLED_FetchWithinCallback
#else
#define MAYBE_FetchWithinCallback FetchWithinCallback
#endif
// Make a request during callback for the same URL.
TEST_F(CertNetFetcherImplTest, MAYBE_FetchWithinCallback) {
  ASSERT_TRUE(test_server_.Start());

  CertNetFetcherImpl fetcher(&context_);

  GURL url = test_server_.GetURL("/cert.crt");

  TestFetchCallback callback[5];
  std::unique_ptr<CertNetFetcher::Request> req[5];
  callback[1].set_extra_closure(
      base::Bind(FetchRequest, &fetcher, url, &callback[4], &req[4]));

  for (size_t i = 0; i < arraysize(callback) - 1; ++i)
    req[i] = StartRequest(&fetcher, url, callback[i]);

  EXPECT_EQ(1, network_delegate_.created_requests());

  for (size_t i = 0; i < arraysize(callback); ++i) {
    std::unique_ptr<FetchResult> result = callback[i].WaitForResult();
    result->VerifySuccess("-cert.crt-\n");
  }

  // The fetch started within a callback should have started a new request
  // rather than attaching to the current job.
  EXPECT_EQ(2, network_delegate_.created_requests());
}

void CancelRequest(std::unique_ptr<CertNetFetcher::Request>* request) {
  request->reset();
}

// Cancel a request while executing a callback for the same job.
TEST_F(CertNetFetcherImplTest, CancelWithinCallback) {
  ASSERT_TRUE(test_server_.Start());

  CertNetFetcherImpl fetcher(&context_);

  GURL url = test_server_.GetURL("/cert.crt");

  TestFetchCallback callback[4];
  std::unique_ptr<CertNetFetcher::Request> request[4];

  for (size_t i = 0; i < arraysize(callback); ++i)
    request[i] = StartRequest(&fetcher, url, callback[i]);

  // Cancel request[2] when the callback for request[1] runs.
  callback[1].set_extra_closure(base::Bind(CancelRequest, &request[2]));

  EXPECT_EQ(1, network_delegate_.created_requests());

  for (size_t i = 0; i < arraysize(request); ++i) {
    if (i == 2)
      continue;

    std::unique_ptr<FetchResult> result = callback[i].WaitForResult();
    result->VerifySuccess("-cert.crt-\n");
  }

  // request[2] was cancelled.
  EXPECT_FALSE(callback[2].HasResult());
}

// Flaky on Android. See http://crbug.com/646147.
#if defined(OS_ANDROID)
#define MAYBE_CancelLastRequestWithinCallback \
  DISABLED_CancelLastRequestWithinCallback
#else
#define MAYBE_CancelLastRequestWithinCallback CancelLastRequestWithinCallback
#endif
// Cancel the final request while executing a callback for the same job. Ensure
// that the job is not deleted twice.
TEST_F(CertNetFetcherImplTest, MAYBE_CancelLastRequestWithinCallback) {
  ASSERT_TRUE(test_server_.Start());

  CertNetFetcherImpl fetcher(&context_);

  GURL url = test_server_.GetURL("/cert.crt");

  TestFetchCallback callback1;
  std::unique_ptr<CertNetFetcher::Request> request1 =
      StartRequest(&fetcher, url, callback1);

  TestFetchCallback callback2;
  std::unique_ptr<CertNetFetcher::Request> request2 =
      StartRequest(&fetcher, url, callback1);

  // Cancel request2 when the callback for request1 runs.
  callback1.set_extra_closure(base::Bind(CancelRequest, &request2));

  EXPECT_EQ(1, network_delegate_.created_requests());

  std::unique_ptr<FetchResult> result = callback1.WaitForResult();
  result->VerifySuccess("-cert.crt-\n");

  // request2 was cancelled.
  EXPECT_FALSE(callback2.HasResult());
}

}  // namespace net
