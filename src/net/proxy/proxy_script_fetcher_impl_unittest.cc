// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/proxy/proxy_script_fetcher_impl.h"

#include <string>
#include <utility>

#include "base/compiler_specific.h"
#include "base/files/file_path.h"
#include "base/macros.h"
#include "base/memory/ptr_util.h"
#include "base/path_service.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/utf_string_conversions.h"
#include "base/threading/thread_task_runner_handle.h"
#include "net/base/filename_util.h"
#include "net/base/load_flags.h"
#include "net/base/network_delegate_impl.h"
#include "net/base/test_completion_callback.h"
#include "net/cert/ct_policy_enforcer.h"
#include "net/cert/mock_cert_verifier.h"
#include "net/cert/multi_log_ct_verifier.h"
#include "net/disk_cache/disk_cache.h"
#include "net/dns/mock_host_resolver.h"
#include "net/http/http_cache.h"
#include "net/http/http_network_session.h"
#include "net/http/http_server_properties_impl.h"
#include "net/http/transport_security_state.h"
#include "net/ssl/ssl_config_service_defaults.h"
#include "net/test/embedded_test_server/embedded_test_server.h"
#include "net/test/gtest_util.h"
#include "net/url_request/url_request_context_storage.h"
#include "net/url_request/url_request_file_job.h"
#include "net/url_request/url_request_job_factory_impl.h"
#include "net/url_request/url_request_test_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "testing/platform_test.h"

#if !defined(DISABLE_FILE_SUPPORT)
#include "net/url_request/file_protocol_handler.h"
#endif

using net::test::IsError;
using net::test::IsOk;

using base::ASCIIToUTF16;

// TODO(eroman):
//   - Test canceling an outstanding request.
//   - Test deleting ProxyScriptFetcher while a request is in progress.

namespace net {

namespace {

const base::FilePath::CharType kDocRoot[] =
    FILE_PATH_LITERAL("net/data/proxy_script_fetcher_unittest");

struct FetchResult {
  int code;
  base::string16 text;
};

// A non-mock URL request which can access http:// and file:// urls, in the case
// the tests were built with file support.
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
        false));
    std::unique_ptr<URLRequestJobFactoryImpl> job_factory =
        base::MakeUnique<URLRequestJobFactoryImpl>();
#if !defined(DISABLE_FILE_SUPPORT)
    job_factory->SetProtocolHandler("file",
                                    base::MakeUnique<FileProtocolHandler>(
                                        base::ThreadTaskRunnerHandle::Get()));
#endif
    storage_.set_job_factory(std::move(job_factory));
  }

  ~RequestContext() override { AssertNoURLRequests(); }

 private:
  URLRequestContextStorage storage_;
};

#if !defined(DISABLE_FILE_SUPPORT)
// Get a file:// url relative to net/data/proxy/proxy_script_fetcher_unittest.
GURL GetTestFileUrl(const std::string& relpath) {
  base::FilePath path;
  PathService::Get(base::DIR_SOURCE_ROOT, &path);
  path = path.AppendASCII("net");
  path = path.AppendASCII("data");
  path = path.AppendASCII("proxy_script_fetcher_unittest");
  GURL base_url = FilePathToFileURL(path);
  return GURL(base_url.spec() + "/" + relpath);
}
#endif  // !defined(DISABLE_FILE_SUPPORT)

// Really simple NetworkDelegate so we can allow local file access on ChromeOS
// without introducing layering violations.  Also causes a test failure if a
// request is seen that doesn't set a load flag to bypass revocation checking.

class BasicNetworkDelegate : public NetworkDelegateImpl {
 public:
  BasicNetworkDelegate() {}
  ~BasicNetworkDelegate() override {}

 private:
  int OnBeforeURLRequest(URLRequest* request,
                         const CompletionCallback& callback,
                         GURL* new_url) override {
    EXPECT_TRUE(request->load_flags() & LOAD_DISABLE_CERT_REVOCATION_CHECKING);
    return OK;
  }

  int OnBeforeStartTransaction(URLRequest* request,
                               const CompletionCallback& callback,
                               HttpRequestHeaders* headers) override {
    return OK;
  }

  void OnStartTransaction(URLRequest* request,
                          const HttpRequestHeaders& headers) override {}

  int OnHeadersReceived(
      URLRequest* request,
      const CompletionCallback& callback,
      const HttpResponseHeaders* original_response_headers,
      scoped_refptr<HttpResponseHeaders>* override_response_headers,
      GURL* allowed_unsafe_redirect_url) override {
    return OK;
  }

  void OnBeforeRedirect(URLRequest* request,
                        const GURL& new_location) override {}

  void OnResponseStarted(URLRequest* request, int net_error) override {}

  void OnCompleted(URLRequest* request, bool started, int net_error) override {}

  void OnURLRequestDestroyed(URLRequest* request) override {}

  void OnPACScriptError(int line_number, const base::string16& error) override {
  }

  NetworkDelegate::AuthRequiredResponse OnAuthRequired(
      URLRequest* request,
      const AuthChallengeInfo& auth_info,
      const AuthCallback& callback,
      AuthCredentials* credentials) override {
    return NetworkDelegate::AUTH_REQUIRED_RESPONSE_NO_ACTION;
  }

  bool OnCanGetCookies(const URLRequest& request,
                       const CookieList& cookie_list) override {
    return true;
  }

  bool OnCanSetCookie(const URLRequest& request,
                      const std::string& cookie_line,
                      CookieOptions* options) override {
    return true;
  }

  bool OnCanAccessFile(const URLRequest& request,
                       const base::FilePath& path) const override {
    return true;
  }

  DISALLOW_COPY_AND_ASSIGN(BasicNetworkDelegate);
};

class ProxyScriptFetcherImplTest : public PlatformTest {
 public:
  ProxyScriptFetcherImplTest() {
    test_server_.AddDefaultHandlers(base::FilePath(kDocRoot));
    context_.set_network_delegate(&network_delegate_);
  }

 protected:
  EmbeddedTestServer test_server_;
  BasicNetworkDelegate network_delegate_;
  RequestContext context_;
};

#if !defined(DISABLE_FILE_SUPPORT)
TEST_F(ProxyScriptFetcherImplTest, FileUrl) {
  ProxyScriptFetcherImpl pac_fetcher(&context_);

  { // Fetch a non-existent file.
    base::string16 text;
    TestCompletionCallback callback;
    int result = pac_fetcher.Fetch(GetTestFileUrl("does-not-exist"),
                                   &text, callback.callback());
    EXPECT_THAT(result, IsError(ERR_IO_PENDING));
    EXPECT_THAT(callback.WaitForResult(), IsError(ERR_FILE_NOT_FOUND));
    EXPECT_TRUE(text.empty());
  }
  { // Fetch a file that exists.
    base::string16 text;
    TestCompletionCallback callback;
    int result = pac_fetcher.Fetch(GetTestFileUrl("pac.txt"),
                                   &text, callback.callback());
    EXPECT_THAT(result, IsError(ERR_IO_PENDING));
    EXPECT_THAT(callback.WaitForResult(), IsOk());
    EXPECT_EQ(ASCIIToUTF16("-pac.txt-\n"), text);
  }
}
#endif  // !defined(DISABLE_FILE_SUPPORT)

// Note that all mime types are allowed for PAC file, to be consistent
// with other browsers.
TEST_F(ProxyScriptFetcherImplTest, HttpMimeType) {
  ASSERT_TRUE(test_server_.Start());

  ProxyScriptFetcherImpl pac_fetcher(&context_);

  { // Fetch a PAC with mime type "text/plain"
    GURL url(test_server_.GetURL("/pac.txt"));
    base::string16 text;
    TestCompletionCallback callback;
    int result = pac_fetcher.Fetch(url, &text, callback.callback());
    EXPECT_THAT(result, IsError(ERR_IO_PENDING));
    EXPECT_THAT(callback.WaitForResult(), IsOk());
    EXPECT_EQ(ASCIIToUTF16("-pac.txt-\n"), text);
  }
  { // Fetch a PAC with mime type "text/html"
    GURL url(test_server_.GetURL("/pac.html"));
    base::string16 text;
    TestCompletionCallback callback;
    int result = pac_fetcher.Fetch(url, &text, callback.callback());
    EXPECT_THAT(result, IsError(ERR_IO_PENDING));
    EXPECT_THAT(callback.WaitForResult(), IsOk());
    EXPECT_EQ(ASCIIToUTF16("-pac.html-\n"), text);
  }
  { // Fetch a PAC with mime type "application/x-ns-proxy-autoconfig"
    GURL url(test_server_.GetURL("/pac.nsproxy"));
    base::string16 text;
    TestCompletionCallback callback;
    int result = pac_fetcher.Fetch(url, &text, callback.callback());
    EXPECT_THAT(result, IsError(ERR_IO_PENDING));
    EXPECT_THAT(callback.WaitForResult(), IsOk());
    EXPECT_EQ(ASCIIToUTF16("-pac.nsproxy-\n"), text);
  }
}

TEST_F(ProxyScriptFetcherImplTest, HttpStatusCode) {
  ASSERT_TRUE(test_server_.Start());

  ProxyScriptFetcherImpl pac_fetcher(&context_);

  { // Fetch a PAC which gives a 500 -- FAIL
    GURL url(test_server_.GetURL("/500.pac"));
    base::string16 text;
    TestCompletionCallback callback;
    int result = pac_fetcher.Fetch(url, &text, callback.callback());
    EXPECT_THAT(result, IsError(ERR_IO_PENDING));
    EXPECT_THAT(callback.WaitForResult(), IsError(ERR_PAC_STATUS_NOT_OK));
    EXPECT_TRUE(text.empty());
  }
  { // Fetch a PAC which gives a 404 -- FAIL
    GURL url(test_server_.GetURL("/404.pac"));
    base::string16 text;
    TestCompletionCallback callback;
    int result = pac_fetcher.Fetch(url, &text, callback.callback());
    EXPECT_THAT(result, IsError(ERR_IO_PENDING));
    EXPECT_THAT(callback.WaitForResult(), IsError(ERR_PAC_STATUS_NOT_OK));
    EXPECT_TRUE(text.empty());
  }
}

TEST_F(ProxyScriptFetcherImplTest, ContentDisposition) {
  ASSERT_TRUE(test_server_.Start());

  ProxyScriptFetcherImpl pac_fetcher(&context_);

  // Fetch PAC scripts via HTTP with a Content-Disposition header -- should
  // have no effect.
  GURL url(test_server_.GetURL("/downloadable.pac"));
  base::string16 text;
  TestCompletionCallback callback;
  int result = pac_fetcher.Fetch(url, &text, callback.callback());
  EXPECT_THAT(result, IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(), IsOk());
  EXPECT_EQ(ASCIIToUTF16("-downloadable.pac-\n"), text);
}

// Verifies that PAC scripts are not being cached.
TEST_F(ProxyScriptFetcherImplTest, NoCache) {
  ASSERT_TRUE(test_server_.Start());

  ProxyScriptFetcherImpl pac_fetcher(&context_);

  // Fetch a PAC script whose HTTP headers make it cacheable for 1 hour.
  GURL url(test_server_.GetURL("/cacheable_1hr.pac"));
  {
    base::string16 text;
    TestCompletionCallback callback;
    int result = pac_fetcher.Fetch(url, &text, callback.callback());
    EXPECT_THAT(result, IsError(ERR_IO_PENDING));
    EXPECT_THAT(callback.WaitForResult(), IsOk());
    EXPECT_EQ(ASCIIToUTF16("-cacheable_1hr.pac-\n"), text);
  }

  // Kill the HTTP server.
  ASSERT_TRUE(test_server_.ShutdownAndWaitUntilComplete());

  // Try to fetch the file again. Since the server is not running anymore, the
  // call should fail, thus indicating that the file was not fetched from the
  // local cache.
  {
    base::string16 text;
    TestCompletionCallback callback;
    int result = pac_fetcher.Fetch(url, &text, callback.callback());
    EXPECT_THAT(result, IsError(ERR_IO_PENDING));

    // Expect any error. The exact error varies by platform.
    EXPECT_NE(OK, callback.WaitForResult());
  }
}

TEST_F(ProxyScriptFetcherImplTest, TooLarge) {
  ASSERT_TRUE(test_server_.Start());

  ProxyScriptFetcherImpl pac_fetcher(&context_);

  // Set the maximum response size to 50 bytes.
  int prev_size = pac_fetcher.SetSizeConstraint(50);

  // These two URLs are the same file, but are http:// vs file://
  GURL urls[] = {
    test_server_.GetURL("/large-pac.nsproxy"),
#if !defined(DISABLE_FILE_SUPPORT)
    GetTestFileUrl("large-pac.nsproxy")
#endif
  };

  // Try fetching URLs that are 101 bytes large. We should abort the request
  // after 50 bytes have been read, and fail with a too large error.
  for (size_t i = 0; i < arraysize(urls); ++i) {
    const GURL& url = urls[i];
    base::string16 text;
    TestCompletionCallback callback;
    int result = pac_fetcher.Fetch(url, &text, callback.callback());
    EXPECT_THAT(result, IsError(ERR_IO_PENDING));
    EXPECT_THAT(callback.WaitForResult(), IsError(ERR_FILE_TOO_BIG));
    EXPECT_TRUE(text.empty());
  }

  // Restore the original size bound.
  pac_fetcher.SetSizeConstraint(prev_size);

  { // Make sure we can still fetch regular URLs.
    GURL url(test_server_.GetURL("/pac.nsproxy"));
    base::string16 text;
    TestCompletionCallback callback;
    int result = pac_fetcher.Fetch(url, &text, callback.callback());
    EXPECT_THAT(result, IsError(ERR_IO_PENDING));
    EXPECT_THAT(callback.WaitForResult(), IsOk());
    EXPECT_EQ(ASCIIToUTF16("-pac.nsproxy-\n"), text);
  }
}

TEST_F(ProxyScriptFetcherImplTest, Hang) {
  ASSERT_TRUE(test_server_.Start());

  ProxyScriptFetcherImpl pac_fetcher(&context_);

  // Set the timeout period to 0.5 seconds.
  base::TimeDelta prev_timeout = pac_fetcher.SetTimeoutConstraint(
      base::TimeDelta::FromMilliseconds(500));

  // Try fetching a URL which takes 1.2 seconds. We should abort the request
  // after 500 ms, and fail with a timeout error.
  {
    GURL url(test_server_.GetURL("/slow/proxy.pac?1.2"));
    base::string16 text;
    TestCompletionCallback callback;
    int result = pac_fetcher.Fetch(url, &text, callback.callback());
    EXPECT_THAT(result, IsError(ERR_IO_PENDING));
    EXPECT_THAT(callback.WaitForResult(), IsError(ERR_TIMED_OUT));
    EXPECT_TRUE(text.empty());
  }

  // Restore the original timeout period.
  pac_fetcher.SetTimeoutConstraint(prev_timeout);

  { // Make sure we can still fetch regular URLs.
    GURL url(test_server_.GetURL("/pac.nsproxy"));
    base::string16 text;
    TestCompletionCallback callback;
    int result = pac_fetcher.Fetch(url, &text, callback.callback());
    EXPECT_THAT(result, IsError(ERR_IO_PENDING));
    EXPECT_THAT(callback.WaitForResult(), IsOk());
    EXPECT_EQ(ASCIIToUTF16("-pac.nsproxy-\n"), text);
  }
}

// The ProxyScriptFetcher should decode any content-codings
// (like gzip, bzip, etc.), and apply any charset conversions to yield
// UTF8.
TEST_F(ProxyScriptFetcherImplTest, Encodings) {
  ASSERT_TRUE(test_server_.Start());

  ProxyScriptFetcherImpl pac_fetcher(&context_);

  // Test a response that is gzip-encoded -- should get inflated.
  {
    GURL url(test_server_.GetURL("/gzipped_pac"));
    base::string16 text;
    TestCompletionCallback callback;
    int result = pac_fetcher.Fetch(url, &text, callback.callback());
    EXPECT_THAT(result, IsError(ERR_IO_PENDING));
    EXPECT_THAT(callback.WaitForResult(), IsOk());
    EXPECT_EQ(ASCIIToUTF16("This data was gzipped.\n"), text);
  }

  // Test a response that was served as UTF-16 (BE). It should
  // be converted to UTF8.
  {
    GURL url(test_server_.GetURL("/utf16be_pac"));
    base::string16 text;
    TestCompletionCallback callback;
    int result = pac_fetcher.Fetch(url, &text, callback.callback());
    EXPECT_THAT(result, IsError(ERR_IO_PENDING));
    EXPECT_THAT(callback.WaitForResult(), IsOk());
    EXPECT_EQ(ASCIIToUTF16("This was encoded as UTF-16BE.\n"), text);
  }
}

TEST_F(ProxyScriptFetcherImplTest, DataURLs) {
  ProxyScriptFetcherImpl pac_fetcher(&context_);

  const char kEncodedUrl[] =
      "data:application/x-ns-proxy-autoconfig;base64,ZnVuY3Rpb24gRmluZFByb3h5R"
      "m9yVVJMKHVybCwgaG9zdCkgewogIGlmIChob3N0ID09ICdmb29iYXIuY29tJykKICAgIHJl"
      "dHVybiAnUFJPWFkgYmxhY2tob2xlOjgwJzsKICByZXR1cm4gJ0RJUkVDVCc7Cn0=";
  const char kPacScript[] =
      "function FindProxyForURL(url, host) {\n"
      "  if (host == 'foobar.com')\n"
      "    return 'PROXY blackhole:80';\n"
      "  return 'DIRECT';\n"
      "}";

  // Test fetching a "data:"-url containing a base64 encoded PAC script.
  {
    GURL url(kEncodedUrl);
    base::string16 text;
    TestCompletionCallback callback;
    int result = pac_fetcher.Fetch(url, &text, callback.callback());
    EXPECT_THAT(result, IsOk());
    EXPECT_EQ(ASCIIToUTF16(kPacScript), text);
  }

  const char kEncodedUrlBroken[] =
      "data:application/x-ns-proxy-autoconfig;base64,ZnVuY3Rpb24gRmluZFByb3h5R";

  // Test a broken "data:"-url containing a base64 encoded PAC script.
  {
    GURL url(kEncodedUrlBroken);
    base::string16 text;
    TestCompletionCallback callback;
    int result = pac_fetcher.Fetch(url, &text, callback.callback());
    EXPECT_THAT(result, IsError(ERR_FAILED));
  }
}

}  // namespace

}  // namespace net
