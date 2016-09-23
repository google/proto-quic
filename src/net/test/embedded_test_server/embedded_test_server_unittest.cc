// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/test/embedded_test_server/embedded_test_server.h"

#include <utility>

#include "base/macros.h"
#include "base/memory/ptr_util.h"
#include "base/memory/weak_ptr.h"
#include "base/path_service.h"
#include "base/run_loop.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/stringprintf.h"
#include "base/synchronization/lock.h"
#include "base/threading/thread.h"
#include "crypto/nss_util.h"
#include "net/base/test_completion_callback.h"
#include "net/http/http_response_headers.h"
#include "net/log/test_net_log.h"
#include "net/socket/client_socket_factory.h"
#include "net/socket/stream_socket.h"
#include "net/test/embedded_test_server/embedded_test_server_connection_listener.h"
#include "net/test/embedded_test_server/http_request.h"
#include "net/test/embedded_test_server/http_response.h"
#include "net/test/embedded_test_server/request_handler_util.h"
#include "net/test/gtest_util.h"
#include "net/url_request/url_fetcher.h"
#include "net/url_request/url_fetcher_delegate.h"
#include "net/url_request/url_request.h"
#include "net/url_request/url_request_test_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

#if defined(USE_NSS_CERTS)
#include "net/cert_net/nss_ocsp.h"
#endif

using net::test::IsOk;

namespace net {
namespace test_server {

namespace {

// Gets the content from the given URLFetcher.
std::string GetContentFromFetcher(const URLFetcher& fetcher) {
  std::string result;
  const bool success = fetcher.GetResponseAsString(&result);
  EXPECT_TRUE(success);
  return result;
}

// Gets the content type from the given URLFetcher.
std::string GetContentTypeFromFetcher(const URLFetcher& fetcher) {
  const HttpResponseHeaders* headers = fetcher.GetResponseHeaders();
  if (headers) {
    std::string content_type;
    if (headers->GetMimeType(&content_type))
      return content_type;
  }
  return std::string();
}

}  // namespace

// Gets notified by the EmbeddedTestServer on incoming connections being
// accepted, read from, or closed.
class TestConnectionListener
    : public net::test_server::EmbeddedTestServerConnectionListener {
 public:
  TestConnectionListener()
      : socket_accepted_count_(0),
        did_read_from_socket_(false),
        task_runner_(base::ThreadTaskRunnerHandle::Get()) {}

  ~TestConnectionListener() override {}

  // Get called from the EmbeddedTestServer thread to be notified that
  // a connection was accepted.
  void AcceptedSocket(const net::StreamSocket& connection) override {
    base::AutoLock lock(lock_);
    ++socket_accepted_count_;
    task_runner_->PostTask(FROM_HERE, accept_loop_.QuitClosure());
  }

  // Get called from the EmbeddedTestServer thread to be notified that
  // a connection was read from.
  void ReadFromSocket(const net::StreamSocket& connection, int rv) override {
    base::AutoLock lock(lock_);
    did_read_from_socket_ = true;
  }

  void WaitUntilFirstConnectionAccepted() { accept_loop_.Run(); }

  size_t SocketAcceptedCount() const {
    base::AutoLock lock(lock_);
    return socket_accepted_count_;
  }

  bool DidReadFromSocket() const {
    base::AutoLock lock(lock_);
    return did_read_from_socket_;
  }

 private:
  size_t socket_accepted_count_;
  bool did_read_from_socket_;

  base::RunLoop accept_loop_;
  scoped_refptr<base::SingleThreadTaskRunner> task_runner_;

  mutable base::Lock lock_;

  DISALLOW_COPY_AND_ASSIGN(TestConnectionListener);
};

class EmbeddedTestServerTest
    : public testing::TestWithParam<EmbeddedTestServer::Type>,
      public URLFetcherDelegate {
 public:
  EmbeddedTestServerTest()
      : num_responses_received_(0),
        num_responses_expected_(0),
        io_thread_("io_thread") {
  }

  void SetUp() override {
#if defined(USE_NSS_CERTS)
    // This is needed so NSS's HTTP client functions are initialized on the
    // right thread. These tests create SSLClientSockets on a different thread.
    // TODO(davidben): Initialization can't be deferred to SSLClientSocket. See
    // https://crbug.com/539520.
    crypto::EnsureNSSInit();
    EnsureNSSHttpIOInit();
#endif

    base::Thread::Options thread_options;
    thread_options.message_loop_type = base::MessageLoop::TYPE_IO;
    ASSERT_TRUE(io_thread_.StartWithOptions(thread_options));

    request_context_getter_ =
        new TestURLRequestContextGetter(io_thread_.task_runner());

    server_.reset(new EmbeddedTestServer(GetParam()));
    server_->SetConnectionListener(&connection_listener_);
  }

  void TearDown() override {
    if (server_->Started())
      ASSERT_TRUE(server_->ShutdownAndWaitUntilComplete());
#if defined(USE_NSS_CERTS)
    ShutdownNSSHttpIO();
#endif
  }

  // URLFetcherDelegate override.
  void OnURLFetchComplete(const URLFetcher* source) override {
    ++num_responses_received_;
    if (num_responses_received_ == num_responses_expected_)
      base::MessageLoop::current()->QuitWhenIdle();
  }

  // Waits until the specified number of responses are received.
  void WaitForResponses(int num_responses) {
    num_responses_received_ = 0;
    num_responses_expected_ = num_responses;
    // Will be terminated in OnURLFetchComplete().
    base::RunLoop().Run();
  }

  // Handles |request| sent to |path| and returns the response per |content|,
  // |content type|, and |code|. Saves the request URL for verification.
  std::unique_ptr<HttpResponse> HandleRequest(const std::string& path,
                                              const std::string& content,
                                              const std::string& content_type,
                                              HttpStatusCode code,
                                              const HttpRequest& request) {
    request_relative_url_ = request.relative_url;

    GURL absolute_url = server_->GetURL(request.relative_url);
    if (absolute_url.path() == path) {
      std::unique_ptr<BasicHttpResponse> http_response(new BasicHttpResponse);
      http_response->set_code(code);
      http_response->set_content(content);
      http_response->set_content_type(content_type);
      return std::move(http_response);
    }

    return nullptr;
  }

 protected:
  int num_responses_received_;
  int num_responses_expected_;
  std::string request_relative_url_;
  base::Thread io_thread_;
  scoped_refptr<TestURLRequestContextGetter> request_context_getter_;
  TestConnectionListener connection_listener_;
  std::unique_ptr<EmbeddedTestServer> server_;
};

TEST_P(EmbeddedTestServerTest, GetBaseURL) {
  ASSERT_TRUE(server_->Start());
  if (GetParam() == EmbeddedTestServer::TYPE_HTTPS) {
    EXPECT_EQ(base::StringPrintf("https://127.0.0.1:%u/", server_->port()),
              server_->base_url().spec());
  } else {
    EXPECT_EQ(base::StringPrintf("http://127.0.0.1:%u/", server_->port()),
              server_->base_url().spec());
  }
}

TEST_P(EmbeddedTestServerTest, GetURL) {
  ASSERT_TRUE(server_->Start());
  if (GetParam() == EmbeddedTestServer::TYPE_HTTPS) {
    EXPECT_EQ(base::StringPrintf("https://127.0.0.1:%u/path?query=foo",
                                 server_->port()),
              server_->GetURL("/path?query=foo").spec());
  } else {
    EXPECT_EQ(base::StringPrintf("http://127.0.0.1:%u/path?query=foo",
                                 server_->port()),
              server_->GetURL("/path?query=foo").spec());
  }
}

TEST_P(EmbeddedTestServerTest, GetURLWithHostname) {
  ASSERT_TRUE(server_->Start());
  if (GetParam() == EmbeddedTestServer::TYPE_HTTPS) {
    EXPECT_EQ(base::StringPrintf("https://foo.com:%d/path?query=foo",
                                 server_->port()),
              server_->GetURL("foo.com", "/path?query=foo").spec());
  } else {
    EXPECT_EQ(
        base::StringPrintf("http://foo.com:%d/path?query=foo", server_->port()),
        server_->GetURL("foo.com", "/path?query=foo").spec());
  }
}

TEST_P(EmbeddedTestServerTest, RegisterRequestHandler) {
  server_->RegisterRequestHandler(
      base::Bind(&EmbeddedTestServerTest::HandleRequest,
                 base::Unretained(this),
                 "/test",
                 "<b>Worked!</b>",
                 "text/html",
                 HTTP_OK));
  ASSERT_TRUE(server_->Start());

  std::unique_ptr<URLFetcher> fetcher =
      URLFetcher::Create(server_->GetURL("/test?q=foo"), URLFetcher::GET, this);
  fetcher->SetRequestContext(request_context_getter_.get());
  fetcher->Start();
  WaitForResponses(1);

  EXPECT_EQ(URLRequestStatus::SUCCESS, fetcher->GetStatus().status());
  EXPECT_EQ(HTTP_OK, fetcher->GetResponseCode());
  EXPECT_EQ("<b>Worked!</b>", GetContentFromFetcher(*fetcher));
  EXPECT_EQ("text/html", GetContentTypeFromFetcher(*fetcher));

  EXPECT_EQ("/test?q=foo", request_relative_url_);
}

TEST_P(EmbeddedTestServerTest, ServeFilesFromDirectory) {
  base::FilePath src_dir;
  ASSERT_TRUE(PathService::Get(base::DIR_SOURCE_ROOT, &src_dir));
  server_->ServeFilesFromDirectory(
      src_dir.AppendASCII("net").AppendASCII("data"));
  ASSERT_TRUE(server_->Start());

  std::unique_ptr<URLFetcher> fetcher =
      URLFetcher::Create(server_->GetURL("/test.html"), URLFetcher::GET, this);
  fetcher->SetRequestContext(request_context_getter_.get());
  fetcher->Start();
  WaitForResponses(1);

  EXPECT_EQ(URLRequestStatus::SUCCESS, fetcher->GetStatus().status());
  EXPECT_EQ(HTTP_OK, fetcher->GetResponseCode());
  EXPECT_EQ("<p>Hello World!</p>", GetContentFromFetcher(*fetcher));
  EXPECT_EQ("text/html", GetContentTypeFromFetcher(*fetcher));
}

TEST_P(EmbeddedTestServerTest, DefaultNotFoundResponse) {
  ASSERT_TRUE(server_->Start());

  std::unique_ptr<URLFetcher> fetcher = URLFetcher::Create(
      server_->GetURL("/non-existent"), URLFetcher::GET, this);
  fetcher->SetRequestContext(request_context_getter_.get());

  fetcher->Start();
  WaitForResponses(1);
  EXPECT_EQ(URLRequestStatus::SUCCESS, fetcher->GetStatus().status());
  EXPECT_EQ(HTTP_NOT_FOUND, fetcher->GetResponseCode());
}

TEST_P(EmbeddedTestServerTest, ConnectionListenerAccept) {
  ASSERT_TRUE(server_->Start());

  TestNetLog net_log;
  net::AddressList address_list;
  EXPECT_TRUE(server_->GetAddressList(&address_list));

  std::unique_ptr<StreamSocket> socket =
      ClientSocketFactory::GetDefaultFactory()->CreateTransportClientSocket(
          address_list, NULL, &net_log, NetLog::Source());
  TestCompletionCallback callback;
  ASSERT_THAT(callback.GetResult(socket->Connect(callback.callback())), IsOk());

  connection_listener_.WaitUntilFirstConnectionAccepted();

  EXPECT_EQ(1u, connection_listener_.SocketAcceptedCount());
  EXPECT_FALSE(connection_listener_.DidReadFromSocket());
}

TEST_P(EmbeddedTestServerTest, ConnectionListenerRead) {
  ASSERT_TRUE(server_->Start());

  std::unique_ptr<URLFetcher> fetcher = URLFetcher::Create(
      server_->GetURL("/non-existent"), URLFetcher::GET, this);
  fetcher->SetRequestContext(request_context_getter_.get());

  fetcher->Start();
  WaitForResponses(1);
  EXPECT_EQ(1u, connection_listener_.SocketAcceptedCount());
  EXPECT_TRUE(connection_listener_.DidReadFromSocket());
}

TEST_P(EmbeddedTestServerTest, ConcurrentFetches) {
  server_->RegisterRequestHandler(
      base::Bind(&EmbeddedTestServerTest::HandleRequest,
                 base::Unretained(this),
                 "/test1",
                 "Raspberry chocolate",
                 "text/html",
                 HTTP_OK));
  server_->RegisterRequestHandler(
      base::Bind(&EmbeddedTestServerTest::HandleRequest,
                 base::Unretained(this),
                 "/test2",
                 "Vanilla chocolate",
                 "text/html",
                 HTTP_OK));
  server_->RegisterRequestHandler(
      base::Bind(&EmbeddedTestServerTest::HandleRequest,
                 base::Unretained(this),
                 "/test3",
                 "No chocolates",
                 "text/plain",
                 HTTP_NOT_FOUND));
  ASSERT_TRUE(server_->Start());

  std::unique_ptr<URLFetcher> fetcher1 =
      URLFetcher::Create(server_->GetURL("/test1"), URLFetcher::GET, this);
  fetcher1->SetRequestContext(request_context_getter_.get());
  std::unique_ptr<URLFetcher> fetcher2 =
      URLFetcher::Create(server_->GetURL("/test2"), URLFetcher::GET, this);
  fetcher2->SetRequestContext(request_context_getter_.get());
  std::unique_ptr<URLFetcher> fetcher3 =
      URLFetcher::Create(server_->GetURL("/test3"), URLFetcher::GET, this);
  fetcher3->SetRequestContext(request_context_getter_.get());

  // Fetch the three URLs concurrently.
  fetcher1->Start();
  fetcher2->Start();
  fetcher3->Start();
  WaitForResponses(3);

  EXPECT_EQ(URLRequestStatus::SUCCESS, fetcher1->GetStatus().status());
  EXPECT_EQ(HTTP_OK, fetcher1->GetResponseCode());
  EXPECT_EQ("Raspberry chocolate", GetContentFromFetcher(*fetcher1));
  EXPECT_EQ("text/html", GetContentTypeFromFetcher(*fetcher1));

  EXPECT_EQ(URLRequestStatus::SUCCESS, fetcher2->GetStatus().status());
  EXPECT_EQ(HTTP_OK, fetcher2->GetResponseCode());
  EXPECT_EQ("Vanilla chocolate", GetContentFromFetcher(*fetcher2));
  EXPECT_EQ("text/html", GetContentTypeFromFetcher(*fetcher2));

  EXPECT_EQ(URLRequestStatus::SUCCESS, fetcher3->GetStatus().status());
  EXPECT_EQ(HTTP_NOT_FOUND, fetcher3->GetResponseCode());
  EXPECT_EQ("No chocolates", GetContentFromFetcher(*fetcher3));
  EXPECT_EQ("text/plain", GetContentTypeFromFetcher(*fetcher3));
}

namespace {

class CancelRequestDelegate : public TestDelegate {
 public:
  CancelRequestDelegate() {}
  ~CancelRequestDelegate() override {}

  void OnResponseStarted(URLRequest* request, int net_error) override {
    TestDelegate::OnResponseStarted(request, net_error);
    base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(
        FROM_HERE, run_loop_.QuitClosure(), base::TimeDelta::FromSeconds(1));
  }

  void WaitUntilDone() { run_loop_.Run(); }

 private:
  base::RunLoop run_loop_;

  DISALLOW_COPY_AND_ASSIGN(CancelRequestDelegate);
};

class InfiniteResponse : public BasicHttpResponse {
 public:
  InfiniteResponse() : weak_ptr_factory_(this) {}

  void SendResponse(const SendBytesCallback& send,
                    const SendCompleteCallback& done) override {
    send.Run(ToResponseString(),
             base::Bind(&InfiniteResponse::SendInfinite,
                        weak_ptr_factory_.GetWeakPtr(), send));
  }

 private:
  void SendInfinite(const SendBytesCallback& send) {
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE,
        base::Bind(send, "echo",
                   base::Bind(&InfiniteResponse::SendInfinite,
                              weak_ptr_factory_.GetWeakPtr(), send)));
  }

  base::WeakPtrFactory<InfiniteResponse> weak_ptr_factory_;

  DISALLOW_COPY_AND_ASSIGN(InfiniteResponse);
};

std::unique_ptr<HttpResponse> HandleInfiniteRequest(
    const HttpRequest& request) {
  return base::WrapUnique(new InfiniteResponse);
}
}

// Tests the case the connection is closed while the server is sending a
// response.  May non-deterministically end up at one of three paths
// (Discover the close event synchronously, asynchronously, or server
// shutting down before it is discovered).
TEST_P(EmbeddedTestServerTest, CloseDuringWrite) {
  CancelRequestDelegate cancel_delegate;
  TestURLRequestContext context;
  cancel_delegate.set_cancel_in_response_started(true);
  server_->RegisterRequestHandler(base::Bind(
      &HandlePrefixedRequest, "/infinite", base::Bind(&HandleInfiniteRequest)));
  ASSERT_TRUE(server_->Start());

  std::unique_ptr<URLRequest> request = context.CreateRequest(
      server_->GetURL("/infinite"), DEFAULT_PRIORITY, &cancel_delegate);
  request->Start();
  cancel_delegate.WaitUntilDone();
}

struct CertificateValuesEntry {
  const EmbeddedTestServer::ServerCertificate server_cert;
  const bool is_expired;
  const char* common_name;
  const char* root;
};

const CertificateValuesEntry kCertificateValuesEntry[] = {
    {EmbeddedTestServer::CERT_OK, false, "127.0.0.1", "Test Root CA"},
    {EmbeddedTestServer::CERT_MISMATCHED_NAME, false, "127.0.0.1",
     "Test Root CA"},
    {EmbeddedTestServer::CERT_COMMON_NAME_IS_DOMAIN, false, "localhost",
     "Test Root CA"},
    {EmbeddedTestServer::CERT_EXPIRED, true, "127.0.0.1", "Test Root CA"},
    {EmbeddedTestServer::CERT_CHAIN_WRONG_ROOT, false, "127.0.0.1", "B CA"},
#if !defined(OS_WIN)
    {EmbeddedTestServer::CERT_BAD_VALIDITY, true, "Leaf Certificate",
     "Test Root CA"},
#endif
};

TEST_P(EmbeddedTestServerTest, GetCertificate) {
  if (GetParam() != EmbeddedTestServer::TYPE_HTTPS)
    return;

  for (const auto& certEntry : kCertificateValuesEntry) {
    server_->SetSSLConfig(certEntry.server_cert);
    scoped_refptr<X509Certificate> cert = server_->GetCertificate();
    DCHECK(cert.get());
    EXPECT_EQ(cert->HasExpired(), certEntry.is_expired);
    EXPECT_EQ(cert->subject().common_name, certEntry.common_name);
    EXPECT_EQ(cert->issuer().common_name, certEntry.root);
  }
}

INSTANTIATE_TEST_CASE_P(EmbeddedTestServerTestInstantiation,
                        EmbeddedTestServerTest,
                        testing::Values(EmbeddedTestServer::TYPE_HTTP,
                                        EmbeddedTestServer::TYPE_HTTPS));

// Below test exercises EmbeddedTestServer's ability to cope with the situation
// where there is no MessageLoop available on the thread at EmbeddedTestServer
// initialization and/or destruction.

typedef std::tr1::tuple<bool, bool, EmbeddedTestServer::Type>
    ThreadingTestParams;

class EmbeddedTestServerThreadingTest
    : public testing::TestWithParam<ThreadingTestParams> {
  void SetUp() override {
#if defined(USE_NSS_CERTS)
    // This is needed so NSS's HTTP client functions are initialized on the
    // right thread. These tests create SSLClientSockets on a different thread.
    // TODO(davidben): Initialization can't be deferred to SSLClientSocket. See
    // https://crbug.com/539520.
    crypto::EnsureNSSInit();
    EnsureNSSHttpIOInit();
#endif
  }

  void TearDown() override {
#if defined(USE_NSS_CERTS)
    ShutdownNSSHttpIO();
#endif
  }
};

class EmbeddedTestServerThreadingTestDelegate
    : public base::PlatformThread::Delegate,
      public URLFetcherDelegate {
 public:
  EmbeddedTestServerThreadingTestDelegate(
      bool message_loop_present_on_initialize,
      bool message_loop_present_on_shutdown,
      EmbeddedTestServer::Type type)
      : message_loop_present_on_initialize_(message_loop_present_on_initialize),
        message_loop_present_on_shutdown_(message_loop_present_on_shutdown),
        type_(type) {}

  // base::PlatformThread::Delegate:
  void ThreadMain() override {
    scoped_refptr<base::SingleThreadTaskRunner> io_thread_runner;
    base::Thread io_thread("io_thread");
    base::Thread::Options thread_options;
    thread_options.message_loop_type = base::MessageLoop::TYPE_IO;
    ASSERT_TRUE(io_thread.StartWithOptions(thread_options));
    io_thread_runner = io_thread.task_runner();

    std::unique_ptr<base::MessageLoop> loop;
    if (message_loop_present_on_initialize_)
      loop.reset(new base::MessageLoopForIO);

    // Create the test server instance.
    EmbeddedTestServer server(type_);
    base::FilePath src_dir;
    ASSERT_TRUE(PathService::Get(base::DIR_SOURCE_ROOT, &src_dir));
    ASSERT_TRUE(server.Start());

    // Make a request and wait for the reply.
    if (!loop)
      loop.reset(new base::MessageLoopForIO);

    std::unique_ptr<URLFetcher> fetcher =
        URLFetcher::Create(server.GetURL("/test?q=foo"), URLFetcher::GET, this);
    fetcher->SetRequestContext(
        new TestURLRequestContextGetter(loop->task_runner()));
    fetcher->Start();
    base::RunLoop().Run();
    fetcher.reset();

    // Shut down.
    if (message_loop_present_on_shutdown_)
      loop.reset();

    ASSERT_TRUE(server.ShutdownAndWaitUntilComplete());
  }

  // URLFetcherDelegate override.
  void OnURLFetchComplete(const URLFetcher* source) override {
    base::MessageLoop::current()->QuitWhenIdle();
  }

 private:
  const bool message_loop_present_on_initialize_;
  const bool message_loop_present_on_shutdown_;
  const EmbeddedTestServer::Type type_;

  DISALLOW_COPY_AND_ASSIGN(EmbeddedTestServerThreadingTestDelegate);
};

TEST_P(EmbeddedTestServerThreadingTest, RunTest) {
  // The actual test runs on a separate thread so it can screw with the presence
  // of a MessageLoop - the test suite already sets up a MessageLoop for the
  // main test thread.
  base::PlatformThreadHandle thread_handle;
  EmbeddedTestServerThreadingTestDelegate delegate(
      std::tr1::get<0>(GetParam()), std::tr1::get<1>(GetParam()),
      std::tr1::get<2>(GetParam()));
  ASSERT_TRUE(base::PlatformThread::Create(0, &delegate, &thread_handle));
  base::PlatformThread::Join(thread_handle);
}

INSTANTIATE_TEST_CASE_P(
    EmbeddedTestServerThreadingTestInstantiation,
    EmbeddedTestServerThreadingTest,
    testing::Combine(testing::Bool(),
                     testing::Bool(),
                     testing::Values(EmbeddedTestServer::TYPE_HTTP,
                                     EmbeddedTestServer::TYPE_HTTPS)));

}  // namespace test_server
}  // namespace net
