// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// End-to-end tests for WebSocket.
//
// A python server is (re)started for each test, which is moderately
// inefficient. However, it makes these tests a good fit for scenarios which
// require special server configurations.

#include <stdint.h>

#include <memory>
#include <string>

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/callback.h"
#include "base/location.h"
#include "base/macros.h"
#include "base/memory/ptr_util.h"
#include "base/run_loop.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/string_piece.h"
#include "base/threading/thread_task_runner_handle.h"
#include "net/base/auth.h"
#include "net/base/proxy_delegate.h"
#include "net/proxy/proxy_service.h"
#include "net/test/embedded_test_server/embedded_test_server.h"
#include "net/test/spawned_test_server/spawned_test_server.h"
#include "net/test/test_data_directory.h"
#include "net/url_request/url_request_test_util.h"
#include "net/websockets/websocket_channel.h"
#include "net/websockets/websocket_event_interface.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/origin.h"

namespace net {

namespace {

static const char kEchoServer[] = "echo-with-no-extension";

// Simplify changing URL schemes.
GURL ReplaceUrlScheme(const GURL& in_url, const base::StringPiece& scheme) {
  GURL::Replacements replacements;
  replacements.SetSchemeStr(scheme);
  return in_url.ReplaceComponents(replacements);
}

// An implementation of WebSocketEventInterface that waits for and records the
// results of the connect.
class ConnectTestingEventInterface : public WebSocketEventInterface {
 public:
  ConnectTestingEventInterface();

  void WaitForResponse();

  bool failed() const { return failed_; }

  // Only set if the handshake failed, otherwise empty.
  std::string failure_message() const;

  std::string selected_subprotocol() const;

  std::string extensions() const;

  // Implementation of WebSocketEventInterface.
  ChannelState OnAddChannelResponse(const std::string& selected_subprotocol,
                                    const std::string& extensions) override;

  ChannelState OnDataFrame(bool fin,
                           WebSocketMessageType type,
                           const std::vector<char>& data) override;

  ChannelState OnFlowControl(int64_t quota) override;

  ChannelState OnClosingHandshake() override;

  ChannelState OnDropChannel(bool was_clean,
                             uint16_t code,
                             const std::string& reason) override;

  ChannelState OnFailChannel(const std::string& message) override;

  ChannelState OnStartOpeningHandshake(
      std::unique_ptr<WebSocketHandshakeRequestInfo> request) override;

  ChannelState OnFinishOpeningHandshake(
      std::unique_ptr<WebSocketHandshakeResponseInfo> response) override;

  ChannelState OnSSLCertificateError(
      std::unique_ptr<SSLErrorCallbacks> ssl_error_callbacks,
      const GURL& url,
      const SSLInfo& ssl_info,
      bool fatal) override;

 private:
  void QuitNestedEventLoop();

  // failed_ is true if the handshake failed (ie. OnFailChannel was called).
  bool failed_;
  std::string selected_subprotocol_;
  std::string extensions_;
  std::string failure_message_;
  base::RunLoop run_loop_;

  DISALLOW_COPY_AND_ASSIGN(ConnectTestingEventInterface);
};

ConnectTestingEventInterface::ConnectTestingEventInterface() : failed_(false) {
}

void ConnectTestingEventInterface::WaitForResponse() {
  run_loop_.Run();
}

std::string ConnectTestingEventInterface::failure_message() const {
  return failure_message_;
}

std::string ConnectTestingEventInterface::selected_subprotocol() const {
  return selected_subprotocol_;
}

std::string ConnectTestingEventInterface::extensions() const {
  return extensions_;
}

// Make the function definitions below less verbose.
typedef ConnectTestingEventInterface::ChannelState ChannelState;

ChannelState ConnectTestingEventInterface::OnAddChannelResponse(
    const std::string& selected_subprotocol,
    const std::string& extensions) {
  selected_subprotocol_ = selected_subprotocol;
  extensions_ = extensions;
  QuitNestedEventLoop();
  return CHANNEL_ALIVE;
}

ChannelState ConnectTestingEventInterface::OnDataFrame(
    bool fin,
    WebSocketMessageType type,
    const std::vector<char>& data) {
  return CHANNEL_ALIVE;
}

ChannelState ConnectTestingEventInterface::OnFlowControl(int64_t quota) {
  return CHANNEL_ALIVE;
}

ChannelState ConnectTestingEventInterface::OnClosingHandshake() {
  return CHANNEL_ALIVE;
}

ChannelState ConnectTestingEventInterface::OnDropChannel(
    bool was_clean,
    uint16_t code,
    const std::string& reason) {
  return CHANNEL_DELETED;
}

ChannelState ConnectTestingEventInterface::OnFailChannel(
    const std::string& message) {
  failed_ = true;
  failure_message_ = message;
  QuitNestedEventLoop();
  return CHANNEL_DELETED;
}

ChannelState ConnectTestingEventInterface::OnStartOpeningHandshake(
    std::unique_ptr<WebSocketHandshakeRequestInfo> request) {
  return CHANNEL_ALIVE;
}

ChannelState ConnectTestingEventInterface::OnFinishOpeningHandshake(
    std::unique_ptr<WebSocketHandshakeResponseInfo> response) {
  return CHANNEL_ALIVE;
}

ChannelState ConnectTestingEventInterface::OnSSLCertificateError(
    std::unique_ptr<SSLErrorCallbacks> ssl_error_callbacks,
    const GURL& url,
    const SSLInfo& ssl_info,
    bool fatal) {
  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE, base::Bind(&SSLErrorCallbacks::CancelSSLRequest,
                            base::Owned(ssl_error_callbacks.release()),
                            ERR_SSL_PROTOCOL_ERROR, &ssl_info));
  return CHANNEL_ALIVE;
}

void ConnectTestingEventInterface::QuitNestedEventLoop() {
  run_loop_.Quit();
}

// A subclass of TestNetworkDelegate that additionally implements the
// OnResolveProxy callback and records the information passed to it.
class TestProxyDelegateWithProxyInfo : public ProxyDelegate {
 public:
  TestProxyDelegateWithProxyInfo() {}

  struct ResolvedProxyInfo {
    GURL url;
    ProxyInfo proxy_info;
  };

  const ResolvedProxyInfo& resolved_proxy_info() const {
    return resolved_proxy_info_;
  }

 protected:
  void OnResolveProxy(const GURL& url,
                      const std::string& method,
                      const ProxyService& proxy_service,
                      ProxyInfo* result) override {
    resolved_proxy_info_.url = url;
    resolved_proxy_info_.proxy_info = *result;
  }

  void OnTunnelConnectCompleted(const HostPortPair& endpoint,
                                const HostPortPair& proxy_server,
                                int net_error) override {}
  void OnFallback(const ProxyServer& bad_proxy, int net_error) override {}
  void OnBeforeTunnelRequest(const HostPortPair& proxy_server,
                             HttpRequestHeaders* extra_headers) override {}
  void OnTunnelHeadersReceived(
      const HostPortPair& origin,
      const HostPortPair& proxy_server,
      const HttpResponseHeaders& response_headers) override {}
  bool IsTrustedSpdyProxy(const net::ProxyServer& proxy_server) override {
    return true;
  }
  void GetAlternativeProxy(
      const GURL& url,
      const ProxyServer& resolved_proxy_server,
      ProxyServer* alternative_proxy_server) const override {}
  void OnAlternativeProxyBroken(
      const ProxyServer& alternative_proxy_server) override {}

 private:
  ResolvedProxyInfo resolved_proxy_info_;

  DISALLOW_COPY_AND_ASSIGN(TestProxyDelegateWithProxyInfo);
};

class WebSocketEndToEndTest : public ::testing::Test {
 protected:
  WebSocketEndToEndTest()
      : event_interface_(),
        proxy_delegate_(new TestProxyDelegateWithProxyInfo),
        context_(true),
        channel_(),
        initialised_context_(false) {}

  // Initialise the URLRequestContext. Normally done automatically by
  // ConnectAndWait(). This method is for the use of tests that need the
  // URLRequestContext initialised before calling ConnectAndWait().
  void InitialiseContext() {
    context_.set_proxy_delegate(proxy_delegate_.get());
    context_.Init();
    initialised_context_ = true;
  }

  // Send the connect request to |socket_url| and wait for a response. Returns
  // true if the handshake succeeded.
  bool ConnectAndWait(const GURL& socket_url) {
    if (!initialised_context_) {
      InitialiseContext();
    }
    url::Origin origin(GURL("http://localhost"));
    GURL first_party_for_cookies("http://localhost/");
    event_interface_ = new ConnectTestingEventInterface;
    channel_.reset(
        new WebSocketChannel(base::WrapUnique(event_interface_), &context_));
    channel_->SendAddChannelRequest(GURL(socket_url), sub_protocols_, origin,
                                    first_party_for_cookies, "");
    event_interface_->WaitForResponse();
    return !event_interface_->failed();
  }

  ConnectTestingEventInterface* event_interface_;  // owned by channel_
  std::unique_ptr<TestProxyDelegateWithProxyInfo> proxy_delegate_;
  TestURLRequestContext context_;
  std::unique_ptr<WebSocketChannel> channel_;
  std::vector<std::string> sub_protocols_;
  bool initialised_context_;
};

// None of these tests work on Android.
// TODO(ricea): Make these tests work on Android. See crbug.com/441711.
#if defined(OS_ANDROID)
#define DISABLED_ON_ANDROID(test) DISABLED_##test
#else
#define DISABLED_ON_ANDROID(test) test
#endif

// Basic test of connectivity. If this test fails, nothing else can be expected
// to work.
TEST_F(WebSocketEndToEndTest, DISABLED_ON_ANDROID(BasicSmokeTest)) {
  SpawnedTestServer ws_server(SpawnedTestServer::TYPE_WS,
                              SpawnedTestServer::kLocalhost,
                              GetWebSocketTestDataDirectory());
  ASSERT_TRUE(ws_server.Start());
  EXPECT_TRUE(ConnectAndWait(ws_server.GetURL(kEchoServer)));
}

// Test for issue crbug.com/433695 "Unencrypted WebSocket connection via
// authenticated proxy times out"
// TODO(ricea): Enable this when the issue is fixed.
TEST_F(WebSocketEndToEndTest, DISABLED_HttpsProxyUnauthedFails) {
  SpawnedTestServer proxy_server(SpawnedTestServer::TYPE_BASIC_AUTH_PROXY,
                                 SpawnedTestServer::kLocalhost,
                                 base::FilePath());
  SpawnedTestServer ws_server(SpawnedTestServer::TYPE_WS,
                              SpawnedTestServer::kLocalhost,
                              GetWebSocketTestDataDirectory());
  ASSERT_TRUE(proxy_server.StartInBackground());
  ASSERT_TRUE(ws_server.StartInBackground());
  ASSERT_TRUE(proxy_server.BlockUntilStarted());
  ASSERT_TRUE(ws_server.BlockUntilStarted());
  std::string proxy_config =
      "https=" + proxy_server.host_port_pair().ToString();
  std::unique_ptr<ProxyService> proxy_service(
      ProxyService::CreateFixed(proxy_config));
  ASSERT_TRUE(proxy_service);
  context_.set_proxy_service(proxy_service.get());
  EXPECT_FALSE(ConnectAndWait(ws_server.GetURL(kEchoServer)));
  EXPECT_EQ("Proxy authentication failed", event_interface_->failure_message());
}

TEST_F(WebSocketEndToEndTest, DISABLED_ON_ANDROID(HttpsWssProxyUnauthedFails)) {
  SpawnedTestServer proxy_server(SpawnedTestServer::TYPE_BASIC_AUTH_PROXY,
                                 SpawnedTestServer::kLocalhost,
                                 base::FilePath());
  SpawnedTestServer wss_server(SpawnedTestServer::TYPE_WSS,
                               SpawnedTestServer::kLocalhost,
                               GetWebSocketTestDataDirectory());
  ASSERT_TRUE(proxy_server.StartInBackground());
  ASSERT_TRUE(wss_server.StartInBackground());
  ASSERT_TRUE(proxy_server.BlockUntilStarted());
  ASSERT_TRUE(wss_server.BlockUntilStarted());
  std::string proxy_config =
      "https=" + proxy_server.host_port_pair().ToString();
  std::unique_ptr<ProxyService> proxy_service(
      ProxyService::CreateFixed(proxy_config));
  ASSERT_TRUE(proxy_service);
  context_.set_proxy_service(proxy_service.get());
  EXPECT_FALSE(ConnectAndWait(wss_server.GetURL(kEchoServer)));
  EXPECT_EQ("Proxy authentication failed", event_interface_->failure_message());
}

// Regression test for crbug/426736 "WebSocket connections not using configured
// system HTTPS Proxy".
TEST_F(WebSocketEndToEndTest, DISABLED_ON_ANDROID(HttpsProxyUsed)) {
  SpawnedTestServer proxy_server(SpawnedTestServer::TYPE_BASIC_AUTH_PROXY,
                                 SpawnedTestServer::kLocalhost,
                                 base::FilePath());
  SpawnedTestServer ws_server(SpawnedTestServer::TYPE_WS,
                              SpawnedTestServer::kLocalhost,
                              GetWebSocketTestDataDirectory());
  ASSERT_TRUE(proxy_server.StartInBackground());
  ASSERT_TRUE(ws_server.StartInBackground());
  ASSERT_TRUE(proxy_server.BlockUntilStarted());
  ASSERT_TRUE(ws_server.BlockUntilStarted());
  std::string proxy_config = "https=" +
                             proxy_server.host_port_pair().ToString() + ";" +
                             "http=" + proxy_server.host_port_pair().ToString();
  std::unique_ptr<ProxyService> proxy_service(
      ProxyService::CreateFixed(proxy_config));
  context_.set_proxy_service(proxy_service.get());
  InitialiseContext();

  // The test server doesn't have an unauthenticated proxy mode. WebSockets
  // cannot provide auth information that isn't already cached, so it's
  // necessary to preflight an HTTP request to authenticate against the proxy.
  // It doesn't matter what the URL is, as long as it is an HTTP navigation.
  GURL http_page =
      ReplaceUrlScheme(ws_server.GetURL("connect_check.html"), "http");
  TestDelegate delegate;
  delegate.set_credentials(
      AuthCredentials(base::ASCIIToUTF16("foo"), base::ASCIIToUTF16("bar")));
  {
    std::unique_ptr<URLRequest> request(
        context_.CreateRequest(http_page, DEFAULT_PRIORITY, &delegate));
    request->Start();
    // TestDelegate exits the message loop when the request completes by
    // default.
    base::RunLoop().Run();
    EXPECT_TRUE(delegate.auth_required_called());
  }

  GURL ws_url = ws_server.GetURL(kEchoServer);
  EXPECT_TRUE(ConnectAndWait(ws_url));
  const TestProxyDelegateWithProxyInfo::ResolvedProxyInfo& info =
      proxy_delegate_->resolved_proxy_info();
  EXPECT_EQ(ws_url, info.url);
  EXPECT_TRUE(info.proxy_info.is_http());
}

// This is a regression test for crbug.com/408061 Crash in
// net::WebSocketBasicHandshakeStream::Upgrade.
TEST_F(WebSocketEndToEndTest, DISABLED_ON_ANDROID(TruncatedResponse)) {
  SpawnedTestServer ws_server(SpawnedTestServer::TYPE_WS,
                              SpawnedTestServer::kLocalhost,
                              GetWebSocketTestDataDirectory());
  ASSERT_TRUE(ws_server.Start());
  InitialiseContext();

  GURL ws_url = ws_server.GetURL("truncated-headers");
  EXPECT_FALSE(ConnectAndWait(ws_url));
}

// Regression test for crbug.com/455215 "HSTS not applied to WebSocket"
TEST_F(WebSocketEndToEndTest, DISABLED_ON_ANDROID(HstsHttpsToWebSocket)) {
  EmbeddedTestServer https_server(net::EmbeddedTestServer::Type::TYPE_HTTPS);
  https_server.SetSSLConfig(
      net::EmbeddedTestServer::CERT_COMMON_NAME_IS_DOMAIN);
  https_server.ServeFilesFromSourceDirectory("net/data/url_request_unittest");

  SpawnedTestServer::SSLOptions ssl_options(
      SpawnedTestServer::SSLOptions::CERT_COMMON_NAME_IS_DOMAIN);
  SpawnedTestServer wss_server(SpawnedTestServer::TYPE_WSS, ssl_options,
                               GetWebSocketTestDataDirectory());

  ASSERT_TRUE(https_server.Start());
  ASSERT_TRUE(wss_server.Start());
  InitialiseContext();
  // Set HSTS via https:
  TestDelegate delegate;
  GURL https_page = https_server.GetURL("/hsts-headers.html");
  std::unique_ptr<URLRequest> request(
      context_.CreateRequest(https_page, DEFAULT_PRIORITY, &delegate));
  request->Start();
  // TestDelegate exits the message loop when the request completes.
  base::RunLoop().Run();
  EXPECT_EQ(OK, delegate.request_status());

  // Check HSTS with ws:
  // Change the scheme from wss: to ws: to verify that it is switched back.
  GURL ws_url = ReplaceUrlScheme(wss_server.GetURL(kEchoServer), "ws");
  EXPECT_TRUE(ConnectAndWait(ws_url));
}

TEST_F(WebSocketEndToEndTest, DISABLED_ON_ANDROID(HstsWebSocketToHttps)) {
  EmbeddedTestServer https_server(net::EmbeddedTestServer::Type::TYPE_HTTPS);
  https_server.SetSSLConfig(
      net::EmbeddedTestServer::CERT_COMMON_NAME_IS_DOMAIN);
  https_server.ServeFilesFromSourceDirectory("net/data/url_request_unittest");

  SpawnedTestServer::SSLOptions ssl_options(
      SpawnedTestServer::SSLOptions::CERT_COMMON_NAME_IS_DOMAIN);
  SpawnedTestServer wss_server(SpawnedTestServer::TYPE_WSS, ssl_options,
                               GetWebSocketTestDataDirectory());
  ASSERT_TRUE(https_server.Start());
  ASSERT_TRUE(wss_server.Start());
  InitialiseContext();
  // Set HSTS via wss:
  GURL wss_url = wss_server.GetURL("set-hsts");
  EXPECT_TRUE(ConnectAndWait(wss_url));

  // Verify via http:
  TestDelegate delegate;
  GURL http_page =
      ReplaceUrlScheme(https_server.GetURL("/simple.html"), "http");
  std::unique_ptr<URLRequest> request(
      context_.CreateRequest(http_page, DEFAULT_PRIORITY, &delegate));
  request->Start();
  // TestDelegate exits the message loop when the request completes.
  base::RunLoop().Run();
  EXPECT_EQ(OK, delegate.request_status());
  EXPECT_TRUE(request->url().SchemeIs("https"));
}

TEST_F(WebSocketEndToEndTest, DISABLED_ON_ANDROID(HstsWebSocketToWebSocket)) {
  SpawnedTestServer::SSLOptions ssl_options(
      SpawnedTestServer::SSLOptions::CERT_COMMON_NAME_IS_DOMAIN);
  SpawnedTestServer wss_server(SpawnedTestServer::TYPE_WSS, ssl_options,
                               GetWebSocketTestDataDirectory());
  ASSERT_TRUE(wss_server.Start());
  InitialiseContext();
  // Set HSTS via wss:
  GURL wss_url = wss_server.GetURL("set-hsts");
  EXPECT_TRUE(ConnectAndWait(wss_url));

  // Verify via wss:
  GURL ws_url = ReplaceUrlScheme(wss_server.GetURL(kEchoServer), "ws");
  EXPECT_TRUE(ConnectAndWait(ws_url));
}

// Regression test for crbug.com/180504 "WebSocket handshake fails when HTTP
// headers have trailing LWS".
TEST_F(WebSocketEndToEndTest, DISABLED_ON_ANDROID(TrailingWhitespace)) {
  SpawnedTestServer ws_server(SpawnedTestServer::TYPE_WS,
                              SpawnedTestServer::kLocalhost,
                              GetWebSocketTestDataDirectory());
  ASSERT_TRUE(ws_server.Start());

  GURL ws_url = ws_server.GetURL("trailing-whitespace");
  sub_protocols_.push_back("sip");
  EXPECT_TRUE(ConnectAndWait(ws_url));
  EXPECT_EQ("sip", event_interface_->selected_subprotocol());
}

// This is a regression test for crbug.com/169448 "WebSockets should support
// header continuations"
// TODO(ricea): HTTP continuation headers have been deprecated by RFC7230.  If
// support for continuation headers is removed from Chrome, then this test will
// break and should be removed.
TEST_F(WebSocketEndToEndTest, DISABLED_ON_ANDROID(HeaderContinuations)) {
  SpawnedTestServer ws_server(SpawnedTestServer::TYPE_WS,
                              SpawnedTestServer::kLocalhost,
                              GetWebSocketTestDataDirectory());
  ASSERT_TRUE(ws_server.Start());

  GURL ws_url = ws_server.GetURL("header-continuation");

  EXPECT_TRUE(ConnectAndWait(ws_url));
  EXPECT_EQ("permessage-deflate; server_max_window_bits=10",
            event_interface_->extensions());
}

}  // namespace

}  // namespace net
