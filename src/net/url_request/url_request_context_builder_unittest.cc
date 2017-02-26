// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/url_request/url_request_context_builder.h"

#include <memory>

#include "base/memory/ptr_util.h"
#include "base/message_loop/message_loop.h"
#include "base/run_loop.h"
#include "base/test/scoped_task_scheduler.h"
#include "build/build_config.h"
#include "net/base/request_priority.h"
#include "net/http/http_auth_challenge_tokenizer.h"
#include "net/http/http_auth_handler.h"
#include "net/http/http_auth_handler_factory.h"
#include "net/log/net_log_with_source.h"
#include "net/ssl/ssl_info.h"
#include "net/test/embedded_test_server/embedded_test_server.h"
#include "net/url_request/url_request.h"
#include "net/url_request/url_request_test_util.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "testing/platform_test.h"

#if defined(OS_LINUX) || defined(OS_ANDROID)
#include "net/proxy/proxy_config.h"
#include "net/proxy/proxy_config_service_fixed.h"
#endif  // defined(OS_LINUX) || defined(OS_ANDROID)

namespace net {

namespace {

class MockHttpAuthHandlerFactory : public HttpAuthHandlerFactory {
 public:
  MockHttpAuthHandlerFactory(std::string supported_scheme, int return_code)
      : return_code_(return_code), supported_scheme_(supported_scheme) {}
  ~MockHttpAuthHandlerFactory() override {}

  int CreateAuthHandler(HttpAuthChallengeTokenizer* challenge,
                        HttpAuth::Target target,
                        const SSLInfo& ssl_info,
                        const GURL& origin,
                        CreateReason reason,
                        int nonce_count,
                        const NetLogWithSource& net_log,
                        std::unique_ptr<HttpAuthHandler>* handler) override {
    handler->reset();

    return challenge->scheme() == supported_scheme_
               ? return_code_
               : ERR_UNSUPPORTED_AUTH_SCHEME;
  }

 private:
  int return_code_;
  std::string supported_scheme_;
};

class URLRequestContextBuilderTest : public PlatformTest {
 protected:
  URLRequestContextBuilderTest()
      : scoped_task_scheduler_(base::MessageLoop::current()) {
    test_server_.AddDefaultHandlers(
        base::FilePath(FILE_PATH_LITERAL("net/data/url_request_unittest")));
#if defined(OS_LINUX) || defined(OS_ANDROID)
    builder_.set_proxy_config_service(
        base::MakeUnique<ProxyConfigServiceFixed>(ProxyConfig::CreateDirect()));
#endif  // defined(OS_LINUX) || defined(OS_ANDROID)
  }

  EmbeddedTestServer test_server_;
  URLRequestContextBuilder builder_;

 private:
  base::test::ScopedTaskScheduler scoped_task_scheduler_;
};

TEST_F(URLRequestContextBuilderTest, DefaultSettings) {
  ASSERT_TRUE(test_server_.Start());

  std::unique_ptr<URLRequestContext> context(builder_.Build());
  TestDelegate delegate;
  std::unique_ptr<URLRequest> request(context->CreateRequest(
      test_server_.GetURL("/echoheader?Foo"), DEFAULT_PRIORITY, &delegate));
  request->set_method("GET");
  request->SetExtraRequestHeaderByName("Foo", "Bar", false);
  request->Start();
  base::RunLoop().Run();
  EXPECT_EQ("Bar", delegate.data_received());
}

TEST_F(URLRequestContextBuilderTest, UserAgent) {
  ASSERT_TRUE(test_server_.Start());

  builder_.set_user_agent("Bar");
  std::unique_ptr<URLRequestContext> context(builder_.Build());
  TestDelegate delegate;
  std::unique_ptr<URLRequest> request(
      context->CreateRequest(test_server_.GetURL("/echoheader?User-Agent"),
                             DEFAULT_PRIORITY, &delegate));
  request->set_method("GET");
  request->Start();
  base::RunLoop().Run();
  EXPECT_EQ("Bar", delegate.data_received());
}

TEST_F(URLRequestContextBuilderTest, DefaultHttpAuthHandlerFactory) {
  GURL gurl("www.google.com");
  std::unique_ptr<HttpAuthHandler> handler;
  std::unique_ptr<URLRequestContext> context(builder_.Build());
  SSLInfo null_ssl_info;

  // Verify that the default basic handler is present
  EXPECT_EQ(OK,
            context->http_auth_handler_factory()->CreateAuthHandlerFromString(
                "basic", HttpAuth::AUTH_SERVER, null_ssl_info, gurl,
                NetLogWithSource(), &handler));
}

TEST_F(URLRequestContextBuilderTest, CustomHttpAuthHandlerFactory) {
  GURL gurl("www.google.com");
  const int kBasicReturnCode = OK;
  std::unique_ptr<HttpAuthHandler> handler;
  builder_.SetHttpAuthHandlerFactory(
      base::MakeUnique<MockHttpAuthHandlerFactory>("ExtraScheme",
                                                   kBasicReturnCode));
  std::unique_ptr<URLRequestContext> context(builder_.Build());
  SSLInfo null_ssl_info;
  // Verify that a handler is returned for a custom scheme.
  EXPECT_EQ(kBasicReturnCode,
            context->http_auth_handler_factory()->CreateAuthHandlerFromString(
                "ExtraScheme", HttpAuth::AUTH_SERVER, null_ssl_info, gurl,
                NetLogWithSource(), &handler));

  // Verify that the default basic handler isn't present
  EXPECT_EQ(ERR_UNSUPPORTED_AUTH_SCHEME,
            context->http_auth_handler_factory()->CreateAuthHandlerFromString(
                "basic", HttpAuth::AUTH_SERVER, null_ssl_info, gurl,
                NetLogWithSource(), &handler));

  // Verify that a handler isn't returned for a bogus scheme.
  EXPECT_EQ(ERR_UNSUPPORTED_AUTH_SCHEME,
            context->http_auth_handler_factory()->CreateAuthHandlerFromString(
                "Bogus", HttpAuth::AUTH_SERVER, null_ssl_info, gurl,
                NetLogWithSource(), &handler));
}

}  // namespace

}  // namespace net
