// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/url_request/url_request_context_builder_mojo.h"

#include "base/run_loop.h"
#include "base/strings/stringprintf.h"
#include "net/base/host_port_pair.h"
#include "net/proxy/proxy_config.h"
#include "net/proxy/proxy_config_service_fixed.h"
#include "net/proxy/test_mojo_proxy_resolver_factory.h"
#include "net/test/embedded_test_server/embedded_test_server.h"
#include "net/test/embedded_test_server/http_request.h"
#include "net/test/embedded_test_server/http_response.h"
#include "net/test/embedded_test_server/simple_connection_listener.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "net/url_request/url_request.h"
#include "net/url_request/url_request_context.h"
#include "net/url_request/url_request_test_util.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "testing/platform_test.h"
#include "url/gurl.h"

namespace net {

namespace {

const char kPacPath[] = "/super.pac";

// When kPacPath is requested, returns a PAC script that uses the test server
// itself as the proxy.
std::unique_ptr<test_server::HttpResponse> HandlePacRequest(
    const test_server::HttpRequest& request) {
  if (request.relative_url != kPacPath)
    return nullptr;
  std::unique_ptr<test_server::BasicHttpResponse> response =
      base::MakeUnique<test_server::BasicHttpResponse>();
  response->set_content(base::StringPrintf(
      "function FindProxyForURL(url, host) { return 'PROXY %s;'; }",
      HostPortPair::FromURL(request.base_url).ToString().c_str()));
  response->set_content_type("text/html");
  return std::move(response);
}

class URLRequestContextBuilderMojoTest : public PlatformTest {
 protected:
  URLRequestContextBuilderMojoTest() {
    test_server_.RegisterRequestHandler(base::Bind(&HandlePacRequest));
    test_server_.AddDefaultHandlers(
        base::FilePath(FILE_PATH_LITERAL("net/data/url_request_unittest")));
  }

  EmbeddedTestServer test_server_;
  URLRequestContextBuilderMojo builder_;
};

TEST_F(URLRequestContextBuilderMojoTest, MojoProxyResolver) {
  EXPECT_TRUE(test_server_.Start());
  TestMojoProxyResolverFactory::GetInstance()->set_resolver_created(false);

  builder_.set_proxy_config_service(base::MakeUnique<ProxyConfigServiceFixed>(
      ProxyConfig::CreateFromCustomPacURL(test_server_.GetURL(kPacPath))));
  builder_.set_mojo_proxy_resolver_factory(
      TestMojoProxyResolverFactory::GetInstance());

  std::unique_ptr<URLRequestContext> context(builder_.Build());
  TestDelegate delegate;
  std::unique_ptr<URLRequest> request(context->CreateRequest(
      GURL("http://hats:12345/echoheader?Foo"), DEFAULT_PRIORITY, &delegate,
      TRAFFIC_ANNOTATION_FOR_TESTS));
  request->SetExtraRequestHeaderByName("Foo", "Bar", false);
  request->Start();
  base::RunLoop().Run();
  EXPECT_EQ("Bar", delegate.data_received());

  // Make sure that the Mojo factory was used.
  EXPECT_TRUE(TestMojoProxyResolverFactory::GetInstance()->resolver_created());
}

// Makes sure that pending PAC requests are correctly shut down during teardown.
TEST_F(URLRequestContextBuilderMojoTest, ShutdownWithHungRequest) {
  test_server::SimpleConnectionListener connection_listener(
      1, test_server::SimpleConnectionListener::FAIL_ON_ADDITIONAL_CONNECTIONS);
  test_server_.SetConnectionListener(&connection_listener);
  EXPECT_TRUE(test_server_.Start());

  builder_.set_proxy_config_service(base::MakeUnique<ProxyConfigServiceFixed>(
      ProxyConfig::CreateFromCustomPacURL(test_server_.GetURL("/hung"))));
  builder_.set_mojo_proxy_resolver_factory(
      TestMojoProxyResolverFactory::GetInstance());

  std::unique_ptr<URLRequestContext> context(builder_.Build());
  TestDelegate delegate;
  std::unique_ptr<URLRequest> request(context->CreateRequest(
      GURL("http://hats:12345/echoheader?Foo"), DEFAULT_PRIORITY, &delegate,
      TRAFFIC_ANNOTATION_FOR_TESTS));
  request->Start();
  connection_listener.WaitForConnections();

  // Tearing down the URLRequestContext should not cause an AssertNoURLRequests
  // failure.
  request.reset();
  context.reset();

  // Have to shut down the test server before |connection_listener| falls out of
  // scope.
  EXPECT_TRUE(test_server_.ShutdownAndWaitUntilComplete());
}

}  // namespace

}  // namespace net
