// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>

#include "base/callback_forward.h"
#include "base/memory/ptr_util.h"
#include "base/memory/weak_ptr.h"
#include "base/message_loop/message_loop.h"
#include "base/run_loop.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/threading/thread_task_runner_handle.h"
#include "net/cookies/cookie_store.h"
#include "net/socket/socket_test_util.h"
#include "net/websockets/websocket_stream_create_test_base.h"
#include "net/websockets/websocket_test_util.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"
#include "url/origin.h"

namespace net {
namespace {

using ::testing::TestWithParam;
using ::testing::ValuesIn;

const char kNoCookieHeader[] = "";

class TestBase : public WebSocketStreamCreateTestBase {
 public:
  void CreateAndConnect(const GURL& url,
                        const url::Origin& origin,
                        const GURL& first_party_for_cookies,
                        const std::string& cookie_header,
                        const std::string& response_body) {
    // We assume cookie_header ends with CRLF if not empty, as
    // WebSocketStandardRequestWithCookies requires. Use AddCRLFIfNotEmpty
    // in a call site.
    CHECK(cookie_header.empty() ||
          base::EndsWith(cookie_header, "\r\n", base::CompareCase::SENSITIVE));

    url_request_context_host_.SetExpectations(
        WebSocketStandardRequestWithCookies(url.path(), url.host(), origin,
                                            cookie_header, std::string(),
                                            std::string()),
        response_body);
    CreateAndConnectStream(url, NoSubProtocols(), origin,
                           first_party_for_cookies, "", nullptr);
  }

  std::string AddCRLFIfNotEmpty(const std::string& s) {
    return s.empty() ? s : s + "\r\n";
  }
};

struct ClientUseCookieParameter {
  // The URL for the WebSocket connection.
  const char* const url;
  // The URL for the previously set cookies.
  const char* const cookie_url;
  // The previously set cookies contents.
  const char* const cookie_line;
  // The Cookie: HTTP header expected to appear in the WS request. An empty
  // string means there is no Cookie: header.
  const char* const cookie_header;
};

class WebSocketStreamClientUseCookieTest
    : public TestBase,
      public TestWithParam<ClientUseCookieParameter> {
 public:
  ~WebSocketStreamClientUseCookieTest() override {
    // Permit any endpoint locks to be released.
    stream_request_.reset();
    stream_.reset();
    base::RunLoop().RunUntilIdle();
  }

  static void SetCookieHelperFunction(const base::Closure& task,
                                      base::WeakPtr<bool> weak_is_called,
                                      base::WeakPtr<bool> weak_result,
                                      bool success) {
    *weak_is_called = true;
    *weak_result = success;
    base::ThreadTaskRunnerHandle::Get()->PostTask(FROM_HERE, task);
  }
};

struct ServerSetCookieParameter {
  // The URL for the WebSocket connection.
  const char* const url;
  // The URL used to query cookies after the response received.
  const char* const cookie_url;
  // The cookies expected to appear for |cookie_url| inquiry.
  const char* const cookie_line;
  // The Set-Cookie: HTTP header attached to the response.
  const char* const cookie_header;
};

class WebSocketStreamServerSetCookieTest
    : public TestBase,
      public TestWithParam<ServerSetCookieParameter> {
 public:
  ~WebSocketStreamServerSetCookieTest() override {
    // Permit any endpoint locks to be released.
    stream_request_.reset();
    stream_.reset();
    base::RunLoop().RunUntilIdle();
  }

  static void GetCookiesHelperFunction(const base::Closure& task,
                                       base::WeakPtr<bool> weak_is_called,
                                       base::WeakPtr<std::string> weak_result,
                                       const std::string& cookies) {
    *weak_is_called = true;
    *weak_result = cookies;
    base::ThreadTaskRunnerHandle::Get()->PostTask(FROM_HERE, task);
  }
};

TEST_P(WebSocketStreamClientUseCookieTest, ClientUseCookie) {
  // For wss tests.
  ssl_data_.push_back(base::MakeUnique<SSLSocketDataProvider>(ASYNC, OK));

  CookieStore* store =
      url_request_context_host_.GetURLRequestContext()->cookie_store();

  const GURL url(GetParam().url);
  const GURL cookie_url(GetParam().cookie_url);
  const url::Origin origin(GURL("http://www.example.com"));
  const GURL first_party_for_cookies("http://www.example.com/");
  const std::string cookie_line(GetParam().cookie_line);
  const std::string cookie_header(AddCRLFIfNotEmpty(GetParam().cookie_header));

  bool is_called = false;
  bool set_cookie_result = false;
  base::WeakPtrFactory<bool> weak_is_called(&is_called);
  base::WeakPtrFactory<bool> weak_set_cookie_result(&set_cookie_result);

  base::RunLoop run_loop;
  store->SetCookieWithOptionsAsync(
      cookie_url, cookie_line, CookieOptions(),
      base::Bind(&SetCookieHelperFunction, run_loop.QuitClosure(),
                 weak_is_called.GetWeakPtr(),
                 weak_set_cookie_result.GetWeakPtr()));
  run_loop.Run();
  ASSERT_TRUE(is_called);
  ASSERT_TRUE(set_cookie_result);

  CreateAndConnect(url, origin, first_party_for_cookies, cookie_header,
                   WebSocketStandardResponse(""));
  WaitUntilConnectDone();
  EXPECT_FALSE(has_failed());
}

TEST_P(WebSocketStreamServerSetCookieTest, ServerSetCookie) {
  // For wss tests.
  ssl_data_.push_back(base::MakeUnique<SSLSocketDataProvider>(ASYNC, OK));

  const GURL url(GetParam().url);
  const GURL cookie_url(GetParam().cookie_url);
  const url::Origin origin(GURL("http://www.example.com"));
  const GURL first_party_for_cookies("http://www.example.com/");
  const std::string cookie_line(GetParam().cookie_line);
  const std::string cookie_header(AddCRLFIfNotEmpty(GetParam().cookie_header));

  const std::string response = base::StringPrintf(
      "HTTP/1.1 101 Switching Protocols\r\n"
      "Upgrade: websocket\r\n"
      "Connection: Upgrade\r\n"
      "%s"
      "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
      "\r\n",
      cookie_header.c_str());

  CookieStore* store =
      url_request_context_host_.GetURLRequestContext()->cookie_store();

  CreateAndConnect(url, origin, first_party_for_cookies, "", response);
  WaitUntilConnectDone();
  EXPECT_FALSE(has_failed());

  bool is_called = false;
  std::string get_cookies_result;
  base::WeakPtrFactory<bool> weak_is_called(&is_called);
  base::WeakPtrFactory<std::string> weak_get_cookies_result(
      &get_cookies_result);
  base::RunLoop run_loop;
  store->GetCookiesWithOptionsAsync(
      cookie_url, CookieOptions(),
      base::Bind(&GetCookiesHelperFunction, run_loop.QuitClosure(),
                 weak_is_called.GetWeakPtr(),
                 weak_get_cookies_result.GetWeakPtr()));
  run_loop.Run();
  EXPECT_TRUE(is_called);
  EXPECT_EQ(cookie_line, get_cookies_result);
}

// Test parameters definitions follow...

const ClientUseCookieParameter kClientUseCookieParameters[] = {
    // Non-secure cookies for ws
    {"ws://www.example.com",
     "http://www.example.com",
     "test-cookie",
     "Cookie: test-cookie"},

    {"ws://www.example.com",
     "https://www.example.com",
     "test-cookie",
     "Cookie: test-cookie"},

    {"ws://www.example.com",
     "ws://www.example.com",
     "test-cookie",
     "Cookie: test-cookie"},

    {"ws://www.example.com",
     "wss://www.example.com",
     "test-cookie",
     "Cookie: test-cookie"},

    // Non-secure cookies for wss
    {"wss://www.example.com",
     "http://www.example.com",
     "test-cookie",
     "Cookie: test-cookie"},

    {"wss://www.example.com",
     "https://www.example.com",
     "test-cookie",
     "Cookie: test-cookie"},

    {"wss://www.example.com",
     "ws://www.example.com",
     "test-cookie",
     "Cookie: test-cookie"},

    {"wss://www.example.com",
     "wss://www.example.com",
     "test-cookie",
     "Cookie: test-cookie"},

    // Secure-cookies for ws
    {"ws://www.example.com",
     "https://www.example.com",
     "test-cookie; secure",
     kNoCookieHeader},

    {"ws://www.example.com",
     "wss://www.example.com",
     "test-cookie; secure",
     kNoCookieHeader},

    // Secure-cookies for wss
    {"wss://www.example.com",
     "https://www.example.com",
     "test-cookie; secure",
     "Cookie: test-cookie"},

    {"wss://www.example.com",
     "wss://www.example.com",
     "test-cookie; secure",
     "Cookie: test-cookie"},

    // Non-secure cookies for ws (sharing domain)
    {"ws://www.example.com",
     "http://www2.example.com",
     "test-cookie; Domain=example.com",
     "Cookie: test-cookie"},

    {"ws://www.example.com",
     "https://www2.example.com",
     "test-cookie; Domain=example.com",
     "Cookie: test-cookie"},

    {"ws://www.example.com",
     "ws://www2.example.com",
     "test-cookie; Domain=example.com",
     "Cookie: test-cookie"},

    {"ws://www.example.com",
     "wss://www2.example.com",
     "test-cookie; Domain=example.com",
     "Cookie: test-cookie"},

    // Non-secure cookies for wss (sharing domain)
    {"wss://www.example.com",
     "http://www2.example.com",
     "test-cookie; Domain=example.com",
     "Cookie: test-cookie"},

    {"wss://www.example.com",
     "https://www2.example.com",
     "test-cookie; Domain=example.com",
     "Cookie: test-cookie"},

    {"wss://www.example.com",
     "ws://www2.example.com",
     "test-cookie; Domain=example.com",
     "Cookie: test-cookie"},

    {"wss://www.example.com",
     "wss://www2.example.com",
     "test-cookie; Domain=example.com",
     "Cookie: test-cookie"},

    // Secure-cookies for ws (sharing domain)
    {"ws://www.example.com",
     "https://www2.example.com",
     "test-cookie; Domain=example.com; secure",
     kNoCookieHeader},

    {"ws://www.example.com",
     "wss://www2.example.com",
     "test-cookie; Domain=example.com; secure",
     kNoCookieHeader},

    // Secure-cookies for wss (sharing domain)
    {"wss://www.example.com",
     "https://www2.example.com",
     "test-cookie; Domain=example.com; secure",
     "Cookie: test-cookie"},

    {"wss://www.example.com",
     "wss://www2.example.com",
     "test-cookie; Domain=example.com; secure",
     "Cookie: test-cookie"},

    // Non-matching cookies for ws
    {"ws://www.example.com",
     "http://www2.example.com",
     "test-cookie",
     kNoCookieHeader},

    {"ws://www.example.com",
     "https://www2.example.com",
     "test-cookie",
     kNoCookieHeader},

    {"ws://www.example.com",
     "ws://www2.example.com",
     "test-cookie",
     kNoCookieHeader},

    {"ws://www.example.com",
     "wss://www2.example.com",
     "test-cookie",
     kNoCookieHeader},

    // Non-matching cookies for wss
    {"wss://www.example.com",
     "http://www2.example.com",
     "test-cookie",
     kNoCookieHeader},

    {"wss://www.example.com",
     "https://www2.example.com",
     "test-cookie",
     kNoCookieHeader},

    {"wss://www.example.com",
     "ws://www2.example.com",
     "test-cookie",
     kNoCookieHeader},

    {"wss://www.example.com",
     "wss://www2.example.com",
     "test-cookie",
     kNoCookieHeader},
};

INSTANTIATE_TEST_CASE_P(WebSocketStreamClientUseCookieTest,
                        WebSocketStreamClientUseCookieTest,
                        ValuesIn(kClientUseCookieParameters));

const ServerSetCookieParameter kServerSetCookieParameters[] = {
    // Cookies coming from ws
    {"ws://www.example.com",
     "http://www.example.com",
     "test-cookie",
     "Set-Cookie: test-cookie"},

    {"ws://www.example.com",
     "https://www.example.com",
     "test-cookie",
     "Set-Cookie: test-cookie"},

    {"ws://www.example.com",
     "ws://www.example.com",
     "test-cookie",
     "Set-Cookie: test-cookie"},

    {"ws://www.example.com",
     "wss://www.example.com",
     "test-cookie",
     "Set-Cookie: test-cookie"},

    // Cookies coming from wss
    {"wss://www.example.com",
     "http://www.example.com",
     "test-cookie",
     "Set-Cookie: test-cookie"},

    {"wss://www.example.com",
     "https://www.example.com",
     "test-cookie",
     "Set-Cookie: test-cookie"},

    {"wss://www.example.com",
     "ws://www.example.com",
     "test-cookie",
     "Set-Cookie: test-cookie"},

    {"wss://www.example.com",
     "wss://www.example.com",
     "test-cookie",
     "Set-Cookie: test-cookie"},

    // cookies coming from ws (sharing domain)
    {"ws://www.example.com",
     "http://www2.example.com",
     "test-cookie",
     "Set-Cookie: test-cookie; Domain=example.com"},

    {"ws://www.example.com",
     "https://www2.example.com",
     "test-cookie",
     "Set-Cookie: test-cookie; Domain=example.com"},

    {"ws://www.example.com",
     "ws://www2.example.com",
     "test-cookie",
     "Set-Cookie: test-cookie; Domain=example.com"},

    {"ws://www.example.com",
     "wss://www2.example.com",
     "test-cookie",
     "Set-Cookie: test-cookie; Domain=example.com"},

    // cookies coming from wss (sharing domain)
    {"wss://www.example.com",
     "http://www2.example.com",
     "test-cookie",
     "Set-Cookie: test-cookie; Domain=example.com"},

    {"wss://www.example.com",
     "https://www2.example.com",
     "test-cookie",
     "Set-Cookie: test-cookie; Domain=example.com"},

    {"wss://www.example.com",
     "ws://www2.example.com",
     "test-cookie",
     "Set-Cookie: test-cookie; Domain=example.com"},

    {"wss://www.example.com",
     "wss://www2.example.com",
     "test-cookie",
     "Set-Cookie: test-cookie; Domain=example.com"},

    // Non-matching cookies coming from ws
    {"ws://www.example.com",
     "http://www2.example.com",
     "",
     "Set-Cookie: test-cookie"},

    {"ws://www.example.com",
     "https://www2.example.com",
     "",
     "Set-Cookie: test-cookie"},

    {"ws://www.example.com",
     "ws://www2.example.com",
     "",
     "Set-Cookie: test-cookie"},

    {"ws://www.example.com",
     "wss://www2.example.com",
     "",
     "Set-Cookie: test-cookie"},

    // Non-matching cookies coming from wss
    {"wss://www.example.com",
     "http://www2.example.com",
     "",
     "Set-Cookie: test-cookie"},

    {"wss://www.example.com",
     "https://www2.example.com",
     "",
     "Set-Cookie: test-cookie"},

    {"wss://www.example.com",
     "ws://www2.example.com",
     "",
     "Set-Cookie: test-cookie"},

    {"wss://www.example.com",
     "wss://www2.example.com",
     "",
     "Set-Cookie: test-cookie"},
};

INSTANTIATE_TEST_CASE_P(WebSocketStreamServerSetCookieTest,
                        WebSocketStreamServerSetCookieTest,
                        ValuesIn(kServerSetCookieParameters));

}  // namespace
}  // namespace net
