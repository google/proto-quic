// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/websockets/websocket_handshake_stream_create_helper.h"

#include <string>
#include <utility>
#include <vector>

#include "base/macros.h"
#include "net/base/completion_callback.h"
#include "net/base/net_errors.h"
#include "net/http/http_request_headers.h"
#include "net/http/http_request_info.h"
#include "net/http/http_response_headers.h"
#include "net/http/http_response_info.h"
#include "net/log/net_log_with_source.h"
#include "net/socket/client_socket_handle.h"
#include "net/socket/socket_test_util.h"
#include "net/test/gtest_util.h"
#include "net/websockets/websocket_basic_handshake_stream.h"
#include "net/websockets/websocket_stream.h"
#include "net/websockets/websocket_test_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"
#include "url/origin.h"

using net::test::IsOk;

using ::testing::_;

namespace net {
namespace {

// This class encapsulates the details of creating a mock ClientSocketHandle.
class MockClientSocketHandleFactory {
 public:
  MockClientSocketHandleFactory()
      : pool_(1, 1, socket_factory_maker_.factory()) {}

  // The created socket expects |expect_written| to be written to the socket,
  // and will respond with |return_to_read|. The test will fail if the expected
  // text is not written, or if all the bytes are not read.
  std::unique_ptr<ClientSocketHandle> CreateClientSocketHandle(
      const std::string& expect_written,
      const std::string& return_to_read) {
    socket_factory_maker_.SetExpectations(expect_written, return_to_read);
    std::unique_ptr<ClientSocketHandle> socket_handle(new ClientSocketHandle);
    socket_handle->Init("a", scoped_refptr<MockTransportSocketParams>(), MEDIUM,
                        ClientSocketPool::RespectLimits::ENABLED,
                        CompletionCallback(), &pool_, NetLogWithSource());
    return socket_handle;
  }

 private:
  WebSocketMockClientSocketFactoryMaker socket_factory_maker_;
  MockTransportClientSocketPool pool_;

  DISALLOW_COPY_AND_ASSIGN(MockClientSocketHandleFactory);
};

class TestConnectDelegate : public WebSocketStream::ConnectDelegate {
 public:
  ~TestConnectDelegate() override {}

  void OnCreateRequest(URLRequest* request) override {}
  void OnSuccess(std::unique_ptr<WebSocketStream> stream) override {}
  void OnFailure(const std::string& failure_message) override {}
  void OnStartOpeningHandshake(
      std::unique_ptr<WebSocketHandshakeRequestInfo> request) override {}
  void OnFinishOpeningHandshake(
      std::unique_ptr<WebSocketHandshakeResponseInfo> response) override {}
  void OnSSLCertificateError(
      std::unique_ptr<WebSocketEventInterface::SSLErrorCallbacks>
          ssl_error_callbacks,
      const SSLInfo& ssl_info,
      bool fatal) override {}
};

class MockWebSocketStreamRequest : public WebSocketStreamRequest {
 public:
  MOCK_METHOD1(OnHandshakeStreamCreated,
               void(WebSocketHandshakeStreamBase* handshake_stream));
  MOCK_METHOD1(OnFailure, void(const std::string& message));
};

class WebSocketHandshakeStreamCreateHelperTest : public ::testing::Test {
 protected:
  std::unique_ptr<WebSocketStream> CreateAndInitializeStream(
      const std::vector<std::string>& sub_protocols,
      const std::string& extra_request_headers,
      const std::string& extra_response_headers) {
    static const char kOrigin[] = "http://localhost";
    WebSocketHandshakeStreamCreateHelper create_helper(&connect_delegate_,
                                                       sub_protocols);

    EXPECT_CALL(stream_request, OnHandshakeStreamCreated(_)).Times(1);
    EXPECT_CALL(stream_request, OnFailure(_)).Times(0);

    create_helper.set_stream_request(&stream_request);

    std::unique_ptr<ClientSocketHandle> socket_handle =
        socket_handle_factory_.CreateClientSocketHandle(
            WebSocketStandardRequest("/", "localhost",
                                     url::Origin(GURL(kOrigin)), "",
                                     extra_request_headers),
            WebSocketStandardResponse(extra_response_headers));

    std::unique_ptr<WebSocketHandshakeStreamBase> handshake =
        create_helper.CreateBasicStream(std::move(socket_handle), false);

    // If in future the implementation type returned by CreateBasicStream()
    // changes, this static_cast will be wrong. However, in that case the test
    // will fail and AddressSanitizer should identify the issue.
    static_cast<WebSocketBasicHandshakeStream*>(handshake.get())
        ->SetWebSocketKeyForTesting("dGhlIHNhbXBsZSBub25jZQ==");

    HttpRequestInfo request_info;
    request_info.url = GURL("ws://localhost/");
    request_info.method = "GET";
    request_info.load_flags = LOAD_DISABLE_CACHE;
    int rv =
        handshake->InitializeStream(&request_info, DEFAULT_PRIORITY,
                                    NetLogWithSource(), CompletionCallback());
    EXPECT_THAT(rv, IsOk());

    HttpRequestHeaders headers;
    headers.SetHeader("Host", "localhost");
    headers.SetHeader("Connection", "Upgrade");
    headers.SetHeader("Pragma", "no-cache");
    headers.SetHeader("Cache-Control", "no-cache");
    headers.SetHeader("Upgrade", "websocket");
    headers.SetHeader("Origin", kOrigin);
    headers.SetHeader("Sec-WebSocket-Version", "13");
    headers.SetHeader("User-Agent", "");
    headers.SetHeader("Accept-Encoding", "gzip, deflate");
    headers.SetHeader("Accept-Language", "en-us,fr");

    HttpResponseInfo response;
    TestCompletionCallback dummy;

    rv = handshake->SendRequest(headers, &response, dummy.callback());

    EXPECT_THAT(rv, IsOk());

    rv = handshake->ReadResponseHeaders(dummy.callback());
    EXPECT_THAT(rv, IsOk());
    EXPECT_EQ(101, response.headers->response_code());
    EXPECT_TRUE(response.headers->HasHeaderValue("Connection", "Upgrade"));
    EXPECT_TRUE(response.headers->HasHeaderValue("Upgrade", "websocket"));
    return handshake->Upgrade();
  }

  MockClientSocketHandleFactory socket_handle_factory_;
  TestConnectDelegate connect_delegate_;
  MockWebSocketStreamRequest stream_request;
};

// Confirm that the basic case works as expected.
TEST_F(WebSocketHandshakeStreamCreateHelperTest, BasicStream) {
  std::unique_ptr<WebSocketStream> stream =
      CreateAndInitializeStream(std::vector<std::string>(), "", "");
  EXPECT_EQ("", stream->GetExtensions());
  EXPECT_EQ("", stream->GetSubProtocol());
}

// Verify that the sub-protocols are passed through.
TEST_F(WebSocketHandshakeStreamCreateHelperTest, SubProtocols) {
  std::vector<std::string> sub_protocols;
  sub_protocols.push_back("chat");
  sub_protocols.push_back("superchat");
  std::unique_ptr<WebSocketStream> stream = CreateAndInitializeStream(
      sub_protocols, "Sec-WebSocket-Protocol: chat, superchat\r\n",
      "Sec-WebSocket-Protocol: superchat\r\n");
  EXPECT_EQ("superchat", stream->GetSubProtocol());
}

// Verify that extension name is available. Bad extension names are tested in
// websocket_stream_test.cc.
TEST_F(WebSocketHandshakeStreamCreateHelperTest, Extensions) {
  std::unique_ptr<WebSocketStream> stream = CreateAndInitializeStream(
      std::vector<std::string>(), "",
      "Sec-WebSocket-Extensions: permessage-deflate\r\n");
  EXPECT_EQ("permessage-deflate", stream->GetExtensions());
}

// Verify that extension parameters are available. Bad parameters are tested in
// websocket_stream_test.cc.
TEST_F(WebSocketHandshakeStreamCreateHelperTest, ExtensionParameters) {
  std::unique_ptr<WebSocketStream> stream = CreateAndInitializeStream(
      std::vector<std::string>(), "",
      "Sec-WebSocket-Extensions: permessage-deflate;"
      " client_max_window_bits=14; server_max_window_bits=14;"
      " server_no_context_takeover; client_no_context_takeover\r\n");

  EXPECT_EQ(
      "permessage-deflate;"
      " client_max_window_bits=14; server_max_window_bits=14;"
      " server_no_context_takeover; client_no_context_takeover",
      stream->GetExtensions());
}

}  // namespace
}  // namespace net
