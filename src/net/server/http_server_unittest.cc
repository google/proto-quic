// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/server/http_server.h"

#include <stdint.h>

#include <algorithm>
#include <memory>
#include <utility>
#include <vector>

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/callback_helpers.h"
#include "base/compiler_specific.h"
#include "base/format_macros.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/memory/ptr_util.h"
#include "base/memory/ref_counted.h"
#include "base/memory/weak_ptr.h"
#include "base/run_loop.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/time/time.h"
#include "net/base/address_list.h"
#include "net/base/io_buffer.h"
#include "net/base/ip_endpoint.h"
#include "net/base/net_errors.h"
#include "net/base/test_completion_callback.h"
#include "net/http/http_response_headers.h"
#include "net/http/http_util.h"
#include "net/log/net_log_source.h"
#include "net/log/net_log_with_source.h"
#include "net/server/http_server_request_info.h"
#include "net/socket/tcp_client_socket.h"
#include "net/socket/tcp_server_socket.h"
#include "net/test/gtest_util.h"
#include "net/url_request/url_fetcher.h"
#include "net/url_request/url_fetcher_delegate.h"
#include "net/url_request/url_request_context.h"
#include "net/url_request/url_request_context_getter.h"
#include "net/url_request/url_request_test_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using net::test::IsOk;

namespace net {

namespace {

const int kMaxExpectedResponseLength = 2048;

void SetTimedOutAndQuitLoop(const base::WeakPtr<bool> timed_out,
                            const base::Closure& quit_loop_func) {
  if (timed_out) {
    *timed_out = true;
    quit_loop_func.Run();
  }
}

bool RunLoopWithTimeout(base::RunLoop* run_loop) {
  bool timed_out = false;
  base::WeakPtrFactory<bool> timed_out_weak_factory(&timed_out);
  base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(
      FROM_HERE,
      base::Bind(&SetTimedOutAndQuitLoop, timed_out_weak_factory.GetWeakPtr(),
                 run_loop->QuitClosure()),
      base::TimeDelta::FromSeconds(1));
  run_loop->Run();
  return !timed_out;
}

class TestHttpClient {
 public:
  TestHttpClient() : connect_result_(OK) {}

  int ConnectAndWait(const IPEndPoint& address) {
    AddressList addresses(address);
    NetLogSource source;
    socket_.reset(new TCPClientSocket(addresses, NULL, NULL, source));

    base::RunLoop run_loop;
    connect_result_ = socket_->Connect(base::Bind(&TestHttpClient::OnConnect,
                                                  base::Unretained(this),
                                                  run_loop.QuitClosure()));
    if (connect_result_ != OK && connect_result_ != ERR_IO_PENDING)
      return connect_result_;

    if (!RunLoopWithTimeout(&run_loop))
      return ERR_TIMED_OUT;
    return connect_result_;
  }

  void Send(const std::string& data) {
    write_buffer_ =
        new DrainableIOBuffer(new StringIOBuffer(data), data.length());
    Write();
  }

  bool Read(std::string* message, int expected_bytes) {
    int total_bytes_received = 0;
    message->clear();
    while (total_bytes_received < expected_bytes) {
      TestCompletionCallback callback;
      ReadInternal(callback.callback());
      int bytes_received = callback.WaitForResult();
      if (bytes_received <= 0)
        return false;

      total_bytes_received += bytes_received;
      message->append(read_buffer_->data(), bytes_received);
    }
    return true;
  }

  bool ReadResponse(std::string* message) {
    if (!Read(message, 1))
      return false;
    while (!IsCompleteResponse(*message)) {
      std::string chunk;
      if (!Read(&chunk, 1))
        return false;
      message->append(chunk);
    }
    return true;
  }

  TCPClientSocket& socket() { return *socket_; }

 private:
  void OnConnect(const base::Closure& quit_loop, int result) {
    connect_result_ = result;
    quit_loop.Run();
  }

  void Write() {
    int result = socket_->Write(
        write_buffer_.get(),
        write_buffer_->BytesRemaining(),
        base::Bind(&TestHttpClient::OnWrite, base::Unretained(this)));
    if (result != ERR_IO_PENDING)
      OnWrite(result);
  }

  void OnWrite(int result) {
    ASSERT_GT(result, 0);
    write_buffer_->DidConsume(result);
    if (write_buffer_->BytesRemaining())
      Write();
  }

  void ReadInternal(const CompletionCallback& callback) {
    read_buffer_ = new IOBufferWithSize(kMaxExpectedResponseLength);
    int result =
        socket_->Read(read_buffer_.get(), kMaxExpectedResponseLength, callback);
    if (result != ERR_IO_PENDING)
      callback.Run(result);
  }

  bool IsCompleteResponse(const std::string& response) {
    // Check end of headers first.
    int end_of_headers = HttpUtil::LocateEndOfHeaders(response.data(),
                                                      response.size());
    if (end_of_headers < 0)
      return false;

    // Return true if response has data equal to or more than content length.
    int64_t body_size = static_cast<int64_t>(response.size()) - end_of_headers;
    DCHECK_LE(0, body_size);
    scoped_refptr<HttpResponseHeaders> headers(new HttpResponseHeaders(
        HttpUtil::AssembleRawHeaders(response.data(), end_of_headers)));
    return body_size >= headers->GetContentLength();
  }

  scoped_refptr<IOBufferWithSize> read_buffer_;
  scoped_refptr<DrainableIOBuffer> write_buffer_;
  std::unique_ptr<TCPClientSocket> socket_;
  int connect_result_;
};

}  // namespace

class HttpServerTest : public testing::Test,
                       public HttpServer::Delegate {
 public:
  HttpServerTest() : quit_after_request_count_(0) {}

  void SetUp() override {
    std::unique_ptr<ServerSocket> server_socket(
        new TCPServerSocket(NULL, NetLogSource()));
    server_socket->ListenWithAddressAndPort("127.0.0.1", 0, 1);
    server_.reset(new HttpServer(std::move(server_socket), this));
    ASSERT_THAT(server_->GetLocalAddress(&server_address_), IsOk());
  }

  void OnConnect(int connection_id) override {
    DCHECK(connection_map_.find(connection_id) == connection_map_.end());
    connection_map_[connection_id] = true;
  }

  void OnHttpRequest(int connection_id,
                     const HttpServerRequestInfo& info) override {
    requests_.push_back(std::make_pair(info, connection_id));
    if (requests_.size() == quit_after_request_count_)
      run_loop_quit_func_.Run();
  }

  void OnWebSocketRequest(int connection_id,
                          const HttpServerRequestInfo& info) override {
    NOTREACHED();
  }

  void OnWebSocketMessage(int connection_id, const std::string& data) override {
    NOTREACHED();
  }

  void OnClose(int connection_id) override {
    DCHECK(connection_map_.find(connection_id) != connection_map_.end());
    connection_map_[connection_id] = false;
  }

  bool RunUntilRequestsReceived(size_t count) {
    quit_after_request_count_ = count;
    if (requests_.size() == count)
      return true;

    base::RunLoop run_loop;
    run_loop_quit_func_ = run_loop.QuitClosure();
    bool success = RunLoopWithTimeout(&run_loop);
    run_loop_quit_func_.Reset();
    return success;
  }

  HttpServerRequestInfo GetRequest(size_t request_index) {
    return requests_[request_index].first;
  }

  int GetConnectionId(size_t request_index) {
    return requests_[request_index].second;
  }

  void HandleAcceptResult(std::unique_ptr<StreamSocket> socket) {
    server_->accepted_socket_ = std::move(socket);
    server_->HandleAcceptResult(OK);
  }

  std::unordered_map<int, bool>& connection_map() { return connection_map_; }

 protected:
  std::unique_ptr<HttpServer> server_;
  IPEndPoint server_address_;
  base::Closure run_loop_quit_func_;
  std::vector<std::pair<HttpServerRequestInfo, int> > requests_;
  std::unordered_map<int /* connection_id */, bool /* connected */>
      connection_map_;

 private:
  size_t quit_after_request_count_;
};

namespace {

class WebSocketTest : public HttpServerTest {
  void OnHttpRequest(int connection_id,
                     const HttpServerRequestInfo& info) override {
    NOTREACHED();
  }

  void OnWebSocketRequest(int connection_id,
                          const HttpServerRequestInfo& info) override {
    HttpServerTest::OnHttpRequest(connection_id, info);
  }

  void OnWebSocketMessage(int connection_id, const std::string& data) override {
  }
};

TEST_F(HttpServerTest, Request) {
  TestHttpClient client;
  ASSERT_THAT(client.ConnectAndWait(server_address_), IsOk());
  client.Send("GET /test HTTP/1.1\r\n\r\n");
  ASSERT_TRUE(RunUntilRequestsReceived(1));
  ASSERT_EQ("GET", GetRequest(0).method);
  ASSERT_EQ("/test", GetRequest(0).path);
  ASSERT_EQ("", GetRequest(0).data);
  ASSERT_EQ(0u, GetRequest(0).headers.size());
  ASSERT_TRUE(base::StartsWith(GetRequest(0).peer.ToString(), "127.0.0.1",
                               base::CompareCase::SENSITIVE));
}

TEST_F(HttpServerTest, RequestWithHeaders) {
  TestHttpClient client;
  ASSERT_THAT(client.ConnectAndWait(server_address_), IsOk());
  const char* const kHeaders[][3] = {
      {"Header", ": ", "1"},
      {"HeaderWithNoWhitespace", ":", "1"},
      {"HeaderWithWhitespace", "   :  \t   ", "1 1 1 \t  "},
      {"HeaderWithColon", ": ", "1:1"},
      {"EmptyHeader", ":", ""},
      {"EmptyHeaderWithWhitespace", ":  \t  ", ""},
      {"HeaderWithNonASCII", ":  ", "\xf7"},
  };
  std::string headers;
  for (size_t i = 0; i < arraysize(kHeaders); ++i) {
    headers +=
        std::string(kHeaders[i][0]) + kHeaders[i][1] + kHeaders[i][2] + "\r\n";
  }

  client.Send("GET /test HTTP/1.1\r\n" + headers + "\r\n");
  ASSERT_TRUE(RunUntilRequestsReceived(1));
  ASSERT_EQ("", GetRequest(0).data);

  for (size_t i = 0; i < arraysize(kHeaders); ++i) {
    std::string field = base::ToLowerASCII(std::string(kHeaders[i][0]));
    std::string value = kHeaders[i][2];
    ASSERT_EQ(1u, GetRequest(0).headers.count(field)) << field;
    ASSERT_EQ(value, GetRequest(0).headers[field]) << kHeaders[i][0];
  }
}

TEST_F(HttpServerTest, RequestWithDuplicateHeaders) {
  TestHttpClient client;
  ASSERT_THAT(client.ConnectAndWait(server_address_), IsOk());
  const char* const kHeaders[][3] = {
      {"FirstHeader", ": ", "1"},
      {"DuplicateHeader", ": ", "2"},
      {"MiddleHeader", ": ", "3"},
      {"DuplicateHeader", ": ", "4"},
      {"LastHeader", ": ", "5"},
  };
  std::string headers;
  for (size_t i = 0; i < arraysize(kHeaders); ++i) {
    headers +=
        std::string(kHeaders[i][0]) + kHeaders[i][1] + kHeaders[i][2] + "\r\n";
  }

  client.Send("GET /test HTTP/1.1\r\n" + headers + "\r\n");
  ASSERT_TRUE(RunUntilRequestsReceived(1));
  ASSERT_EQ("", GetRequest(0).data);

  for (size_t i = 0; i < arraysize(kHeaders); ++i) {
    std::string field = base::ToLowerASCII(std::string(kHeaders[i][0]));
    std::string value = (field == "duplicateheader") ? "2,4" : kHeaders[i][2];
    ASSERT_EQ(1u, GetRequest(0).headers.count(field)) << field;
    ASSERT_EQ(value, GetRequest(0).headers[field]) << kHeaders[i][0];
  }
}

TEST_F(HttpServerTest, HasHeaderValueTest) {
  TestHttpClient client;
  ASSERT_THAT(client.ConnectAndWait(server_address_), IsOk());
  const char* const kHeaders[] = {
      "Header: Abcd",
      "HeaderWithNoWhitespace:E",
      "HeaderWithWhitespace   :  \t   f \t  ",
      "DuplicateHeader: g",
      "HeaderWithComma: h, i ,j",
      "DuplicateHeader: k",
      "EmptyHeader:",
      "EmptyHeaderWithWhitespace:  \t  ",
      "HeaderWithNonASCII:  \xf7",
  };
  std::string headers;
  for (size_t i = 0; i < arraysize(kHeaders); ++i) {
    headers += std::string(kHeaders[i]) + "\r\n";
  }

  client.Send("GET /test HTTP/1.1\r\n" + headers + "\r\n");
  ASSERT_TRUE(RunUntilRequestsReceived(1));
  ASSERT_EQ("", GetRequest(0).data);

  ASSERT_TRUE(GetRequest(0).HasHeaderValue("header", "abcd"));
  ASSERT_FALSE(GetRequest(0).HasHeaderValue("header", "bc"));
  ASSERT_TRUE(GetRequest(0).HasHeaderValue("headerwithnowhitespace", "e"));
  ASSERT_TRUE(GetRequest(0).HasHeaderValue("headerwithwhitespace", "f"));
  ASSERT_TRUE(GetRequest(0).HasHeaderValue("duplicateheader", "g"));
  ASSERT_TRUE(GetRequest(0).HasHeaderValue("headerwithcomma", "h"));
  ASSERT_TRUE(GetRequest(0).HasHeaderValue("headerwithcomma", "i"));
  ASSERT_TRUE(GetRequest(0).HasHeaderValue("headerwithcomma", "j"));
  ASSERT_TRUE(GetRequest(0).HasHeaderValue("duplicateheader", "k"));
  ASSERT_FALSE(GetRequest(0).HasHeaderValue("emptyheader", "x"));
  ASSERT_FALSE(GetRequest(0).HasHeaderValue("emptyheaderwithwhitespace", "x"));
  ASSERT_TRUE(GetRequest(0).HasHeaderValue("headerwithnonascii", "\xf7"));
}

TEST_F(HttpServerTest, RequestWithBody) {
  TestHttpClient client;
  ASSERT_THAT(client.ConnectAndWait(server_address_), IsOk());
  std::string body = "a" + std::string(1 << 10, 'b') + "c";
  client.Send(base::StringPrintf(
      "GET /test HTTP/1.1\r\n"
      "SomeHeader: 1\r\n"
      "Content-Length: %" PRIuS "\r\n\r\n%s",
      body.length(),
      body.c_str()));
  ASSERT_TRUE(RunUntilRequestsReceived(1));
  ASSERT_EQ(2u, GetRequest(0).headers.size());
  ASSERT_EQ(body.length(), GetRequest(0).data.length());
  ASSERT_EQ('a', body[0]);
  ASSERT_EQ('c', *body.rbegin());
}

TEST_F(WebSocketTest, RequestWebSocket) {
  TestHttpClient client;
  ASSERT_THAT(client.ConnectAndWait(server_address_), IsOk());
  client.Send(
      "GET /test HTTP/1.1\r\n"
      "Upgrade: WebSocket\r\n"
      "Connection: SomethingElse, Upgrade\r\n"
      "Sec-WebSocket-Version: 8\r\n"
      "Sec-WebSocket-Key: key\r\n"
      "\r\n");
  ASSERT_TRUE(RunUntilRequestsReceived(1));
}

TEST_F(HttpServerTest, RequestWithTooLargeBody) {
  class TestURLFetcherDelegate : public URLFetcherDelegate {
   public:
    TestURLFetcherDelegate(const base::Closure& quit_loop_func)
        : quit_loop_func_(quit_loop_func) {}
    ~TestURLFetcherDelegate() override {}

    void OnURLFetchComplete(const URLFetcher* source) override {
      EXPECT_EQ(HTTP_INTERNAL_SERVER_ERROR, source->GetResponseCode());
      quit_loop_func_.Run();
    }

   private:
    base::Closure quit_loop_func_;
  };

  base::RunLoop run_loop;
  TestURLFetcherDelegate delegate(run_loop.QuitClosure());

  scoped_refptr<URLRequestContextGetter> request_context_getter(
      new TestURLRequestContextGetter(base::ThreadTaskRunnerHandle::Get()));
  std::unique_ptr<URLFetcher> fetcher =
      URLFetcher::Create(GURL(base::StringPrintf("http://127.0.0.1:%d/test",
                                                 server_address_.port())),
                         URLFetcher::GET, &delegate);
  fetcher->SetRequestContext(request_context_getter.get());
  fetcher->AddExtraRequestHeader(
      base::StringPrintf("content-length:%d", 1 << 30));
  fetcher->Start();

  ASSERT_TRUE(RunLoopWithTimeout(&run_loop));
  ASSERT_EQ(0u, requests_.size());
}

TEST_F(HttpServerTest, Send200) {
  TestHttpClient client;
  ASSERT_THAT(client.ConnectAndWait(server_address_), IsOk());
  client.Send("GET /test HTTP/1.1\r\n\r\n");
  ASSERT_TRUE(RunUntilRequestsReceived(1));
  server_->Send200(GetConnectionId(0), "Response!", "text/plain");

  std::string response;
  ASSERT_TRUE(client.ReadResponse(&response));
  ASSERT_TRUE(base::StartsWith(response, "HTTP/1.1 200 OK",
                               base::CompareCase::SENSITIVE));
  ASSERT_TRUE(
      base::EndsWith(response, "Response!", base::CompareCase::SENSITIVE));
}

TEST_F(HttpServerTest, SendRaw) {
  TestHttpClient client;
  ASSERT_THAT(client.ConnectAndWait(server_address_), IsOk());
  client.Send("GET /test HTTP/1.1\r\n\r\n");
  ASSERT_TRUE(RunUntilRequestsReceived(1));
  server_->SendRaw(GetConnectionId(0), "Raw Data ");
  server_->SendRaw(GetConnectionId(0), "More Data");
  server_->SendRaw(GetConnectionId(0), "Third Piece of Data");

  const std::string expected_response("Raw Data More DataThird Piece of Data");
  std::string response;
  ASSERT_TRUE(client.Read(&response, expected_response.length()));
  ASSERT_EQ(expected_response, response);
}

TEST_F(HttpServerTest, WrongProtocolRequest) {
  const char* const kBadProtocolRequests[] = {
      "GET /test HTTP/1.0\r\n\r\n",
      "GET /test foo\r\n\r\n",
      "GET /test \r\n\r\n",
  };

  for (size_t i = 0; i < arraysize(kBadProtocolRequests); ++i) {
    TestHttpClient client;
    ASSERT_THAT(client.ConnectAndWait(server_address_), IsOk());

    client.Send(kBadProtocolRequests[i]);
    ASSERT_FALSE(RunUntilRequestsReceived(1));

    // Assert that the delegate was updated properly.
    ASSERT_EQ(1u, connection_map().size());
    ASSERT_FALSE(connection_map().begin()->second);

    // Assert that the socket was opened...
    ASSERT_TRUE(client.socket().WasEverUsed());

    // ...then closed when the server disconnected. Verify that the socket was
    // closed by checking that a Read() fails.
    std::string response;
    ASSERT_FALSE(client.Read(&response, 1u));
    ASSERT_EQ(std::string(), response);

    // Reset the state of the connection map.
    connection_map().clear();
  }
}

class MockStreamSocket : public StreamSocket {
 public:
  MockStreamSocket()
      : connected_(true),
        read_buf_(NULL),
        read_buf_len_(0) {}

  // StreamSocket
  int Connect(const CompletionCallback& callback) override {
    return ERR_NOT_IMPLEMENTED;
  }
  void Disconnect() override {
    connected_ = false;
    if (!read_callback_.is_null()) {
      read_buf_ = NULL;
      read_buf_len_ = 0;
      base::ResetAndReturn(&read_callback_).Run(ERR_CONNECTION_CLOSED);
    }
  }
  bool IsConnected() const override { return connected_; }
  bool IsConnectedAndIdle() const override { return IsConnected(); }
  int GetPeerAddress(IPEndPoint* address) const override {
    return ERR_NOT_IMPLEMENTED;
  }
  int GetLocalAddress(IPEndPoint* address) const override {
    return ERR_NOT_IMPLEMENTED;
  }
  const NetLogWithSource& NetLog() const override { return net_log_; }
  void SetSubresourceSpeculation() override {}
  void SetOmniboxSpeculation() override {}
  bool WasEverUsed() const override { return true; }
  bool WasAlpnNegotiated() const override { return false; }
  NextProto GetNegotiatedProtocol() const override { return kProtoUnknown; }
  bool GetSSLInfo(SSLInfo* ssl_info) override { return false; }
  void GetConnectionAttempts(ConnectionAttempts* out) const override {
    out->clear();
  }
  void ClearConnectionAttempts() override {}
  void AddConnectionAttempts(const ConnectionAttempts& attempts) override {}
  int64_t GetTotalReceivedBytes() const override {
    NOTIMPLEMENTED();
    return 0;
  }

  // Socket
  int Read(IOBuffer* buf,
           int buf_len,
           const CompletionCallback& callback) override {
    if (!connected_) {
      return ERR_SOCKET_NOT_CONNECTED;
    }
    if (pending_read_data_.empty()) {
      read_buf_ = buf;
      read_buf_len_ = buf_len;
      read_callback_ = callback;
      return ERR_IO_PENDING;
    }
    DCHECK_GT(buf_len, 0);
    int read_len = std::min(static_cast<int>(pending_read_data_.size()),
                            buf_len);
    memcpy(buf->data(), pending_read_data_.data(), read_len);
    pending_read_data_.erase(0, read_len);
    return read_len;
  }
  int Write(IOBuffer* buf,
            int buf_len,
            const CompletionCallback& callback) override {
    return ERR_NOT_IMPLEMENTED;
  }
  int SetReceiveBufferSize(int32_t size) override {
    return ERR_NOT_IMPLEMENTED;
  }
  int SetSendBufferSize(int32_t size) override { return ERR_NOT_IMPLEMENTED; }

  void DidRead(const char* data, int data_len) {
    if (!read_buf_.get()) {
      pending_read_data_.append(data, data_len);
      return;
    }
    int read_len = std::min(data_len, read_buf_len_);
    memcpy(read_buf_->data(), data, read_len);
    pending_read_data_.assign(data + read_len, data_len - read_len);
    read_buf_ = NULL;
    read_buf_len_ = 0;
    base::ResetAndReturn(&read_callback_).Run(read_len);
  }

 private:
  ~MockStreamSocket() override {}

  bool connected_;
  scoped_refptr<IOBuffer> read_buf_;
  int read_buf_len_;
  CompletionCallback read_callback_;
  std::string pending_read_data_;
  NetLogWithSource net_log_;

  DISALLOW_COPY_AND_ASSIGN(MockStreamSocket);
};

TEST_F(HttpServerTest, RequestWithBodySplitAcrossPackets) {
  MockStreamSocket* socket = new MockStreamSocket();
  HandleAcceptResult(base::WrapUnique<StreamSocket>(socket));
  std::string body("body");
  std::string request_text = base::StringPrintf(
      "GET /test HTTP/1.1\r\n"
      "SomeHeader: 1\r\n"
      "Content-Length: %" PRIuS "\r\n\r\n%s",
      body.length(),
      body.c_str());
  socket->DidRead(request_text.c_str(), request_text.length() - 2);
  ASSERT_EQ(0u, requests_.size());
  socket->DidRead(request_text.c_str() + request_text.length() - 2, 2);
  ASSERT_EQ(1u, requests_.size());
  ASSERT_EQ(body, GetRequest(0).data);
}

TEST_F(HttpServerTest, MultipleRequestsOnSameConnection) {
  // The idea behind this test is that requests with or without bodies should
  // not break parsing of the next request.
  TestHttpClient client;
  ASSERT_THAT(client.ConnectAndWait(server_address_), IsOk());
  std::string body = "body";
  client.Send(base::StringPrintf(
      "GET /test HTTP/1.1\r\n"
      "Content-Length: %" PRIuS "\r\n\r\n%s",
      body.length(),
      body.c_str()));
  ASSERT_TRUE(RunUntilRequestsReceived(1));
  ASSERT_EQ(body, GetRequest(0).data);

  int client_connection_id = GetConnectionId(0);
  server_->Send200(client_connection_id, "Content for /test", "text/plain");
  std::string response1;
  ASSERT_TRUE(client.ReadResponse(&response1));
  ASSERT_TRUE(base::StartsWith(response1, "HTTP/1.1 200 OK",
                               base::CompareCase::SENSITIVE));
  ASSERT_TRUE(base::EndsWith(response1, "Content for /test",
                             base::CompareCase::SENSITIVE));

  client.Send("GET /test2 HTTP/1.1\r\n\r\n");
  ASSERT_TRUE(RunUntilRequestsReceived(2));
  ASSERT_EQ("/test2", GetRequest(1).path);

  ASSERT_EQ(client_connection_id, GetConnectionId(1));
  server_->Send404(client_connection_id);
  std::string response2;
  ASSERT_TRUE(client.ReadResponse(&response2));
  ASSERT_TRUE(base::StartsWith(response2, "HTTP/1.1 404 Not Found",
                               base::CompareCase::SENSITIVE));

  client.Send("GET /test3 HTTP/1.1\r\n\r\n");
  ASSERT_TRUE(RunUntilRequestsReceived(3));
  ASSERT_EQ("/test3", GetRequest(2).path);

  ASSERT_EQ(client_connection_id, GetConnectionId(2));
  server_->Send200(client_connection_id, "Content for /test3", "text/plain");
  std::string response3;
  ASSERT_TRUE(client.ReadResponse(&response3));
  ASSERT_TRUE(base::StartsWith(response3, "HTTP/1.1 200 OK",
                               base::CompareCase::SENSITIVE));
  ASSERT_TRUE(base::EndsWith(response3, "Content for /test3",
                             base::CompareCase::SENSITIVE));
}

class CloseOnConnectHttpServerTest : public HttpServerTest {
 public:
  void OnConnect(int connection_id) override {
    HttpServerTest::OnConnect(connection_id);
    connection_ids_.push_back(connection_id);
    server_->Close(connection_id);
  }

 protected:
  std::vector<int> connection_ids_;
};

TEST_F(CloseOnConnectHttpServerTest, ServerImmediatelyClosesConnection) {
  TestHttpClient client;
  ASSERT_THAT(client.ConnectAndWait(server_address_), IsOk());
  client.Send("GET / HTTP/1.1\r\n\r\n");
  ASSERT_FALSE(RunUntilRequestsReceived(1));
  ASSERT_EQ(1ul, connection_ids_.size());
  ASSERT_EQ(0ul, requests_.size());
}

}  // namespace

}  // namespace net
