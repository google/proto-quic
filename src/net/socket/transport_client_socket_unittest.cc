// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <string>

#include "base/bind.h"
#include "base/memory/ref_counted.h"
#include "base/run_loop.h"
#include "net/base/address_list.h"
#include "net/base/io_buffer.h"
#include "net/base/ip_address.h"
#include "net/base/net_errors.h"
#include "net/base/test_completion_callback.h"
#include "net/dns/mock_host_resolver.h"
#include "net/log/net_log.h"
#include "net/log/net_log_event_type.h"
#include "net/log/test_net_log.h"
#include "net/log/test_net_log_entry.h"
#include "net/log/test_net_log_util.h"
#include "net/socket/client_socket_factory.h"
#include "net/socket/tcp_client_socket.h"
#include "net/socket/tcp_server_socket.h"
#include "net/test/gtest_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "testing/platform_test.h"

using net::test::IsError;
using net::test::IsOk;

namespace net {

namespace {

const char kServerReply[] = "HTTP/1.1 404 Not Found";

enum ClientSocketTestTypes { TCP, SCTP };

}  // namespace

class TransportClientSocketTest
    : public ::testing::TestWithParam<ClientSocketTestTypes> {
 public:
  TransportClientSocketTest()
      : listen_port_(0),
        socket_factory_(ClientSocketFactory::GetDefaultFactory()),
        close_server_socket_on_next_send_(false) {}

  virtual ~TransportClientSocketTest() {}

  // Testcase hooks
  void SetUp() override;

  void CloseServerSocket() {
    // delete the connected_sock_, which will close it.
    connected_sock_.reset();
  }

  void AcceptCallback(int res) {
    ASSERT_THAT(res, IsOk());
    connect_loop_.Quit();
  }

  int DrainClientSocket(IOBuffer* buf,
                        uint32_t buf_len,
                        uint32_t bytes_to_read,
                        TestCompletionCallback* callback);

  // Establishes a connection to the server.
  void EstablishConnection(TestCompletionCallback* callback);

  // Sends a request from the client to the server socket. Makes the server read
  // the request and send a response.
  void SendRequestAndResponse();

  // Makes |connected_sock_| to read |expected_bytes_read| bytes. Returns the
  // the data read as a string.
  std::string ReadServerData(int expected_bytes_read);

  // Sends server response.
  void SendServerResponse();

  void set_close_server_socket_on_next_send(bool close) {
    close_server_socket_on_next_send_ = close;
  }

 protected:
  base::RunLoop connect_loop_;
  uint16_t listen_port_;
  TestNetLog net_log_;
  ClientSocketFactory* const socket_factory_;
  std::unique_ptr<StreamSocket> sock_;
  std::unique_ptr<StreamSocket> connected_sock_;

 private:
  std::unique_ptr<TCPServerSocket> listen_sock_;
  bool close_server_socket_on_next_send_;
};

void TransportClientSocketTest::SetUp() {
  ::testing::TestWithParam<ClientSocketTestTypes>::SetUp();

  // Open a server socket on an ephemeral port.
  listen_sock_.reset(new TCPServerSocket(NULL, NetLog::Source()));
  IPEndPoint local_address(IPAddress::IPv4Localhost(), 0);
  ASSERT_THAT(listen_sock_->Listen(local_address, 1), IsOk());
  // Get the server's address (including the actual port number).
  ASSERT_THAT(listen_sock_->GetLocalAddress(&local_address), IsOk());
  listen_port_ = local_address.port();
  listen_sock_->Accept(&connected_sock_,
                       base::Bind(&TransportClientSocketTest::AcceptCallback,
                                  base::Unretained(this)));

  AddressList addr;
  // MockHostResolver resolves everything to 127.0.0.1.
  std::unique_ptr<HostResolver> resolver(new MockHostResolver());
  HostResolver::RequestInfo info(HostPortPair("localhost", listen_port_));
  TestCompletionCallback callback;
  std::unique_ptr<HostResolver::Request> request;
  int rv = resolver->Resolve(info, DEFAULT_PRIORITY, &addr, callback.callback(),
                             &request, NetLogWithSource());
  CHECK_EQ(ERR_IO_PENDING, rv);
  rv = callback.WaitForResult();
  CHECK_EQ(rv, OK);
  sock_ = socket_factory_->CreateTransportClientSocket(addr, NULL, &net_log_,
                                                       NetLog::Source());
}

int TransportClientSocketTest::DrainClientSocket(
    IOBuffer* buf,
    uint32_t buf_len,
    uint32_t bytes_to_read,
    TestCompletionCallback* callback) {
  int rv = OK;
  uint32_t bytes_read = 0;

  while (bytes_read < bytes_to_read) {
    rv = sock_->Read(buf, buf_len, callback->callback());
    EXPECT_TRUE(rv >= 0 || rv == ERR_IO_PENDING);
    rv = callback->GetResult(rv);
    EXPECT_GT(rv, 0);
    bytes_read += rv;
  }

  return static_cast<int>(bytes_read);
}

void TransportClientSocketTest::EstablishConnection(
    TestCompletionCallback* callback) {
  int rv = sock_->Connect(callback->callback());
  // Wait for |listen_sock_| to accept a connection.
  connect_loop_.Run();
  // Now wait for the client socket to accept the connection.
  EXPECT_THAT(callback->GetResult(rv), IsOk());
}

void TransportClientSocketTest::SendRequestAndResponse() {
  // Send client request.
  const char request_text[] = "GET / HTTP/1.0\r\n\r\n";
  int request_len = strlen(request_text);
  scoped_refptr<DrainableIOBuffer> request_buffer(
      new DrainableIOBuffer(new IOBuffer(request_len), request_len));
  memcpy(request_buffer->data(), request_text, request_len);

  int bytes_written = 0;
  while (request_buffer->BytesRemaining() > 0) {
    TestCompletionCallback write_callback;
    int write_result =
        sock_->Write(request_buffer.get(), request_buffer->BytesRemaining(),
                     write_callback.callback());
    write_result = write_callback.GetResult(write_result);
    ASSERT_GT(write_result, 0);
    ASSERT_LE(bytes_written + write_result, request_len);
    request_buffer->DidConsume(write_result);
    bytes_written += write_result;
  }
  ASSERT_EQ(request_len, bytes_written);

  // Confirm that the server receives what client sent.
  std::string data_received = ReadServerData(bytes_written);
  ASSERT_TRUE(connected_sock_->IsConnectedAndIdle());
  ASSERT_EQ(request_text, data_received);

  // Write server response.
  SendServerResponse();
}

void TransportClientSocketTest::SendServerResponse() {
  // TODO(dkegel): this might not be long enough to tickle some bugs.
  int reply_len = strlen(kServerReply);
  scoped_refptr<DrainableIOBuffer> write_buffer(
      new DrainableIOBuffer(new IOBuffer(reply_len), reply_len));
  memcpy(write_buffer->data(), kServerReply, reply_len);
  int bytes_written = 0;
  while (write_buffer->BytesRemaining() > 0) {
    TestCompletionCallback write_callback;
    int write_result = connected_sock_->Write(write_buffer.get(),
                                              write_buffer->BytesRemaining(),
                                              write_callback.callback());
    write_result = write_callback.GetResult(write_result);
    ASSERT_GE(write_result, 0);
    ASSERT_LE(bytes_written + write_result, reply_len);
    write_buffer->DidConsume(write_result);
    bytes_written += write_result;
  }
  if (close_server_socket_on_next_send_)
    CloseServerSocket();
}

std::string TransportClientSocketTest::ReadServerData(int expected_bytes_read) {
  int bytes_read = 0;
  scoped_refptr<IOBufferWithSize> read_buffer(
      new IOBufferWithSize(expected_bytes_read));
  while (bytes_read < expected_bytes_read) {
    TestCompletionCallback read_callback;
    int rv = connected_sock_->Read(read_buffer.get(),
                                   expected_bytes_read - bytes_read,
                                   read_callback.callback());
    EXPECT_TRUE(rv >= 0 || rv == ERR_IO_PENDING);
    rv = read_callback.GetResult(rv);
    EXPECT_GE(rv, 0);
    bytes_read += rv;
  }
  EXPECT_EQ(expected_bytes_read, bytes_read);
  return std::string(read_buffer->data(), bytes_read);
}

// TODO(leighton):  Add SCTP to this list when it is ready.
INSTANTIATE_TEST_CASE_P(StreamSocket,
                        TransportClientSocketTest,
                        ::testing::Values(TCP));

TEST_P(TransportClientSocketTest, Connect) {
  TestCompletionCallback callback;
  EXPECT_FALSE(sock_->IsConnected());

  int rv = sock_->Connect(callback.callback());
  // Wait for |listen_sock_| to accept a connection.
  connect_loop_.Run();

  TestNetLogEntry::List net_log_entries;
  net_log_.GetEntries(&net_log_entries);
  EXPECT_TRUE(
      LogContainsBeginEvent(net_log_entries, 0, NetLogEventType::SOCKET_ALIVE));
  EXPECT_TRUE(
      LogContainsBeginEvent(net_log_entries, 1, NetLogEventType::TCP_CONNECT));
  // Now wait for the client socket to accept the connection.
  if (rv != OK) {
    ASSERT_EQ(rv, ERR_IO_PENDING);
    rv = callback.WaitForResult();
    EXPECT_EQ(rv, OK);
  }

  EXPECT_TRUE(sock_->IsConnected());
  net_log_.GetEntries(&net_log_entries);
  EXPECT_TRUE(
      LogContainsEndEvent(net_log_entries, -1, NetLogEventType::TCP_CONNECT));

  sock_->Disconnect();
  EXPECT_FALSE(sock_->IsConnected());
}

TEST_P(TransportClientSocketTest, IsConnected) {
  scoped_refptr<IOBuffer> buf(new IOBuffer(4096));
  TestCompletionCallback callback;
  uint32_t bytes_read;

  EXPECT_FALSE(sock_->IsConnected());
  EXPECT_FALSE(sock_->IsConnectedAndIdle());

  EstablishConnection(&callback);

  EXPECT_TRUE(sock_->IsConnected());
  EXPECT_TRUE(sock_->IsConnectedAndIdle());

  // Send the request and wait for the server to respond.
  SendRequestAndResponse();

  // Drain a single byte so we know we've received some data.
  bytes_read = DrainClientSocket(buf.get(), 1, 1, &callback);
  ASSERT_EQ(bytes_read, 1u);

  // Socket should be considered connected, but not idle, due to
  // pending data.
  EXPECT_TRUE(sock_->IsConnected());
  EXPECT_FALSE(sock_->IsConnectedAndIdle());

  bytes_read =
      DrainClientSocket(buf.get(), 4096, strlen(kServerReply) - 1, &callback);
  ASSERT_EQ(bytes_read, strlen(kServerReply) - 1);

  // After draining the data, the socket should be back to connected
  // and idle.
  EXPECT_TRUE(sock_->IsConnected());
  EXPECT_TRUE(sock_->IsConnectedAndIdle());

  // This time close the server socket immediately after the server response.
  set_close_server_socket_on_next_send(true);
  SendRequestAndResponse();

  bytes_read = DrainClientSocket(buf.get(), 1, 1, &callback);
  ASSERT_EQ(bytes_read, 1u);

  // As above because of data.
  EXPECT_TRUE(sock_->IsConnected());
  EXPECT_FALSE(sock_->IsConnectedAndIdle());

  bytes_read =
      DrainClientSocket(buf.get(), 4096, strlen(kServerReply) - 1, &callback);
  ASSERT_EQ(bytes_read, strlen(kServerReply) - 1);

  // Once the data is drained, the socket should now be seen as not
  // connected.
  if (sock_->IsConnected()) {
    // In the unlikely event that the server's connection closure is not
    // processed in time, wait for the connection to be closed.
    int rv = sock_->Read(buf.get(), 4096, callback.callback());
    EXPECT_EQ(0, callback.GetResult(rv));
    EXPECT_FALSE(sock_->IsConnected());
  }
  EXPECT_FALSE(sock_->IsConnectedAndIdle());
}

TEST_P(TransportClientSocketTest, Read) {
  TestCompletionCallback callback;
  EstablishConnection(&callback);

  SendRequestAndResponse();

  scoped_refptr<IOBuffer> buf(new IOBuffer(4096));
  uint32_t bytes_read =
      DrainClientSocket(buf.get(), 4096, strlen(kServerReply), &callback);
  ASSERT_EQ(bytes_read, strlen(kServerReply));
  ASSERT_EQ(std::string(kServerReply), std::string(buf->data(), bytes_read));

  // All data has been read now.  Read once more to force an ERR_IO_PENDING, and
  // then close the server socket, and note the close.

  int rv = sock_->Read(buf.get(), 4096, callback.callback());
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));
  CloseServerSocket();
  EXPECT_EQ(0, callback.WaitForResult());
}

TEST_P(TransportClientSocketTest, Read_SmallChunks) {
  TestCompletionCallback callback;
  EstablishConnection(&callback);

  SendRequestAndResponse();

  scoped_refptr<IOBuffer> buf(new IOBuffer(1));
  uint32_t bytes_read = 0;
  while (bytes_read < strlen(kServerReply)) {
    int rv = sock_->Read(buf.get(), 1, callback.callback());
    EXPECT_TRUE(rv >= 0 || rv == ERR_IO_PENDING);

    rv = callback.GetResult(rv);

    ASSERT_EQ(1, rv);
    bytes_read += rv;
  }

  // All data has been read now.  Read once more to force an ERR_IO_PENDING, and
  // then close the server socket, and note the close.

  int rv = sock_->Read(buf.get(), 1, callback.callback());
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));
  CloseServerSocket();
  EXPECT_EQ(0, callback.WaitForResult());
}

TEST_P(TransportClientSocketTest, Read_Interrupted) {
  TestCompletionCallback callback;
  EstablishConnection(&callback);

  SendRequestAndResponse();

  // Do a partial read and then exit.  This test should not crash!
  scoped_refptr<IOBuffer> buf(new IOBuffer(16));
  int rv = sock_->Read(buf.get(), 16, callback.callback());
  EXPECT_TRUE(rv >= 0 || rv == ERR_IO_PENDING);

  rv = callback.GetResult(rv);

  EXPECT_NE(0, rv);
}

TEST_P(TransportClientSocketTest, FullDuplex_ReadFirst) {
  TestCompletionCallback callback;
  EstablishConnection(&callback);

  // Read first.  There's no data, so it should return ERR_IO_PENDING.
  const int kBufLen = 4096;
  scoped_refptr<IOBuffer> buf(new IOBuffer(kBufLen));
  int rv = sock_->Read(buf.get(), kBufLen, callback.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  const int kWriteBufLen = 64 * 1024;
  scoped_refptr<IOBuffer> request_buffer(new IOBuffer(kWriteBufLen));
  char* request_data = request_buffer->data();
  memset(request_data, 'A', kWriteBufLen);
  TestCompletionCallback write_callback;

  int bytes_written = 0;
  while (true) {
    rv = sock_->Write(request_buffer.get(), kWriteBufLen,
                      write_callback.callback());
    ASSERT_TRUE(rv >= 0 || rv == ERR_IO_PENDING);
    if (rv == ERR_IO_PENDING) {
      ReadServerData(bytes_written);
      SendServerResponse();
      rv = write_callback.WaitForResult();
      break;
    }
    bytes_written += rv;
  }

  // At this point, both read and write have returned ERR_IO_PENDING, and the
  // write callback has executed.  We wait for the read callback to run now to
  // make sure that the socket can handle full duplex communications.

  rv = callback.WaitForResult();
  EXPECT_GE(rv, 0);
}

// FLaky on Win 10 Tests x64 builder: http://crbug/552053
TEST_P(TransportClientSocketTest, DISABLED_FullDuplex_WriteFirst) {
  TestCompletionCallback callback;
  EstablishConnection(&callback);

  const int kWriteBufLen = 64 * 1024;
  scoped_refptr<IOBuffer> request_buffer(new IOBuffer(kWriteBufLen));
  char* request_data = request_buffer->data();
  memset(request_data, 'A', kWriteBufLen);
  TestCompletionCallback write_callback;

  int bytes_written = 0;
  while (true) {
    int rv = sock_->Write(request_buffer.get(), kWriteBufLen,
                          write_callback.callback());
    ASSERT_TRUE(rv >= 0 || rv == ERR_IO_PENDING);

    if (rv == ERR_IO_PENDING)
      break;
    bytes_written += rv;
  }

  // Now we have the Write() blocked on ERR_IO_PENDING.  It's time to force the
  // Read() to block on ERR_IO_PENDING too.

  const int kBufLen = 4096;
  scoped_refptr<IOBuffer> buf(new IOBuffer(kBufLen));
  while (true) {
    int rv = sock_->Read(buf.get(), kBufLen, callback.callback());
    ASSERT_TRUE(rv >= 0 || rv == ERR_IO_PENDING);
    if (rv == ERR_IO_PENDING)
      break;
  }

  // At this point, both read and write have returned ERR_IO_PENDING.  Now we
  // run the write and read callbacks to make sure they can handle full duplex
  // communications.

  ReadServerData(bytes_written);
  SendServerResponse();
  int rv = write_callback.WaitForResult();
  EXPECT_GE(rv, 0);

  // It's possible the read is blocked because it's already read all the data.
  // Close the server socket, so there will at least be a 0-byte read.
  CloseServerSocket();

  rv = callback.WaitForResult();
  EXPECT_GE(rv, 0);
}

}  // namespace net
