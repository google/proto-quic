// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/socket/tcp_socket.h"

#include <stddef.h>
#include <string.h>

#include <memory>
#include <string>
#include <vector>

#include "base/memory/ref_counted.h"
#include "base/time/time.h"
#include "net/base/address_list.h"
#include "net/base/io_buffer.h"
#include "net/base/ip_endpoint.h"
#include "net/base/net_errors.h"
#include "net/base/sockaddr_storage.h"
#include "net/base/test_completion_callback.h"
#include "net/log/net_log_source.h"
#include "net/socket/socket_performance_watcher.h"
#include "net/socket/tcp_client_socket.h"
#include "net/test/gtest_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "testing/platform_test.h"

using net::test::IsOk;

namespace net {

namespace {

class TestSocketPerformanceWatcher : public SocketPerformanceWatcher {
 public:
  explicit TestSocketPerformanceWatcher(bool should_notify_updated_rtt)
      : should_notify_updated_rtt_(should_notify_updated_rtt),
        connection_changed_count_(0u),
        rtt_notification_count_(0u) {}
  ~TestSocketPerformanceWatcher() override {}

  bool ShouldNotifyUpdatedRTT() const override {
    return should_notify_updated_rtt_;
  }

  void OnUpdatedRTTAvailable(const base::TimeDelta& rtt) override {
    rtt_notification_count_++;
  }

  void OnConnectionChanged() override { connection_changed_count_++; }

  size_t rtt_notification_count() const { return rtt_notification_count_; }

  size_t connection_changed_count() const { return connection_changed_count_; }

 private:
  const bool should_notify_updated_rtt_;
  size_t connection_changed_count_;
  size_t rtt_notification_count_;

  DISALLOW_COPY_AND_ASSIGN(TestSocketPerformanceWatcher);
};

const int kListenBacklog = 5;

class TCPSocketTest : public PlatformTest {
 protected:
  TCPSocketTest() : socket_(NULL, NULL, NetLogSource()) {}

  void SetUpListenIPv4() {
    ASSERT_THAT(socket_.Open(ADDRESS_FAMILY_IPV4), IsOk());
    ASSERT_THAT(socket_.Bind(IPEndPoint(IPAddress::IPv4Localhost(), 0)),
                IsOk());
    ASSERT_THAT(socket_.Listen(kListenBacklog), IsOk());
    ASSERT_THAT(socket_.GetLocalAddress(&local_address_), IsOk());
  }

  void SetUpListenIPv6(bool* success) {
    *success = false;

    if (socket_.Open(ADDRESS_FAMILY_IPV6) != OK ||
        socket_.Bind(IPEndPoint(IPAddress::IPv6Localhost(), 0)) != OK ||
        socket_.Listen(kListenBacklog) != OK) {
      LOG(ERROR) << "Failed to listen on ::1 - probably because IPv6 is "
          "disabled. Skipping the test";
      return;
    }
    ASSERT_THAT(socket_.GetLocalAddress(&local_address_), IsOk());
    *success = true;
  }

  void TestAcceptAsync() {
    TestCompletionCallback accept_callback;
    std::unique_ptr<TCPSocket> accepted_socket;
    IPEndPoint accepted_address;
    ASSERT_EQ(ERR_IO_PENDING,
              socket_.Accept(&accepted_socket, &accepted_address,
                             accept_callback.callback()));

    TestCompletionCallback connect_callback;
    TCPClientSocket connecting_socket(local_address_list(), NULL, NULL,
                                      NetLogSource());
    connecting_socket.Connect(connect_callback.callback());

    EXPECT_THAT(connect_callback.WaitForResult(), IsOk());
    EXPECT_THAT(accept_callback.WaitForResult(), IsOk());

    EXPECT_TRUE(accepted_socket.get());

    // Both sockets should be on the loopback network interface.
    EXPECT_EQ(accepted_address.address(), local_address_.address());
  }

#if defined(TCP_INFO) || defined(OS_LINUX)
  // Tests that notifications to Socket Performance Watcher (SPW) are delivered
  // correctly. |should_notify_updated_rtt| is true if the SPW is interested in
  // receiving RTT notifications. |num_messages| is the number of messages that
  // are written/read by the sockets. |expect_connection_changed_count| is the
  // expected number of connection change notifications received by the SPW.
  // |expect_rtt_notification_count| is the expected number of RTT
  // notifications received by the SPW. This test works by writing
  // |num_messages| to the socket. A different socket (with a SPW attached to
  // it) reads the messages.
  void TestSPWNotifications(bool should_notify_updated_rtt,
                            size_t num_messages,
                            size_t expect_connection_changed_count,
                            size_t expect_rtt_notification_count) {
    ASSERT_NO_FATAL_FAILURE(SetUpListenIPv4());

    TestCompletionCallback connect_callback;

    std::unique_ptr<TestSocketPerformanceWatcher> watcher(
        new TestSocketPerformanceWatcher(should_notify_updated_rtt));
    TestSocketPerformanceWatcher* watcher_ptr = watcher.get();

    TCPSocket connecting_socket(std::move(watcher), NULL, NetLogSource());

    int result = connecting_socket.Open(ADDRESS_FAMILY_IPV4);
    ASSERT_THAT(result, IsOk());
    connecting_socket.Connect(local_address_, connect_callback.callback());

    TestCompletionCallback accept_callback;
    std::unique_ptr<TCPSocket> accepted_socket;
    IPEndPoint accepted_address;
    result = socket_.Accept(&accepted_socket, &accepted_address,
                            accept_callback.callback());
    ASSERT_THAT(accept_callback.GetResult(result), IsOk());

    ASSERT_TRUE(accepted_socket.get());

    // Both sockets should be on the loopback network interface.
    EXPECT_EQ(accepted_address.address(), local_address_.address());

    ASSERT_THAT(connect_callback.WaitForResult(), IsOk());

    for (size_t i = 0; i < num_messages; ++i) {
      // Use a 1 byte message so that the watcher is notified at most once per
      // message.
      const std::string message("t");

      scoped_refptr<IOBufferWithSize> write_buffer(
          new IOBufferWithSize(message.size()));
      memmove(write_buffer->data(), message.data(), message.size());

      TestCompletionCallback write_callback;
      int write_result = accepted_socket->Write(
          write_buffer.get(), write_buffer->size(), write_callback.callback());

      scoped_refptr<IOBufferWithSize> read_buffer(
          new IOBufferWithSize(message.size()));
      TestCompletionCallback read_callback;
      int read_result = connecting_socket.Read(
          read_buffer.get(), read_buffer->size(), read_callback.callback());

      ASSERT_EQ(1, write_callback.GetResult(write_result));
      ASSERT_EQ(1, read_callback.GetResult(read_result));
    }
    EXPECT_EQ(expect_connection_changed_count,
              watcher_ptr->connection_changed_count());
    EXPECT_EQ(expect_rtt_notification_count,
              watcher_ptr->rtt_notification_count());
  }
#endif  // defined(TCP_INFO) || defined(OS_LINUX)

  AddressList local_address_list() const {
    return AddressList(local_address_);
  }

  TCPSocket socket_;
  IPEndPoint local_address_;
};

// Test listening and accepting with a socket bound to an IPv4 address.
TEST_F(TCPSocketTest, Accept) {
  ASSERT_NO_FATAL_FAILURE(SetUpListenIPv4());

  TestCompletionCallback connect_callback;
  // TODO(yzshen): Switch to use TCPSocket when it supports client socket
  // operations.
  TCPClientSocket connecting_socket(local_address_list(), NULL, NULL,
                                    NetLogSource());
  connecting_socket.Connect(connect_callback.callback());

  TestCompletionCallback accept_callback;
  std::unique_ptr<TCPSocket> accepted_socket;
  IPEndPoint accepted_address;
  int result = socket_.Accept(&accepted_socket, &accepted_address,
                              accept_callback.callback());
  if (result == ERR_IO_PENDING)
    result = accept_callback.WaitForResult();
  ASSERT_THAT(result, IsOk());

  EXPECT_TRUE(accepted_socket.get());

  // Both sockets should be on the loopback network interface.
  EXPECT_EQ(accepted_address.address(), local_address_.address());

  EXPECT_THAT(connect_callback.WaitForResult(), IsOk());
}

// Test Accept() callback.
TEST_F(TCPSocketTest, AcceptAsync) {
  ASSERT_NO_FATAL_FAILURE(SetUpListenIPv4());
  TestAcceptAsync();
}

#if defined(OS_WIN)
// Test Accept() for AdoptListenSocket.
TEST_F(TCPSocketTest, AcceptForAdoptedListenSocket) {
  // Create a socket to be used with AdoptListenSocket.
  SOCKET existing_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  ASSERT_THAT(socket_.AdoptListenSocket(existing_socket), IsOk());

  IPEndPoint address(IPAddress::IPv4Localhost(), 0);
  SockaddrStorage storage;
  ASSERT_TRUE(address.ToSockAddr(storage.addr, &storage.addr_len));
  ASSERT_EQ(0, bind(existing_socket, storage.addr, storage.addr_len));

  ASSERT_THAT(socket_.Listen(kListenBacklog), IsOk());
  ASSERT_THAT(socket_.GetLocalAddress(&local_address_), IsOk());

  TestAcceptAsync();
}
#endif

// Accept two connections simultaneously.
TEST_F(TCPSocketTest, Accept2Connections) {
  ASSERT_NO_FATAL_FAILURE(SetUpListenIPv4());

  TestCompletionCallback accept_callback;
  std::unique_ptr<TCPSocket> accepted_socket;
  IPEndPoint accepted_address;

  ASSERT_EQ(ERR_IO_PENDING,
            socket_.Accept(&accepted_socket, &accepted_address,
                           accept_callback.callback()));

  TestCompletionCallback connect_callback;
  TCPClientSocket connecting_socket(local_address_list(), NULL, NULL,
                                    NetLogSource());
  connecting_socket.Connect(connect_callback.callback());

  TestCompletionCallback connect_callback2;
  TCPClientSocket connecting_socket2(local_address_list(), NULL, NULL,
                                     NetLogSource());
  connecting_socket2.Connect(connect_callback2.callback());

  EXPECT_THAT(accept_callback.WaitForResult(), IsOk());

  TestCompletionCallback accept_callback2;
  std::unique_ptr<TCPSocket> accepted_socket2;
  IPEndPoint accepted_address2;

  int result = socket_.Accept(&accepted_socket2, &accepted_address2,
                              accept_callback2.callback());
  if (result == ERR_IO_PENDING)
    result = accept_callback2.WaitForResult();
  ASSERT_THAT(result, IsOk());

  EXPECT_THAT(connect_callback.WaitForResult(), IsOk());
  EXPECT_THAT(connect_callback2.WaitForResult(), IsOk());

  EXPECT_TRUE(accepted_socket.get());
  EXPECT_TRUE(accepted_socket2.get());
  EXPECT_NE(accepted_socket.get(), accepted_socket2.get());

  EXPECT_EQ(accepted_address.address(), local_address_.address());
  EXPECT_EQ(accepted_address2.address(), local_address_.address());
}

// Test listening and accepting with a socket bound to an IPv6 address.
TEST_F(TCPSocketTest, AcceptIPv6) {
  bool initialized = false;
  ASSERT_NO_FATAL_FAILURE(SetUpListenIPv6(&initialized));
  if (!initialized)
    return;

  TestCompletionCallback connect_callback;
  TCPClientSocket connecting_socket(local_address_list(), NULL, NULL,
                                    NetLogSource());
  connecting_socket.Connect(connect_callback.callback());

  TestCompletionCallback accept_callback;
  std::unique_ptr<TCPSocket> accepted_socket;
  IPEndPoint accepted_address;
  int result = socket_.Accept(&accepted_socket, &accepted_address,
                              accept_callback.callback());
  if (result == ERR_IO_PENDING)
    result = accept_callback.WaitForResult();
  ASSERT_THAT(result, IsOk());

  EXPECT_TRUE(accepted_socket.get());

  // Both sockets should be on the loopback network interface.
  EXPECT_EQ(accepted_address.address(), local_address_.address());

  EXPECT_THAT(connect_callback.WaitForResult(), IsOk());
}

TEST_F(TCPSocketTest, ReadWrite) {
  ASSERT_NO_FATAL_FAILURE(SetUpListenIPv4());

  TestCompletionCallback connect_callback;
  TCPSocket connecting_socket(NULL, NULL, NetLogSource());
  int result = connecting_socket.Open(ADDRESS_FAMILY_IPV4);
  ASSERT_THAT(result, IsOk());
  connecting_socket.Connect(local_address_, connect_callback.callback());

  TestCompletionCallback accept_callback;
  std::unique_ptr<TCPSocket> accepted_socket;
  IPEndPoint accepted_address;
  result = socket_.Accept(&accepted_socket, &accepted_address,
                          accept_callback.callback());
  ASSERT_THAT(accept_callback.GetResult(result), IsOk());

  ASSERT_TRUE(accepted_socket.get());

  // Both sockets should be on the loopback network interface.
  EXPECT_EQ(accepted_address.address(), local_address_.address());

  EXPECT_THAT(connect_callback.WaitForResult(), IsOk());

  const std::string message("test message");
  std::vector<char> buffer(message.size());

  size_t bytes_written = 0;
  while (bytes_written < message.size()) {
    scoped_refptr<IOBufferWithSize> write_buffer(
        new IOBufferWithSize(message.size() - bytes_written));
    memmove(write_buffer->data(), message.data() + bytes_written,
            message.size() - bytes_written);

    TestCompletionCallback write_callback;
    int write_result = accepted_socket->Write(
        write_buffer.get(), write_buffer->size(), write_callback.callback());
    write_result = write_callback.GetResult(write_result);
    ASSERT_TRUE(write_result >= 0);
    bytes_written += write_result;
    ASSERT_TRUE(bytes_written <= message.size());
  }

  size_t bytes_read = 0;
  while (bytes_read < message.size()) {
    scoped_refptr<IOBufferWithSize> read_buffer(
        new IOBufferWithSize(message.size() - bytes_read));
    TestCompletionCallback read_callback;
    int read_result = connecting_socket.Read(
        read_buffer.get(), read_buffer->size(), read_callback.callback());
    read_result = read_callback.GetResult(read_result);
    ASSERT_TRUE(read_result >= 0);
    ASSERT_TRUE(bytes_read + read_result <= message.size());
    memmove(&buffer[bytes_read], read_buffer->data(), read_result);
    bytes_read += read_result;
  }

  std::string received_message(buffer.begin(), buffer.end());
  ASSERT_EQ(message, received_message);
}

// These tests require kernel support for tcp_info struct, and so they are
// enabled only on certain platforms.
#if defined(TCP_INFO) || defined(OS_LINUX)
// If SocketPerformanceWatcher::ShouldNotifyUpdatedRTT always returns false,
// then the wtatcher should not receive any notifications.
TEST_F(TCPSocketTest, SPWNotInterested) {
  TestSPWNotifications(false, 2u, 0u, 0u);
}

// One notification should be received when the socket connects. One
// additional notification should be received for each message read.
TEST_F(TCPSocketTest, SPWNoAdvance) {
  TestSPWNotifications(true, 2u, 0u, 3u);
}
#endif  // defined(TCP_INFO) || defined(OS_LINUX)

}  // namespace
}  // namespace net
