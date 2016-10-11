// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file contains some tests for TCPClientSocket.
// transport_client_socket_unittest.cc contans some other tests that
// are common for TCP and other types of sockets.

#include "net/socket/tcp_client_socket.h"

#include <stddef.h>

#include "net/base/ip_address.h"
#include "net/base/ip_endpoint.h"
#include "net/base/net_errors.h"
#include "net/base/test_completion_callback.h"
#include "net/log/net_log_source.h"
#include "net/socket/socket_performance_watcher.h"
#include "net/socket/tcp_server_socket.h"
#include "net/test/gtest_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using net::test::IsError;
using net::test::IsOk;

namespace base {
class TimeDelta;
}

namespace net {

namespace {

// Try binding a socket to loopback interface and verify that we can
// still connect to a server on the same interface.
TEST(TCPClientSocketTest, BindLoopbackToLoopback) {
  IPAddress lo_address = IPAddress::IPv4Localhost();

  TCPServerSocket server(NULL, NetLogSource());
  ASSERT_THAT(server.Listen(IPEndPoint(lo_address, 0), 1), IsOk());
  IPEndPoint server_address;
  ASSERT_THAT(server.GetLocalAddress(&server_address), IsOk());

  TCPClientSocket socket(AddressList(server_address), NULL, NULL,
                         NetLogSource());

  EXPECT_THAT(socket.Bind(IPEndPoint(lo_address, 0)), IsOk());

  IPEndPoint local_address_result;
  EXPECT_THAT(socket.GetLocalAddress(&local_address_result), IsOk());
  EXPECT_EQ(lo_address, local_address_result.address());

  TestCompletionCallback connect_callback;
  EXPECT_THAT(socket.Connect(connect_callback.callback()),
              IsError(ERR_IO_PENDING));

  TestCompletionCallback accept_callback;
  std::unique_ptr<StreamSocket> accepted_socket;
  int result = server.Accept(&accepted_socket, accept_callback.callback());
  if (result == ERR_IO_PENDING)
    result = accept_callback.WaitForResult();
  ASSERT_THAT(result, IsOk());

  EXPECT_THAT(connect_callback.WaitForResult(), IsOk());

  EXPECT_TRUE(socket.IsConnected());
  socket.Disconnect();
  EXPECT_FALSE(socket.IsConnected());
  EXPECT_EQ(ERR_SOCKET_NOT_CONNECTED,
            socket.GetLocalAddress(&local_address_result));
}

// Try to bind socket to the loopback interface and connect to an
// external address, verify that connection fails.
TEST(TCPClientSocketTest, BindLoopbackToExternal) {
  IPAddress external_ip(72, 14, 213, 105);
  TCPClientSocket socket(AddressList::CreateFromIPAddress(external_ip, 80),
                         NULL, NULL, NetLogSource());

  EXPECT_THAT(socket.Bind(IPEndPoint(IPAddress::IPv4Localhost(), 0)), IsOk());

  TestCompletionCallback connect_callback;
  int result = socket.Connect(connect_callback.callback());
  if (result == ERR_IO_PENDING)
    result = connect_callback.WaitForResult();

  // We may get different errors here on different system, but
  // connect() is not expected to succeed.
  EXPECT_NE(OK, result);
}

// Bind a socket to the IPv4 loopback interface and try to connect to
// the IPv6 loopback interface, verify that connection fails.
TEST(TCPClientSocketTest, BindLoopbackToIPv6) {
  TCPServerSocket server(NULL, NetLogSource());
  int listen_result =
      server.Listen(IPEndPoint(IPAddress::IPv6Localhost(), 0), 1);
  if (listen_result != OK) {
    LOG(ERROR) << "Failed to listen on ::1 - probably because IPv6 is disabled."
        " Skipping the test";
    return;
  }

  IPEndPoint server_address;
  ASSERT_THAT(server.GetLocalAddress(&server_address), IsOk());
  TCPClientSocket socket(AddressList(server_address), NULL, NULL,
                         NetLogSource());

  EXPECT_THAT(socket.Bind(IPEndPoint(IPAddress::IPv4Localhost(), 0)), IsOk());

  TestCompletionCallback connect_callback;
  int result = socket.Connect(connect_callback.callback());
  if (result == ERR_IO_PENDING)
    result = connect_callback.WaitForResult();

  EXPECT_NE(OK, result);
}

class TestSocketPerformanceWatcher : public SocketPerformanceWatcher {
 public:
  TestSocketPerformanceWatcher() : connection_changed_count_(0u) {}
  ~TestSocketPerformanceWatcher() override {}

  bool ShouldNotifyUpdatedRTT() const override { return true; }

  void OnUpdatedRTTAvailable(const base::TimeDelta& rtt) override {}

  void OnConnectionChanged() override { connection_changed_count_++; }

  size_t connection_changed_count() const { return connection_changed_count_; }

 private:
  size_t connection_changed_count_;

  DISALLOW_COPY_AND_ASSIGN(TestSocketPerformanceWatcher);
};

// TestSocketPerformanceWatcher requires kernel support for tcp_info struct, and
// so it is enabled only on certain platforms.
#if defined(TCP_INFO) || defined(OS_LINUX)
#define MAYBE_TestSocketPerformanceWatcher TestSocketPerformanceWatcher
#else
#define MAYBE_TestSocketPerformanceWatcher TestSocketPerformanceWatcher
#endif
// Tests if the socket performance watcher is notified if the same socket is
// used for a different connection.
TEST(TCPClientSocketTest, MAYBE_TestSocketPerformanceWatcher) {
  const size_t kNumIPs = 2;
  IPAddressList ip_list;
  for (size_t i = 0; i < kNumIPs; ++i)
    ip_list.push_back(IPAddress(72, 14, 213, i));

  std::unique_ptr<TestSocketPerformanceWatcher> watcher(
      new TestSocketPerformanceWatcher());
  TestSocketPerformanceWatcher* watcher_ptr = watcher.get();

  TCPClientSocket socket(
      AddressList::CreateFromIPAddressList(ip_list, "example.com"),
      std::move(watcher), NULL, NetLogSource());

  EXPECT_THAT(socket.Bind(IPEndPoint(IPAddress::IPv4Localhost(), 0)), IsOk());

  TestCompletionCallback connect_callback;

  ASSERT_NE(OK, connect_callback.GetResult(
                    socket.Connect(connect_callback.callback())));

  EXPECT_EQ(kNumIPs - 1, watcher_ptr->connection_changed_count());
}

}  // namespace

}  // namespace net
