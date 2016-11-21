// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/socket/udp_socket.h"

#include "base/bind.h"
#include "base/location.h"
#include "base/macros.h"
#include "base/memory/ptr_util.h"
#include "base/memory/weak_ptr.h"
#include "base/run_loop.h"
#include "base/single_thread_task_runner.h"
#include "base/threading/thread_task_runner_handle.h"
#include "net/base/io_buffer.h"
#include "net/base/ip_address.h"
#include "net/base/ip_endpoint.h"
#include "net/base/net_errors.h"
#include "net/base/test_completion_callback.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_source.h"
#include "net/log/test_net_log.h"
#include "net/log/test_net_log_entry.h"
#include "net/log/test_net_log_util.h"
#include "net/socket/udp_client_socket.h"
#include "net/socket/udp_server_socket.h"
#include "net/test/gtest_util.h"
#include "net/test/net_test_suite.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "testing/platform_test.h"

#if defined(OS_ANDROID)
#include "base/android/build_info.h"
#endif

#if defined(OS_IOS)
#include <TargetConditionals.h>
#endif

using net::test::IsError;
using net::test::IsOk;

namespace net {

namespace {

class UDPSocketTest : public PlatformTest {
 public:
  UDPSocketTest() : buffer_(new IOBufferWithSize(kMaxRead)) {}

  // Blocks until data is read from the socket.
  std::string RecvFromSocket(UDPServerSocket* socket) {
    TestCompletionCallback callback;

    int rv = socket->RecvFrom(
        buffer_.get(), kMaxRead, &recv_from_address_, callback.callback());
    if (rv == ERR_IO_PENDING)
      rv = callback.WaitForResult();
    if (rv < 0)
      return std::string();  // error!
    return std::string(buffer_->data(), rv);
  }

  // Loop until |msg| has been written to the socket or until an
  // error occurs.
  // If |address| is specified, then it is used for the destination
  // to send to. Otherwise, will send to the last socket this server
  // received from.
  int SendToSocket(UDPServerSocket* socket, const std::string& msg) {
    return SendToSocket(socket, msg, recv_from_address_);
  }

  int SendToSocket(UDPServerSocket* socket,
                   std::string msg,
                   const IPEndPoint& address) {
    TestCompletionCallback callback;

    int length = msg.length();
    scoped_refptr<StringIOBuffer> io_buffer(new StringIOBuffer(msg));
    scoped_refptr<DrainableIOBuffer> buffer(
        new DrainableIOBuffer(io_buffer.get(), length));

    int bytes_sent = 0;
    while (buffer->BytesRemaining()) {
      int rv = socket->SendTo(
          buffer.get(), buffer->BytesRemaining(), address, callback.callback());
      if (rv == ERR_IO_PENDING)
        rv = callback.WaitForResult();
      if (rv <= 0)
        return bytes_sent > 0 ? bytes_sent : rv;
      bytes_sent += rv;
      buffer->DidConsume(rv);
    }
    return bytes_sent;
  }

  std::string ReadSocket(UDPClientSocket* socket) {
    TestCompletionCallback callback;

    int rv = socket->Read(buffer_.get(), kMaxRead, callback.callback());
    if (rv == ERR_IO_PENDING)
      rv = callback.WaitForResult();
    if (rv < 0)
      return std::string();  // error!
    return std::string(buffer_->data(), rv);
  }

  // Loop until |msg| has been written to the socket or until an
  // error occurs.
  int WriteSocket(UDPClientSocket* socket, const std::string& msg) {
    TestCompletionCallback callback;

    int length = msg.length();
    scoped_refptr<StringIOBuffer> io_buffer(new StringIOBuffer(msg));
    scoped_refptr<DrainableIOBuffer> buffer(
        new DrainableIOBuffer(io_buffer.get(), length));

    int bytes_sent = 0;
    while (buffer->BytesRemaining()) {
      int rv = socket->Write(
          buffer.get(), buffer->BytesRemaining(), callback.callback());
      if (rv == ERR_IO_PENDING)
        rv = callback.WaitForResult();
      if (rv <= 0)
        return bytes_sent > 0 ? bytes_sent : rv;
      bytes_sent += rv;
      buffer->DidConsume(rv);
    }
    return bytes_sent;
  }

  void WriteSocketIgnoreResult(UDPClientSocket* socket,
                               const std::string& msg) {
    WriteSocket(socket, msg);
  }

  // Creates an address from ip address and port and writes it to |*address|.
  void CreateUDPAddress(const std::string& ip_str,
                        uint16_t port,
                        IPEndPoint* address) {
    IPAddress ip_address;
    if (!ip_address.AssignFromIPLiteral(ip_str))
      return;
    *address = IPEndPoint(ip_address, port);
  }

  // Run unit test for a connection test.
  // |use_nonblocking_io| is used to switch between overlapped and non-blocking
  // IO on Windows. It has no effect in other ports.
  void ConnectTest(bool use_nonblocking_io);

 protected:
  static const int kMaxRead = 1024;
  scoped_refptr<IOBufferWithSize> buffer_;
  IPEndPoint recv_from_address_;
};

void ReadCompleteCallback(int* result_out, base::Closure callback, int result) {
  *result_out = result;
  callback.Run();
}

void UDPSocketTest::ConnectTest(bool use_nonblocking_io) {
  const uint16_t kPort = 9999;
  std::string simple_message("hello world!");

  // Setup the server to listen.
  IPEndPoint bind_address;
  CreateUDPAddress("127.0.0.1", kPort, &bind_address);
  TestNetLog server_log;
  std::unique_ptr<UDPServerSocket> server(
      new UDPServerSocket(&server_log, NetLogSource()));
  if (use_nonblocking_io)
    server->UseNonBlockingIO();
  server->AllowAddressReuse();
  int rv = server->Listen(bind_address);
  ASSERT_THAT(rv, IsOk());

  // Setup the client.
  IPEndPoint server_address;
  CreateUDPAddress("127.0.0.1", kPort, &server_address);
  TestNetLog client_log;
  std::unique_ptr<UDPClientSocket> client(
      new UDPClientSocket(DatagramSocket::DEFAULT_BIND, RandIntCallback(),
                          &client_log, NetLogSource()));
  if (use_nonblocking_io)
    client->UseNonBlockingIO();

  rv = client->Connect(server_address);
  EXPECT_THAT(rv, IsOk());

  // Client sends to the server.
  rv = WriteSocket(client.get(), simple_message);
  EXPECT_EQ(simple_message.length(), static_cast<size_t>(rv));

  // Server waits for message.
  std::string str = RecvFromSocket(server.get());
  DCHECK(simple_message == str);

  // Server echoes reply.
  rv = SendToSocket(server.get(), simple_message);
  EXPECT_EQ(simple_message.length(), static_cast<size_t>(rv));

  // Client waits for response.
  str = ReadSocket(client.get());
  DCHECK(simple_message == str);

  // Test asynchronous read. Server waits for message.
  base::RunLoop run_loop;
  int read_result = 0;
  rv = server->RecvFrom(
      buffer_.get(), kMaxRead, &recv_from_address_,
      base::Bind(&ReadCompleteCallback, &read_result, run_loop.QuitClosure()));
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Client sends to the server.
  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE,
      base::Bind(&UDPSocketTest::WriteSocketIgnoreResult,
                 base::Unretained(this), client.get(), simple_message));
  run_loop.Run();
  EXPECT_EQ(simple_message.length(), static_cast<size_t>(read_result));
  EXPECT_EQ(simple_message, std::string(buffer_->data(), read_result));

  // Delete sockets so they log their final events.
  server.reset();
  client.reset();

  // Check the server's log.
  TestNetLogEntry::List server_entries;
  server_log.GetEntries(&server_entries);
  EXPECT_EQ(5u, server_entries.size());
  EXPECT_TRUE(
      LogContainsBeginEvent(server_entries, 0, NetLogEventType::SOCKET_ALIVE));
  EXPECT_TRUE(LogContainsEvent(server_entries, 1,
                               NetLogEventType::UDP_BYTES_RECEIVED,
                               NetLogEventPhase::NONE));
  EXPECT_TRUE(LogContainsEvent(server_entries, 2,
                               NetLogEventType::UDP_BYTES_SENT,
                               NetLogEventPhase::NONE));
  EXPECT_TRUE(LogContainsEvent(server_entries, 3,
                               NetLogEventType::UDP_BYTES_RECEIVED,
                               NetLogEventPhase::NONE));
  EXPECT_TRUE(
      LogContainsEndEvent(server_entries, 4, NetLogEventType::SOCKET_ALIVE));

  // Check the client's log.
  TestNetLogEntry::List client_entries;
  client_log.GetEntries(&client_entries);
  EXPECT_EQ(7u, client_entries.size());
  EXPECT_TRUE(
      LogContainsBeginEvent(client_entries, 0, NetLogEventType::SOCKET_ALIVE));
  EXPECT_TRUE(
      LogContainsBeginEvent(client_entries, 1, NetLogEventType::UDP_CONNECT));
  EXPECT_TRUE(
      LogContainsEndEvent(client_entries, 2, NetLogEventType::UDP_CONNECT));
  EXPECT_TRUE(LogContainsEvent(client_entries, 3,
                               NetLogEventType::UDP_BYTES_SENT,
                               NetLogEventPhase::NONE));
  EXPECT_TRUE(LogContainsEvent(client_entries, 4,
                               NetLogEventType::UDP_BYTES_RECEIVED,
                               NetLogEventPhase::NONE));
  EXPECT_TRUE(LogContainsEvent(client_entries, 5,
                               NetLogEventType::UDP_BYTES_SENT,
                               NetLogEventPhase::NONE));
  EXPECT_TRUE(
      LogContainsEndEvent(client_entries, 6, NetLogEventType::SOCKET_ALIVE));
}

TEST_F(UDPSocketTest, Connect) {
  // The variable |use_nonblocking_io| has no effect in non-Windows ports.
  ConnectTest(false);
}

#if defined(OS_WIN)
TEST_F(UDPSocketTest, ConnectNonBlocking) {
  ConnectTest(true);
}
#endif

#if defined(OS_MACOSX)
// UDPSocketPrivate_Broadcast is disabled for OSX because it requires
// root permissions on OSX 10.7+.
TEST_F(UDPSocketTest, DISABLED_Broadcast) {
#elif defined(OS_ANDROID)
// Disabled for Android because devices attached to testbots don't have default
// network, so broadcasting to 255.255.255.255 returns error -109 (Address not
// reachable). crbug.com/139144.
TEST_F(UDPSocketTest, DISABLED_Broadcast) {
#else
TEST_F(UDPSocketTest, Broadcast) {
#endif
  const uint16_t kPort = 9999;
  std::string first_message("first message"), second_message("second message");

  IPEndPoint broadcast_address;
  CreateUDPAddress("255.255.255.255", kPort, &broadcast_address);
  IPEndPoint listen_address;
  CreateUDPAddress("0.0.0.0", kPort, &listen_address);

  TestNetLog server1_log, server2_log;
  std::unique_ptr<UDPServerSocket> server1(
      new UDPServerSocket(&server1_log, NetLogSource()));
  std::unique_ptr<UDPServerSocket> server2(
      new UDPServerSocket(&server2_log, NetLogSource()));
  server1->AllowAddressReuse();
  server1->AllowBroadcast();
  server2->AllowAddressReuse();
  server2->AllowBroadcast();

  int rv = server1->Listen(listen_address);
  EXPECT_THAT(rv, IsOk());
  rv = server2->Listen(listen_address);
  EXPECT_THAT(rv, IsOk());

  rv = SendToSocket(server1.get(), first_message, broadcast_address);
  ASSERT_EQ(static_cast<int>(first_message.size()), rv);
  std::string str = RecvFromSocket(server1.get());
  ASSERT_EQ(first_message, str);
  str = RecvFromSocket(server2.get());
  ASSERT_EQ(first_message, str);

  rv = SendToSocket(server2.get(), second_message, broadcast_address);
  ASSERT_EQ(static_cast<int>(second_message.size()), rv);
  str = RecvFromSocket(server1.get());
  ASSERT_EQ(second_message, str);
  str = RecvFromSocket(server2.get());
  ASSERT_EQ(second_message, str);
}

// In this test, we verify that random binding logic works, which attempts
// to bind to a random port and returns if succeeds, otherwise retries for
// |kBindRetries| number of times.

// To generate the scenario, we first create |kBindRetries| number of
// UDPClientSockets with default binding policy and connect to the same
// peer and save the used port numbers.  Then we get rid of the last
// socket, making sure that the local port it was bound to is available.
// Finally, we create a socket with random binding policy, passing it a
// test PRNG that would serve used port numbers in the array, one after
// another.  At the end, we make sure that the test socket was bound to the
// port that became available after deleting the last socket with default
// binding policy.

// We do not test the randomness of bound ports, but that we are using
// passed in PRNG correctly, thus, it's the duty of PRNG to produce strong
// random numbers.
static const int kBindRetries = 10;

class TestPrng {
 public:
  explicit TestPrng(const std::deque<int>& numbers) : numbers_(numbers) {}
  int GetNext(int /* min */, int /* max */) {
    DCHECK(!numbers_.empty());
    int rv = numbers_.front();
    numbers_.pop_front();
    return rv;
  }
 private:
  std::deque<int> numbers_;

  DISALLOW_COPY_AND_ASSIGN(TestPrng);
};

TEST_F(UDPSocketTest, ConnectRandomBind) {
  std::vector<std::unique_ptr<UDPClientSocket>> sockets;
  IPEndPoint peer_address;
  CreateUDPAddress("127.0.0.1", 53, &peer_address);

  // Create and connect sockets and save port numbers.
  std::deque<int> used_ports;
  for (int i = 0; i < kBindRetries; ++i) {
    UDPClientSocket* socket = new UDPClientSocket(
        DatagramSocket::DEFAULT_BIND, RandIntCallback(), NULL, NetLogSource());
    sockets.push_back(base::WrapUnique(socket));
    EXPECT_THAT(socket->Connect(peer_address), IsOk());

    IPEndPoint client_address;
    EXPECT_THAT(socket->GetLocalAddress(&client_address), IsOk());
    used_ports.push_back(client_address.port());
  }

  // Free the last socket, its local port is still in |used_ports|.
  sockets.pop_back();

  TestPrng test_prng(used_ports);
  RandIntCallback rand_int_cb =
      base::Bind(&TestPrng::GetNext, base::Unretained(&test_prng));

  // Create a socket with random binding policy and connect.
  std::unique_ptr<UDPClientSocket> test_socket(new UDPClientSocket(
      DatagramSocket::RANDOM_BIND, rand_int_cb, NULL, NetLogSource()));
  EXPECT_THAT(test_socket->Connect(peer_address), IsOk());

  // Make sure that the last port number in the |used_ports| was used.
  IPEndPoint client_address;
  EXPECT_THAT(test_socket->GetLocalAddress(&client_address), IsOk());
  EXPECT_EQ(used_ports.back(), client_address.port());
}

// Return a privileged port (under 1024) so binding will fail.
int PrivilegedRand(int min, int max) {
  // Chosen by fair dice roll.  Guaranteed to be random.
  return 4;
}

#if defined(OS_IOS) && !TARGET_IPHONE_SIMULATOR
// TODO(droger): On iOS this test fails on device (but passes on simulator).
// See http://crbug.com/227760.
#define MAYBE_ConnectFail DISABLED_ConnectFail
#else
#define MAYBE_ConnectFail ConnectFail
#endif
TEST_F(UDPSocketTest, MAYBE_ConnectFail) {
  IPEndPoint peer_address;
  CreateUDPAddress("0.0.0.0", 53, &peer_address);

  std::unique_ptr<UDPSocket> socket(new UDPSocket(DatagramSocket::RANDOM_BIND,
                                                  base::Bind(&PrivilegedRand),
                                                  NULL, NetLogSource()));
  int rv = socket->Open(peer_address.GetFamily());
  EXPECT_THAT(rv, IsOk());
  rv = socket->Connect(peer_address);
  // Connect should have failed since we couldn't bind to that port,
  EXPECT_NE(OK, rv);
  // Make sure that UDPSocket actually closed the socket.
  EXPECT_FALSE(socket->is_connected());
}

// In this test, we verify that connect() on a socket will have the effect
// of filtering reads on this socket only to data read from the destination
// we connected to.
//
// The purpose of this test is that some documentation indicates that connect
// binds the client's sends to send to a particular server endpoint, but does
// not bind the client's reads to only be from that endpoint, and that we need
// to always use recvfrom() to disambiguate.
TEST_F(UDPSocketTest, VerifyConnectBindsAddr) {
  const uint16_t kPort1 = 9999;
  const uint16_t kPort2 = 10000;
  std::string simple_message("hello world!");
  std::string foreign_message("BAD MESSAGE TO GET!!");

  // Setup the first server to listen.
  IPEndPoint bind_address;
  CreateUDPAddress("127.0.0.1", kPort1, &bind_address);
  UDPServerSocket server1(NULL, NetLogSource());
  server1.AllowAddressReuse();
  int rv = server1.Listen(bind_address);
  ASSERT_THAT(rv, IsOk());

  // Setup the second server to listen.
  CreateUDPAddress("127.0.0.1", kPort2, &bind_address);
  UDPServerSocket server2(NULL, NetLogSource());
  server2.AllowAddressReuse();
  rv = server2.Listen(bind_address);
  ASSERT_THAT(rv, IsOk());

  // Setup the client, connected to server 1.
  IPEndPoint server_address;
  CreateUDPAddress("127.0.0.1", kPort1, &server_address);
  UDPClientSocket client(DatagramSocket::DEFAULT_BIND, RandIntCallback(), NULL,
                         NetLogSource());
  rv = client.Connect(server_address);
  EXPECT_THAT(rv, IsOk());

  // Client sends to server1.
  rv = WriteSocket(&client, simple_message);
  EXPECT_EQ(simple_message.length(), static_cast<size_t>(rv));

  // Server1 waits for message.
  std::string str = RecvFromSocket(&server1);
  DCHECK(simple_message == str);

  // Get the client's address.
  IPEndPoint client_address;
  rv = client.GetLocalAddress(&client_address);
  EXPECT_THAT(rv, IsOk());

  // Server2 sends reply.
  rv = SendToSocket(&server2, foreign_message,
                    client_address);
  EXPECT_EQ(foreign_message.length(), static_cast<size_t>(rv));

  // Server1 sends reply.
  rv = SendToSocket(&server1, simple_message,
                    client_address);
  EXPECT_EQ(simple_message.length(), static_cast<size_t>(rv));

  // Client waits for response.
  str = ReadSocket(&client);
  DCHECK(simple_message == str);
}

TEST_F(UDPSocketTest, ClientGetLocalPeerAddresses) {
  struct TestData {
    std::string remote_address;
    std::string local_address;
    bool may_fail;
  } tests[] = {
    { "127.0.00.1", "127.0.0.1", false },
    { "::1", "::1", true },
#if !defined(OS_ANDROID) && !defined(OS_IOS)
    // Addresses below are disabled on Android. See crbug.com/161248
    // They are also disabled on iOS. See https://crbug.com/523225
    { "192.168.1.1", "127.0.0.1", false },
    { "2001:db8:0::42", "::1", true },
#endif
  };
  for (size_t i = 0; i < arraysize(tests); i++) {
    SCOPED_TRACE(std::string("Connecting from ") +  tests[i].local_address +
                 std::string(" to ") + tests[i].remote_address);

    IPAddress ip_address;
    EXPECT_TRUE(ip_address.AssignFromIPLiteral(tests[i].remote_address));
    IPEndPoint remote_address(ip_address, 80);
    EXPECT_TRUE(ip_address.AssignFromIPLiteral(tests[i].local_address));
    IPEndPoint local_address(ip_address, 80);

    UDPClientSocket client(DatagramSocket::DEFAULT_BIND, RandIntCallback(),
                           NULL, NetLogSource());
    int rv = client.Connect(remote_address);
    if (tests[i].may_fail && rv == ERR_ADDRESS_UNREACHABLE) {
      // Connect() may return ERR_ADDRESS_UNREACHABLE for IPv6
      // addresses if IPv6 is not configured.
      continue;
    }

    EXPECT_LE(ERR_IO_PENDING, rv);

    IPEndPoint fetched_local_address;
    rv = client.GetLocalAddress(&fetched_local_address);
    EXPECT_THAT(rv, IsOk());

    // TODO(mbelshe): figure out how to verify the IP and port.
    //                The port is dynamically generated by the udp stack.
    //                The IP is the real IP of the client, not necessarily
    //                loopback.
    //EXPECT_EQ(local_address.address(), fetched_local_address.address());

    IPEndPoint fetched_remote_address;
    rv = client.GetPeerAddress(&fetched_remote_address);
    EXPECT_THAT(rv, IsOk());

    EXPECT_EQ(remote_address, fetched_remote_address);
  }
}

TEST_F(UDPSocketTest, ServerGetLocalAddress) {
  IPEndPoint bind_address;
  CreateUDPAddress("127.0.0.1", 0, &bind_address);
  UDPServerSocket server(NULL, NetLogSource());
  int rv = server.Listen(bind_address);
  EXPECT_THAT(rv, IsOk());

  IPEndPoint local_address;
  rv = server.GetLocalAddress(&local_address);
  EXPECT_EQ(rv, 0);

  // Verify that port was allocated.
  EXPECT_GT(local_address.port(), 0);
  EXPECT_EQ(local_address.address(), bind_address.address());
}

TEST_F(UDPSocketTest, ServerGetPeerAddress) {
  IPEndPoint bind_address;
  CreateUDPAddress("127.0.0.1", 0, &bind_address);
  UDPServerSocket server(NULL, NetLogSource());
  int rv = server.Listen(bind_address);
  EXPECT_THAT(rv, IsOk());

  IPEndPoint peer_address;
  rv = server.GetPeerAddress(&peer_address);
  EXPECT_EQ(rv, ERR_SOCKET_NOT_CONNECTED);
}

TEST_F(UDPSocketTest, ClientSetDoNotFragment) {
  for (std::string ip : {"127.0.0.1", "::1"}) {
    LOG(INFO) << "ip: " << ip;
    UDPClientSocket client(DatagramSocket::DEFAULT_BIND, RandIntCallback(),
                           nullptr, NetLogSource());
    IPAddress ip_address;
    EXPECT_TRUE(ip_address.AssignFromIPLiteral(ip));
    IPEndPoint remote_address(ip_address, 80);
    int rv = client.Connect(remote_address);
    // May fail on IPv6 is IPv6 is not configured.
    if (ip_address.IsIPv6() && rv == ERR_ADDRESS_UNREACHABLE)
      return;
    EXPECT_THAT(rv, IsOk());

#if defined(OS_MACOSX)
    EXPECT_EQ(ERR_NOT_IMPLEMENTED, client.SetDoNotFragment());
#else
    rv = client.SetDoNotFragment();
    EXPECT_THAT(rv, IsOk());
#endif
  }
}

TEST_F(UDPSocketTest, ServerSetDoNotFragment) {
  for (std::string ip : {"127.0.0.1", "::1"}) {
    LOG(INFO) << "ip: " << ip;
    IPEndPoint bind_address;
    CreateUDPAddress(ip, 0, &bind_address);
    UDPServerSocket server(nullptr, NetLogSource());
    int rv = server.Listen(bind_address);
    // May fail on IPv6 is IPv6 is not configure
    if (bind_address.address().IsIPv6() && rv == ERR_ADDRESS_INVALID)
      return;
    EXPECT_THAT(rv, IsOk());

#if defined(OS_MACOSX)
    EXPECT_EQ(ERR_NOT_IMPLEMENTED, server.SetDoNotFragment());
#else
    rv = server.SetDoNotFragment();
    EXPECT_THAT(rv, IsOk());
#endif
  }
}

// Close the socket while read is pending.
TEST_F(UDPSocketTest, CloseWithPendingRead) {
  IPEndPoint bind_address;
  CreateUDPAddress("127.0.0.1", 0, &bind_address);
  UDPServerSocket server(NULL, NetLogSource());
  int rv = server.Listen(bind_address);
  EXPECT_THAT(rv, IsOk());

  TestCompletionCallback callback;
  IPEndPoint from;
  rv = server.RecvFrom(buffer_.get(), kMaxRead, &from, callback.callback());
  EXPECT_EQ(rv, ERR_IO_PENDING);

  server.Close();

  EXPECT_FALSE(callback.have_result());
}

#if defined(OS_ANDROID)
// Some Android devices do not support multicast socket.
// The ones supporting multicast need WifiManager.MulitcastLock to enable it.
// http://goo.gl/jjAk9
#define MAYBE_JoinMulticastGroup DISABLED_JoinMulticastGroup
#else
#define MAYBE_JoinMulticastGroup JoinMulticastGroup
#endif  // defined(OS_ANDROID)

TEST_F(UDPSocketTest, MAYBE_JoinMulticastGroup) {
  const uint16_t kPort = 9999;
  const char kGroup[] = "237.132.100.17";

  IPEndPoint bind_address;
  CreateUDPAddress("0.0.0.0", kPort, &bind_address);
  IPAddress group_ip;
  EXPECT_TRUE(group_ip.AssignFromIPLiteral(kGroup));

  UDPSocket socket(DatagramSocket::DEFAULT_BIND, RandIntCallback(), NULL,
                   NetLogSource());
  EXPECT_THAT(socket.Open(bind_address.GetFamily()), IsOk());
  EXPECT_THAT(socket.Bind(bind_address), IsOk());
  EXPECT_THAT(socket.JoinGroup(group_ip), IsOk());
  // Joining group multiple times.
  EXPECT_NE(OK, socket.JoinGroup(group_ip));
  EXPECT_THAT(socket.LeaveGroup(group_ip), IsOk());
  // Leaving group multiple times.
  EXPECT_NE(OK, socket.LeaveGroup(group_ip));

  socket.Close();
}

TEST_F(UDPSocketTest, MulticastOptions) {
  const uint16_t kPort = 9999;
  IPEndPoint bind_address;
  CreateUDPAddress("0.0.0.0", kPort, &bind_address);

  UDPSocket socket(DatagramSocket::DEFAULT_BIND, RandIntCallback(), NULL,
                   NetLogSource());
  // Before binding.
  EXPECT_THAT(socket.SetMulticastLoopbackMode(false), IsOk());
  EXPECT_THAT(socket.SetMulticastLoopbackMode(true), IsOk());
  EXPECT_THAT(socket.SetMulticastTimeToLive(0), IsOk());
  EXPECT_THAT(socket.SetMulticastTimeToLive(3), IsOk());
  EXPECT_NE(OK, socket.SetMulticastTimeToLive(-1));
  EXPECT_THAT(socket.SetMulticastInterface(0), IsOk());

  EXPECT_THAT(socket.Open(bind_address.GetFamily()), IsOk());
  EXPECT_THAT(socket.Bind(bind_address), IsOk());

  EXPECT_NE(OK, socket.SetMulticastLoopbackMode(false));
  EXPECT_NE(OK, socket.SetMulticastTimeToLive(0));
  EXPECT_NE(OK, socket.SetMulticastInterface(0));

  socket.Close();
}

// Checking that DSCP bits are set correctly is difficult,
// but let's check that the code doesn't crash at least.
TEST_F(UDPSocketTest, SetDSCP) {
  // Setup the server to listen.
  IPEndPoint bind_address;
  UDPSocket client(DatagramSocket::DEFAULT_BIND, RandIntCallback(), NULL,
                   NetLogSource());
  // We need a real IP, but we won't actually send anything to it.
  CreateUDPAddress("8.8.8.8", 9999, &bind_address);
  int rv = client.Open(bind_address.GetFamily());
  EXPECT_THAT(rv, IsOk());

  rv = client.Connect(bind_address);
  if (rv != OK) {
    // Let's try localhost then..
    CreateUDPAddress("127.0.0.1", 9999, &bind_address);
    rv = client.Connect(bind_address);
  }
  EXPECT_THAT(rv, IsOk());

  client.SetDiffServCodePoint(DSCP_NO_CHANGE);
  client.SetDiffServCodePoint(DSCP_AF41);
  client.SetDiffServCodePoint(DSCP_DEFAULT);
  client.SetDiffServCodePoint(DSCP_CS2);
  client.SetDiffServCodePoint(DSCP_NO_CHANGE);
  client.SetDiffServCodePoint(DSCP_DEFAULT);
  client.Close();
}

TEST_F(UDPSocketTest, TestBindToNetwork) {
  UDPSocket socket(DatagramSocket::RANDOM_BIND, base::Bind(&PrivilegedRand),
                   NULL, NetLogSource());
  ASSERT_EQ(OK, socket.Open(ADDRESS_FAMILY_IPV4));
  // Test unsuccessful binding, by attempting to bind to a bogus NetworkHandle.
  int rv = socket.BindToNetwork(65536);
#if !defined(OS_ANDROID)
  EXPECT_EQ(ERR_NOT_IMPLEMENTED, rv);
#else
  if (base::android::BuildInfo::GetInstance()->sdk_int() <
      base::android::SDK_VERSION_LOLLIPOP) {
    EXPECT_EQ(ERR_NOT_IMPLEMENTED, rv);
  } else if (base::android::BuildInfo::GetInstance()->sdk_int() >=
             base::android::SDK_VERSION_LOLLIPOP &&
             base::android::BuildInfo::GetInstance()->sdk_int() <
             base::android::SDK_VERSION_MARSHMALLOW) {
    // On Lollipop, we assume if the user has a NetworkHandle that they must
    // have gotten it from a legitimate source, so if binding to the network
    // fails it's assumed to be because the network went away so
    // ERR_NETWORK_CHANGED is returned. In this test the network never existed
    // anyhow.  ConnectivityService.MAX_NET_ID is 65535, so 65536 won't be used.
    EXPECT_EQ(ERR_NETWORK_CHANGED, rv);
  } else if (base::android::BuildInfo::GetInstance()->sdk_int() >=
             base::android::SDK_VERSION_MARSHMALLOW) {
    // On Marshmallow and newer releases, the NetworkHandle is munged by
    // Network.getNetworkHandle() and 65536 isn't munged so it's rejected.
    EXPECT_EQ(ERR_INVALID_ARGUMENT, rv);
  }

  if (base::android::BuildInfo::GetInstance()->sdk_int() >=
      base::android::SDK_VERSION_LOLLIPOP) {
    EXPECT_EQ(
        ERR_INVALID_ARGUMENT,
        socket.BindToNetwork(NetworkChangeNotifier::kInvalidNetworkHandle));

    // Test successful binding, if possible.
    if (NetworkChangeNotifier::AreNetworkHandlesSupported()) {
      NetworkChangeNotifier::NetworkHandle network_handle =
          NetworkChangeNotifier::GetDefaultNetwork();
      if (network_handle != NetworkChangeNotifier::kInvalidNetworkHandle) {
        EXPECT_EQ(OK, socket.BindToNetwork(network_handle));
      }
    }
  }
#endif
}

}  // namespace

#if defined(OS_WIN)

namespace {

const HANDLE kFakeHandle = (HANDLE)19;
const QOS_FLOWID kFakeFlowId = (QOS_FLOWID)27;

BOOL WINAPI FakeQOSCreateHandleFAIL(PQOS_VERSION version, PHANDLE handle) {
  EXPECT_EQ(0, version->MinorVersion);
  EXPECT_EQ(1, version->MajorVersion);
  SetLastError(ERROR_OPEN_FAILED);
  return false;
}

BOOL WINAPI FakeQOSCreateHandle(PQOS_VERSION version, PHANDLE handle) {
  EXPECT_EQ(0, version->MinorVersion);
  EXPECT_EQ(1, version->MajorVersion);
  *handle = kFakeHandle;
  return true;
}

BOOL WINAPI FakeQOSCloseHandle(HANDLE handle) {
  EXPECT_EQ(kFakeHandle, handle);
  return true;
}

QOS_TRAFFIC_TYPE g_expected_traffic_type;

BOOL WINAPI FakeQOSAddSocketToFlow(HANDLE handle,
                                   SOCKET socket,
                                   PSOCKADDR addr,
                                   QOS_TRAFFIC_TYPE traffic_type,
                                   DWORD flags,
                                   PQOS_FLOWID flow_id) {
  EXPECT_EQ(kFakeHandle, handle);
  EXPECT_EQ(NULL, addr);
  EXPECT_EQ(static_cast<DWORD>(QOS_NON_ADAPTIVE_FLOW), flags);
  EXPECT_EQ(0u, *flow_id);
  *flow_id = kFakeFlowId;
  return true;
}

BOOL WINAPI FakeQOSRemoveSocketFromFlow(HANDLE handle,
                                        SOCKET socket,
                                        QOS_FLOWID flowid,
                                        DWORD reserved) {
  EXPECT_EQ(kFakeHandle, handle);
  EXPECT_EQ(0u, socket);
  EXPECT_EQ(kFakeFlowId, flowid);
  EXPECT_EQ(0u, reserved);
  return true;
}

DWORD g_expected_dscp;

BOOL WINAPI FakeQOSSetFlow(HANDLE handle,
                           QOS_FLOWID flow_id,
                           QOS_SET_FLOW op,
                           ULONG size,
                           PVOID data,
                           DWORD reserved,
                           LPOVERLAPPED overlapped) {
  EXPECT_EQ(kFakeHandle, handle);
  EXPECT_EQ(QOSSetOutgoingDSCPValue, op);
  EXPECT_EQ(sizeof(DWORD), size);
  EXPECT_EQ(g_expected_dscp, *reinterpret_cast<DWORD*>(data));
  EXPECT_EQ(kFakeFlowId, flow_id);
  EXPECT_EQ(0u, reserved);
  EXPECT_EQ(NULL, overlapped);
  return true;
}

}  // namespace

// Mock out the Qwave functions and make sure they are
// called correctly. Must be in net namespace for friendship
// reasons.
TEST_F(UDPSocketTest, SetDSCPFake) {
  // Setup the server to listen.
  IPEndPoint bind_address;
  // We need a real IP, but we won't actually send anything to it.
  CreateUDPAddress("8.8.8.8", 9999, &bind_address);
  UDPSocket client(DatagramSocket::DEFAULT_BIND, RandIntCallback(), NULL,
                   NetLogSource());
  int rv = client.SetDiffServCodePoint(DSCP_AF41);
  EXPECT_THAT(rv, IsError(ERR_SOCKET_NOT_CONNECTED));

  rv = client.Open(bind_address.GetFamily());
  EXPECT_THAT(rv, IsOk());

  rv = client.Connect(bind_address);
  EXPECT_THAT(rv, IsOk());

  QwaveAPI& qos(QwaveAPI::Get());
  qos.create_handle_func_ = FakeQOSCreateHandleFAIL;
  qos.close_handle_func_ = FakeQOSCloseHandle;
  qos.add_socket_to_flow_func_ = FakeQOSAddSocketToFlow;
  qos.remove_socket_from_flow_func_ = FakeQOSRemoveSocketFromFlow;
  qos.set_flow_func_ = FakeQOSSetFlow;
  qos.qwave_supported_ = true;

  EXPECT_THAT(client.SetDiffServCodePoint(DSCP_NO_CHANGE), IsOk());
  EXPECT_EQ(ERROR_NOT_SUPPORTED, client.SetDiffServCodePoint(DSCP_AF41));
  qos.create_handle_func_ = FakeQOSCreateHandle;
  g_expected_dscp = DSCP_AF41;
  g_expected_traffic_type = QOSTrafficTypeAudioVideo;
  EXPECT_THAT(client.SetDiffServCodePoint(DSCP_AF41), IsOk());
  g_expected_dscp = DSCP_DEFAULT;
  g_expected_traffic_type = QOSTrafficTypeBestEffort;
  EXPECT_THAT(client.SetDiffServCodePoint(DSCP_DEFAULT), IsOk());
  g_expected_dscp = DSCP_CS2;
  g_expected_traffic_type = QOSTrafficTypeExcellentEffort;
  EXPECT_THAT(client.SetDiffServCodePoint(DSCP_CS2), IsOk());
  g_expected_dscp = DSCP_CS3;
  g_expected_traffic_type = QOSTrafficTypeExcellentEffort;
  EXPECT_THAT(client.SetDiffServCodePoint(DSCP_NO_CHANGE), IsOk());
  g_expected_dscp = DSCP_DEFAULT;
  g_expected_traffic_type = QOSTrafficTypeBestEffort;
  EXPECT_THAT(client.SetDiffServCodePoint(DSCP_DEFAULT), IsOk());
  client.Close();
}
#endif

}  // namespace net
