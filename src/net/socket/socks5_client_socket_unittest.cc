// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/socket/socks5_client_socket.h"

#include <algorithm>
#include <iterator>
#include <map>
#include <utility>

#include "base/macros.h"
#include "base/sys_byteorder.h"
#include "net/base/address_list.h"
#include "net/base/test_completion_callback.h"
#include "net/base/winsock_init.h"
#include "net/dns/mock_host_resolver.h"
#include "net/log/net_log.h"
#include "net/log/net_log_event_type.h"
#include "net/log/test_net_log.h"
#include "net/log/test_net_log_entry.h"
#include "net/log/test_net_log_util.h"
#include "net/socket/client_socket_factory.h"
#include "net/socket/socket_test_util.h"
#include "net/socket/tcp_client_socket.h"
#include "net/test/gtest_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "testing/platform_test.h"

using net::test::IsError;
using net::test::IsOk;

//-----------------------------------------------------------------------------

namespace net {

namespace {

// Base class to test SOCKS5ClientSocket
class SOCKS5ClientSocketTest : public PlatformTest {
 public:
  SOCKS5ClientSocketTest();
  // Create a SOCKSClientSocket on top of a MockSocket.
  std::unique_ptr<SOCKS5ClientSocket> BuildMockSocket(
      MockRead reads[],
      size_t reads_count,
      MockWrite writes[],
      size_t writes_count,
      const std::string& hostname,
      int port,
      NetLog* net_log);

  void SetUp() override;

 protected:
  const uint16_t kNwPort;
  TestNetLog net_log_;
  std::unique_ptr<SOCKS5ClientSocket> user_sock_;
  AddressList address_list_;
  // Filled in by BuildMockSocket() and owned by its return value
  // (which |user_sock| is set to).
  StreamSocket* tcp_sock_;
  TestCompletionCallback callback_;
  std::unique_ptr<MockHostResolver> host_resolver_;
  std::unique_ptr<SocketDataProvider> data_;

 private:
  DISALLOW_COPY_AND_ASSIGN(SOCKS5ClientSocketTest);
};

SOCKS5ClientSocketTest::SOCKS5ClientSocketTest()
  : kNwPort(base::HostToNet16(80)),
    host_resolver_(new MockHostResolver) {
}

// Set up platform before every test case
void SOCKS5ClientSocketTest::SetUp() {
  PlatformTest::SetUp();

  // Resolve the "localhost" AddressList used by the TCP connection to connect.
  HostResolver::RequestInfo info(HostPortPair("www.socks-proxy.com", 1080));
  TestCompletionCallback callback;
  std::unique_ptr<HostResolver::Request> request;
  int rv = host_resolver_->Resolve(info, DEFAULT_PRIORITY, &address_list_,
                                   callback.callback(), &request,
                                   NetLogWithSource());
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback.WaitForResult();
  ASSERT_THAT(rv, IsOk());
}

std::unique_ptr<SOCKS5ClientSocket> SOCKS5ClientSocketTest::BuildMockSocket(
    MockRead reads[],
    size_t reads_count,
    MockWrite writes[],
    size_t writes_count,
    const std::string& hostname,
    int port,
    NetLog* net_log) {
  TestCompletionCallback callback;
  data_.reset(new StaticSocketDataProvider(reads, reads_count,
                                           writes, writes_count));
  tcp_sock_ = new MockTCPClientSocket(address_list_, net_log, data_.get());

  int rv = tcp_sock_->Connect(callback.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(tcp_sock_->IsConnected());

  std::unique_ptr<ClientSocketHandle> connection(new ClientSocketHandle);
  // |connection| takes ownership of |tcp_sock_|, but keep a
  // non-owning pointer to it.
  connection->SetSocket(std::unique_ptr<StreamSocket>(tcp_sock_));
  return std::unique_ptr<SOCKS5ClientSocket>(new SOCKS5ClientSocket(
      std::move(connection),
      HostResolver::RequestInfo(HostPortPair(hostname, port))));
}

// Tests a complete SOCKS5 handshake and the disconnection.
TEST_F(SOCKS5ClientSocketTest, CompleteHandshake) {
  const std::string payload_write = "random data";
  const std::string payload_read = "moar random data";

  const char kOkRequest[] = {
    0x05,  // Version
    0x01,  // Command (CONNECT)
    0x00,  // Reserved.
    0x03,  // Address type (DOMAINNAME).
    0x09,  // Length of domain (9)
    // Domain string:
    'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't',
    0x00, 0x50,  // 16-bit port (80)
  };

  MockWrite data_writes[] = {
      MockWrite(ASYNC, kSOCKS5GreetRequest, kSOCKS5GreetRequestLength),
      MockWrite(ASYNC, kOkRequest, arraysize(kOkRequest)),
      MockWrite(ASYNC, payload_write.data(), payload_write.size()) };
  MockRead data_reads[] = {
      MockRead(ASYNC, kSOCKS5GreetResponse, kSOCKS5GreetResponseLength),
      MockRead(ASYNC, kSOCKS5OkResponse, kSOCKS5OkResponseLength),
      MockRead(ASYNC, payload_read.data(), payload_read.size()) };

  user_sock_ = BuildMockSocket(data_reads, arraysize(data_reads),
                               data_writes, arraysize(data_writes),
                               "localhost", 80, &net_log_);

  // At this state the TCP connection is completed but not the SOCKS handshake.
  EXPECT_TRUE(tcp_sock_->IsConnected());
  EXPECT_FALSE(user_sock_->IsConnected());

  int rv = user_sock_->Connect(callback_.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_FALSE(user_sock_->IsConnected());

  TestNetLogEntry::List net_log_entries;
  net_log_.GetEntries(&net_log_entries);
  EXPECT_TRUE(LogContainsBeginEvent(net_log_entries, 0,
                                    NetLogEventType::SOCKS5_CONNECT));

  rv = callback_.WaitForResult();

  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(user_sock_->IsConnected());

  net_log_.GetEntries(&net_log_entries);
  EXPECT_TRUE(LogContainsEndEvent(net_log_entries, -1,
                                  NetLogEventType::SOCKS5_CONNECT));

  scoped_refptr<IOBuffer> buffer(new IOBuffer(payload_write.size()));
  memcpy(buffer->data(), payload_write.data(), payload_write.size());
  rv = user_sock_->Write(
      buffer.get(), payload_write.size(), callback_.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback_.WaitForResult();
  EXPECT_EQ(static_cast<int>(payload_write.size()), rv);

  buffer = new IOBuffer(payload_read.size());
  rv =
      user_sock_->Read(buffer.get(), payload_read.size(), callback_.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback_.WaitForResult();
  EXPECT_EQ(static_cast<int>(payload_read.size()), rv);
  EXPECT_EQ(payload_read, std::string(buffer->data(), payload_read.size()));

  user_sock_->Disconnect();
  EXPECT_FALSE(tcp_sock_->IsConnected());
  EXPECT_FALSE(user_sock_->IsConnected());
}

// Test that you can call Connect() again after having called Disconnect().
TEST_F(SOCKS5ClientSocketTest, ConnectAndDisconnectTwice) {
  const std::string hostname = "my-host-name";
  const char kSOCKS5DomainRequest[] = {
      0x05,  // VER
      0x01,  // CMD
      0x00,  // RSV
      0x03,  // ATYPE
  };

  std::string request(kSOCKS5DomainRequest, arraysize(kSOCKS5DomainRequest));
  request.push_back(static_cast<char>(hostname.size()));
  request.append(hostname);
  request.append(reinterpret_cast<const char*>(&kNwPort), sizeof(kNwPort));

  for (int i = 0; i < 2; ++i) {
    MockWrite data_writes[] = {
        MockWrite(SYNCHRONOUS, kSOCKS5GreetRequest, kSOCKS5GreetRequestLength),
        MockWrite(SYNCHRONOUS, request.data(), request.size())
    };
    MockRead data_reads[] = {
        MockRead(SYNCHRONOUS, kSOCKS5GreetResponse, kSOCKS5GreetResponseLength),
        MockRead(SYNCHRONOUS, kSOCKS5OkResponse, kSOCKS5OkResponseLength)
    };

    user_sock_ = BuildMockSocket(data_reads, arraysize(data_reads),
                                 data_writes, arraysize(data_writes),
                                 hostname, 80, NULL);

    int rv = user_sock_->Connect(callback_.callback());
    EXPECT_THAT(rv, IsOk());
    EXPECT_TRUE(user_sock_->IsConnected());

    user_sock_->Disconnect();
    EXPECT_FALSE(user_sock_->IsConnected());
  }
}

// Test that we fail trying to connect to a hosname longer than 255 bytes.
TEST_F(SOCKS5ClientSocketTest, LargeHostNameFails) {
  // Create a string of length 256, where each character is 'x'.
  std::string large_host_name;
  std::fill_n(std::back_inserter(large_host_name), 256, 'x');

  // Create a SOCKS socket, with mock transport socket.
  MockWrite data_writes[] = {MockWrite()};
  MockRead data_reads[] = {MockRead()};
  user_sock_ = BuildMockSocket(data_reads, arraysize(data_reads),
                               data_writes, arraysize(data_writes),
                               large_host_name, 80, NULL);

  // Try to connect -- should fail (without having read/written anything to
  // the transport socket first) because the hostname is too long.
  TestCompletionCallback callback;
  int rv = user_sock_->Connect(callback.callback());
  EXPECT_THAT(rv, IsError(ERR_SOCKS_CONNECTION_FAILED));
}

TEST_F(SOCKS5ClientSocketTest, PartialReadWrites) {
  const std::string hostname = "www.google.com";

  const char kOkRequest[] = {
    0x05,  // Version
    0x01,  // Command (CONNECT)
    0x00,  // Reserved.
    0x03,  // Address type (DOMAINNAME).
    0x0E,  // Length of domain (14)
    // Domain string:
    'w', 'w', 'w', '.', 'g', 'o', 'o', 'g', 'l', 'e', '.', 'c', 'o', 'm',
    0x00, 0x50,  // 16-bit port (80)
  };

  // Test for partial greet request write
  {
    const char partial1[] = { 0x05, 0x01 };
    const char partial2[] = { 0x00 };
    MockWrite data_writes[] = {
        MockWrite(ASYNC, partial1, arraysize(partial1)),
        MockWrite(ASYNC, partial2, arraysize(partial2)),
        MockWrite(ASYNC, kOkRequest, arraysize(kOkRequest)) };
    MockRead data_reads[] = {
        MockRead(ASYNC, kSOCKS5GreetResponse, kSOCKS5GreetResponseLength),
        MockRead(ASYNC, kSOCKS5OkResponse, kSOCKS5OkResponseLength) };
    user_sock_ = BuildMockSocket(data_reads, arraysize(data_reads),
                                 data_writes, arraysize(data_writes),
                                 hostname, 80, &net_log_);
    int rv = user_sock_->Connect(callback_.callback());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

    TestNetLogEntry::List net_log_entries;
    net_log_.GetEntries(&net_log_entries);
    EXPECT_TRUE(LogContainsBeginEvent(net_log_entries, 0,
                                      NetLogEventType::SOCKS5_CONNECT));

    rv = callback_.WaitForResult();
    EXPECT_THAT(rv, IsOk());
    EXPECT_TRUE(user_sock_->IsConnected());

    net_log_.GetEntries(&net_log_entries);
    EXPECT_TRUE(LogContainsEndEvent(net_log_entries, -1,
                                    NetLogEventType::SOCKS5_CONNECT));
  }

  // Test for partial greet response read
  {
    const char partial1[] = { 0x05 };
    const char partial2[] = { 0x00 };
    MockWrite data_writes[] = {
        MockWrite(ASYNC, kSOCKS5GreetRequest, kSOCKS5GreetRequestLength),
        MockWrite(ASYNC, kOkRequest, arraysize(kOkRequest)) };
    MockRead data_reads[] = {
        MockRead(ASYNC, partial1, arraysize(partial1)),
        MockRead(ASYNC, partial2, arraysize(partial2)),
        MockRead(ASYNC, kSOCKS5OkResponse, kSOCKS5OkResponseLength) };
    user_sock_ = BuildMockSocket(data_reads, arraysize(data_reads),
                                 data_writes, arraysize(data_writes),
                                 hostname, 80, &net_log_);
    int rv = user_sock_->Connect(callback_.callback());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

    TestNetLogEntry::List net_log_entries;
    net_log_.GetEntries(&net_log_entries);
    EXPECT_TRUE(LogContainsBeginEvent(net_log_entries, 0,
                                      NetLogEventType::SOCKS5_CONNECT));
    rv = callback_.WaitForResult();
    EXPECT_THAT(rv, IsOk());
    EXPECT_TRUE(user_sock_->IsConnected());
    net_log_.GetEntries(&net_log_entries);
    EXPECT_TRUE(LogContainsEndEvent(net_log_entries, -1,
                                    NetLogEventType::SOCKS5_CONNECT));
  }

  // Test for partial handshake request write.
  {
    const int kSplitPoint = 3;  // Break handshake write into two parts.
    MockWrite data_writes[] = {
        MockWrite(ASYNC, kSOCKS5GreetRequest, kSOCKS5GreetRequestLength),
        MockWrite(ASYNC, kOkRequest, kSplitPoint),
        MockWrite(ASYNC, kOkRequest + kSplitPoint,
                  arraysize(kOkRequest) - kSplitPoint)
    };
    MockRead data_reads[] = {
        MockRead(ASYNC, kSOCKS5GreetResponse, kSOCKS5GreetResponseLength),
        MockRead(ASYNC, kSOCKS5OkResponse, kSOCKS5OkResponseLength) };
    user_sock_ = BuildMockSocket(data_reads, arraysize(data_reads),
                                 data_writes, arraysize(data_writes),
                                 hostname, 80, &net_log_);
    int rv = user_sock_->Connect(callback_.callback());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
    TestNetLogEntry::List net_log_entries;
    net_log_.GetEntries(&net_log_entries);
    EXPECT_TRUE(LogContainsBeginEvent(net_log_entries, 0,
                                      NetLogEventType::SOCKS5_CONNECT));
    rv = callback_.WaitForResult();
    EXPECT_THAT(rv, IsOk());
    EXPECT_TRUE(user_sock_->IsConnected());
    net_log_.GetEntries(&net_log_entries);
    EXPECT_TRUE(LogContainsEndEvent(net_log_entries, -1,
                                    NetLogEventType::SOCKS5_CONNECT));
  }

  // Test for partial handshake response read
  {
    const int kSplitPoint = 6;  // Break the handshake read into two parts.
    MockWrite data_writes[] = {
        MockWrite(ASYNC, kSOCKS5GreetRequest, kSOCKS5GreetRequestLength),
        MockWrite(ASYNC, kOkRequest, arraysize(kOkRequest))
    };
    MockRead data_reads[] = {
        MockRead(ASYNC, kSOCKS5GreetResponse, kSOCKS5GreetResponseLength),
        MockRead(ASYNC, kSOCKS5OkResponse, kSplitPoint),
        MockRead(ASYNC, kSOCKS5OkResponse + kSplitPoint,
                 kSOCKS5OkResponseLength - kSplitPoint)
    };

    user_sock_ = BuildMockSocket(data_reads, arraysize(data_reads),
                                 data_writes, arraysize(data_writes),
                                 hostname, 80, &net_log_);
    int rv = user_sock_->Connect(callback_.callback());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
    TestNetLogEntry::List net_log_entries;
    net_log_.GetEntries(&net_log_entries);
    EXPECT_TRUE(LogContainsBeginEvent(net_log_entries, 0,
                                      NetLogEventType::SOCKS5_CONNECT));
    rv = callback_.WaitForResult();
    EXPECT_THAT(rv, IsOk());
    EXPECT_TRUE(user_sock_->IsConnected());
    net_log_.GetEntries(&net_log_entries);
    EXPECT_TRUE(LogContainsEndEvent(net_log_entries, -1,
                                    NetLogEventType::SOCKS5_CONNECT));
  }
}

}  // namespace

}  // namespace net
