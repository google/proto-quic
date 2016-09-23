// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/bind.h"
#include "base/memory/weak_ptr.h"
#include "base/message_loop/message_loop.h"
#include "base/run_loop.h"
#include "base/test/perf_time_logger.h"
#include "net/base/io_buffer.h"
#include "net/base/ip_endpoint.h"
#include "net/base/net_errors.h"
#include "net/base/test_completion_callback.h"
#include "net/test/gtest_util.h"
#include "net/test/net_test_suite.h"
#include "net/udp/udp_client_socket.h"
#include "net/udp/udp_server_socket.h"
#include "net/udp/udp_socket.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "testing/platform_test.h"

using net::test::IsOk;

namespace net {

namespace {

class UDPSocketPerfTest : public PlatformTest {
 public:
  UDPSocketPerfTest()
      : buffer_(new IOBufferWithSize(kPacketSize)), weak_factory_(this) {}

  void DoneWritePacketsToSocket(UDPClientSocket* socket,
                                int num_of_packets,
                                base::Closure done_callback,
                                int error) {
    WritePacketsToSocket(socket, num_of_packets, done_callback);
  }

  // Send |num_of_packets| to |socket|. Invoke |done_callback| when done.
  void WritePacketsToSocket(UDPClientSocket* socket,
                            int num_of_packets,
                            base::Closure done_callback);

  // Use non-blocking IO if |use_nonblocking_io| is true. This variable only
  // has effect on Windows.
  void WriteBenchmark(bool use_nonblocking_io);

 protected:
  static const int kPacketSize = 1024;
  scoped_refptr<IOBufferWithSize> buffer_;
  base::WeakPtrFactory<UDPSocketPerfTest> weak_factory_;
};

// Creates and address from an ip/port and returns it in |address|.
void CreateUDPAddress(const std::string& ip_str,
                      uint16_t port,
                      IPEndPoint* address) {
  IPAddress ip_address;
  if (!ip_address.AssignFromIPLiteral(ip_str))
    return;
  *address = IPEndPoint(ip_address, port);
}

void UDPSocketPerfTest::WritePacketsToSocket(UDPClientSocket* socket,
                                             int num_of_packets,
                                             base::Closure done_callback) {
  scoped_refptr<IOBufferWithSize> io_buffer(new IOBufferWithSize(kPacketSize));
  memset(io_buffer->data(), 'G', kPacketSize);

  while (num_of_packets) {
    int rv =
        socket->Write(io_buffer.get(), io_buffer->size(),
                      base::Bind(&UDPSocketPerfTest::DoneWritePacketsToSocket,
                                 weak_factory_.GetWeakPtr(), socket,
                                 num_of_packets - 1, done_callback));
    if (rv == ERR_IO_PENDING)
      break;
    --num_of_packets;
  }
  if (!num_of_packets) {
    done_callback.Run();
    return;
  }
}

void UDPSocketPerfTest::WriteBenchmark(bool use_nonblocking_io) {
  base::MessageLoopForIO message_loop;
  const uint16_t kPort = 9999;

  // Setup the server to listen.
  IPEndPoint bind_address;
  CreateUDPAddress("127.0.0.1", kPort, &bind_address);
  std::unique_ptr<UDPServerSocket> server(
      new UDPServerSocket(nullptr, NetLog::Source()));
  if (use_nonblocking_io)
    server->UseNonBlockingIO();
  int rv = server->Listen(bind_address);
  ASSERT_THAT(rv, IsOk());

  // Setup the client.
  IPEndPoint server_address;
  CreateUDPAddress("127.0.0.1", kPort, &server_address);
  std::unique_ptr<UDPClientSocket> client(
      new UDPClientSocket(DatagramSocket::DEFAULT_BIND, RandIntCallback(),
                          nullptr, NetLog::Source()));
  if (use_nonblocking_io)
    client->UseNonBlockingIO();
  rv = client->Connect(server_address);
  EXPECT_THAT(rv, IsOk());

  base::RunLoop run_loop;
  base::TimeTicks start_ticks = base::TimeTicks::Now();
  int packets = 100000;
  client->SetSendBufferSize(1024);
  WritePacketsToSocket(client.get(), packets, run_loop.QuitClosure());
  run_loop.Run();

  double elapsed = (base::TimeTicks::Now() - start_ticks).InSecondsF();
  LOG(INFO) << "Write speed: " << packets / 1024 / elapsed << " MB/s";
}

TEST_F(UDPSocketPerfTest, Write) {
  base::PerfTimeLogger timer("UDP_socket_write");
  WriteBenchmark(false);
}

TEST_F(UDPSocketPerfTest, WriteNonBlocking) {
  base::PerfTimeLogger timer("UDP_socket_write_nonblocking");
  WriteBenchmark(true);
}

}  // namespace

}  // namespace net
