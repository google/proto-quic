// Copyright (c) 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/quic/quic_client.h"

#include <dirent.h>
#include <stdio.h>

#include <memory>

#include "base/strings/string_util.h"
#include "net/quic/test_tools/crypto_test_utils.h"
#include "net/quic/test_tools/quic_test_utils.h"
#include "net/tools/epoll_server/epoll_server.h"
#include "net/tools/quic/test_tools/quic_client_peer.h"
#include "testing/gtest/include/gtest/gtest.h"

using net::EpollServer;
using net::test::CryptoTestUtils;

namespace net {
namespace test {
namespace {

int NumOpenFDs() {
  int number_of_open_fds = 0;
  char buf[256];
  struct dirent* dp;

  base::snprintf(buf, arraysize(buf), "/proc/%i/fd/", getpid());
  DIR* dir = opendir(buf);
  while ((dp = readdir(dir)) != NULL)
    number_of_open_fds++;
  closedir(dir);

  return number_of_open_fds;
}

// Creates a new QuicClient and Initializes it. Caller is responsible for
// deletion.
QuicClient* CreateAndInitializeQuicClient(EpollServer* eps, uint16_t port) {
  IPEndPoint server_address(IPEndPoint(net::test::Loopback4(), port));
  QuicServerId server_id("hostname", server_address.port(),
                         PRIVACY_MODE_DISABLED);
  QuicVersionVector versions = QuicSupportedVersions();
  QuicClient* client =
      new QuicClient(server_address, server_id, versions, eps,
                     CryptoTestUtils::ProofVerifierForTesting());
  EXPECT_TRUE(client->Initialize());
  return client;
}

TEST(QuicClientTest, DoNotLeakFDs) {
  // Create a ProofVerifier before counting the number of open FDs to work
  // around some ASAN weirdness.
  delete CryptoTestUtils::ProofVerifierForTesting();

  // Make sure that the QuicClient doesn't leak FDs. Doing so could cause port
  // exhaustion in long running processes which repeatedly create clients.

  // Record initial number of FDs, after creation of EpollServer.
  EpollServer eps;
  int number_of_open_fds = NumOpenFDs();

  // Create a number of clients, initialize them, and verify this has resulted
  // in additional FDs being opened.
  const int kNumClients = 50;
  for (int i = 0; i < kNumClients; ++i) {
    std::unique_ptr<QuicClient> client(
        CreateAndInitializeQuicClient(&eps, net::test::kTestPort + i));

    // Initializing the client will create a new FD.
    EXPECT_LT(number_of_open_fds, NumOpenFDs());
  }

  // The FDs created by the QuicClients should now be closed.
  EXPECT_EQ(number_of_open_fds, NumOpenFDs());
}

TEST(QuicClientTest, CreateAndCleanUpUDPSockets) {
  // Create a ProofVerifier before counting the number of open FDs to work
  // around some ASAN weirdness.
  delete CryptoTestUtils::ProofVerifierForTesting();

  EpollServer eps;
  int number_of_open_fds = NumOpenFDs();

  std::unique_ptr<QuicClient> client(
      CreateAndInitializeQuicClient(&eps, net::test::kTestPort));
  EXPECT_EQ(number_of_open_fds + 1, NumOpenFDs());
  // Create more UDP sockets.
  EXPECT_TRUE(QuicClientPeer::CreateUDPSocketAndBind(client.get()));
  EXPECT_EQ(number_of_open_fds + 2, NumOpenFDs());
  EXPECT_TRUE(QuicClientPeer::CreateUDPSocketAndBind(client.get()));
  EXPECT_EQ(number_of_open_fds + 3, NumOpenFDs());

  // Clean up UDP sockets.
  QuicClientPeer::CleanUpUDPSocket(client.get(), client->GetLatestFD());
  EXPECT_EQ(number_of_open_fds + 2, NumOpenFDs());
  QuicClientPeer::CleanUpUDPSocket(client.get(), client->GetLatestFD());
  EXPECT_EQ(number_of_open_fds + 1, NumOpenFDs());
}

}  // namespace
}  // namespace test
}  // namespace net
