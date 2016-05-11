// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/quic/test_tools/quic_client_peer.h"

#include "net/tools/quic/quic_client.h"

namespace net {
namespace test {

// static
QuicCryptoClientConfig* QuicClientPeer::GetCryptoConfig(QuicClient* client) {
  return client->crypto_config();
}

// static
bool QuicClientPeer::CreateUDPSocketAndBind(QuicClient* client) {
  return client->CreateUDPSocketAndBind();
}

// static
void QuicClientPeer::CleanUpUDPSocket(QuicClient* client, int fd) {
  client->CleanUpUDPSocket(fd);
}

// static
void QuicClientPeer::SetClientPort(QuicClient* client, int port) {
  client->fd_address_map_.back().second =
      IPEndPoint(client->GetLatestClientAddress().address(), port);
}

// static
void QuicClientPeer::SetWriter(QuicClient* client, QuicPacketWriter* writer) {
  client->set_writer(writer);
}

}  // namespace test
}  // namespace net
