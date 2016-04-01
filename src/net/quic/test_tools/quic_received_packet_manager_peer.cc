// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/test_tools/quic_received_packet_manager_peer.h"

#include "net/quic/quic_protocol.h"
#include "net/quic/quic_received_packet_manager.h"

namespace net {
namespace test {

// static
void QuicReceivedPacketManagerPeer::SetCumulativeEntropyUpTo(
    QuicReceivedPacketManager* received_packet_manager,
    QuicPacketNumber peer_least_unacked,
    QuicPacketEntropyHash entropy_hash) {
  received_packet_manager->entropy_tracker_.SetCumulativeEntropyUpTo(
      peer_least_unacked, entropy_hash);
}

// static
bool QuicReceivedPacketManagerPeer::DontWaitForPacketsBefore(
    QuicReceivedPacketManager* received_packet_manager,
    QuicPacketNumber least_unacked) {
  return received_packet_manager->DontWaitForPacketsBefore(least_unacked);
}

}  // namespace test
}  // namespace net
