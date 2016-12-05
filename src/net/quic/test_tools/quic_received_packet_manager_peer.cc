// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/test_tools/quic_received_packet_manager_peer.h"

#include "net/quic/core/quic_packets.h"
#include "net/quic/core/quic_received_packet_manager.h"

namespace net {
namespace test {

// static
bool QuicReceivedPacketManagerPeer::DontWaitForPacketsBefore(
    QuicReceivedPacketManager* received_packet_manager,
    QuicPacketNumber least_unacked) {
  return received_packet_manager->DontWaitForPacketsBefore(least_unacked);
}

}  // namespace test
}  // namespace net
