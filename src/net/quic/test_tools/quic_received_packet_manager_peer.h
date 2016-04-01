// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_TEST_TOOLS_QUIC_RECEIVED_PACKET_MANAGER_PEER_H_
#define NET_QUIC_TEST_TOOLS_QUIC_RECEIVED_PACKET_MANAGER_PEER_H_

#include "base/macros.h"
#include "net/quic/quic_protocol.h"

namespace net {

class QuicReceivedPacketManager;

namespace test {

class QuicReceivedPacketManagerPeer {
 public:
  static void SetCumulativeEntropyUpTo(
      QuicReceivedPacketManager* received_packet_manager,
      QuicPacketNumber peer_least_unacked,
      QuicPacketEntropyHash entropy_hash);

  static bool DontWaitForPacketsBefore(
      QuicReceivedPacketManager* received_packet_manager,
      QuicPacketNumber least_unacked);

 private:
  DISALLOW_COPY_AND_ASSIGN(QuicReceivedPacketManagerPeer);
};

}  // namespace test

}  // namespace net

#endif  // NET_QUIC_TEST_TOOLS_QUIC_RECEIVED_PACKET_MANAGER_PEER_H_
