// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_TEST_TOOLS_QUIC_MULTIPATH_SENT_PACKET_MANAGER_PEER_H_
#define NET_QUIC_TEST_TOOLS_QUIC_MULTIPATH_SENT_PACKET_MANAGER_PEER_H_

#include "base/macros.h"
#include "net/quic/core/quic_multipath_sent_packet_manager.h"
#include "net/quic/test_tools/quic_sent_packet_manager_peer.h"

namespace net {
namespace test {

class QuicMultipathSentPacketManagerPeer {
 public:
  // Add a path |manager| with close state.
  static void AddPathWithCloseState(
      QuicMultipathSentPacketManager* multipath_manager,
      QuicSentPacketManagerInterface* manager);

  // Add a path |manager| with active state.
  static void AddPathWithActiveState(
      QuicMultipathSentPacketManager* multipath_manager,
      QuicSentPacketManagerInterface* manager);
};

}  // namespace test
}  // namespace net

#endif  // NET_QUIC_TEST_TOOLS_QUIC_MULTIPATH_SENT_PACKET_MANAGER_PEER_H_
