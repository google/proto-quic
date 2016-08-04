// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/test_tools/quic_multipath_sent_packet_manager_peer.h"

namespace net {
namespace test {

// static
void QuicMultipathSentPacketManagerPeer::AddPathWithCloseState(
    QuicMultipathSentPacketManager* multipath_manager,
    QuicSentPacketManagerInterface* manager) {
  multipath_manager->path_managers_info_.push_back(
      QuicMultipathSentPacketManager::PathSentPacketManagerInfo(
          manager, QuicMultipathSentPacketManager::CLOSING));
}

// static
void QuicMultipathSentPacketManagerPeer::AddPathWithActiveState(
    QuicMultipathSentPacketManager* multipath_manager,
    QuicSentPacketManagerInterface* manager) {
  multipath_manager->path_managers_info_.push_back(
      QuicMultipathSentPacketManager::PathSentPacketManagerInfo(
          manager, QuicMultipathSentPacketManager::ACTIVE));
}

}  // namespace test
}  // namespace net
