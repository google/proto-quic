// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// A connection level received packet manager which manages multiple per path
// received packet managers.

#ifndef NET_QUIC_CORE_QUIC_MULTIPATH_RECEIVED_PACKET_MANAGER_H_
#define NET_QUIC_CORE_QUIC_MULTIPATH_RECEIVED_PACKET_MANAGER_H_

#include <memory>
#include <unordered_map>
#include <vector>

#include "net/quic/core/quic_packets.h"
#include "net/quic/core/quic_received_packet_manager.h"
#include "net/quic/platform/api/quic_export.h"

namespace net {

namespace test {
class QuicMultipathReceivedPacketManagerPeer;
}  // namespace test

class QUIC_EXPORT_PRIVATE QuicMultipathReceivedPacketManager {
 public:
  explicit QuicMultipathReceivedPacketManager(QuicConnectionStats* stats);
  ~QuicMultipathReceivedPacketManager();
  QuicMultipathReceivedPacketManager(
      const QuicMultipathReceivedPacketManager&) = delete;
  QuicMultipathReceivedPacketManager& operator=(
      const QuicMultipathReceivedPacketManager&) = delete;

  // Called when a new path with |path_id| is created.
  void OnPathCreated(QuicPathId path_id, QuicConnectionStats* stats);

  // Called when path with |path_id| is closed.
  void OnPathClosed(QuicPathId path_id);

  // Records packet receipt information on path with |path_id|.
  void RecordPacketReceived(QuicPathId path_id,
                            const QuicPacketHeader& header,
                            QuicTime receipt_time);

  // Checks whether |packet_number| is missing on path with |path_id|.
  bool IsMissing(QuicPathId path_id, QuicPacketNumber packet_number);

  // Checks if we're still waiting for the packet with |packet_number| on path
  // with |path_id|.
  bool IsAwaitingPacket(QuicPathId path_id, QuicPacketNumber packet_number);

  // If |force_all_paths| is false, populates ack information for paths whose
  // ack has been updated since UpdateReceivedPacketInfo was called last time.
  // Otherwise, populates ack for all paths.
  void UpdateReceivedPacketInfo(std::vector<QuicAckFrame>* ack_frames,
                                QuicTime approximate_now,
                                bool force_all_paths);

  // Updates internal state based on stop_waiting frames for corresponding path.
  void UpdatePacketInformationSentByPeer(
      const std::vector<QuicStopWaitingFrame>& stop_waitings);

  // Returns true when there are new missing packets to be reported within 3
  // packets of the largest observed on path with |path_id|.
  bool HasNewMissingPackets(QuicPathId path_id) const;

  QuicPacketNumber GetPeerLeastPacketAwaitingAck(QuicPathId path_id);

 private:
  friend class test::QuicMultipathReceivedPacketManagerPeer;

  // Map mapping path id to path received packet manager.
  std::unordered_map<QuicPathId, std::unique_ptr<QuicReceivedPacketManager>>
      path_managers_;
};

}  // namespace net

#endif  // NET_QUIC_CORE_QUIC_MULTIPATH_RECEIVED_PACKET_MANAGER_H_
