// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_CORE_QUIC_RECEIVED_PACKET_MANAGER_H_
#define NET_QUIC_CORE_QUIC_RECEIVED_PACKET_MANAGER_H_

#include "base/macros.h"
#include "net/quic/core/quic_config.h"
#include "net/quic/core/quic_framer.h"
#include "net/quic/core/quic_packets.h"
#include "net/quic/platform/api/quic_export.h"

namespace net {

namespace test {
class QuicConnectionPeer;
class QuicReceivedPacketManagerPeer;
}  // namespace test

struct QuicConnectionStats;

// Records all received packets by a connection.
class QUIC_EXPORT_PRIVATE QuicReceivedPacketManager {
 public:
  explicit QuicReceivedPacketManager(QuicConnectionStats* stats);
  virtual ~QuicReceivedPacketManager();

  // Updates the internal state concerning which packets have been received.
  // header: the packet header.
  // timestamp: the arrival time of the packet.
  virtual void RecordPacketReceived(const QuicPacketHeader& header,
                                    QuicTime receipt_time);

  // Checks whether |packet_number| is missing and less than largest observed.
  virtual bool IsMissing(QuicPacketNumber packet_number);

  // Checks if we're still waiting for the packet with |packet_number|.
  virtual bool IsAwaitingPacket(QuicPacketNumber packet_number);

  // Retrieves a frame containing a QuicAckFrame.  The ack frame may not be
  // changed outside QuicReceivedPacketManager and must be serialized before
  // another packet is received, or it will change.
  const QuicFrame GetUpdatedAckFrame(QuicTime approximate_now);

  // Updates internal state based on |stop_waiting|.
  virtual void UpdatePacketInformationSentByPeer(
      const QuicStopWaitingFrame& stop_waiting);

  // Returns true if there are any missing packets.
  bool HasMissingPackets() const;

  // Returns true when there are new missing packets to be reported within 3
  // packets of the largest observed.
  virtual bool HasNewMissingPackets() const;

  QuicPacketNumber peer_least_packet_awaiting_ack() {
    return peer_least_packet_awaiting_ack_;
  }

  virtual bool ack_frame_updated() const;

  QuicPacketNumber GetLargestObserved() const;

  // For logging purposes.
  const QuicAckFrame& ack_frame() const { return ack_frame_; }

 private:
  friend class test::QuicConnectionPeer;
  friend class test::QuicReceivedPacketManagerPeer;

  // Deletes all missing packets before least unacked. The connection won't
  // process any packets with packet number before |least_unacked| that it
  // received after this call. Returns true if there were missing packets before
  // |least_unacked| unacked, false otherwise.
  bool DontWaitForPacketsBefore(QuicPacketNumber least_unacked);

  // Least packet number of the the packet sent by the peer for which it
  // hasn't received an ack.
  QuicPacketNumber peer_least_packet_awaiting_ack_;

  // Received packet information used to produce acks.
  QuicAckFrame ack_frame_;

  // True if |ack_frame_| has been updated since UpdateReceivedPacketInfo was
  // last called.
  bool ack_frame_updated_;

  // The time we received the largest_observed packet number, or zero if
  // no packet numbers have been received since UpdateReceivedPacketInfo.
  // Needed for calculating ack_delay_time.
  QuicTime time_largest_observed_;

  QuicConnectionStats* stats_;

  DISALLOW_COPY_AND_ASSIGN(QuicReceivedPacketManager);
};

}  // namespace net

#endif  // NET_QUIC_CORE_QUIC_RECEIVED_PACKET_MANAGER_H_
