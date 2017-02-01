// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_CORE_FRAMES_QUIC_ACK_FRAME_H_
#define NET_QUIC_CORE_FRAMES_QUIC_ACK_FRAME_H_

#include <ostream>
#include <string>

#include "base/strings/string_piece.h"
#include "net/quic/core/quic_types.h"
#include "net/quic/platform/api/quic_containers.h"
#include "net/quic/platform/api/quic_export.h"

namespace net {

// A sequence of packet numbers where each number is unique. Intended to be used
// in a sliding window fashion, where smaller old packet numbers are removed and
// larger new packet numbers are added, with the occasional random access.
class QUIC_EXPORT_PRIVATE PacketNumberQueue {
 public:
  using const_iterator = QuicIntervalSet<QuicPacketNumber>::const_iterator;
  using const_reverse_iterator =
      QuicIntervalSet<QuicPacketNumber>::const_reverse_iterator;

  PacketNumberQueue();
  PacketNumberQueue(const PacketNumberQueue& other);
  PacketNumberQueue(PacketNumberQueue&& other);
  ~PacketNumberQueue();

  PacketNumberQueue& operator=(const PacketNumberQueue& other);
  PacketNumberQueue& operator=(PacketNumberQueue&& other);

  // Adds |packet_number| to the set of packets in the queue.
  void Add(QuicPacketNumber packet_number);

  // Adds packets between [lower, higher) to the set of packets in the queue. It
  // is undefined behavior to call this with |higher| < |lower|.
  void Add(QuicPacketNumber lower, QuicPacketNumber higher);

  // Removes |packet_number| from the set of packets in the queue.
  void Remove(QuicPacketNumber packet_number);

  // Removes packets numbers between [lower, higher) to the set of packets in
  // the queue. It is undefined behavior to call this with |higher| < |lower|.
  void Remove(QuicPacketNumber lower, QuicPacketNumber higher);

  // Removes packets with values less than |higher| from the set of packets in
  // the queue. Returns true if packets were removed.
  bool RemoveUpTo(QuicPacketNumber higher);

  // Mutates packet number set so that it contains only those packet numbers
  // from minimum to maximum packet number not currently in the set. Do nothing
  // if packet number set is empty.
  void Complement();

  // Returns true if the queue contains |packet_number|.
  bool Contains(QuicPacketNumber packet_number) const;

  // Returns true if the queue is empty.
  bool Empty() const;

  // Returns the minimum packet number stored in the queue. It is undefined
  // behavior to call this if the queue is empty.
  QuicPacketNumber Min() const;

  // Returns the maximum packet number stored in the queue. It is undefined
  // behavior to call this if the queue is empty.
  QuicPacketNumber Max() const;

  // Returns the number of unique packets stored in the queue. Inefficient; only
  // exposed for testing.
  size_t NumPacketsSlow() const;

  // Returns the number of disjoint packet number intervals contained in the
  // queue.
  size_t NumIntervals() const;

  // Returns the length of last interval.
  QuicPacketNumber LastIntervalLength() const;

  // Returns iterators over the packet number intervals.
  const_iterator begin() const;
  const_iterator end() const;
  const_reverse_iterator rbegin() const;
  const_reverse_iterator rend() const;
  const_iterator lower_bound(QuicPacketNumber packet_number) const;

  friend QUIC_EXPORT_PRIVATE std::ostream& operator<<(
      std::ostream& os,
      const PacketNumberQueue& q);

 private:
  QuicIntervalSet<QuicPacketNumber> packet_number_intervals_;
};

struct QUIC_EXPORT_PRIVATE QuicAckFrame {
  QuicAckFrame();
  QuicAckFrame(const QuicAckFrame& other);
  ~QuicAckFrame();

  friend QUIC_EXPORT_PRIVATE std::ostream& operator<<(std::ostream& os,
                                                      const QuicAckFrame& s);

  // The highest packet number we've observed from the peer.
  QuicPacketNumber largest_observed;

  // Time elapsed since largest_observed was received until this Ack frame was
  // sent.
  QuicTime::Delta ack_delay_time;

  // Vector of <packet_number, time> for when packets arrived.
  PacketTimeVector received_packet_times;

  // Set of packets.
  PacketNumberQueue packets;

  // Path which this ack belongs to.
  QuicPathId path_id;
};

// True if the packet number is greater than largest_observed or is listed
// as missing.
// Always returns false for packet numbers less than least_unacked.
QUIC_EXPORT_PRIVATE bool IsAwaitingPacket(
    const QuicAckFrame& ack_frame,
    QuicPacketNumber packet_number,
    QuicPacketNumber peer_least_packet_awaiting_ack);

}  // namespace net

#endif  // NET_QUIC_CORE_FRAMES_QUIC_ACK_FRAME_H_
