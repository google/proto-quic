// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/frames/quic_ack_frame.h"

#include "net/quic/core/quic_constants.h"
#include "net/quic/platform/api/quic_bug_tracker.h"

namespace net {

bool IsAwaitingPacket(const QuicAckFrame& ack_frame,
                      QuicPacketNumber packet_number,
                      QuicPacketNumber peer_least_packet_awaiting_ack) {
  return packet_number >= peer_least_packet_awaiting_ack &&
         !ack_frame.packets.Contains(packet_number);
}

QuicAckFrame::QuicAckFrame()
    : largest_observed(0), ack_delay_time(QuicTime::Delta::Infinite()) {}

QuicAckFrame::QuicAckFrame(const QuicAckFrame& other) = default;

QuicAckFrame::~QuicAckFrame() {}

std::ostream& operator<<(std::ostream& os, const QuicAckFrame& ack_frame) {
  os << "{ largest_observed: " << ack_frame.largest_observed
     << ", ack_delay_time: " << ack_frame.ack_delay_time.ToMicroseconds()
     << ", packets: [ " << ack_frame.packets << " ]"
     << ", received_packets: [ ";
  for (const std::pair<QuicPacketNumber, QuicTime>& p :
       ack_frame.received_packet_times) {
    os << p.first << " at " << p.second.ToDebuggingValue() << " ";
  }
  os << " ] }\n";
  return os;
}

PacketNumberQueue::PacketNumberQueue() = default;
PacketNumberQueue::PacketNumberQueue(const PacketNumberQueue& other) = default;
PacketNumberQueue::PacketNumberQueue(PacketNumberQueue&& other) = default;
PacketNumberQueue::~PacketNumberQueue() {}

PacketNumberQueue& PacketNumberQueue::operator=(
    const PacketNumberQueue& other) = default;
PacketNumberQueue& PacketNumberQueue::operator=(PacketNumberQueue&& other) =
    default;

void PacketNumberQueue::Add(QuicPacketNumber packet_number) {
  packet_number_intervals_.Add(packet_number, packet_number + 1);
}

void PacketNumberQueue::Add(QuicPacketNumber lower, QuicPacketNumber higher) {
  packet_number_intervals_.Add(lower, higher);
}

void PacketNumberQueue::Remove(QuicPacketNumber packet_number) {
  packet_number_intervals_.Difference(packet_number, packet_number + 1);
}

void PacketNumberQueue::Remove(QuicPacketNumber lower,
                               QuicPacketNumber higher) {
  packet_number_intervals_.Difference(lower, higher);
}

bool PacketNumberQueue::RemoveUpTo(QuicPacketNumber higher) {
  if (Empty()) {
    return false;
  }
  const QuicPacketNumber old_min = Min();
  packet_number_intervals_.Difference(0, higher);
  return Empty() || old_min != Min();
}

void PacketNumberQueue::RemoveSmallestInterval() {
  QUIC_BUG_IF(packet_number_intervals_.Size() < 2)
      << (Empty() ? "No intervals to remove."
                  : "Can't remove the last interval.");

  packet_number_intervals_.Difference(*packet_number_intervals_.begin());
}

bool PacketNumberQueue::Contains(QuicPacketNumber packet_number) const {
  return packet_number_intervals_.Contains(packet_number);
}

bool PacketNumberQueue::Empty() const {
  return packet_number_intervals_.Empty();
}

QuicPacketNumber PacketNumberQueue::Min() const {
  DCHECK(!Empty());
  return packet_number_intervals_.begin()->min();
}

QuicPacketNumber PacketNumberQueue::Max() const {
  DCHECK(!Empty());
  return packet_number_intervals_.rbegin()->max() - 1;
}

size_t PacketNumberQueue::NumPacketsSlow() const {
  size_t num_packets = 0;
  for (const auto& interval : packet_number_intervals_) {
    num_packets += interval.Length();
  }
  return num_packets;
}

size_t PacketNumberQueue::NumIntervals() const {
  return packet_number_intervals_.Size();
}

QuicPacketNumber PacketNumberQueue::LastIntervalLength() const {
  DCHECK(!Empty());
  return packet_number_intervals_.rbegin()->Length();
}

PacketNumberQueue::const_iterator PacketNumberQueue::begin() const {
  return packet_number_intervals_.begin();
}

PacketNumberQueue::const_iterator PacketNumberQueue::end() const {
  return packet_number_intervals_.end();
}

PacketNumberQueue::const_reverse_iterator PacketNumberQueue::rbegin() const {
  return packet_number_intervals_.rbegin();
}

PacketNumberQueue::const_reverse_iterator PacketNumberQueue::rend() const {
  return packet_number_intervals_.rend();
}

std::ostream& operator<<(std::ostream& os, const PacketNumberQueue& q) {
  for (const Interval<QuicPacketNumber>& interval : q) {
    for (QuicPacketNumber packet_number = interval.min();
         packet_number < interval.max(); ++packet_number) {
      os << packet_number << " ";
    }
  }
  return os;
}

}  // namespace net
