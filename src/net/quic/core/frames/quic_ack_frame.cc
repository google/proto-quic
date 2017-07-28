// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/frames/quic_ack_frame.h"

#include "net/quic/core/quic_constants.h"
#include "net/quic/platform/api/quic_bug_tracker.h"
#include "net/quic/platform/api/quic_flag_utils.h"

namespace net {

PacketNumberQueue::const_iterator::const_iterator(const const_iterator& other) =
    default;
PacketNumberQueue::const_iterator::const_iterator(const_iterator&& other) =
    default;
PacketNumberQueue::const_iterator::~const_iterator() {}

PacketNumberQueue::const_iterator::const_iterator(
    typename QuicIntervalSet<QuicPacketNumber>::const_iterator it)
    : vector_it_(it), use_deque_it_(false) {}

PacketNumberQueue::const_reverse_iterator::const_reverse_iterator(
    const const_reverse_iterator& other) = default;
PacketNumberQueue::const_reverse_iterator::const_reverse_iterator(
    const_reverse_iterator&& other) = default;
PacketNumberQueue::const_reverse_iterator::~const_reverse_iterator() {}

PacketNumberQueue::const_iterator::const_iterator(
    typename std::deque<Interval<QuicPacketNumber>>::const_iterator it)
    : deque_it_(it), use_deque_it_(true) {}

PacketNumberQueue::const_reverse_iterator::const_reverse_iterator(
    const typename QuicIntervalSet<QuicPacketNumber>::const_reverse_iterator&
        it)
    : vector_it_(it), use_deque_it_(false) {}

PacketNumberQueue::const_reverse_iterator::const_reverse_iterator(
    const typename std::deque<
        Interval<QuicPacketNumber>>::const_reverse_iterator& it)
    : deque_it_(it), use_deque_it_(true) {}

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
PacketNumberQueue::PacketNumberQueue()
    : use_deque_(FLAGS_quic_reloadable_flag_quic_frames_deque) {
  if (use_deque_) {
    QUIC_FLAG_COUNT(quic_reloadable_flag_quic_frames_deque);
  }
}

PacketNumberQueue::PacketNumberQueue(const PacketNumberQueue& other) = default;
PacketNumberQueue::PacketNumberQueue(PacketNumberQueue&& other) = default;
PacketNumberQueue::~PacketNumberQueue() {}

PacketNumberQueue& PacketNumberQueue::operator=(
    const PacketNumberQueue& other) = default;
PacketNumberQueue& PacketNumberQueue::operator=(PacketNumberQueue&& other) =
    default;

void PacketNumberQueue::Add(QuicPacketNumber packet_number) {
  if (use_deque_) {
    // Check if the deque is empty
    if (packet_number_deque_.empty()) {
      packet_number_deque_.push_front(
          Interval<QuicPacketNumber>(packet_number, packet_number + 1));
      return;
    }

    // Check for the typical case,
    // when the next packet in order is acked
    if ((packet_number_deque_.back()).max() == packet_number) {
      (packet_number_deque_.back()).SetMax(packet_number + 1);
      return;
    }
    // Check if the next packet in order is skipped
    if ((packet_number_deque_.back()).max() < packet_number) {
      packet_number_deque_.push_back(
          Interval<QuicPacketNumber>(packet_number, packet_number + 1));
      return;
    }
    // Check if the packet can be  popped on the front
    if ((packet_number_deque_.front()).min() > packet_number + 1) {
      packet_number_deque_.push_front(
          Interval<QuicPacketNumber>(packet_number, packet_number + 1));
      return;
    }
    if ((packet_number_deque_.front()).min() == packet_number + 1) {
      (packet_number_deque_.front()).SetMin(packet_number);
      return;
    }

    int i = packet_number_deque_.size() - 1;
    // Iterating through the queue backwards
    // to find a proper place for the packet
    while (i >= 0) {
      // Check if the packet is contained in an interval already
      if (packet_number_deque_[i].max() > packet_number &&
          packet_number_deque_[i].min() <= packet_number) {
        return;
      }

      // Check if the packet can extend an interval
      // and merges two intervals if needed
      if (packet_number_deque_[i].max() == packet_number) {
        packet_number_deque_[i].SetMax(packet_number + 1);
        if (static_cast<size_t>(i) < packet_number_deque_.size() - 1 &&
            packet_number_deque_[i].max() ==
                packet_number_deque_[i + 1].min()) {
          packet_number_deque_[i].SetMax(packet_number_deque_[i + 1].max());
          packet_number_deque_.erase(packet_number_deque_.begin() + i + 1);
        }
        return;
      }
      if (packet_number_deque_[i].min() == packet_number + 1) {
        packet_number_deque_[i].SetMin(packet_number);
        if (i > 0 && packet_number_deque_[i].min() ==
                         packet_number_deque_[i - 1].max()) {
          packet_number_deque_[i - 1].SetMax(packet_number_deque_[i].max());
          packet_number_deque_.erase(packet_number_deque_.begin() + i);
        }
        return;
      }

      // Check if we need to make a new interval for the packet
      if (packet_number_deque_[i].max() < packet_number + 1) {
        packet_number_deque_.insert(
            packet_number_deque_.begin() + i + 1,
            Interval<QuicPacketNumber>(packet_number, packet_number + 1));
        return;
      }
      i--;
    }
  } else {
    packet_number_intervals_.Add(packet_number, packet_number + 1);
  }
}

void PacketNumberQueue::Add(QuicPacketNumber lower, QuicPacketNumber higher) {
  if (lower >= higher) {
    return;
  }
  if (use_deque_) {
    if (packet_number_deque_.empty()) {
      packet_number_deque_.push_front(
          Interval<QuicPacketNumber>(lower, higher));

    } else if ((packet_number_deque_.back()).max() == lower) {
      // Check for the typical case,
      // when the next packet in order is acked
      (packet_number_deque_.back()).SetMax(higher);

    } else if ((packet_number_deque_.back()).max() < lower) {
      // Check if the next packet in order is skipped
      packet_number_deque_.push_back(Interval<QuicPacketNumber>(lower, higher));

      // Check if the packets are being added in reverse order
    } else if ((packet_number_deque_.front()).min() == higher) {
      (packet_number_deque_.front()).SetMax(lower);
    } else if ((packet_number_deque_.front()).min() > higher) {
      packet_number_deque_.push_front(
          Interval<QuicPacketNumber>(lower, higher));

    } else {
      // Iterating through the interval and adding packets one by one
      for (size_t i = lower; i != higher; i++) {
        PacketNumberQueue::Add(i);
      }
    }
  } else {
    packet_number_intervals_.Add(lower, higher);
  }
}

bool PacketNumberQueue::RemoveUpTo(QuicPacketNumber higher) {
  if (Empty()) {
    return false;
  }
  const QuicPacketNumber old_min = Min();
  if (use_deque_) {
    while (!packet_number_deque_.empty()) {
      if (packet_number_deque_.front().max() < higher) {
        packet_number_deque_.pop_front();
      } else if (packet_number_deque_.front().min() < higher &&
                 packet_number_deque_.front().max() >= higher) {
        packet_number_deque_.front().SetMin(higher);
        if (packet_number_deque_.front().max() ==
            packet_number_deque_.front().min()) {
          packet_number_deque_.pop_front();
        }
        break;
      } else {
        break;
      }
    }
  } else {
    packet_number_intervals_.Difference(0, higher);
  }

  return Empty() || old_min != Min();
}

void PacketNumberQueue::RemoveSmallestInterval() {
  if (use_deque_) {
    QUIC_BUG_IF(packet_number_deque_.size() < 2)
        << (Empty() ? "No intervals to remove."
                    : "Can't remove the last interval.");
    packet_number_deque_.pop_front();
  } else {
    QUIC_BUG_IF(packet_number_intervals_.Size() < 2)
        << (Empty() ? "No intervals to remove."
                    : "Can't remove the last interval.");
    packet_number_intervals_.Difference(*packet_number_intervals_.begin());
  }
}

bool PacketNumberQueue::Contains(QuicPacketNumber packet_number) const {
  if (use_deque_) {
    if (packet_number_deque_.empty()) {
      return false;
    }
    int low = 0;
    int high = packet_number_deque_.size() - 1;

    while (low <= high) {
      int mid = (low + high) / 2;
      if (packet_number_deque_[mid].min() > packet_number) {
        high = mid - 1;
        continue;
      }
      if (packet_number_deque_[mid].max() <= packet_number) {
        low = mid + 1;
        continue;
      }
      DCHECK(packet_number_deque_[mid].max() > packet_number);
      DCHECK(packet_number_deque_[mid].min() <= packet_number);
      return true;
    }
    return false;
  } else {
    return packet_number_intervals_.Contains(packet_number);
  }
}

bool PacketNumberQueue::Empty() const {
  if (use_deque_) {
    return packet_number_deque_.empty();
  } else {
    return packet_number_intervals_.Empty();
  }
}

QuicPacketNumber PacketNumberQueue::Min() const {
  DCHECK(!Empty());
  if (use_deque_) {
    return packet_number_deque_.front().min();
  } else {
    return packet_number_intervals_.begin()->min();
  }
}

QuicPacketNumber PacketNumberQueue::Max() const {
  DCHECK(!Empty());
  if (use_deque_) {
    return packet_number_deque_.back().max() - 1;
  } else {
    return packet_number_intervals_.rbegin()->max() - 1;
  }
}

size_t PacketNumberQueue::NumPacketsSlow() const {
  if (use_deque_) {
    size_t n_packets = 0;
    for (size_t i = 0; i < packet_number_deque_.size(); i++) {
      n_packets += packet_number_deque_[i].Length();
    }
    return n_packets;
  } else {
    size_t num_packets = 0;
    for (const auto& interval : packet_number_intervals_) {
      num_packets += interval.Length();
    }
    return num_packets;
  }
}

size_t PacketNumberQueue::NumIntervals() const {
  if (use_deque_) {
    return packet_number_deque_.size();
  } else {
    return packet_number_intervals_.Size();
  }
}

PacketNumberQueue::const_iterator PacketNumberQueue::begin() const {
  if (use_deque_) {
    return PacketNumberQueue::const_iterator(packet_number_deque_.begin());
  } else {
    return PacketNumberQueue::const_iterator(packet_number_intervals_.begin());
  }
}

PacketNumberQueue::const_iterator PacketNumberQueue::end() const {
  if (use_deque_) {
    return const_iterator(packet_number_deque_.end());
  } else {
    return const_iterator(packet_number_intervals_.end());
  }
}

PacketNumberQueue::const_reverse_iterator PacketNumberQueue::rbegin() const {
  if (use_deque_) {
    return const_reverse_iterator(packet_number_deque_.rbegin());
  } else {
    return const_reverse_iterator(packet_number_intervals_.rbegin());
  }
}

PacketNumberQueue::const_reverse_iterator PacketNumberQueue::rend() const {
  if (use_deque_) {
    return const_reverse_iterator(packet_number_deque_.rend());
  } else {
    return const_reverse_iterator(packet_number_intervals_.rend());
  }
}

QuicPacketNumber PacketNumberQueue::LastIntervalLength() const {
  DCHECK(!Empty());
  if (use_deque_) {
    return packet_number_deque_[packet_number_deque_.size() - 1].Length();
  } else {
    return packet_number_intervals_.rbegin()->Length();
  }
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
