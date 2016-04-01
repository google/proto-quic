// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/congestion_control/send_algorithm_simulator.h"

#include <stdint.h>

#include <limits>

#include "base/logging.h"
#include "base/rand_util.h"
#include "net/quic/crypto/quic_random.h"

using std::list;
using std::max;
using std::min;
using std::string;
using std::vector;

namespace net {

namespace {

const QuicByteCount kPacketSize = 1200;

}  // namespace

SendAlgorithmSimulator::Sender::Sender(SendAlgorithmInterface* send_algorithm,
                                       RttStats* rtt_stats)
    : Sender(send_algorithm, rtt_stats, QuicTime::Delta::Zero()) {}

SendAlgorithmSimulator::Sender::Sender(SendAlgorithmInterface* send_algorithm,
                                       RttStats* rtt_stats,
                                       QuicTime::Delta additional_rtt)
    : send_algorithm(send_algorithm),
      rtt_stats(rtt_stats),
      additional_rtt(additional_rtt),
      last_sent(0),
      last_acked(0),
      next_acked(1),
      max_cwnd(0),
      min_cwnd(100000),
      max_cwnd_drop(0),
      last_cwnd(0),
      last_transfer_bandwidth(QuicBandwidth::Zero()),
      last_transfer_loss_rate(0) {}

SendAlgorithmSimulator::Transfer::Transfer(Sender* sender,
                                           QuicByteCount num_bytes,
                                           QuicTime start_time,
                                           string name)
    : sender(sender),
      num_bytes(num_bytes),
      bytes_acked(0),
      bytes_lost(0),
      bytes_in_flight(0),
      start_time(start_time),
      name(name) {}

SendAlgorithmSimulator::SendAlgorithmSimulator(MockClock* clock,
                                               QuicBandwidth bandwidth,
                                               QuicTime::Delta rtt)
    : clock_(clock),
      lose_next_ack_(false),
      forward_loss_rate_(0),
      reverse_loss_rate_(0),
      loss_correlation_(0),
      bandwidth_(bandwidth),
      rtt_(rtt),
      buffer_size_(1000000),
      delayed_ack_timer_(QuicTime::Delta::FromMilliseconds(100)) {
  uint32_t seed = base::RandInt(0, std::numeric_limits<int32_t>::max());
  DVLOG(1) << "Seeding SendAlgorithmSimulator with " << seed;
  simple_random_.set_seed(seed);
}

SendAlgorithmSimulator::~SendAlgorithmSimulator() {}

void SendAlgorithmSimulator::AddTransfer(Sender* sender, size_t num_bytes) {
  AddTransfer(sender, num_bytes, clock_->Now(),
              StringPrintf("#%zu", pending_transfers_.size()));
}

void SendAlgorithmSimulator::AddTransfer(Sender* sender,
                                         size_t num_bytes,
                                         QuicTime start_time,
                                         string name) {
  pending_transfers_.push_back(Transfer(sender, num_bytes, start_time, name));
  // Record initial stats from when the transfer begins.
  pending_transfers_.back().sender->RecordStats();
}

void SendAlgorithmSimulator::TransferBytes() {
  TransferBytes(std::numeric_limits<uint64_t>::max(),
                QuicTime::Delta::Infinite());
}

void SendAlgorithmSimulator::TransferBytes(QuicByteCount max_bytes,
                                           QuicTime::Delta max_time) {
  const QuicTime end_time =
      max_time.IsInfinite() ? QuicTime::Zero().Add(QuicTime::Delta::Infinite())
                            : clock_->Now().Add(max_time);
  QuicByteCount bytes_sent = 0;
  while (!pending_transfers_.empty() && clock_->Now() < end_time &&
         bytes_sent < max_bytes) {
    // Determine the times of next send and of the next ack arrival.
    PacketEvent send_event = NextSendEvent();
    PacketEvent ack_event = NextAckEvent();
    // If both times are infinite, fire a TLP.
    if (ack_event.time_delta.IsInfinite() &&
        send_event.time_delta.IsInfinite()) {
      DVLOG(1) << "Both times are infinite, simulating a TLP.";
      // TODO(ianswett): Use a more sophisticated TLP timer or never lose
      // the last ack?
      clock_->AdvanceTime(QuicTime::Delta::FromMilliseconds(100));
      SendDataNow(&pending_transfers_.front());
    } else if (ack_event.time_delta < send_event.time_delta) {
      DVLOG(1) << "Handling ack of largest observed:"
               << ack_event.transfer->sender->next_acked
               << ", advancing time:" << ack_event.time_delta.ToMicroseconds()
               << "us";
      // Ack data all the data up to ack time and lose any missing packet
      // numbers.
      clock_->AdvanceTime(ack_event.time_delta);
      HandlePendingAck(ack_event.transfer);
    } else {
      DVLOG(1) << "Sending transfer '" << send_event.transfer->name
               << "', advancing time:" << send_event.time_delta.ToMicroseconds()
               << "us";
      clock_->AdvanceTime(send_event.time_delta);
      SendDataNow(send_event.transfer);
      bytes_sent += kPacketSize;
    }
  }
}

SendAlgorithmSimulator::PacketEvent SendAlgorithmSimulator::NextSendEvent() {
  QuicTime::Delta next_send_time = QuicTime::Delta::Infinite();
  Transfer* transfer = nullptr;
  for (vector<Transfer>::iterator it = pending_transfers_.begin();
       it != pending_transfers_.end(); ++it) {
    // If we've already sent enough bytes, wait for them to be acked.
    if (it->bytes_acked + it->bytes_in_flight >= it->num_bytes) {
      continue;
    }
    // If the flow hasn't started, use the start time.
    QuicTime::Delta transfer_send_time = it->start_time.Subtract(clock_->Now());
    if (clock_->Now() >= it->start_time) {
      transfer_send_time = it->sender->send_algorithm->TimeUntilSend(
          clock_->Now(), it->bytes_in_flight);
    }
    if (transfer_send_time < next_send_time) {
      next_send_time = transfer_send_time;
      transfer = &(*it);
    }
  }
  DVLOG(1) << "NextSendTime returning delta(ms):"
           << next_send_time.ToMilliseconds() << ", transfer '"
           << transfer->name;
  return PacketEvent(next_send_time, transfer);
}

// NextAck takes into account packet loss in both forward and reverse
// direction, as well as correlated losses.  And it assumes the receiver acks
// every other packet when there is no loss.
SendAlgorithmSimulator::PacketEvent SendAlgorithmSimulator::NextAckEvent() {
  if (sent_packets_.empty()) {
    DVLOG(1) << "No outstanding packets to ack for any transfer.";
    return PacketEvent(QuicTime::Delta::Infinite(), nullptr);
  }

  // For each connection, find the next acked packet.
  QuicTime::Delta ack_time = QuicTime::Delta::Infinite();
  Transfer* transfer = nullptr;
  for (vector<Transfer>::iterator it = pending_transfers_.begin();
       it != pending_transfers_.end(); ++it) {
    QuicTime::Delta transfer_ack_time = FindNextAcked(&(*it));
    if (transfer_ack_time < ack_time) {
      ack_time = transfer_ack_time;
      transfer = &(*it);
    }
  }

  return PacketEvent(ack_time, transfer);
}

QuicTime::Delta SendAlgorithmSimulator::FindNextAcked(Transfer* transfer) {
  Sender* sender = transfer->sender;
  if (sender->next_acked == sender->last_acked) {
    // Determine if the next ack is lost only once, to ensure determinism.
    lose_next_ack_ = reverse_loss_rate_ * std::numeric_limits<uint64_t>::max() >
                     simple_random_.RandUint64();
  }

  QuicPacketNumber next_acked = sender->last_acked;
  QuicTime::Delta next_ack_delay =
      FindNextAck(transfer, sender->last_acked, &next_acked);
  if (lose_next_ack_) {
    next_ack_delay = FindNextAck(transfer, next_acked, &next_acked);
  }
  sender->next_acked = next_acked;
  return next_ack_delay;
}

QuicTime::Delta SendAlgorithmSimulator::FindNextAck(
    const Transfer* transfer,
    QuicPacketNumber last_acked,
    QuicPacketNumber* next_acked) const {
  *next_acked = last_acked;
  QuicTime::Delta ack_delay = QuicTime::Delta::Infinite();
  // Remove any packets that are simulated as lost.
  for (list<SentPacket>::const_iterator it = sent_packets_.begin();
       it != sent_packets_.end(); ++it) {
    if (transfer != it->transfer) {
      continue;
    }
    // Skip over any packets less than or equal to last_acked.
    if (it->packet_number <= last_acked) {
      continue;
    }
    // Lost packets don't trigger an ack.
    if (it->lost) {
      continue;
    }
    DCHECK_LT(*next_acked, it->packet_number);
    // Consider a delayed ack for the current next_acked.
    if (ack_delay < it->ack_time.Subtract(clock_->Now())) {
      break;
    }
    *next_acked = it->packet_number;
    ack_delay = it->ack_time.Subtract(clock_->Now());
    if (HasRecentLostPackets(transfer, *next_acked) ||
        (*next_acked - last_acked) >= 2) {
      break;
    }
    ack_delay = ack_delay.Add(delayed_ack_timer_);
  }

  DVLOG(1) << "FindNextAck found next_acked_:" << transfer->sender->next_acked
           << " last_acked:" << transfer->sender->last_acked
           << " ack_time(ms):" << ack_delay.ToMilliseconds();
  return ack_delay;
}

bool SendAlgorithmSimulator::HasRecentLostPackets(
    const Transfer* transfer,
    QuicPacketNumber next_acked) const {
  QuicPacketNumber last_packet = transfer->sender->last_acked;
  for (list<SentPacket>::const_iterator it = sent_packets_.begin();
       it != sent_packets_.end() && it->packet_number < next_acked; ++it) {
    if (transfer != it->transfer) {
      continue;
    }
    // Lost packets don't trigger an ack.
    if (it->lost) {
      return true;
    }
    // Buffer dropped packets are skipped automatically, but still end up
    // being lost and cause acks to be sent immediately.
    if (it->packet_number > last_packet + 1) {
      return true;
    }
    last_packet = it->packet_number;
  }
  return false;
}

void SendAlgorithmSimulator::HandlePendingAck(Transfer* transfer) {
  Sender* sender = transfer->sender;
  DCHECK_LT(sender->last_acked, sender->next_acked);
  SendAlgorithmInterface::CongestionVector acked_packets;
  SendAlgorithmInterface::CongestionVector lost_packets;
  DVLOG(1) << "Acking packets from:" << sender->last_acked << " to "
           << sender->next_acked
           << " bytes_in_flight:" << transfer->bytes_in_flight
           << " Now():" << (clock_->Now().ToDebuggingValue() / 1000) << "ms";
  // Some entries may be missing from the sent_packets_ array, if they were
  // dropped due to buffer overruns.
  SentPacket largest_observed;
  list<SentPacket>::iterator it = sent_packets_.begin();
  while (sender->last_acked < sender->next_acked) {
    ++sender->last_acked;
    // Find the next SentPacket for this transfer.
    while (it->transfer != transfer) {
      DCHECK(it != sent_packets_.end());
      ++it;
    }
    // If it's missing from the array, it's a loss.
    if (it->packet_number > sender->last_acked) {
      DVLOG(1) << "Lost packet:" << sender->last_acked
               << " dropped by buffer overflow.";
      lost_packets.push_back(std::make_pair(sender->last_acked, kPacketSize));
      continue;
    }
    if (it->lost) {
      lost_packets.push_back(std::make_pair(sender->last_acked, kPacketSize));
    } else {
      acked_packets.push_back(std::make_pair(sender->last_acked, kPacketSize));
    }
    // This packet has been acked or lost, remove it from sent_packets_.
    largest_observed = *it;
    sent_packets_.erase(it++);
  }

  DCHECK(!largest_observed.lost);
  DVLOG(1) << "Updating RTT from send_time:"
           << largest_observed.send_time.ToDebuggingValue()
           << " to ack_time:" << largest_observed.ack_time.ToDebuggingValue();
  QuicTime::Delta measured_rtt =
      largest_observed.ack_time.Subtract(largest_observed.send_time);
  DCHECK_GE(measured_rtt.ToMicroseconds(), rtt_.ToMicroseconds());
  sender->rtt_stats->UpdateRtt(measured_rtt, QuicTime::Delta::Zero(),
                               clock_->Now());
  sender->send_algorithm->OnCongestionEvent(true, transfer->bytes_in_flight,
                                            acked_packets, lost_packets);
  DCHECK_LE(kPacketSize * (acked_packets.size() + lost_packets.size()),
            transfer->bytes_in_flight);
  transfer->bytes_in_flight -=
      kPacketSize * (acked_packets.size() + lost_packets.size());

  sender->RecordStats();
  transfer->bytes_acked += acked_packets.size() * kPacketSize;
  transfer->bytes_lost += lost_packets.size() * kPacketSize;
  if (transfer->bytes_acked >= transfer->num_bytes) {
    // Remove completed transfers and record transfer bandwidth.
    QuicTime::Delta transfer_time =
        clock_->Now().Subtract(transfer->start_time);
    sender->last_transfer_loss_rate =
        static_cast<float>(transfer->bytes_lost) /
        (transfer->bytes_lost + transfer->bytes_acked);
    sender->last_transfer_bandwidth = QuicBandwidth::FromBytesAndTimeDelta(
        transfer->num_bytes, transfer_time);
    DCHECK_GE(bandwidth_.ToBitsPerSecond(),
              sender->last_transfer_bandwidth.ToBitsPerSecond());
    for (vector<Transfer>::iterator it = pending_transfers_.begin();
         it != pending_transfers_.end(); ++it) {
      if (transfer == &(*it)) {
        pending_transfers_.erase(it);
        break;
      }
    }
  }
}

void SendAlgorithmSimulator::SendDataNow(Transfer* transfer) {
  Sender* sender = transfer->sender;
  ++sender->last_sent;
  DVLOG(1) << "Sending packet:" << sender->last_sent
           << " name:" << transfer->name
           << " bytes_in_flight:" << transfer->bytes_in_flight
           << " cwnd:" << sender->send_algorithm->GetCongestionWindow()
           << " Now():" << (clock_->Now().ToDebuggingValue() / 1000) << "ms";
  sender->send_algorithm->OnPacketSent(clock_->Now(), transfer->bytes_in_flight,
                                       sender->last_sent, kPacketSize,
                                       HAS_RETRANSMITTABLE_DATA);
  // Lose the packet immediately if the buffer is full.
  if (sent_packets_.size() * kPacketSize < buffer_size_) {
    // TODO(ianswett): This buffer simulation is an approximation.
    // An ack time of zero means loss.
    bool packet_lost =
        forward_loss_rate_ * std::numeric_limits<uint64_t>::max() >
        simple_random_.RandUint64();
    // Handle correlated loss.
    if (!sent_packets_.empty() && sent_packets_.back().lost &&
        loss_correlation_ * std::numeric_limits<uint64_t>::max() >
            simple_random_.RandUint64()) {
      packet_lost = true;
    }
    DVLOG(1) << "losing packet:" << sender->last_sent
             << " name:" << transfer->name << " due to random loss.";

    // If the number of bytes in flight are less than the bdp, there's
    // no buffering delay.  Bytes lost from the buffer are not counted.
    QuicByteCount bdp = bandwidth_.ToBytesPerPeriod(rtt_);
    QuicTime ack_time = clock_->Now().Add(rtt_).Add(sender->additional_rtt);
    if (kPacketSize > bdp) {
      ack_time = ack_time.Add(bandwidth_.TransferTime(kPacketSize - bdp));
    }
    QuicTime queue_ack_time = sent_packets_.empty()
                                  ? QuicTime::Zero()
                                  : sent_packets_.back().ack_time.Add(
                                        bandwidth_.TransferTime(kPacketSize));
    ack_time = QuicTime::Max(ack_time, queue_ack_time);
    sent_packets_.push_back(SentPacket(sender->last_sent, clock_->Now(),
                                       ack_time, packet_lost, transfer));
  } else {
    DVLOG(1) << "losing packet:" << sender->last_sent
             << " name:" << transfer->name << " because the buffer was full.";
  }
  transfer->bytes_in_flight += kPacketSize;
}

}  // namespace net
