// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// A test only class to enable simulations of send algorithms.

#ifndef NET_QUIC_CONGESTION_CONTROL_SEND_ALGORITHM_SIMULATOR_H_
#define NET_QUIC_CONGESTION_CONTROL_SEND_ALGORITHM_SIMULATOR_H_

#include <stddef.h>

#include <algorithm>
#include <string>
#include <vector>

#include "base/format_macros.h"
#include "base/macros.h"
#include "base/strings/stringprintf.h"
#include "net/quic/congestion_control/send_algorithm_interface.h"
#include "net/quic/quic_protocol.h"
#include "net/quic/quic_time.h"
#include "net/quic/test_tools/mock_clock.h"
#include "net/quic/test_tools/quic_test_utils.h"

using base::StringPrintf;

namespace net {

class SendAlgorithmSimulator {
 public:
  struct Sender {
    Sender(SendAlgorithmInterface* send_algorithm, RttStats* rtt_stats);
    Sender(SendAlgorithmInterface* send_algorithm,
           RttStats* rtt_stats,
           QuicTime::Delta additional_rtt);

    void RecordStats() {
      QuicByteCount cwnd = send_algorithm->GetCongestionWindow();
      max_cwnd = std::max(max_cwnd, cwnd);
      min_cwnd = std::min(min_cwnd, cwnd);
      if (last_cwnd > cwnd) {
        max_cwnd_drop = std::max(max_cwnd_drop, last_cwnd - cwnd);
      }
      last_cwnd = cwnd;
    }

    std::string DebugString() {
      return StringPrintf("observed goodput(bytes/s):%" PRId64
                          " loss rate:%f"
                          " cwnd:%" PRIu64 " max_cwnd:%" PRIu64
                          " min_cwnd:%" PRIu64 " max_cwnd_drop:%" PRIu64,
                          last_transfer_bandwidth.ToBytesPerSecond(),
                          last_transfer_loss_rate,
                          send_algorithm->GetCongestionWindow(), max_cwnd,
                          min_cwnd, max_cwnd_drop);
    }

    SendAlgorithmInterface* send_algorithm;
    RttStats* rtt_stats;
    QuicTime::Delta additional_rtt;

    // Last packet number the sender sent.
    QuicPacketNumber last_sent;
    // Last packet number acked.
    QuicPacketNumber last_acked;
    // packet number to ack up to.
    QuicPacketNumber next_acked;

    // Stats collected for understanding the congestion control.
    QuicByteCount max_cwnd;
    QuicByteCount min_cwnd;
    QuicByteCount max_cwnd_drop;
    QuicByteCount last_cwnd;

    QuicBandwidth last_transfer_bandwidth;
    float last_transfer_loss_rate;
  };

  struct Transfer {
    Transfer(Sender* sender,
             QuicByteCount num_bytes,
             QuicTime start_time,
             std::string name);

    Sender* sender;
    QuicByteCount num_bytes;
    QuicByteCount bytes_acked;
    QuicByteCount bytes_lost;
    QuicByteCount bytes_in_flight;
    QuicTime start_time;
    std::string name;
  };

  struct SentPacket {
    SentPacket()
        : packet_number(0),
          send_time(QuicTime::Zero()),
          ack_time(QuicTime::Zero()),
          lost(false),
          transfer(nullptr) {}
    SentPacket(QuicPacketNumber packet_number,
               QuicTime send_time,
               QuicTime ack_time,
               bool lost,
               Transfer* transfer)
        : packet_number(packet_number),
          send_time(send_time),
          ack_time(ack_time),
          lost(lost),
          transfer(transfer) {}

    QuicPacketNumber packet_number;
    QuicTime send_time;
    QuicTime ack_time;
    bool lost;
    Transfer* transfer;
  };

  // |rtt_stats| should be the same RttStats used by the |send_algorithm|.
  SendAlgorithmSimulator(MockClock* clock_,
                         QuicBandwidth bandwidth,
                         QuicTime::Delta rtt);
  ~SendAlgorithmSimulator();

  // For local ad-hoc testing.
  void set_bandwidth(QuicBandwidth bandwidth) { bandwidth_ = bandwidth; }

  void set_forward_loss_rate(float loss_rate) {
    DCHECK_LT(loss_rate, 1.0f);
    forward_loss_rate_ = loss_rate;
  }

  // For local ad-hoc testing.
  void set_reverse_loss_rate(float loss_rate) {
    DCHECK_LT(loss_rate, 1.0f);
    reverse_loss_rate_ = loss_rate;
  }

  // For local ad-hoc testing.
  void set_loss_correlation(float loss_correlation) {
    DCHECK_LT(loss_correlation, 1.0f);
    loss_correlation_ = loss_correlation;
  }

  void set_buffer_size(size_t buffer_size_bytes) {
    buffer_size_ = buffer_size_bytes;
  }

  void set_delayed_ack_timer(QuicTime::Delta delayed_ack_timer) {
    delayed_ack_timer_ = delayed_ack_timer;
  }

  // Advance the time by |delta| without sending anything.
  // For local ad-hoc testing.
  void AdvanceTime(QuicTime::Delta delta);

  // Adds a pending sender.  The send will run when TransferBytes is called.
  // Adding two transfers with the same sender is unsupported.
  void AddTransfer(Sender* sender, size_t num_bytes);

  // Adds a pending sending to start at the specified time.
  void AddTransfer(Sender* sender,
                   size_t num_bytes,
                   QuicTime start_time,
                   std::string name);

  // Convenience method to transfer all bytes.
  void TransferBytes();

  // Transfers bytes through the connection until |max_bytes| are reached,
  // |max_time| is reached, or all senders have finished sending.  If max_bytes
  // is 0, it does not apply, and if |max_time| is Zero, no time limit applies.
  void TransferBytes(QuicByteCount max_bytes, QuicTime::Delta max_time);

 private:
  // A pending packet event, either a send or an ack.
  struct PacketEvent {
    PacketEvent(QuicTime::Delta time_delta, Transfer* transfer)
        : time_delta(time_delta), transfer(transfer) {}

    QuicTime::Delta time_delta;
    Transfer* transfer;
  };

  // NextSendTime returns the next time any of the pending transfers send,
  // and populates transfer if the send time is not infinite.
  PacketEvent NextSendEvent();

  // NextAckTime takes into account packet loss in both forward and reverse
  // direction, as well as delayed ack behavior.
  PacketEvent NextAckEvent();

  // Sets the next acked.
  QuicTime::Delta FindNextAcked(Transfer* transfer);

  // Sets the |next_acked| packet for the |transfer| starting at the specified
  // |last_acked|.  Returns QuicTime::Delta::Infinite and doesn't set
  // |next_acked| if there is no ack after |last_acked|.
  QuicTime::Delta FindNextAck(const Transfer* transfer,
                              QuicPacketNumber last_acked,
                              QuicPacketNumber* next_acked) const;

  // Returns true if any of the packets |transfer| is waiting for less than
  // next_acked have been lost.
  bool HasRecentLostPackets(const Transfer* transfer,
                            QuicPacketNumber next_acked) const;

  // Process all the acks that should have arrived by the current time, and
  // lose any packets that are missing.  Returns the number of bytes acked.
  void HandlePendingAck(Transfer* transfer);

  void SendDataNow(Transfer* transfer);

  // List of all pending transfers waiting to use the connection.
  std::vector<Transfer> pending_transfers_;

  MockClock* clock_;
  // Whether the next ack should be lost.
  bool lose_next_ack_;
  // The times acks are expected, assuming acks are not lost and every packet
  // is acked.
  std::list<SentPacket> sent_packets_;

  test::SimpleRandom simple_random_;
  float forward_loss_rate_;  // Loss rate on the forward path.
  float reverse_loss_rate_;  // Loss rate on the reverse path.
  float loss_correlation_;   // Likelihood the subsequent packet is lost.
  QuicBandwidth bandwidth_;
  QuicTime::Delta rtt_;
  size_t buffer_size_;  // In bytes.
  QuicTime::Delta delayed_ack_timer_;

  DISALLOW_COPY_AND_ASSIGN(SendAlgorithmSimulator);
};

}  // namespace net

#endif  // NET_QUIC_CONGESTION_CONTROL_SEND_ALGORITHM_SIMULATOR_H_
