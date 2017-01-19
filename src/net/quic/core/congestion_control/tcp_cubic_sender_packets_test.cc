// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/congestion_control/tcp_cubic_sender_packets.h"

#include <algorithm>
#include <memory>

#include "net/quic/core/congestion_control/rtt_stats.h"
#include "net/quic/core/congestion_control/send_algorithm_interface.h"
#include "net/quic/core/crypto/crypto_protocol.h"
#include "net/quic/core/proto/cached_network_parameters.pb.h"
#include "net/quic/core/quic_packets.h"
#include "net/quic/core/quic_utils.h"
#include "net/quic/platform/api/quic_logging.h"
#include "net/quic/test_tools/mock_clock.h"
#include "net/quic/test_tools/quic_config_peer.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {
namespace test {

// TODO(ianswett): A number of theses tests were written with the assumption of
// an initial CWND of 10. They have carefully calculated values which should be
// updated to be based on kInitialCongestionWindow.
const uint32_t kInitialCongestionWindowPackets = 10;
const uint32_t kMaxCongestionWindowPackets = 200;
const uint32_t kDefaultWindowTCP =
    kInitialCongestionWindowPackets * kDefaultTCPMSS;
const float kRenoBeta = 0.7f;  // Reno backoff factor.

class TcpCubicSenderPacketsPeer : public TcpCubicSenderPackets {
 public:
  TcpCubicSenderPacketsPeer(const QuicClock* clock,
                            bool reno,
                            QuicPacketCount max_tcp_congestion_window)
      : TcpCubicSenderPackets(clock,
                              &rtt_stats_,
                              reno,
                              kInitialCongestionWindowPackets,
                              max_tcp_congestion_window,
                              &stats_) {}

  QuicPacketCount congestion_window() { return congestion_window_; }

  QuicPacketCount max_congestion_window() { return max_tcp_congestion_window_; }

  QuicPacketCount slowstart_threshold() { return slowstart_threshold_; }

  const HybridSlowStart& hybrid_slow_start() const {
    return hybrid_slow_start_;
  }

  float GetRenoBeta() const { return RenoBeta(); }

  RttStats rtt_stats_;
  QuicConnectionStats stats_;
};

class TcpCubicSenderPacketsTest : public ::testing::Test {
 protected:
  TcpCubicSenderPacketsTest()
      : one_ms_(QuicTime::Delta::FromMilliseconds(1)),
        sender_(new TcpCubicSenderPacketsPeer(&clock_,
                                              true,
                                              kMaxCongestionWindowPackets)),
        packet_number_(1),
        acked_packet_number_(0),
        bytes_in_flight_(0) {}

  int SendAvailableSendWindow() {
    return SendAvailableSendWindow(kDefaultTCPMSS);
  }

  int SendAvailableSendWindow(QuicPacketLength packet_length) {
    // Send as long as TimeUntilSend returns Zero.
    int packets_sent = 0;
    bool can_send =
        sender_->TimeUntilSend(clock_.Now(), bytes_in_flight_).IsZero();
    while (can_send) {
      sender_->OnPacketSent(clock_.Now(), bytes_in_flight_, packet_number_++,
                            kDefaultTCPMSS, HAS_RETRANSMITTABLE_DATA);
      ++packets_sent;
      bytes_in_flight_ += kDefaultTCPMSS;
      can_send =
          sender_->TimeUntilSend(clock_.Now(), bytes_in_flight_).IsZero();
    }
    return packets_sent;
  }

  // Normal is that TCP acks every other segment.
  void AckNPackets(int n) {
    sender_->rtt_stats_.UpdateRtt(QuicTime::Delta::FromMilliseconds(60),
                                  QuicTime::Delta::Zero(), clock_.Now());
    SendAlgorithmInterface::CongestionVector acked_packets;
    SendAlgorithmInterface::CongestionVector lost_packets;
    for (int i = 0; i < n; ++i) {
      ++acked_packet_number_;
      acked_packets.push_back(
          std::make_pair(acked_packet_number_, kDefaultTCPMSS));
    }
    sender_->OnCongestionEvent(true, bytes_in_flight_, clock_.Now(),
                               acked_packets, lost_packets);
    bytes_in_flight_ -= n * kDefaultTCPMSS;
    clock_.AdvanceTime(one_ms_);
  }

  void LoseNPackets(int n) { LoseNPackets(n, kDefaultTCPMSS); }

  void LoseNPackets(int n, QuicPacketLength packet_length) {
    SendAlgorithmInterface::CongestionVector acked_packets;
    SendAlgorithmInterface::CongestionVector lost_packets;
    for (int i = 0; i < n; ++i) {
      ++acked_packet_number_;
      lost_packets.push_back(
          std::make_pair(acked_packet_number_, packet_length));
    }
    sender_->OnCongestionEvent(false, bytes_in_flight_, clock_.Now(),
                               acked_packets, lost_packets);
    bytes_in_flight_ -= n * packet_length;
  }

  // Does not increment acked_packet_number_.
  void LosePacket(QuicPacketNumber packet_number) {
    SendAlgorithmInterface::CongestionVector acked_packets;
    SendAlgorithmInterface::CongestionVector lost_packets;
    lost_packets.push_back(std::make_pair(packet_number, kDefaultTCPMSS));
    sender_->OnCongestionEvent(false, bytes_in_flight_, clock_.Now(),
                               acked_packets, lost_packets);
    bytes_in_flight_ -= kDefaultTCPMSS;
  }

  const QuicTime::Delta one_ms_;
  MockClock clock_;
  std::unique_ptr<TcpCubicSenderPacketsPeer> sender_;
  QuicPacketNumber packet_number_;
  QuicPacketNumber acked_packet_number_;
  QuicByteCount bytes_in_flight_;
};

TEST_F(TcpCubicSenderPacketsTest, SimpleSender) {
  // At startup make sure we are at the default.
  EXPECT_EQ(kDefaultWindowTCP, sender_->GetCongestionWindow());
  // At startup make sure we can send.
  EXPECT_TRUE(sender_->TimeUntilSend(clock_.Now(), 0).IsZero());
  // Make sure we can send.
  EXPECT_TRUE(sender_->TimeUntilSend(clock_.Now(), 0).IsZero());
  // And that window is un-affected.
  EXPECT_EQ(kDefaultWindowTCP, sender_->GetCongestionWindow());

  // Fill the send window with data, then verify that we can't send.
  SendAvailableSendWindow();
  EXPECT_FALSE(
      sender_->TimeUntilSend(clock_.Now(), sender_->GetCongestionWindow())
          .IsZero());
}

TEST_F(TcpCubicSenderPacketsTest, ApplicationLimitedSlowStart) {
  // Send exactly 10 packets and ensure the CWND ends at 14 packets.
  const int kNumberOfAcks = 5;
  // At startup make sure we can send.
  EXPECT_TRUE(sender_->TimeUntilSend(clock_.Now(), 0).IsZero());
  // Make sure we can send.
  EXPECT_TRUE(sender_->TimeUntilSend(clock_.Now(), 0).IsZero());

  SendAvailableSendWindow();
  for (int i = 0; i < kNumberOfAcks; ++i) {
    AckNPackets(2);
  }
  QuicByteCount bytes_to_send = sender_->GetCongestionWindow();
  // It's expected 2 acks will arrive when the bytes_in_flight are greater than
  // half the CWND.
  EXPECT_EQ(kDefaultWindowTCP + kDefaultTCPMSS * 2 * 2, bytes_to_send);
}

TEST_F(TcpCubicSenderPacketsTest, ExponentialSlowStart) {
  const int kNumberOfAcks = 20;
  // At startup make sure we can send.
  EXPECT_TRUE(sender_->TimeUntilSend(clock_.Now(), 0).IsZero());
  EXPECT_EQ(QuicBandwidth::Zero(), sender_->BandwidthEstimate());
  // Make sure we can send.
  EXPECT_TRUE(sender_->TimeUntilSend(clock_.Now(), 0).IsZero());

  for (int i = 0; i < kNumberOfAcks; ++i) {
    // Send our full send window.
    SendAvailableSendWindow();
    AckNPackets(2);
  }
  const QuicByteCount cwnd = sender_->GetCongestionWindow();
  EXPECT_EQ(kDefaultWindowTCP + kDefaultTCPMSS * 2 * kNumberOfAcks, cwnd);
  EXPECT_EQ(QuicBandwidth::FromBytesAndTimeDelta(
                cwnd, sender_->rtt_stats_.smoothed_rtt()),
            sender_->BandwidthEstimate());
}

TEST_F(TcpCubicSenderPacketsTest, SlowStartPacketLoss) {
  sender_->SetNumEmulatedConnections(1);
  const int kNumberOfAcks = 10;
  for (int i = 0; i < kNumberOfAcks; ++i) {
    // Send our full send window.
    SendAvailableSendWindow();
    AckNPackets(2);
  }
  SendAvailableSendWindow();
  QuicByteCount expected_send_window =
      kDefaultWindowTCP + (kDefaultTCPMSS * 2 * kNumberOfAcks);
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());

  // Lose a packet to exit slow start.
  LoseNPackets(1);
  size_t packets_in_recovery_window = expected_send_window / kDefaultTCPMSS;

  // We should now have fallen out of slow start with a reduced window.
  expected_send_window *= kRenoBeta;
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());

  // Recovery phase. We need to ack every packet in the recovery window before
  // we exit recovery.
  size_t number_of_packets_in_window = expected_send_window / kDefaultTCPMSS;
  QUIC_DLOG(INFO) << "number_packets: " << number_of_packets_in_window;
  AckNPackets(packets_in_recovery_window);
  SendAvailableSendWindow();
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());

  // We need to ack an entire window before we increase CWND by 1.
  AckNPackets(number_of_packets_in_window - 2);
  SendAvailableSendWindow();
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());

  // Next ack should increase cwnd by 1.
  AckNPackets(1);
  expected_send_window += kDefaultTCPMSS;
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());

  // Now RTO and ensure slow start gets reset.
  EXPECT_TRUE(sender_->hybrid_slow_start().started());
  sender_->OnRetransmissionTimeout(true);
  EXPECT_FALSE(sender_->hybrid_slow_start().started());
}

TEST_F(TcpCubicSenderPacketsTest, SlowStartPacketLossWithLargeReduction) {
  QuicConfig config;
  QuicTagVector options;
  options.push_back(kSSLR);
  QuicConfigPeer::SetReceivedConnectionOptions(&config, options);
  sender_->SetFromConfig(config, Perspective::IS_SERVER);

  sender_->SetNumEmulatedConnections(1);
  const int kNumberOfAcks = (kDefaultWindowTCP / (2 * kDefaultTCPMSS)) - 1;
  for (int i = 0; i < kNumberOfAcks; ++i) {
    // Send our full send window.
    SendAvailableSendWindow();
    AckNPackets(2);
  }
  SendAvailableSendWindow();
  QuicByteCount expected_send_window =
      kDefaultWindowTCP + (kDefaultTCPMSS * 2 * kNumberOfAcks);
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());

  // Lose a packet to exit slow start. We should now have fallen out of
  // slow start with a window reduced by 1.
  LoseNPackets(1);
  expected_send_window -= kDefaultTCPMSS;
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());

  // Lose 5 packets in recovery and verify that congestion window is reduced
  // further.
  LoseNPackets(5);
  expected_send_window -= 5 * kDefaultTCPMSS;
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());
  // Lose another 10 packets and ensure it reduces below half the peak CWND,
  // because we never acked the full IW.
  LoseNPackets(10);
  expected_send_window -= 10 * kDefaultTCPMSS;
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());

  size_t packets_in_recovery_window = expected_send_window / kDefaultTCPMSS;

  // Recovery phase. We need to ack every packet in the recovery window before
  // we exit recovery.
  size_t number_of_packets_in_window = expected_send_window / kDefaultTCPMSS;
  QUIC_DLOG(INFO) << "number_packets: " << number_of_packets_in_window;
  AckNPackets(packets_in_recovery_window);
  SendAvailableSendWindow();
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());

  // We need to ack the rest of the window before cwnd increases by 1.
  AckNPackets(number_of_packets_in_window - 1);
  SendAvailableSendWindow();
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());

  // Next ack should increase cwnd by 1.
  AckNPackets(1);
  expected_send_window += kDefaultTCPMSS;
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());

  // Now RTO and ensure slow start gets reset.
  EXPECT_TRUE(sender_->hybrid_slow_start().started());
  sender_->OnRetransmissionTimeout(true);
  EXPECT_FALSE(sender_->hybrid_slow_start().started());
}

TEST_F(TcpCubicSenderPacketsTest, SlowStartHalfPacketLossWithLargeReduction) {
  QuicConfig config;
  QuicTagVector options;
  options.push_back(kSSLR);
  QuicConfigPeer::SetReceivedConnectionOptions(&config, options);
  sender_->SetFromConfig(config, Perspective::IS_SERVER);

  sender_->SetNumEmulatedConnections(1);
  const int kNumberOfAcks = 10;
  for (int i = 0; i < kNumberOfAcks; ++i) {
    // Send our full send window in half sized packets.
    SendAvailableSendWindow(kDefaultTCPMSS / 2);
    AckNPackets(2);
  }
  SendAvailableSendWindow(kDefaultTCPMSS / 2);
  QuicByteCount expected_send_window =
      kDefaultWindowTCP + (kDefaultTCPMSS * 2 * kNumberOfAcks);
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());

  // Lose a packet to exit slow start. We should now have fallen out of
  // slow start with a window reduced by 1.
  LoseNPackets(1);
  expected_send_window -= kDefaultTCPMSS;
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());

  // Lose 10 packets in recovery and verify that congestion window is reduced
  // by 5 packets.
  LoseNPackets(10, kDefaultTCPMSS / 2);
  expected_send_window -= 5 * kDefaultTCPMSS;
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());
}

TEST_F(TcpCubicSenderPacketsTest, SlowStartPacketLossWithMaxHalfReduction) {
  QuicConfig config;
  QuicTagVector options;
  options.push_back(kSSLR);
  QuicConfigPeer::SetReceivedConnectionOptions(&config, options);
  sender_->SetFromConfig(config, Perspective::IS_SERVER);

  sender_->SetNumEmulatedConnections(1);
  const int kNumberOfAcks = kInitialCongestionWindowPackets / 2;
  for (int i = 0; i < kNumberOfAcks; ++i) {
    // Send our full send window.
    SendAvailableSendWindow();
    AckNPackets(2);
  }
  SendAvailableSendWindow();
  QuicByteCount expected_send_window =
      kDefaultWindowTCP + (kDefaultTCPMSS * 2 * kNumberOfAcks);
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());

  // Lose a packet to exit slow start. We should now have fallen out of
  // slow start with a window reduced by 1.
  LoseNPackets(1);
  expected_send_window -= kDefaultTCPMSS;
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());

  // Lose half the outstanding packets in recovery and verify the congestion
  // window is only reduced by a max of half.
  LoseNPackets(kNumberOfAcks * 2);
  expected_send_window -= (kNumberOfAcks * 2 - 1) * kDefaultTCPMSS;
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());
  LoseNPackets(5);
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());
}

TEST_F(TcpCubicSenderPacketsTest, NoPRRWhenLessThanOnePacketInFlight) {
  SendAvailableSendWindow();
  LoseNPackets(kInitialCongestionWindowPackets - 1);
  AckNPackets(1);
  // PRR will allow 2 packets for every ack during recovery.
  EXPECT_EQ(2, SendAvailableSendWindow());
  // Simulate abandoning all packets by supplying a bytes_in_flight of 0.
  // PRR should now allow a packet to be sent, even though prr's state
  // variables believe it has sent enough packets.
  EXPECT_EQ(QuicTime::Delta::Zero(), sender_->TimeUntilSend(clock_.Now(), 0));
}

TEST_F(TcpCubicSenderPacketsTest, SlowStartPacketLossPRR) {
  sender_->SetNumEmulatedConnections(1);
  // Test based on the first example in RFC6937.
  // Ack 10 packets in 5 acks to raise the CWND to 20, as in the example.
  const int kNumberOfAcks = 5;
  for (int i = 0; i < kNumberOfAcks; ++i) {
    // Send our full send window.
    SendAvailableSendWindow();
    AckNPackets(2);
  }
  SendAvailableSendWindow();
  QuicByteCount expected_send_window =
      kDefaultWindowTCP + (kDefaultTCPMSS * 2 * kNumberOfAcks);
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());

  LoseNPackets(1);

  // We should now have fallen out of slow start with a reduced window.
  size_t send_window_before_loss = expected_send_window;
  expected_send_window *= kRenoBeta;
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());

  // Testing TCP proportional rate reduction.
  // We should send packets paced over the received acks for the remaining
  // outstanding packets. The number of packets before we exit recovery is the
  // original CWND minus the packet that has been lost and the one which
  // triggered the loss.
  size_t remaining_packets_in_recovery =
      send_window_before_loss / kDefaultTCPMSS - 2;

  for (size_t i = 0; i < remaining_packets_in_recovery; ++i) {
    AckNPackets(1);
    SendAvailableSendWindow();
    EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());
  }

  // We need to ack another window before we increase CWND by 1.
  size_t number_of_packets_in_window = expected_send_window / kDefaultTCPMSS;
  for (size_t i = 0; i < number_of_packets_in_window; ++i) {
    AckNPackets(1);
    EXPECT_EQ(1, SendAvailableSendWindow());
    EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());
  }

  AckNPackets(1);
  expected_send_window += kDefaultTCPMSS;
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());
}

TEST_F(TcpCubicSenderPacketsTest, SlowStartBurstPacketLossPRR) {
  sender_->SetNumEmulatedConnections(1);
  // Test based on the second example in RFC6937, though we also implement
  // forward acknowledgements, so the first two incoming acks will trigger
  // PRR immediately.
  // Ack 20 packets in 10 acks to raise the CWND to 30.
  const int kNumberOfAcks = 10;
  for (int i = 0; i < kNumberOfAcks; ++i) {
    // Send our full send window.
    SendAvailableSendWindow();
    AckNPackets(2);
  }
  SendAvailableSendWindow();
  QuicByteCount expected_send_window =
      kDefaultWindowTCP + (kDefaultTCPMSS * 2 * kNumberOfAcks);
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());

  // Lose one more than the congestion window reduction, so that after loss,
  // bytes_in_flight is lesser than the congestion window.
  size_t send_window_after_loss = kRenoBeta * expected_send_window;
  size_t num_packets_to_lose =
      (expected_send_window - send_window_after_loss) / kDefaultTCPMSS + 1;
  LoseNPackets(num_packets_to_lose);
  // Immediately after the loss, ensure at least one packet can be sent.
  // Losses without subsequent acks can occur with timer based loss detection.
  EXPECT_TRUE(sender_->TimeUntilSend(clock_.Now(), bytes_in_flight_).IsZero());
  AckNPackets(1);

  // We should now have fallen out of slow start with a reduced window.
  expected_send_window *= kRenoBeta;
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());

  // Only 2 packets should be allowed to be sent, per PRR-SSRB
  EXPECT_EQ(2, SendAvailableSendWindow());

  // Ack the next packet, which triggers another loss.
  LoseNPackets(1);
  AckNPackets(1);

  // Send 2 packets to simulate PRR-SSRB.
  EXPECT_EQ(2, SendAvailableSendWindow());

  // Ack the next packet, which triggers another loss.
  LoseNPackets(1);
  AckNPackets(1);

  // Send 2 packets to simulate PRR-SSRB.
  EXPECT_EQ(2, SendAvailableSendWindow());

  // Exit recovery and return to sending at the new rate.
  for (int i = 0; i < kNumberOfAcks; ++i) {
    AckNPackets(1);
    EXPECT_EQ(1, SendAvailableSendWindow());
  }
}

TEST_F(TcpCubicSenderPacketsTest, RTOCongestionWindow) {
  EXPECT_EQ(kDefaultWindowTCP, sender_->GetCongestionWindow());
  EXPECT_EQ(kMaxCongestionWindowPackets, sender_->slowstart_threshold());

  // Expect the window to decrease to the minimum once the RTO fires
  // and slow start threshold to be set to 1/2 of the CWND.
  sender_->OnRetransmissionTimeout(true);
  EXPECT_EQ(2 * kDefaultTCPMSS, sender_->GetCongestionWindow());
  EXPECT_EQ(5u, sender_->slowstart_threshold());
}

TEST_F(TcpCubicSenderPacketsTest, RTOCongestionWindowNoRetransmission) {
  EXPECT_EQ(kDefaultWindowTCP, sender_->GetCongestionWindow());

  // Expect the window to remain unchanged if the RTO fires but no
  // packets are retransmitted.
  sender_->OnRetransmissionTimeout(false);
  EXPECT_EQ(kDefaultWindowTCP, sender_->GetCongestionWindow());
}

TEST_F(TcpCubicSenderPacketsTest, SlowStartMaxSendWindow) {
  const QuicPacketCount kMaxCongestionWindowTCP = 50;
  const int kNumberOfAcks = 100;
  sender_.reset(
      new TcpCubicSenderPacketsPeer(&clock_, false, kMaxCongestionWindowTCP));

  for (int i = 0; i < kNumberOfAcks; ++i) {
    // Send our full send window.
    SendAvailableSendWindow();
    AckNPackets(2);
  }
  QuicByteCount expected_send_window = kMaxCongestionWindowTCP * kDefaultTCPMSS;
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());
}

TEST_F(TcpCubicSenderPacketsTest, TcpRenoMaxCongestionWindow) {
  const QuicPacketCount kMaxCongestionWindowTCP = 50;
  const int kNumberOfAcks = 1000;
  sender_.reset(
      new TcpCubicSenderPacketsPeer(&clock_, true, kMaxCongestionWindowTCP));

  SendAvailableSendWindow();
  AckNPackets(2);
  // Make sure we fall out of slow start.
  LoseNPackets(1);

  for (int i = 0; i < kNumberOfAcks; ++i) {
    // Send our full send window.
    SendAvailableSendWindow();
    AckNPackets(2);
  }

  QuicByteCount expected_send_window = kMaxCongestionWindowTCP * kDefaultTCPMSS;
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());
}

TEST_F(TcpCubicSenderPacketsTest, TcpCubicMaxCongestionWindow) {
  const QuicPacketCount kMaxCongestionWindowTCP = 50;
  // Set to 10000 to compensate for small cubic alpha.
  const int kNumberOfAcks = 10000;

  sender_.reset(
      new TcpCubicSenderPacketsPeer(&clock_, false, kMaxCongestionWindowTCP));

  SendAvailableSendWindow();
  AckNPackets(2);
  // Make sure we fall out of slow start.
  LoseNPackets(1);

  for (int i = 0; i < kNumberOfAcks; ++i) {
    // Send our full send window.
    SendAvailableSendWindow();
    AckNPackets(2);
  }

  QuicByteCount expected_send_window = kMaxCongestionWindowTCP * kDefaultTCPMSS;
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());
}

TEST_F(TcpCubicSenderPacketsTest, TcpCubicResetEpochOnQuiescence) {
  const int kMaxCongestionWindow = 50;
  const QuicByteCount kMaxCongestionWindowBytes =
      kMaxCongestionWindow * kDefaultTCPMSS;
  sender_.reset(
      new TcpCubicSenderPacketsPeer(&clock_, false, kMaxCongestionWindow));

  int num_sent = SendAvailableSendWindow();

  // Make sure we fall out of slow start.
  QuicByteCount saved_cwnd = sender_->GetCongestionWindow();
  LoseNPackets(1);
  EXPECT_GT(saved_cwnd, sender_->GetCongestionWindow());

  // Ack the rest of the outstanding packets to get out of recovery.
  for (int i = 1; i < num_sent; ++i) {
    AckNPackets(1);
  }
  EXPECT_EQ(0u, bytes_in_flight_);

  // Send a new window of data and ack all; cubic growth should occur.
  saved_cwnd = sender_->GetCongestionWindow();
  num_sent = SendAvailableSendWindow();
  for (int i = 0; i < num_sent; ++i) {
    AckNPackets(1);
  }
  EXPECT_LT(saved_cwnd, sender_->GetCongestionWindow());
  EXPECT_GT(kMaxCongestionWindowBytes, sender_->GetCongestionWindow());
  EXPECT_EQ(0u, bytes_in_flight_);

  // Quiescent time of 100 seconds
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(100000));

  // Send new window of data and ack one packet. Cubic epoch should have
  // been reset; ensure cwnd increase is not dramatic.
  saved_cwnd = sender_->GetCongestionWindow();
  SendAvailableSendWindow();
  AckNPackets(1);
  EXPECT_NEAR(saved_cwnd, sender_->GetCongestionWindow(), kDefaultTCPMSS);
  EXPECT_GT(kMaxCongestionWindowBytes, sender_->GetCongestionWindow());
}

TEST_F(TcpCubicSenderPacketsTest, MultipleLossesInOneWindow) {
  SendAvailableSendWindow();
  const QuicByteCount initial_window = sender_->GetCongestionWindow();
  LosePacket(acked_packet_number_ + 1);
  const QuicByteCount post_loss_window = sender_->GetCongestionWindow();
  EXPECT_GT(initial_window, post_loss_window);
  LosePacket(acked_packet_number_ + 3);
  EXPECT_EQ(post_loss_window, sender_->GetCongestionWindow());
  LosePacket(packet_number_ - 1);
  EXPECT_EQ(post_loss_window, sender_->GetCongestionWindow());

  // Lose a later packet and ensure the window decreases.
  LosePacket(packet_number_);
  EXPECT_GT(post_loss_window, sender_->GetCongestionWindow());
}

TEST_F(TcpCubicSenderPacketsTest, DontTrackAckPackets) {
  // Send a packet with no retransmittable data, and ensure it's not tracked.
  EXPECT_FALSE(sender_->OnPacketSent(clock_.Now(), bytes_in_flight_,
                                     packet_number_++, kDefaultTCPMSS,
                                     NO_RETRANSMITTABLE_DATA));

  // Send a data packet with retransmittable data, and ensure it is tracked.
  EXPECT_TRUE(sender_->OnPacketSent(clock_.Now(), bytes_in_flight_,
                                    packet_number_++, kDefaultTCPMSS,
                                    HAS_RETRANSMITTABLE_DATA));
}

TEST_F(TcpCubicSenderPacketsTest, ConfigureInitialWindow) {
  QuicConfig config;

  QuicTagVector options;
  options.push_back(kIW03);
  QuicConfigPeer::SetReceivedConnectionOptions(&config, options);
  sender_->SetFromConfig(config, Perspective::IS_SERVER);
  EXPECT_EQ(3u, sender_->congestion_window());

  options.clear();
  options.push_back(kIW10);
  QuicConfigPeer::SetReceivedConnectionOptions(&config, options);
  sender_->SetFromConfig(config, Perspective::IS_SERVER);
  EXPECT_EQ(10u, sender_->congestion_window());

  options.clear();
  options.push_back(kIW20);
  QuicConfigPeer::SetReceivedConnectionOptions(&config, options);
  sender_->SetFromConfig(config, Perspective::IS_SERVER);
  EXPECT_EQ(20u, sender_->congestion_window());

  options.clear();
  options.push_back(kIW50);
  QuicConfigPeer::SetReceivedConnectionOptions(&config, options);
  sender_->SetFromConfig(config, Perspective::IS_SERVER);
  EXPECT_EQ(50u, sender_->congestion_window());
}

TEST_F(TcpCubicSenderPacketsTest, ConfigureMinimumWindow) {
  QuicConfig config;

  // Verify that kCOPT: kMIN1 forces the min CWND to 1 packet.
  QuicTagVector options;
  options.push_back(kMIN1);
  QuicConfigPeer::SetReceivedConnectionOptions(&config, options);
  sender_->SetFromConfig(config, Perspective::IS_SERVER);
  sender_->OnRetransmissionTimeout(true);
  EXPECT_EQ(1u, sender_->congestion_window());
}

TEST_F(TcpCubicSenderPacketsTest,
       2ConnectionCongestionAvoidanceAtEndOfRecovery) {
  sender_->SetNumEmulatedConnections(2);
  // Ack 10 packets in 5 acks to raise the CWND to 20.
  const int kNumberOfAcks = 5;
  for (int i = 0; i < kNumberOfAcks; ++i) {
    // Send our full send window.
    SendAvailableSendWindow();
    AckNPackets(2);
  }
  SendAvailableSendWindow();
  QuicByteCount expected_send_window =
      kDefaultWindowTCP + (kDefaultTCPMSS * 2 * kNumberOfAcks);
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());

  LoseNPackets(1);

  // We should now have fallen out of slow start with a reduced window.
  expected_send_window = expected_send_window * sender_->GetRenoBeta();
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());

  // No congestion window growth should occur in recovery phase, i.e., until the
  // currently outstanding 20 packets are acked.
  for (int i = 0; i < 10; ++i) {
    // Send our full send window.
    SendAvailableSendWindow();
    EXPECT_TRUE(sender_->InRecovery());
    AckNPackets(2);
    EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());
  }
  EXPECT_FALSE(sender_->InRecovery());

  // Out of recovery now. Congestion window should not grow for half an RTT.
  size_t packets_in_send_window = expected_send_window / kDefaultTCPMSS;
  SendAvailableSendWindow();
  AckNPackets(packets_in_send_window / 2 - 2);
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());

  // Next ack should increase congestion window by 1MSS.
  SendAvailableSendWindow();
  AckNPackets(2);
  expected_send_window += kDefaultTCPMSS;
  packets_in_send_window += 1;
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());

  // Congestion window should remain steady again for half an RTT.
  SendAvailableSendWindow();
  AckNPackets(packets_in_send_window / 2 - 1);
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());

  // Next ack should cause congestion window to grow by 1MSS.
  SendAvailableSendWindow();
  AckNPackets(2);
  expected_send_window += kDefaultTCPMSS;
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());
}

TEST_F(TcpCubicSenderPacketsTest,
       1ConnectionCongestionAvoidanceAtEndOfRecovery) {
  sender_->SetNumEmulatedConnections(1);
  // Ack 10 packets in 5 acks to raise the CWND to 20.
  const int kNumberOfAcks = 5;
  for (int i = 0; i < kNumberOfAcks; ++i) {
    // Send our full send window.
    SendAvailableSendWindow();
    AckNPackets(2);
  }
  SendAvailableSendWindow();
  QuicByteCount expected_send_window =
      kDefaultWindowTCP + (kDefaultTCPMSS * 2 * kNumberOfAcks);
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());

  LoseNPackets(1);

  // We should now have fallen out of slow start with a reduced window.
  expected_send_window *= kRenoBeta;
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());

  // No congestion window growth should occur in recovery phase, i.e., until the
  // currently outstanding 20 packets are acked.
  for (int i = 0; i < 10; ++i) {
    // Send our full send window.
    SendAvailableSendWindow();
    EXPECT_TRUE(sender_->InRecovery());
    AckNPackets(2);
    EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());
  }
  EXPECT_FALSE(sender_->InRecovery());

  // Out of recovery now. Congestion window should not grow during RTT.
  for (uint64_t i = 0; i < expected_send_window / kDefaultTCPMSS - 2; i += 2) {
    // Send our full send window.
    SendAvailableSendWindow();
    AckNPackets(2);
    EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());
  }

  // Next ack should cause congestion window to grow by 1MSS.
  SendAvailableSendWindow();
  AckNPackets(2);
  expected_send_window += kDefaultTCPMSS;
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());
}

TEST_F(TcpCubicSenderPacketsTest, BandwidthResumption) {
  // Test that when provided with CachedNetworkParameters and opted in to the
  // bandwidth resumption experiment, that the TcpCubicSenderPackets sets
  // initial CWND appropriately.

  // Set some common values.
  CachedNetworkParameters cached_network_params;
  const QuicPacketCount kNumberOfPackets = 123;
  const int kBandwidthEstimateBytesPerSecond =
      kNumberOfPackets * kDefaultTCPMSS;
  cached_network_params.set_bandwidth_estimate_bytes_per_second(
      kBandwidthEstimateBytesPerSecond);
  cached_network_params.set_min_rtt_ms(1000);

  // Make sure that a bandwidth estimate results in a changed CWND.
  cached_network_params.set_timestamp(clock_.WallNow().ToUNIXSeconds() -
                                      (kNumSecondsPerHour - 1));
  sender_->ResumeConnectionState(cached_network_params, false);
  EXPECT_EQ(kNumberOfPackets, sender_->congestion_window());

  // Resumed CWND is limited to be in a sensible range.
  cached_network_params.set_bandwidth_estimate_bytes_per_second(
      (kMaxCongestionWindowPackets + 1) * kDefaultTCPMSS);
  sender_->ResumeConnectionState(cached_network_params, false);
  EXPECT_EQ(kMaxCongestionWindowPackets, sender_->congestion_window());

  // Resume with an illegal value of 0 and verify the server uses 1 instead.
  cached_network_params.set_bandwidth_estimate_bytes_per_second(0);
  sender_->ResumeConnectionState(cached_network_params, false);
  EXPECT_EQ(sender_->min_congestion_window(), sender_->congestion_window());

  // Resume to the max value.
  cached_network_params.set_max_bandwidth_estimate_bytes_per_second(
      kMaxCongestionWindowPackets * kDefaultTCPMSS);
  sender_->ResumeConnectionState(cached_network_params, true);
  EXPECT_EQ(kMaxCongestionWindowPackets * kDefaultTCPMSS,
            sender_->GetCongestionWindow());
}

TEST_F(TcpCubicSenderPacketsTest, PaceBelowCWND) {
  QuicConfig config;

  // Verify that kCOPT: kMIN4 forces the min CWND to 1 packet, but allows up
  // to 4 to be sent.
  QuicTagVector options;
  options.push_back(kMIN4);
  QuicConfigPeer::SetReceivedConnectionOptions(&config, options);
  sender_->SetFromConfig(config, Perspective::IS_SERVER);
  sender_->OnRetransmissionTimeout(true);
  EXPECT_EQ(1u, sender_->congestion_window());
  EXPECT_TRUE(
      sender_->TimeUntilSend(QuicTime::Zero(), kDefaultTCPMSS).IsZero());
  EXPECT_TRUE(
      sender_->TimeUntilSend(QuicTime::Zero(), 2 * kDefaultTCPMSS).IsZero());
  EXPECT_TRUE(
      sender_->TimeUntilSend(QuicTime::Zero(), 3 * kDefaultTCPMSS).IsZero());
  EXPECT_FALSE(
      sender_->TimeUntilSend(QuicTime::Zero(), 4 * kDefaultTCPMSS).IsZero());
}

TEST_F(TcpCubicSenderPacketsTest, NoPRR) {
  QuicTime::Delta rtt = QuicTime::Delta::FromMilliseconds(100);
  sender_->rtt_stats_.UpdateRtt(rtt, QuicTime::Delta::Zero(), QuicTime::Zero());

  sender_->SetNumEmulatedConnections(1);
  // Verify that kCOPT: kNPRR allows all packets to be sent, even if only one
  // ack has been received.
  QuicTagVector options;
  options.push_back(kNPRR);
  QuicConfig config;
  QuicConfigPeer::SetReceivedConnectionOptions(&config, options);
  sender_->SetFromConfig(config, Perspective::IS_SERVER);
  SendAvailableSendWindow();
  LoseNPackets(9);
  AckNPackets(1);

  // We should now have fallen out of slow start with a reduced window.
  EXPECT_EQ(kRenoBeta * kDefaultWindowTCP, sender_->GetCongestionWindow());
  const QuicPacketCount window_in_packets =
      kRenoBeta * kDefaultWindowTCP / kDefaultTCPMSS;
  const QuicBandwidth expected_pacing_rate =
      QuicBandwidth::FromBytesAndTimeDelta(kRenoBeta * kDefaultWindowTCP,
                                           sender_->rtt_stats_.smoothed_rtt());
  EXPECT_EQ(expected_pacing_rate, sender_->PacingRate(0));
  EXPECT_EQ(window_in_packets,
            static_cast<uint64_t>(SendAvailableSendWindow()));
  EXPECT_EQ(expected_pacing_rate,
            sender_->PacingRate(kRenoBeta * kDefaultWindowTCP));
}

TEST_F(TcpCubicSenderPacketsTest, PaceSlowerAboveCwnd) {
  QuicTime::Delta rtt(QuicTime::Delta::FromMilliseconds(60));
  sender_->rtt_stats_.UpdateRtt(rtt, QuicTime::Delta::Zero(), clock_.Now());

  QuicConfig config;
  QuicTagVector options;
  options.push_back(kRATE);
  QuicConfigPeer::SetReceivedConnectionOptions(&config, options);
  sender_->SetFromConfig(config, Perspective::IS_SERVER);
  EXPECT_EQ(10u, sender_->congestion_window());
  sender_->SetNumEmulatedConnections(1);
  // Lose a packet to exit slow start.
  LoseNPackets(1);
  const QuicPacketCount cwnd = 7;
  EXPECT_EQ(cwnd * kDefaultTCPMSS, sender_->GetCongestionWindow());

  EXPECT_TRUE(
      sender_->TimeUntilSend(QuicTime::Zero(), kDefaultTCPMSS).IsZero());
  EXPECT_EQ(
      sender_->PacingRate(kDefaultTCPMSS),
      QuicBandwidth::FromBytesAndTimeDelta(7 * kDefaultTCPMSS, rtt) * 1.25);
  for (QuicPacketCount i = cwnd + 1; i < 1.5 * cwnd; ++i) {
    EXPECT_TRUE(
        sender_->TimeUntilSend(QuicTime::Zero(), i * kDefaultTCPMSS).IsZero());
    EXPECT_EQ(sender_->PacingRate(i * kDefaultTCPMSS),
              QuicBandwidth::FromBytesAndTimeDelta(cwnd * kDefaultTCPMSS, rtt) *
                  0.75);
  }
  EXPECT_FALSE(
      sender_->TimeUntilSend(QuicTime::Zero(), 11 * kDefaultTCPMSS).IsZero());
}

TEST_F(TcpCubicSenderPacketsTest, ResetAfterConnectionMigration) {
  EXPECT_EQ(kDefaultWindowTCP, sender_->GetCongestionWindow());
  EXPECT_EQ(kMaxCongestionWindowPackets, sender_->slowstart_threshold());

  // Starts with slow start.
  sender_->SetNumEmulatedConnections(1);
  const int kNumberOfAcks = 10;
  for (int i = 0; i < kNumberOfAcks; ++i) {
    // Send our full send window.
    SendAvailableSendWindow();
    AckNPackets(2);
  }
  SendAvailableSendWindow();
  QuicByteCount expected_send_window =
      kDefaultWindowTCP + (kDefaultTCPMSS * 2 * kNumberOfAcks);
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());

  // Loses a packet to exit slow start.
  LoseNPackets(1);

  // We should now have fallen out of slow start with a reduced window. Slow
  // start threshold is also updated.
  expected_send_window *= kRenoBeta;
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());
  EXPECT_EQ(expected_send_window / kDefaultTCPMSS,
            sender_->slowstart_threshold());

  // Resets cwnd and slow start threshold on connection migrations.
  sender_->OnConnectionMigration();
  EXPECT_EQ(kDefaultWindowTCP, sender_->GetCongestionWindow());
  EXPECT_EQ(kMaxCongestionWindowPackets, sender_->slowstart_threshold());
  EXPECT_FALSE(sender_->hybrid_slow_start().started());
}

TEST_F(TcpCubicSenderPacketsTest, DefaultMaxCwnd) {
  RttStats rtt_stats;
  QuicConnectionStats stats;
  std::unique_ptr<SendAlgorithmInterface> sender(SendAlgorithmInterface::Create(
      &clock_, &rtt_stats, /*unacked_packets=*/nullptr, kCubic,
      QuicRandom::GetInstance(), &stats, kInitialCongestionWindow));

  SendAlgorithmInterface::CongestionVector acked_packets;
  SendAlgorithmInterface::CongestionVector missing_packets;
  for (uint64_t i = 1; i < kDefaultMaxCongestionWindowPackets; ++i) {
    acked_packets.clear();
    acked_packets.push_back(std::make_pair(i, 1350));
    sender->OnCongestionEvent(true, sender->GetCongestionWindow(), clock_.Now(),
                              acked_packets, missing_packets);
  }
  EXPECT_EQ(kDefaultMaxCongestionWindowPackets,
            sender->GetCongestionWindow() / kDefaultTCPMSS);
}

TEST_F(TcpCubicSenderPacketsTest, LimitCwndIncreaseInCongestionAvoidance) {
  // Enable Cubic.
  sender_.reset(new TcpCubicSenderPacketsPeer(
      &clock_, false, kDefaultMaxCongestionWindowPackets));

  int num_sent = SendAvailableSendWindow();

  // Make sure we fall out of slow start.
  QuicByteCount saved_cwnd = sender_->GetCongestionWindow();
  LoseNPackets(1);
  EXPECT_GT(saved_cwnd, sender_->GetCongestionWindow());

  // Ack the rest of the outstanding packets to get out of recovery.
  for (int i = 1; i < num_sent; ++i) {
    AckNPackets(1);
  }
  EXPECT_EQ(0u, bytes_in_flight_);
  // Send a new window of data and ack all; cubic growth should occur.
  saved_cwnd = sender_->GetCongestionWindow();
  num_sent = SendAvailableSendWindow();

  // Ack packets until the CWND increases.
  while (sender_->GetCongestionWindow() == saved_cwnd) {
    AckNPackets(1);
    SendAvailableSendWindow();
  }
  EXPECT_EQ(bytes_in_flight_, sender_->GetCongestionWindow());
  saved_cwnd = sender_->GetCongestionWindow();

  // Advance time 2 seconds waiting for an ack.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(2000));

  // Ack one packet.  The CWND should increase by only one packet.
  AckNPackets(1);
  EXPECT_EQ(saved_cwnd + kDefaultTCPMSS, sender_->GetCongestionWindow());
}

}  // namespace test
}  // namespace net
