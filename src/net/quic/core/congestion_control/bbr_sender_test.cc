// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/congestion_control/bbr_sender.h"

#include <algorithm>
#include <map>
#include <memory>

#include "net/quic/core/congestion_control/rtt_stats.h"
#include "net/quic/core/quic_packets.h"
#include "net/quic/core/quic_utils.h"
#include "net/quic/platform/api/quic_logging.h"
#include "net/quic/test_tools/mock_clock.h"
#include "net/quic/test_tools/quic_config_peer.h"
#include "net/quic/test_tools/quic_connection_peer.h"
#include "net/quic/test_tools/quic_sent_packet_manager_peer.h"
#include "net/quic/test_tools/quic_test_utils.h"
#include "net/quic/test_tools/simulator/quic_endpoint.h"
#include "net/quic/test_tools/simulator/simulator.h"
#include "net/quic/test_tools/simulator/switch.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {
namespace test {

// Use the initial CWND of 10, as 32 is too much for the test network.
const uint32_t kInitialCongestionWindowPackets = 10;
const uint32_t kDefaultWindowTCP =
    kInitialCongestionWindowPackets * kDefaultTCPMSS;

// Test network parameters.  Here, the topology of the network is:
//
//          BBR sender
//               |
//               |  <-- local link (10 Mbps, 2 ms delay)
//               |
//        Network switch
//               *  <-- the bottleneck queue in the direction
//               |          of the receiver
//               |
//               |  <-- test link (4 Mbps, 30 ms delay)
//               |
//               |
//           Receiver
//
// The reason the bandwidths chosen are relatively low is the fact that the
// connection simulator uses QuicTime for its internal clock, and as such has
// the granularity of 1us, meaning that at bandwidth higher than 20 Mbps the
// packets can start to land on the same timestamp.
const QuicBandwidth kTestLinkBandwidth =
    QuicBandwidth::FromKBitsPerSecond(4000);
const QuicBandwidth kLocalLinkBandwidth =
    QuicBandwidth::FromKBitsPerSecond(10000);
const QuicTime::Delta kTestPropagationDelay =
    QuicTime::Delta::FromMilliseconds(30);
const QuicTime::Delta kLocalPropagationDelay =
    QuicTime::Delta::FromMilliseconds(2);
const QuicTime::Delta kTestTransferTime =
    kTestLinkBandwidth.TransferTime(kMaxPacketSize) +
    kLocalLinkBandwidth.TransferTime(kMaxPacketSize);
const QuicTime::Delta kTestRtt =
    (kTestPropagationDelay + kLocalPropagationDelay + kTestTransferTime) * 2;
const QuicByteCount kTestBdp = kTestRtt * kTestLinkBandwidth;

class BbrSenderTest : public ::testing::Test {
 protected:
  BbrSenderTest()
      : simulator_(),
        bbr_sender_(&simulator_,
                    "BBR sender",
                    "Receiver",
                    Perspective::IS_CLIENT,
                    42),
        receiver_(&simulator_,
                  "Receiver",
                  "BBR sender",
                  Perspective::IS_SERVER,
                  42) {
    rtt_stats_ = bbr_sender_.connection()->sent_packet_manager().GetRttStats();
    sender_ = new BbrSender(
        rtt_stats_,
        QuicSentPacketManagerPeer::GetUnackedPacketMap(
            QuicConnectionPeer::GetSentPacketManager(bbr_sender_.connection())),
        kInitialCongestionWindowPackets, kDefaultMaxCongestionWindowPackets,
        &random_);
    QuicConnectionPeer::SetSendAlgorithm(bbr_sender_.connection(), sender_);

    clock_ = simulator_.GetClock();
    simulator_.set_random_generator(&random_);

    uint64_t seed = QuicRandom::GetInstance()->RandUint64();
    random_.set_seed(seed);
    QUIC_LOG(INFO) << "BbrSenderTest simulator set up.  Seed: " << seed;
  }

  simulator::Simulator simulator_;
  simulator::QuicEndpoint bbr_sender_;
  simulator::QuicEndpoint receiver_;
  std::unique_ptr<simulator::Switch> switch_;
  std::unique_ptr<simulator::SymmetricLink> bbr_sender_link_;
  std::unique_ptr<simulator::SymmetricLink> receiver_link_;

  SimpleRandom random_;

  // Owned by different components of the connection.
  const QuicClock* clock_;
  const RttStats* rtt_stats_;
  BbrSender* sender_;
  QuicFlagSaver flags_;

  // Creates a default setup, which is a network with a bottleneck between the
  // receiver and the switch.  The switch has the buffers four times larger than
  // the bottleneck BDP, which should guarantee a lack of losses.
  void CreateDefaultSetup() {
    switch_.reset(
        new simulator::Switch(&simulator_, "Switch", 8, 2 * kTestBdp));
    bbr_sender_link_.reset(new simulator::SymmetricLink(
        &bbr_sender_, switch_->port(1), kLocalLinkBandwidth,
        kLocalPropagationDelay));
    receiver_link_.reset(new simulator::SymmetricLink(
        &receiver_, switch_->port(2), kTestLinkBandwidth,
        kTestPropagationDelay));
  }

  // Same as the default setup, except the buffer now is half of the BDP.
  void CreateSmallBufferSetup() {
    switch_.reset(
        new simulator::Switch(&simulator_, "Switch", 8, 0.5 * kTestBdp));
    bbr_sender_link_.reset(new simulator::SymmetricLink(
        &bbr_sender_, switch_->port(1), kLocalLinkBandwidth,
        kTestPropagationDelay));
    receiver_link_.reset(new simulator::SymmetricLink(
        &receiver_, switch_->port(2), kTestLinkBandwidth,
        kTestPropagationDelay));
  }

  void DoSimpleTransfer(QuicByteCount transfer_size, QuicTime::Delta deadline) {
    bbr_sender_.AddBytesToTransfer(transfer_size);
    bool simulator_result = simulator_.RunUntilOrTimeout(
        [this]() { return bbr_sender_.bytes_to_transfer() == 0; }, deadline);
    EXPECT_TRUE(simulator_result)
        << "Simple transfer failed.  Bytes remaining: "
        << bbr_sender_.bytes_to_transfer();
    QUIC_LOG(INFO) << "Simple transfer state: " << sender_->ExportDebugState();
  }

  // Drive the simulator by sending enough data to enter PROBE_BW.
  void DriveOutOfStartup() {
    ASSERT_FALSE(sender_->ExportDebugState().is_at_full_bandwidth);
    DoSimpleTransfer(1024 * 1024, QuicTime::Delta::FromSeconds(15));
    EXPECT_EQ(BbrSender::PROBE_BW, sender_->ExportDebugState().mode);
    ExpectApproxEq(kTestLinkBandwidth,
                   sender_->ExportDebugState().max_bandwidth, 0.01f);
  }

  // Send |bytes|-sized bursts of data |number_of_bursts| times, waiting for
  // |wait_time| between each burst.
  void SendBursts(size_t number_of_bursts,
                  QuicByteCount bytes,
                  QuicTime::Delta wait_time) {
    ASSERT_EQ(0u, bbr_sender_.bytes_to_transfer());
    for (size_t i = 0; i < number_of_bursts; i++) {
      bbr_sender_.AddBytesToTransfer(bytes);

      // Transfer data and wait for three seconds between each transfer.
      simulator_.RunFor(wait_time);

      // Ensure the connection did not time out.
      ASSERT_TRUE(bbr_sender_.connection()->connected());
      ASSERT_TRUE(receiver_.connection()->connected());
    }

    simulator_.RunFor(wait_time + kTestRtt);
    ASSERT_EQ(0u, bbr_sender_.bytes_to_transfer());
  }
};

// Test a simple long data transfer in the default setup.
TEST_F(BbrSenderTest, SimpleTransfer) {
  CreateDefaultSetup();

  // At startup make sure we are at the default.
  EXPECT_EQ(kDefaultWindowTCP, sender_->GetCongestionWindow());
  // At startup make sure we can send.
  EXPECT_TRUE(sender_->TimeUntilSend(clock_->Now(), 0).IsZero());
  // Make sure we can send.
  EXPECT_TRUE(sender_->TimeUntilSend(clock_->Now(), 0).IsZero());
  // And that window is un-affected.
  EXPECT_EQ(kDefaultWindowTCP, sender_->GetCongestionWindow());

  // Verify that Sender is in slow start.
  EXPECT_TRUE(sender_->InSlowStart());

  // Verify that pacing rate is based on the initial RTT.
  QuicBandwidth expected_pacing_rate = QuicBandwidth::FromBytesAndTimeDelta(
      2.885 * kDefaultWindowTCP,
      QuicTime::Delta::FromMicroseconds(rtt_stats_->initial_rtt_us()));
  ExpectApproxEq(expected_pacing_rate.ToBitsPerSecond(),
                 sender_->PacingRate(0).ToBitsPerSecond(), 0.01f);

  ASSERT_GE(kTestBdp, kDefaultWindowTCP + kDefaultTCPMSS);

  DoSimpleTransfer(12 * 1024 * 1024, QuicTime::Delta::FromSeconds(30));
  EXPECT_EQ(BbrSender::PROBE_BW, sender_->ExportDebugState().mode);
  EXPECT_EQ(0u, bbr_sender_.connection()->GetStats().packets_lost);
  EXPECT_FALSE(sender_->ExportDebugState().last_sample_is_app_limited);

  // The margin here is quite high, since there exists a possibility that the
  // connection just exited high gain cycle.
  ExpectApproxEq(kTestRtt, rtt_stats_->smoothed_rtt(), 0.2f);
}

// Test a simple transfer in a situation when the buffer is less than BDP.
TEST_F(BbrSenderTest, SimpleTransferSmallBuffer) {
  CreateSmallBufferSetup();

  DoSimpleTransfer(12 * 1024 * 1024, QuicTime::Delta::FromSeconds(30));
  EXPECT_EQ(BbrSender::PROBE_BW, sender_->ExportDebugState().mode);
  ExpectApproxEq(kTestLinkBandwidth, sender_->ExportDebugState().max_bandwidth,
                 0.01f);
  EXPECT_GE(bbr_sender_.connection()->GetStats().packets_lost, 0u);
  EXPECT_FALSE(sender_->ExportDebugState().last_sample_is_app_limited);
}

// Test the number of losses incurred by the startup phase in a situation when
// the buffer is less than BDP.
TEST_F(BbrSenderTest, PacketLossOnSmallBufferStartup) {
  CreateSmallBufferSetup();

  DriveOutOfStartup();
  float loss_rate =
      static_cast<float>(bbr_sender_.connection()->GetStats().packets_lost) /
      bbr_sender_.connection()->GetStats().packets_sent;
  EXPECT_LE(loss_rate, 0.27);
}

// Ensures the code transitions loss recovery states correctly (NOT_IN_RECOVERY
// -> CONSERVATION -> GROWTH -> NOT_IN_RECOVERY).
TEST_F(BbrSenderTest, RecoveryStates) {
  const QuicTime::Delta timeout = QuicTime::Delta::FromSeconds(10);
  bool simulator_result;
  CreateSmallBufferSetup();

  bbr_sender_.AddBytesToTransfer(100 * 1024 * 1024);
  ASSERT_EQ(BbrSender::NOT_IN_RECOVERY,
            sender_->ExportDebugState().recovery_state);

  simulator_result = simulator_.RunUntilOrTimeout(
      [this]() {
        return sender_->ExportDebugState().recovery_state !=
               BbrSender::NOT_IN_RECOVERY;
      },
      timeout);
  ASSERT_TRUE(simulator_result);
  ASSERT_EQ(BbrSender::CONSERVATION,
            sender_->ExportDebugState().recovery_state);

  simulator_result = simulator_.RunUntilOrTimeout(
      [this]() {
        return sender_->ExportDebugState().recovery_state !=
               BbrSender::CONSERVATION;
      },
      timeout);
  ASSERT_TRUE(simulator_result);
  ASSERT_EQ(BbrSender::GROWTH, sender_->ExportDebugState().recovery_state);

  simulator_result = simulator_.RunUntilOrTimeout(
      [this]() {
        return sender_->ExportDebugState().recovery_state != BbrSender::GROWTH;
      },
      timeout);
  ASSERT_TRUE(simulator_result);
  ASSERT_EQ(BbrSender::NOT_IN_RECOVERY,
            sender_->ExportDebugState().recovery_state);
}

// Verify the behavior of the algorithm in the case when the connection sends
// small bursts of data after sending continuously for a while.
TEST_F(BbrSenderTest, ApplicationLimitedBursts) {
  CreateDefaultSetup();

  DriveOutOfStartup();
  EXPECT_FALSE(sender_->ExportDebugState().last_sample_is_app_limited);

  SendBursts(20, 512, QuicTime::Delta::FromSeconds(3));
  EXPECT_TRUE(sender_->ExportDebugState().last_sample_is_app_limited);
  ExpectApproxEq(kTestLinkBandwidth, sender_->ExportDebugState().max_bandwidth,
                 0.01f);
}

// Verify the behavior of the algorithm in the case when the connection sends
// small bursts of data and then starts sending continuously.
TEST_F(BbrSenderTest, ApplicationLimitedBurstsWithoutPrior) {
  CreateDefaultSetup();

  SendBursts(40, 512, QuicTime::Delta::FromSeconds(3));
  EXPECT_TRUE(sender_->ExportDebugState().last_sample_is_app_limited);

  DriveOutOfStartup();
  ExpectApproxEq(kTestLinkBandwidth, sender_->ExportDebugState().max_bandwidth,
                 0.01f);
  EXPECT_FALSE(sender_->ExportDebugState().last_sample_is_app_limited);
}

// Verify that the DRAIN phase works correctly.
TEST_F(BbrSenderTest, Drain) {
  CreateDefaultSetup();
  const QuicTime::Delta timeout = QuicTime::Delta::FromSeconds(10);
  // Get the queue at the bottleneck, which is the outgoing queue at the port to
  // which the receiver is connected.
  const simulator::Queue* queue = switch_->port_queue(2);
  bool simulator_result;

  // We have no intention of ever finishing this transfer.
  bbr_sender_.AddBytesToTransfer(100 * 1024 * 1024);

  // Run the startup, and verify that it fills up the queue.
  ASSERT_EQ(BbrSender::STARTUP, sender_->ExportDebugState().mode);
  simulator_result = simulator_.RunUntilOrTimeout(
      [this]() {
        return sender_->ExportDebugState().mode != BbrSender::STARTUP;
      },
      timeout);
  ASSERT_TRUE(simulator_result);
  ASSERT_EQ(BbrSender::DRAIN, sender_->ExportDebugState().mode);
  // BBR uses CWND gain of 2.88 during STARTUP, hence it will fill the buffer
  // with approximately 1.88 BDPs.  Here, we use 1.5 to give some margin for
  // error.
  EXPECT_GE(queue->bytes_queued(), 1.5 * kTestBdp);

  // Observe increased RTT due to bufferbloat.
  const QuicTime::Delta queueing_delay =
      kTestLinkBandwidth.TransferTime(queue->bytes_queued());
  ExpectApproxEq(kTestRtt + queueing_delay, rtt_stats_->latest_rtt(), 0.1f);

  // Transition to the drain phase and verify that it makes the queue
  // have at most a BDP worth of packets.
  simulator_result = simulator_.RunUntilOrTimeout(
      [this]() { return sender_->ExportDebugState().mode != BbrSender::DRAIN; },
      timeout);
  ASSERT_TRUE(simulator_result);
  ASSERT_EQ(BbrSender::PROBE_BW, sender_->ExportDebugState().mode);
  EXPECT_LE(queue->bytes_queued(), kTestBdp);

  // Wait for a few round trips and ensure we're in appropriate phase of gain
  // cycling before taking an RTT measurement.
  const QuicRoundTripCount start_round_trip =
      sender_->ExportDebugState().round_trip_count;
  simulator_result = simulator_.RunUntilOrTimeout(
      [this, start_round_trip]() {
        QuicRoundTripCount rounds_passed =
            sender_->ExportDebugState().round_trip_count - start_round_trip;
        return rounds_passed >= 4 &&
               sender_->ExportDebugState().gain_cycle_index == 7;
      },
      timeout);
  ASSERT_TRUE(simulator_result);

  // Observe the bufferbloat go away.
  ExpectApproxEq(kTestRtt, rtt_stats_->smoothed_rtt(), 0.1f);
}

// Verify that the connection enters and exits PROBE_RTT correctly.
TEST_F(BbrSenderTest, ProbeRtt) {
  CreateDefaultSetup();
  DriveOutOfStartup();

  // We have no intention of ever finishing this transfer.
  bbr_sender_.AddBytesToTransfer(100 * 1024 * 1024);

  // Wait until the connection enters PROBE_RTT.
  const QuicTime::Delta timeout = QuicTime::Delta::FromSeconds(12);
  bool simulator_result = simulator_.RunUntilOrTimeout(
      [this]() {
        return sender_->ExportDebugState().mode == BbrSender::PROBE_RTT;
      },
      timeout);
  ASSERT_TRUE(simulator_result);
  ASSERT_EQ(BbrSender::PROBE_RTT, sender_->ExportDebugState().mode);

  // Exit PROBE_RTT.
  const QuicTime probe_rtt_start = clock_->Now();
  const QuicTime::Delta time_to_exit_probe_rtt =
      kTestRtt + QuicTime::Delta::FromMilliseconds(200);
  simulator_.RunFor(1.5 * time_to_exit_probe_rtt);
  EXPECT_EQ(BbrSender::PROBE_BW, sender_->ExportDebugState().mode);
  EXPECT_GE(sender_->ExportDebugState().min_rtt_timestamp, probe_rtt_start);
}

// Ensure that a connection that is app-limited and is at sufficiently low
// bandwidth will not exit high gain phase, and similarly ensure that the
// connection will exit low gain early if the number of bytes in flight is low.
TEST_F(BbrSenderTest, InFlightAwareGainCycling) {
  CreateDefaultSetup();
  DriveOutOfStartup();

  const QuicTime::Delta timeout = QuicTime::Delta::FromSeconds(5);
  bool simulator_result;

  // Start a few cycles prior to the high gain one.
  simulator_result = simulator_.RunUntilOrTimeout(
      [this]() { return sender_->ExportDebugState().gain_cycle_index == 6; },
      timeout);

  // Send at 10% of available rate.  Run for 3 seconds, checking in the middle
  // and at the end.  The pacing gain should be high throughout.
  QuicBandwidth target_bandwidth = 0.1f * kTestLinkBandwidth;
  QuicTime::Delta burst_interval = QuicTime::Delta::FromMilliseconds(300);
  for (int i = 0; i < 2; i++) {
    SendBursts(5, target_bandwidth * burst_interval, burst_interval);
    EXPECT_EQ(BbrSender::PROBE_BW, sender_->ExportDebugState().mode);
    EXPECT_EQ(0, sender_->ExportDebugState().gain_cycle_index);
    ExpectApproxEq(kTestLinkBandwidth,
                   sender_->ExportDebugState().max_bandwidth, 0.01f);
  }

  // Now that in-flight is almost zero and the pacing gain is still above 1,
  // send approximately 1.25 BDPs worth of data.  This should cause the
  // PROBE_BW mode to enter low gain cycle, and exit it earlier than one min_rtt
  // due to running out of data to send.
  bbr_sender_.AddBytesToTransfer(1.3 * kTestBdp);
  simulator_result = simulator_.RunUntilOrTimeout(
      [this]() { return sender_->ExportDebugState().gain_cycle_index == 1; },
      timeout);
  ASSERT_TRUE(simulator_result);
  simulator_.RunFor(0.75 * sender_->ExportDebugState().min_rtt);
  EXPECT_EQ(BbrSender::PROBE_BW, sender_->ExportDebugState().mode);
  EXPECT_EQ(2, sender_->ExportDebugState().gain_cycle_index);
}

// Ensure that the pacing rate does not drop at startup.
TEST_F(BbrSenderTest, NoBandwidthDropOnStartup) {
  CreateDefaultSetup();

  const QuicTime::Delta timeout = QuicTime::Delta::FromSeconds(5);
  bool simulator_result;

  QuicBandwidth initial_rate = QuicBandwidth::FromBytesAndTimeDelta(
      kInitialCongestionWindowPackets * kDefaultTCPMSS,
      QuicTime::Delta::FromMicroseconds(rtt_stats_->initial_rtt_us()));
  EXPECT_GE(sender_->PacingRate(0), initial_rate);

  // Send a packet.
  bbr_sender_.AddBytesToTransfer(1000);
  simulator_result = simulator_.RunUntilOrTimeout(
      [this]() { return receiver_.bytes_received() == 1000; }, timeout);
  ASSERT_TRUE(simulator_result);
  EXPECT_GE(sender_->PacingRate(0), initial_rate);

  // Wait for a while.
  simulator_.RunFor(QuicTime::Delta::FromSeconds(2));
  EXPECT_GE(sender_->PacingRate(0), initial_rate);

  // Send another packet.
  bbr_sender_.AddBytesToTransfer(1000);
  simulator_result = simulator_.RunUntilOrTimeout(
      [this]() { return receiver_.bytes_received() == 2000; }, timeout);
  ASSERT_TRUE(simulator_result);
  EXPECT_GE(sender_->PacingRate(0), initial_rate);
}

}  // namespace test
}  // namespace net
