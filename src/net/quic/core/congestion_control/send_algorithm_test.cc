// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <algorithm>
#include <map>
#include <memory>

#include "net/quic/core/congestion_control/rtt_stats.h"
#include "net/quic/core/congestion_control/send_algorithm_interface.h"
#include "net/quic/core/quic_types.h"
#include "net/quic/core/quic_utils.h"
#include "net/quic/platform/api/quic_logging.h"
#include "net/quic/platform/api/quic_str_cat.h"
#include "net/quic/platform/api/quic_test.h"
#include "net/quic/test_tools/mock_clock.h"
#include "net/quic/test_tools/quic_config_peer.h"
#include "net/quic/test_tools/quic_connection_peer.h"
#include "net/quic/test_tools/quic_sent_packet_manager_peer.h"
#include "net/quic/test_tools/quic_test_utils.h"
#include "net/quic/test_tools/simulator/quic_endpoint.h"
#include "net/quic/test_tools/simulator/simulator.h"
#include "net/quic/test_tools/simulator/switch.h"

using std::string;

namespace net {
namespace test {
namespace {

// Use the initial CWND of 10, as 32 is too much for the test network.
const uint32_t kInitialCongestionWindowPackets = 10;

// Test network parameters.  Here, the topology of the network is:
//
//           QUIC Sender
//               |
//               |  <-- local link
//               |
//        Network switch
//               *  <-- the bottleneck queue in the direction
//               |          of the receiver
//               |
//               |  <-- test link
//               |
//               |
//           Receiver
//
// When setting the bandwidth of the local link and test link, choose
// a bandwidth lower than 20Mbps, as the clock-granularity of the
// simulator can only handle a granularity of 1us.

// Default settings between the switch and the sender.
const QuicBandwidth kLocalLinkBandwidth =
    QuicBandwidth::FromKBitsPerSecond(10000);
const QuicTime::Delta kLocalPropagationDelay =
    QuicTime::Delta::FromMilliseconds(2);

// Wired network settings.  A typical desktop network setup, a
// high-bandwidth, 30ms test link to the receiver.
const QuicBandwidth kTestLinkWiredBandwidth =
    QuicBandwidth::FromKBitsPerSecond(4000);
const QuicTime::Delta kTestLinkWiredPropagationDelay =
    QuicTime::Delta::FromMilliseconds(50);
const QuicTime::Delta kTestWiredTransferTime =
    kTestLinkWiredBandwidth.TransferTime(kMaxPacketSize) +
    kLocalLinkBandwidth.TransferTime(kMaxPacketSize);
const QuicTime::Delta kTestWiredRtt =
    (kTestLinkWiredPropagationDelay + kLocalPropagationDelay +
     kTestWiredTransferTime) *
    2;
const QuicByteCount kTestWiredBdp = kTestWiredRtt * kTestLinkWiredBandwidth;

// Small BDP, Bandwidth-policed network settings.  In this scenario,
// the receiver has a low-bandwidth, short propagation-delay link,
// resulting in a small BDP.  We model the policer by setting the
// queue size to only one packet.
const QuicBandwidth kTestLinkLowBdpBandwidth =
    QuicBandwidth::FromKBitsPerSecond(200);
const QuicTime::Delta kTestLinkLowBdpPropagationDelay =
    QuicTime::Delta::FromMilliseconds(50);
const QuicByteCount kTestPolicerQueue = kMaxPacketSize;

// Satellite network settings.  In a satellite network, the bottleneck
// buffer is typically sized for non-satellite links , but the
// propagation delay of the test link to the receiver is as much as a
// quarter second.
const QuicTime::Delta kTestSatellitePropagationDelay =
    QuicTime::Delta::FromMilliseconds(250);

// Cellular scenarios.  In a cellular network, the bottleneck queue at
// the edge of the network can be as great as 3MB.
const QuicBandwidth kTestLink2GBandwidth =
    QuicBandwidth::FromKBitsPerSecond(100);
const QuicBandwidth kTestLink3GBandwidth =
    QuicBandwidth::FromKBitsPerSecond(1500);
const QuicByteCount kCellularQueue = 3 * 1024 * 1024;
const QuicTime::Delta kTestCellularPropagationDelay =
    QuicTime::Delta::FromMilliseconds(40);

// Small RTT scenario, below the per-ack-update threshold of 30ms.
const QuicTime::Delta kTestLinkSmallRTTDelay =
    QuicTime::Delta::FromMilliseconds(10);

const char* CongestionControlTypeToString(CongestionControlType cc_type) {
  switch (cc_type) {
    case kCubic:
      return "CUBIC_PACKETS";
    case kCubicBytes:
      return "CUBIC_BYTES";
    case kReno:
      return "RENO_PACKETS";
    case kRenoBytes:
      return "RENO_BYTES";
    case kBBR:
      return "BBR";
    case kPCC:
      return "PCC";
    default:
      QUIC_DLOG(FATAL) << "Unexpected CongestionControlType";
      return nullptr;
  }
}

struct TestParams {
  explicit TestParams(CongestionControlType congestion_control_type,
                      bool fix_convex_mode,
                      bool fix_cubic_quantization,
                      bool fix_beta_last_max,
                      bool allow_per_ack_updates)
      : congestion_control_type(congestion_control_type),
        fix_convex_mode(fix_convex_mode),
        fix_cubic_quantization(fix_cubic_quantization),
        fix_beta_last_max(fix_beta_last_max),
        allow_per_ack_updates(allow_per_ack_updates) {}

  friend std::ostream& operator<<(std::ostream& os, const TestParams& p) {
    os << "{ congestion_control_type: "
       << CongestionControlTypeToString(p.congestion_control_type);
    os << "  fix_convex_mode: " << p.fix_convex_mode
       << "  fix_cubic_quantization: " << p.fix_cubic_quantization
       << "  fix_beta_last_max: " << p.fix_beta_last_max;
    os << "  allow_per_ack_updates: " << p.allow_per_ack_updates;
    os << " }";
    return os;
  }

  CongestionControlType congestion_control_type;
  bool fix_convex_mode;
  bool fix_cubic_quantization;
  bool fix_beta_last_max;
  bool allow_per_ack_updates;
};

string TestParamToString(const testing::TestParamInfo<TestParams>& params) {
  return QuicStrCat(
      CongestionControlTypeToString(params.param.congestion_control_type), "_",
      "convex_mode_", params.param.fix_convex_mode, "_", "cubic_quantization_",
      params.param.fix_cubic_quantization, "_", "beta_last_max_",
      params.param.fix_beta_last_max, "_", "allow_per_ack_updates_",
      params.param.allow_per_ack_updates);
}

// Constructs various test permutations.
std::vector<TestParams> GetTestParams() {
  std::vector<TestParams> params;
  for (const CongestionControlType congestion_control_type :
       {kBBR, kCubic, kCubicBytes, kReno, kRenoBytes, kPCC}) {
    params.push_back(
        TestParams(congestion_control_type, false, false, false, false));
    if (congestion_control_type != kCubic &&
        congestion_control_type != kCubicBytes) {
      continue;
    }
    params.push_back(
        TestParams(congestion_control_type, true, true, true, true));
  }
  return params;
}

}  // namespace

class SendAlgorithmTest : public QuicTestWithParam<TestParams> {
 protected:
  SendAlgorithmTest()
      : simulator_(),
        quic_sender_(&simulator_,
                     "QUIC sender",
                     "Receiver",
                     Perspective::IS_CLIENT,
                     42),
        receiver_(&simulator_,
                  "Receiver",
                  "QUIC sender",
                  Perspective::IS_SERVER,
                  42) {
    FLAGS_quic_reloadable_flag_quic_fix_cubic_convex_mode = true;
    FLAGS_quic_reloadable_flag_quic_fix_cubic_bytes_quantization = true;
    FLAGS_quic_reloadable_flag_quic_fix_beta_last_max = true;
    FLAGS_quic_reloadable_flag_quic_enable_cubic_per_ack_updates = true;
    rtt_stats_ = quic_sender_.connection()->sent_packet_manager().GetRttStats();
    sender_ = SendAlgorithmInterface::Create(
        simulator_.GetClock(), rtt_stats_,
        QuicSentPacketManagerPeer::GetUnackedPacketMap(
            QuicConnectionPeer::GetSentPacketManager(
                quic_sender_.connection())),
        GetParam().congestion_control_type, &random_, &stats_,
        kInitialCongestionWindowPackets);

    SetExperimentalOptionsInServerConfig();

    QuicConnectionPeer::SetSendAlgorithm(quic_sender_.connection(), sender_);
    // TODO(jokulik):  Remove once b/38032710 is fixed.
    // Disable pacing for PCC.
    if (sender_->GetCongestionControlType() == kPCC) {
      QuicSentPacketManagerPeer::SetUsingPacing(
          QuicConnectionPeer::GetSentPacketManager(quic_sender_.connection()),
          false);
    }
    clock_ = simulator_.GetClock();
    simulator_.set_random_generator(&random_);

    uint64_t seed = QuicRandom::GetInstance()->RandUint64();
    random_.set_seed(seed);
    QUIC_LOG(INFO) << "SendAlgorithmTest simulator set up.  Seed: " << seed;
  }

  // Sets experimental options in the server config, as if they had
  // been sent by the client.
  void SetExperimentalOptionsInServerConfig() {
    QuicConfig client_config;
    QuicTagVector options;
    if (GetParam().fix_convex_mode) {
      options.push_back(kCCVX);
    }
    if (GetParam().fix_cubic_quantization) {
      options.push_back(kCBQT);
    }
    if (GetParam().fix_beta_last_max) {
      options.push_back(kBLMX);
    }
    if (GetParam().allow_per_ack_updates) {
      options.push_back(kCPAU);
    }

    if (!options.empty()) {
      client_config.SetInitialReceivedConnectionOptions(options);
      sender_->SetFromConfig(client_config, Perspective::IS_SERVER);
    }
  }

  // Creates a simulated network, with default settings between the
  // sender and the switch and the given settings from the switch to
  // the receiver.
  void CreateSetup(const QuicBandwidth& test_bandwidth,
                   const QuicTime::Delta& test_link_delay,
                   QuicByteCount bottleneck_queue_length) {
    switch_.reset(new simulator::Switch(&simulator_, "Switch", 8,
                                        bottleneck_queue_length));
    quic_sender_link_.reset(new simulator::SymmetricLink(
        &quic_sender_, switch_->port(1), kLocalLinkBandwidth,
        kLocalPropagationDelay));
    receiver_link_.reset(new simulator::SymmetricLink(
        &receiver_, switch_->port(2), test_bandwidth, test_link_delay));
  }

  void DoSimpleTransfer(QuicByteCount transfer_size, QuicTime::Delta deadline) {
    quic_sender_.AddBytesToTransfer(transfer_size);
    bool simulator_result = simulator_.RunUntilOrTimeout(
        [this]() { return quic_sender_.bytes_to_transfer() == 0; }, deadline);
    EXPECT_TRUE(simulator_result)
        << "Simple transfer failed.  Bytes remaining: "
        << quic_sender_.bytes_to_transfer();
  }

  void SendBursts(size_t number_of_bursts,
                  QuicByteCount bytes,
                  QuicTime::Delta rtt,
                  QuicTime::Delta wait_time) {
    ASSERT_EQ(0u, quic_sender_.bytes_to_transfer());
    for (size_t i = 0; i < number_of_bursts; i++) {
      quic_sender_.AddBytesToTransfer(bytes);

      // Transfer data and wait for three seconds between each transfer.
      simulator_.RunFor(wait_time);

      // Ensure the connection did not time out.
      ASSERT_TRUE(quic_sender_.connection()->connected());
      ASSERT_TRUE(receiver_.connection()->connected());
    }

    simulator_.RunFor(wait_time + rtt);
    EXPECT_EQ(0u, quic_sender_.bytes_to_transfer());
  }

  // Estimates the elapsed time for a given transfer size, given the
  // bottleneck bandwidth and link propagation delay.
  QuicTime::Delta EstimatedElapsedTime(
      QuicByteCount transfer_size_bytes,
      QuicBandwidth test_link_bandwidth,
      const QuicTime::Delta& test_link_delay) const {
    return test_link_bandwidth.TransferTime(transfer_size_bytes) +
           2 * test_link_delay;
  }

  QuicTime QuicSenderStartTime() {
    return quic_sender_.connection()->GetStats().connection_creation_time;
  }

  void PrintTransferStats() {
    const QuicConnectionStats& stats = quic_sender_.connection()->GetStats();
    QUIC_LOG(INFO) << "Summary for scenario " << GetParam();
    QUIC_LOG(INFO) << "Sender stats is " << stats;
    const double rtx_rate =
        static_cast<double>(stats.bytes_retransmitted) / stats.bytes_sent;
    QUIC_LOG(INFO) << "Retransmit rate (num_rtx/num_total_sent): " << rtx_rate;
    QUIC_LOG(INFO) << "Connection elapsed time: "
                   << (clock_->Now() - QuicSenderStartTime()).ToMilliseconds()
                   << " (ms)";
  }

  simulator::Simulator simulator_;
  simulator::QuicEndpoint quic_sender_;
  simulator::QuicEndpoint receiver_;
  std::unique_ptr<simulator::Switch> switch_;
  std::unique_ptr<simulator::SymmetricLink> quic_sender_link_;
  std::unique_ptr<simulator::SymmetricLink> receiver_link_;
  QuicConnectionStats stats_;

  SimpleRandom random_;

  // Owned by different components of the connection.
  const QuicClock* clock_;
  const RttStats* rtt_stats_;
  SendAlgorithmInterface* sender_;
};

INSTANTIATE_TEST_CASE_P(SendAlgorithmTests,
                        SendAlgorithmTest,
                        ::testing::ValuesIn(GetTestParams()),
                        TestParamToString);

// Test a simple long data transfer in the default setup.
TEST_P(SendAlgorithmTest, SimpleWiredNetworkTransfer) {
  CreateSetup(kTestLinkWiredBandwidth, kTestLinkWiredPropagationDelay,
              kTestWiredBdp);
  const QuicByteCount kTransferSizeBytes = 12 * 1024 * 1024;
  const QuicTime::Delta maximum_elapsed_time =
      EstimatedElapsedTime(kTransferSizeBytes, kTestLinkWiredBandwidth,
                           kTestLinkWiredPropagationDelay) *
      1.2;
  DoSimpleTransfer(kTransferSizeBytes, maximum_elapsed_time);
  PrintTransferStats();
}

TEST_P(SendAlgorithmTest, LowBdpPolicedNetworkTransfer) {
  CreateSetup(kTestLinkLowBdpBandwidth, kTestLinkLowBdpPropagationDelay,
              kTestPolicerQueue);
  const QuicByteCount kTransferSizeBytes = 5 * 1024 * 1024;
  const QuicTime::Delta maximum_elapsed_time =
      EstimatedElapsedTime(kTransferSizeBytes, kTestLinkLowBdpBandwidth,
                           kTestLinkLowBdpPropagationDelay) *
      1.2;
  DoSimpleTransfer(kTransferSizeBytes, maximum_elapsed_time);
  PrintTransferStats();
}

TEST_P(SendAlgorithmTest, AppLimitedBurstsOverWiredNetwork) {
  CreateSetup(kTestLinkWiredBandwidth, kTestLinkWiredPropagationDelay,
              kTestWiredBdp);
  const QuicByteCount kBurstSizeBytes = 512;
  const int kNumBursts = 20;
  const QuicTime::Delta kWaitTime = QuicTime::Delta::FromSeconds(3);
  SendBursts(kNumBursts, kBurstSizeBytes, kTestWiredRtt, kWaitTime);
  PrintTransferStats();

  const QuicTime::Delta estimated_burst_time =
      EstimatedElapsedTime(kBurstSizeBytes, kTestLinkWiredBandwidth,
                           kTestLinkWiredPropagationDelay) +
      kWaitTime;
  const QuicTime::Delta max_elapsed_time =
      kNumBursts * estimated_burst_time + kWaitTime;
  const QuicTime::Delta actual_elapsed_time =
      clock_->Now() - QuicSenderStartTime();
  EXPECT_GE(max_elapsed_time, actual_elapsed_time);
}

TEST_P(SendAlgorithmTest, SatelliteNetworkTransfer) {
  CreateSetup(kTestLinkWiredBandwidth, kTestSatellitePropagationDelay,
              kTestWiredBdp);
  const QuicByteCount kTransferSizeBytes = 20 * 1024 * 1024;
  const QuicTime::Delta maximum_elapsed_time =
      EstimatedElapsedTime(kTransferSizeBytes, kTestLinkWiredBandwidth,
                           kTestSatellitePropagationDelay) *
      1.25;
  DoSimpleTransfer(kTransferSizeBytes, maximum_elapsed_time);
  PrintTransferStats();
}

TEST_P(SendAlgorithmTest, 2GNetworkTransfer) {
  CreateSetup(kTestLink2GBandwidth, kTestCellularPropagationDelay,
              kCellularQueue);
  const QuicByteCount kTransferSizeBytes = 1024 * 1024;
  const QuicTime::Delta maximum_elapsed_time =
      EstimatedElapsedTime(kTransferSizeBytes, kTestLink2GBandwidth,
                           kTestCellularPropagationDelay) *
      1.2;
  DoSimpleTransfer(kTransferSizeBytes, maximum_elapsed_time);
  PrintTransferStats();
}

TEST_P(SendAlgorithmTest, 3GNetworkTransfer) {
  CreateSetup(kTestLink3GBandwidth, kTestCellularPropagationDelay,
              kCellularQueue);
  const QuicByteCount kTransferSizeBytes = 5 * 1024 * 1024;
  const QuicTime::Delta maximum_elapsed_time =
      EstimatedElapsedTime(kTransferSizeBytes, kTestLink3GBandwidth,
                           kTestCellularPropagationDelay) *
      1.2;
  DoSimpleTransfer(kTransferSizeBytes, maximum_elapsed_time);
  PrintTransferStats();
}

TEST_P(SendAlgorithmTest, LowRTTTransfer) {
  CreateSetup(kTestLinkWiredBandwidth, kTestLinkSmallRTTDelay, kCellularQueue);

  const QuicByteCount kTransferSizeBytes = 12 * 1024 * 1024;
  const QuicTime::Delta maximum_elapsed_time =
      EstimatedElapsedTime(kTransferSizeBytes, kTestLinkWiredBandwidth,
                           kTestLinkSmallRTTDelay) *
      1.2;
  DoSimpleTransfer(kTransferSizeBytes, maximum_elapsed_time);
  PrintTransferStats();
}

}  // namespace test
}  // namespace net
