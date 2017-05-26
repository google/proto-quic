// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/congestion_control/bandwidth_sampler.h"

#include "net/quic/platform/api/quic_flags.h"
#include "net/quic/platform/api/quic_test.h"
#include "net/quic/test_tools/mock_clock.h"

namespace net {
namespace test {

class BandwidthSamplerPeer {
 public:
  static size_t GetNumberOfTrackedPackets(const BandwidthSampler& sampler) {
    if (FLAGS_quic_reloadable_flag_quic_faster_bandwidth_sampler) {
      return sampler.connection_state_map_new_.number_of_present_entries();
    }
    return sampler.connection_state_map_.size();
  }

  static QuicByteCount GetPacketSize(const BandwidthSampler& sampler,
                                     QuicPacketNumber packet_number) {
    if (FLAGS_quic_reloadable_flag_quic_faster_bandwidth_sampler) {
      return sampler.connection_state_map_new_.GetEntry(packet_number)->size;
    }
    auto iterator = sampler.connection_state_map_.find(packet_number);
    return iterator->second.size;
  }
};

const QuicByteCount kRegularPacketSize = 1280;
// Enforce divisibility for some of the tests.
static_assert((kRegularPacketSize & 31) == 0,
              "kRegularPacketSize has to be five times divisible by 2");

// A test fixture with utility methods for BandwidthSampler tests.
class BandwidthSamplerTest : public QuicTest {
 protected:
  BandwidthSamplerTest() : bytes_in_flight_(0) {
    // Ensure that the clock does not start at zero.
    clock_.AdvanceTime(QuicTime::Delta::FromSeconds(1));
  }

  MockClock clock_;
  BandwidthSampler sampler_;
  QuicByteCount bytes_in_flight_;

  void SendPacketInner(QuicPacketNumber packet_number,
                       QuicByteCount bytes,
                       HasRetransmittableData has_retransmittable_data) {
    sampler_.OnPacketSent(clock_.Now(), packet_number, bytes, bytes_in_flight_,
                          has_retransmittable_data);
    if (has_retransmittable_data == HAS_RETRANSMITTABLE_DATA) {
      bytes_in_flight_ += bytes;
    }
  }

  void SendPacket(QuicPacketNumber packet_number) {
    SendPacketInner(packet_number, kRegularPacketSize,
                    HAS_RETRANSMITTABLE_DATA);
  }

  BandwidthSample AckPacketInner(QuicPacketNumber packet_number) {
    QuicByteCount size =
        BandwidthSamplerPeer::GetPacketSize(sampler_, packet_number);
    bytes_in_flight_ -= size;
    return sampler_.OnPacketAcknowledged(clock_.Now(), packet_number);
  }

  // Acknowledge receipt of a packet and expect it to be not app-limited.
  QuicBandwidth AckPacket(QuicPacketNumber packet_number) {
    BandwidthSample sample = AckPacketInner(packet_number);
    EXPECT_FALSE(sample.is_app_limited);
    return sample.bandwidth;
  }

  void LosePacket(QuicPacketNumber packet_number) {
    QuicByteCount size =
        BandwidthSamplerPeer::GetPacketSize(sampler_, packet_number);
    bytes_in_flight_ -= size;
    sampler_.OnPacketLost(packet_number);
  }

  // Sends one packet and acks it.  Then, send 20 packets.  Finally, send
  // another 20 packets while acknowledging previous 20.
  void Send40PacketsAndAckFirst20(QuicTime::Delta time_between_packets) {
    // Send 20 packets at a constant inter-packet time.
    for (QuicPacketNumber i = 1; i <= 20; i++) {
      SendPacket(i);
      clock_.AdvanceTime(time_between_packets);
    }

    // Ack packets 1 to 20, while sending new packets at the same rate as
    // before.
    for (QuicPacketNumber i = 1; i <= 20; i++) {
      AckPacket(i);
      SendPacket(i + 20);
      clock_.AdvanceTime(time_between_packets);
    }
  }
};

// Test the sampler in a simple stop-and-wait sender setting.
TEST_F(BandwidthSamplerTest, SendAndWait) {
  QuicTime::Delta time_between_packets = QuicTime::Delta::FromMilliseconds(10);
  QuicBandwidth expected_bandwidth =
      QuicBandwidth::FromBytesPerSecond(kRegularPacketSize * 100);

  // Send packets at the constant bandwidth.
  for (QuicPacketNumber i = 1; i < 20; i++) {
    SendPacket(i);
    clock_.AdvanceTime(time_between_packets);
    QuicBandwidth current_sample = AckPacket(i);
    EXPECT_EQ(expected_bandwidth, current_sample);
  }

  // Send packets at the exponentially decreasing bandwidth.
  for (QuicPacketNumber i = 20; i < 25; i++) {
    time_between_packets = time_between_packets * 2;
    expected_bandwidth = expected_bandwidth * 0.5;

    SendPacket(i);
    clock_.AdvanceTime(time_between_packets);
    QuicBandwidth current_sample = AckPacket(i);
    EXPECT_EQ(expected_bandwidth, current_sample);
  }
  EXPECT_EQ(0u, BandwidthSamplerPeer::GetNumberOfTrackedPackets(sampler_));
  EXPECT_EQ(0u, bytes_in_flight_);
}

// Test the sampler during regular windowed sender scenario with fixed
// CWND of 20.
TEST_F(BandwidthSamplerTest, SendPaced) {
  const QuicTime::Delta time_between_packets =
      QuicTime::Delta::FromMilliseconds(1);
  QuicBandwidth expected_bandwidth =
      QuicBandwidth::FromKBytesPerSecond(kRegularPacketSize);

  Send40PacketsAndAckFirst20(time_between_packets);

  // Ack the packets 21 to 40, arriving at the correct bandwidth.
  QuicBandwidth last_bandwidth = QuicBandwidth::Zero();
  for (QuicPacketNumber i = 21; i <= 40; i++) {
    last_bandwidth = AckPacket(i);
    EXPECT_EQ(expected_bandwidth, last_bandwidth);
    clock_.AdvanceTime(time_between_packets);
  }
  EXPECT_EQ(0u, BandwidthSamplerPeer::GetNumberOfTrackedPackets(sampler_));
  EXPECT_EQ(0u, bytes_in_flight_);
}

// Test the sampler in a scenario where 50% of packets is consistently lost.
TEST_F(BandwidthSamplerTest, SendWithLosses) {
  const QuicTime::Delta time_between_packets =
      QuicTime::Delta::FromMilliseconds(1);
  QuicBandwidth expected_bandwidth =
      QuicBandwidth::FromKBytesPerSecond(kRegularPacketSize) * 0.5;

  // Send 20 packets, each 1 ms apart.
  for (QuicPacketNumber i = 1; i <= 20; i++) {
    SendPacket(i);
    clock_.AdvanceTime(time_between_packets);
  }

  // Ack packets 1 to 20, losing every even-numbered packet, while sending new
  // packets at the same rate as before.
  for (QuicPacketNumber i = 1; i <= 20; i++) {
    if (i % 2 == 0) {
      AckPacket(i);
    } else {
      LosePacket(i);
    }
    SendPacket(i + 20);
    clock_.AdvanceTime(time_between_packets);
  }

  // Ack the packets 21 to 40 with the same loss pattern.
  QuicBandwidth last_bandwidth = QuicBandwidth::Zero();
  for (QuicPacketNumber i = 21; i <= 40; i++) {
    if (i % 2 == 0) {
      last_bandwidth = AckPacket(i);
      EXPECT_EQ(expected_bandwidth, last_bandwidth);
    } else {
      LosePacket(i);
    }
    clock_.AdvanceTime(time_between_packets);
  }
  EXPECT_EQ(0u, BandwidthSamplerPeer::GetNumberOfTrackedPackets(sampler_));
  EXPECT_EQ(0u, bytes_in_flight_);
}

// Test the sampler in a scenario where the 50% of packets are not
// congestion controlled (specifically, non-retransmittable data is not
// congestion controlled).  Should be functionally consistent in behavior with
// the SendWithLosses test.
TEST_F(BandwidthSamplerTest, NotCongestionControlled) {
  const QuicTime::Delta time_between_packets =
      QuicTime::Delta::FromMilliseconds(1);
  QuicBandwidth expected_bandwidth =
      QuicBandwidth::FromKBytesPerSecond(kRegularPacketSize) * 0.5;

  // Send 20 packets, each 1 ms apart. Every even packet is not congestion
  // controlled.
  for (QuicPacketNumber i = 1; i <= 20; i++) {
    SendPacketInner(
        i, kRegularPacketSize,
        i % 2 == 0 ? HAS_RETRANSMITTABLE_DATA : NO_RETRANSMITTABLE_DATA);
    clock_.AdvanceTime(time_between_packets);
  }

  // Ensure only congestion controlled packets are tracked.
  EXPECT_EQ(10u, BandwidthSamplerPeer::GetNumberOfTrackedPackets(sampler_));

  // Ack packets 2 to 21, ignoring every even-numbered packet, while sending new
  // packets at the same rate as before.
  for (QuicPacketNumber i = 1; i <= 20; i++) {
    if (i % 2 == 0) {
      AckPacket(i);
    }
    SendPacketInner(
        i + 20, kRegularPacketSize,
        i % 2 == 0 ? HAS_RETRANSMITTABLE_DATA : NO_RETRANSMITTABLE_DATA);
    clock_.AdvanceTime(time_between_packets);
  }

  // Ack the packets 22 to 41 with the same congestion controlled pattern.
  QuicBandwidth last_bandwidth = QuicBandwidth::Zero();
  for (QuicPacketNumber i = 21; i <= 40; i++) {
    if (i % 2 == 0) {
      last_bandwidth = AckPacket(i);
      EXPECT_EQ(expected_bandwidth, last_bandwidth);
    }
    clock_.AdvanceTime(time_between_packets);
  }

  // Since only congestion controlled packets are entered into the map, it has
  // to be empty at this point.
  EXPECT_EQ(0u, BandwidthSamplerPeer::GetNumberOfTrackedPackets(sampler_));
  EXPECT_EQ(0u, bytes_in_flight_);
}

// Simulate a situation where ACKs arrive in burst and earlier than usual, thus
// producing an ACK rate which is higher than the original send rate.
TEST_F(BandwidthSamplerTest, CompressedAck) {
  const QuicTime::Delta time_between_packets =
      QuicTime::Delta::FromMilliseconds(1);
  QuicBandwidth expected_bandwidth =
      QuicBandwidth::FromKBytesPerSecond(kRegularPacketSize);

  Send40PacketsAndAckFirst20(time_between_packets);

  // Simulate an RTT somewhat lower than the one for 1-to-21 transmission.
  clock_.AdvanceTime(time_between_packets * 15);

  // Ack the packets 21 to 40 almost immediately at once.
  QuicBandwidth last_bandwidth = QuicBandwidth::Zero();
  QuicTime::Delta ridiculously_small_time_delta =
      QuicTime::Delta::FromMicroseconds(20);
  for (QuicPacketNumber i = 21; i <= 40; i++) {
    last_bandwidth = AckPacket(i);
    clock_.AdvanceTime(ridiculously_small_time_delta);
  }
  EXPECT_EQ(expected_bandwidth, last_bandwidth);
  EXPECT_EQ(0u, BandwidthSamplerPeer::GetNumberOfTrackedPackets(sampler_));
  EXPECT_EQ(0u, bytes_in_flight_);
}

// Tests receiving ACK packets in the reverse order.
TEST_F(BandwidthSamplerTest, ReorderedAck) {
  const QuicTime::Delta time_between_packets =
      QuicTime::Delta::FromMilliseconds(1);
  QuicBandwidth expected_bandwidth =
      QuicBandwidth::FromKBytesPerSecond(kRegularPacketSize);

  Send40PacketsAndAckFirst20(time_between_packets);

  // Ack the packets 21 to 40 in the reverse order, while sending packets 41 to
  // 60.
  QuicBandwidth last_bandwidth = QuicBandwidth::Zero();
  for (QuicPacketNumber i = 0; i < 20; i++) {
    last_bandwidth = AckPacket(40 - i);
    EXPECT_EQ(expected_bandwidth, last_bandwidth);
    SendPacket(41 + i);
    clock_.AdvanceTime(time_between_packets);
  }

  // Ack the packets 41 to 60, now in the regular order.
  for (QuicPacketNumber i = 41; i <= 60; i++) {
    last_bandwidth = AckPacket(i);
    EXPECT_EQ(expected_bandwidth, last_bandwidth);
    clock_.AdvanceTime(time_between_packets);
  }
  EXPECT_EQ(0u, BandwidthSamplerPeer::GetNumberOfTrackedPackets(sampler_));
  EXPECT_EQ(0u, bytes_in_flight_);
}

// Test the app-limited logic.
TEST_F(BandwidthSamplerTest, AppLimited) {
  const QuicTime::Delta time_between_packets =
      QuicTime::Delta::FromMilliseconds(1);
  QuicBandwidth expected_bandwidth =
      QuicBandwidth::FromKBytesPerSecond(kRegularPacketSize);

  Send40PacketsAndAckFirst20(time_between_packets);

  // We are now app-limited. Ack 21 to 40 as usual, but do not send anything for
  // now.
  sampler_.OnAppLimited();
  for (QuicPacketNumber i = 21; i <= 40; i++) {
    QuicBandwidth current_sample = AckPacket(i);
    EXPECT_EQ(expected_bandwidth, current_sample);
    clock_.AdvanceTime(time_between_packets);
  }

  // Enter quiescence.
  clock_.AdvanceTime(QuicTime::Delta::FromSeconds(1));

  // Send packets 41 to 60, all of which would be marked as app-limited.
  for (QuicPacketNumber i = 41; i <= 60; i++) {
    SendPacket(i);
    clock_.AdvanceTime(time_between_packets);
  }

  // Ack packets 41 to 60, while sending packets 61 to 80.  41 to 60 should be
  // app-limited and underestimate the bandwidth due to that.
  for (QuicPacketNumber i = 41; i <= 60; i++) {
    BandwidthSample sample = AckPacketInner(i);
    EXPECT_TRUE(sample.is_app_limited);
    EXPECT_LT(sample.bandwidth, 0.7f * expected_bandwidth);

    SendPacket(i + 20);
    clock_.AdvanceTime(time_between_packets);
  }

  // Run out of packets, and then ack packet 61 to 80, all of which should have
  // correct non-app-limited samples.
  for (QuicPacketNumber i = 61; i <= 80; i++) {
    QuicBandwidth last_bandwidth = AckPacket(i);
    EXPECT_EQ(expected_bandwidth, last_bandwidth);
    clock_.AdvanceTime(time_between_packets);
  }

  EXPECT_EQ(0u, BandwidthSamplerPeer::GetNumberOfTrackedPackets(sampler_));
  EXPECT_EQ(0u, bytes_in_flight_);
}

// Test the samples taken at the first flight of packets sent.
TEST_F(BandwidthSamplerTest, FirstRoundTrip) {
  const QuicTime::Delta time_between_packets =
      QuicTime::Delta::FromMilliseconds(1);
  const QuicTime::Delta rtt = QuicTime::Delta::FromMilliseconds(800);
  const int num_packets = 10;
  const QuicByteCount num_bytes = kRegularPacketSize * num_packets;
  const QuicBandwidth real_bandwidth =
      QuicBandwidth::FromBytesAndTimeDelta(num_bytes, rtt);

  for (QuicPacketNumber i = 1; i <= 10; i++) {
    SendPacket(i);
    clock_.AdvanceTime(time_between_packets);
  }

  clock_.AdvanceTime(rtt - num_packets * time_between_packets);

  QuicBandwidth last_sample = QuicBandwidth::Zero();
  for (QuicPacketNumber i = 1; i <= 10; i++) {
    QuicBandwidth sample = AckPacket(i);
    EXPECT_GT(sample, last_sample);
    last_sample = sample;
    clock_.AdvanceTime(time_between_packets);
  }

  // The final measured sample for the first flight of sample is expected to be
  // smaller than the real bandwidth, yet it should not lose more than 10%. The
  // specific value of the error depends on the difference between the RTT and
  // the time it takes to exhaust the congestion window (i.e. in the limit when
  // all packets are sent simultaneously, last sample would indicate the real
  // bandwidth).
  EXPECT_LT(last_sample, real_bandwidth);
  EXPECT_GT(last_sample, 0.9f * real_bandwidth);
}

// Test sampler's ability to remove obsolete packets.
TEST_F(BandwidthSamplerTest, RemoveObsoletePackets) {
  SendPacket(1);
  SendPacket(2);
  SendPacket(3);
  SendPacket(4);
  SendPacket(5);

  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(100));

  EXPECT_EQ(5u, BandwidthSamplerPeer::GetNumberOfTrackedPackets(sampler_));
  sampler_.RemoveObsoletePackets(4);
  EXPECT_EQ(2u, BandwidthSamplerPeer::GetNumberOfTrackedPackets(sampler_));
  sampler_.OnPacketLost(4);
  EXPECT_EQ(1u, BandwidthSamplerPeer::GetNumberOfTrackedPackets(sampler_));
  AckPacket(5);
  EXPECT_EQ(0u, BandwidthSamplerPeer::GetNumberOfTrackedPackets(sampler_));
}

}  // namespace test
}  // namespace net
