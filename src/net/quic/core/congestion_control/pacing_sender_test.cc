// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/congestion_control/pacing_sender.h"

#include <memory>

#include "net/quic/core/quic_packets.h"
#include "net/quic/platform/api/quic_logging.h"
#include "net/quic/platform/api/quic_test.h"
#include "net/quic/test_tools/mock_clock.h"
#include "net/quic/test_tools/quic_test_utils.h"
#include "testing/gtest/include/gtest/gtest.h"

using testing::Return;
using testing::StrictMock;
using testing::_;

namespace net {
namespace test {

const QuicByteCount kBytesInFlight = 1024;
const int kInitialBurstPackets = 10;

class PacingSenderTest : public QuicTest {
 protected:
  PacingSenderTest()
      : zero_time_(QuicTime::Delta::Zero()),
        infinite_time_(QuicTime::Delta::Infinite()),
        packet_number_(1),
        mock_sender_(new StrictMock<MockSendAlgorithm>()),
        pacing_sender_(new PacingSender) {
    pacing_sender_->set_sender(mock_sender_.get());
    // Pick arbitrary time.
    clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(9));
  }

  ~PacingSenderTest() override {}

  void InitPacingRate(QuicPacketCount burst_size, QuicBandwidth bandwidth) {
    mock_sender_.reset(new StrictMock<MockSendAlgorithm>());
    pacing_sender_.reset(new PacingSender);
    pacing_sender_->set_sender(mock_sender_.get());
    EXPECT_CALL(*mock_sender_, PacingRate(_)).WillRepeatedly(Return(bandwidth));
    if (burst_size == 0) {
      EXPECT_CALL(*mock_sender_, OnCongestionEvent(_, _, _, _, _));
      SendAlgorithmInterface::CongestionVector lost_packets;
      lost_packets.push_back(std::make_pair(1, kMaxPacketSize));
      SendAlgorithmInterface::CongestionVector empty;
      pacing_sender_->OnCongestionEvent(true, 1234, clock_.Now(), empty,
                                        lost_packets);
    } else if (burst_size != kInitialBurstPackets) {
      QUIC_LOG(FATAL) << "Unsupported burst_size " << burst_size
                      << " specificied, only 0 and " << kInitialBurstPackets
                      << " are supported.";
    }
  }

  void CheckPacketIsSentImmediately(HasRetransmittableData retransmittable_data,
                                    QuicByteCount bytes_in_flight,
                                    bool in_recovery) {
    // In order for the packet to be sendable, the underlying sender must
    // permit it to be sent immediately.
    for (int i = 0; i < 2; ++i) {
      EXPECT_CALL(*mock_sender_, TimeUntilSend(clock_.Now(), bytes_in_flight))
          .WillOnce(Return(zero_time_));
      // Verify that the packet can be sent immediately.
      EXPECT_EQ(zero_time_,
                pacing_sender_->TimeUntilSend(clock_.Now(), bytes_in_flight));
    }

    // Actually send the packet.
    if (bytes_in_flight == 0) {
      EXPECT_CALL(*mock_sender_, InRecovery()).WillOnce(Return(in_recovery));
    }
    EXPECT_CALL(*mock_sender_,
                OnPacketSent(clock_.Now(), bytes_in_flight, packet_number_,
                             kMaxPacketSize, retransmittable_data));
    pacing_sender_->OnPacketSent(clock_.Now(), bytes_in_flight,
                                 packet_number_++, kMaxPacketSize,
                                 retransmittable_data);
  }

  void CheckPacketIsSentImmediately() {
    CheckPacketIsSentImmediately(HAS_RETRANSMITTABLE_DATA, kBytesInFlight,
                                 false);
  }

  void CheckPacketIsDelayed(QuicTime::Delta delay) {
    // In order for the packet to be sendable, the underlying sender must
    // permit it to be sent immediately.
    for (int i = 0; i < 2; ++i) {
      EXPECT_CALL(*mock_sender_, TimeUntilSend(clock_.Now(), kBytesInFlight))
          .WillOnce(Return(zero_time_));
      // Verify that the packet is delayed.
      EXPECT_EQ(delay.ToMicroseconds(),
                pacing_sender_->TimeUntilSend(clock_.Now(), kBytesInFlight)
                    .ToMicroseconds());
    }
  }

  void UpdateRtt() {
    EXPECT_CALL(*mock_sender_,
                OnCongestionEvent(true, kBytesInFlight, _, _, _));
    SendAlgorithmInterface::CongestionVector empty_map;
    pacing_sender_->OnCongestionEvent(true, kBytesInFlight, clock_.Now(),
                                      empty_map, empty_map);
  }

  const QuicTime::Delta zero_time_;
  const QuicTime::Delta infinite_time_;
  MockClock clock_;
  QuicPacketNumber packet_number_;
  std::unique_ptr<StrictMock<MockSendAlgorithm>> mock_sender_;
  std::unique_ptr<PacingSender> pacing_sender_;
};

TEST_F(PacingSenderTest, NoSend) {
  for (int i = 0; i < 2; ++i) {
    EXPECT_CALL(*mock_sender_, TimeUntilSend(clock_.Now(), kBytesInFlight))
        .WillOnce(Return(infinite_time_));
    EXPECT_EQ(infinite_time_,
              pacing_sender_->TimeUntilSend(clock_.Now(), kBytesInFlight));
  }
}

TEST_F(PacingSenderTest, SendNow) {
  for (int i = 0; i < 2; ++i) {
    EXPECT_CALL(*mock_sender_, TimeUntilSend(clock_.Now(), kBytesInFlight))
        .WillOnce(Return(zero_time_));
    EXPECT_EQ(zero_time_,
              pacing_sender_->TimeUntilSend(clock_.Now(), kBytesInFlight));
  }
}

TEST_F(PacingSenderTest, VariousSending) {
  // Configure pacing rate of 1 packet per 1 ms, no initial burst.
  InitPacingRate(0, QuicBandwidth::FromBytesAndTimeDelta(
                        kMaxPacketSize, QuicTime::Delta::FromMilliseconds(1)));

  // Now update the RTT and verify that packets are actually paced.
  UpdateRtt();

  CheckPacketIsSentImmediately();
  CheckPacketIsSentImmediately();

  // The first packet was a "make up", then we sent two packets "into the
  // future", so the delay should be 2.
  CheckPacketIsDelayed(QuicTime::Delta::FromMilliseconds(2));

  // Wake up on time.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(2));
  CheckPacketIsSentImmediately();
  CheckPacketIsSentImmediately();
  CheckPacketIsDelayed(QuicTime::Delta::FromMilliseconds(2));

  // Wake up late.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(4));
  CheckPacketIsSentImmediately();
  CheckPacketIsSentImmediately();
  CheckPacketIsSentImmediately();
  CheckPacketIsSentImmediately();
  CheckPacketIsDelayed(QuicTime::Delta::FromMilliseconds(2));

  // Wake up really late.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(8));
  CheckPacketIsSentImmediately();
  CheckPacketIsSentImmediately();
  CheckPacketIsSentImmediately();
  CheckPacketIsSentImmediately();
  CheckPacketIsSentImmediately();
  CheckPacketIsSentImmediately();
  CheckPacketIsSentImmediately();
  CheckPacketIsSentImmediately();
  CheckPacketIsDelayed(QuicTime::Delta::FromMilliseconds(2));

  // Wake up really late again, but application pause partway through.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(8));
  CheckPacketIsSentImmediately();
  CheckPacketIsSentImmediately();
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(100));
  CheckPacketIsSentImmediately();
  CheckPacketIsSentImmediately();
  CheckPacketIsSentImmediately();
  CheckPacketIsDelayed(QuicTime::Delta::FromMilliseconds(2));

  // Wake up too early.
  CheckPacketIsDelayed(QuicTime::Delta::FromMilliseconds(2));

  // Wake up early, but after enough time has passed to permit a send.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(1));
  CheckPacketIsSentImmediately();
  CheckPacketIsDelayed(QuicTime::Delta::FromMilliseconds(2));
}

TEST_F(PacingSenderTest, InitialBurst) {
  // Configure pacing rate of 1 packet per 1 ms.
  InitPacingRate(10, QuicBandwidth::FromBytesAndTimeDelta(
                         kMaxPacketSize, QuicTime::Delta::FromMilliseconds(1)));

  EXPECT_CALL(*mock_sender_, GetCongestionWindow())
      .WillOnce(Return(10 * kDefaultTCPMSS));
  // Update the RTT and verify that the first 10 packets aren't paced.
  UpdateRtt();

  // Send 10 packets, and verify that they are not paced.
  for (int i = 0; i < kInitialBurstPackets; ++i) {
    CheckPacketIsSentImmediately();
  }

  // The first packet was a "make up", then we sent two packets "into the
  // future", so the delay should be 2ms.
  CheckPacketIsSentImmediately();
  CheckPacketIsSentImmediately();
  CheckPacketIsDelayed(QuicTime::Delta::FromMilliseconds(2));

  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
  CheckPacketIsSentImmediately();

  // Next time TimeUntilSend is called with no bytes in flight, pacing should
  // allow a packet to be sent, and when it's sent, the tokens are refilled.
  CheckPacketIsSentImmediately(HAS_RETRANSMITTABLE_DATA, 0, false);
  for (int i = 0; i < kInitialBurstPackets - 1; ++i) {
    CheckPacketIsSentImmediately();
  }

  // The first packet was a "make up", then we sent two packets "into the
  // future", so the delay should be 2ms.
  CheckPacketIsSentImmediately();
  CheckPacketIsSentImmediately();
  CheckPacketIsDelayed(QuicTime::Delta::FromMilliseconds(2));
}

TEST_F(PacingSenderTest, InitialBurstNoRttMeasurement) {
  // Configure pacing rate of 1 packet per 1 ms.
  InitPacingRate(10, QuicBandwidth::FromBytesAndTimeDelta(
                         kMaxPacketSize, QuicTime::Delta::FromMilliseconds(1)));

  EXPECT_CALL(*mock_sender_, GetCongestionWindow())
      .WillOnce(Return(10 * kDefaultTCPMSS));
  // Send 10 packets, and verify that they are not paced.
  for (int i = 0; i < kInitialBurstPackets; ++i) {
    CheckPacketIsSentImmediately();
  }

  // The first packet was a "make up", then we sent two packets "into the
  // future", so the delay should be 2ms.
  CheckPacketIsSentImmediately();
  CheckPacketIsSentImmediately();
  CheckPacketIsDelayed(QuicTime::Delta::FromMilliseconds(2));

  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
  CheckPacketIsSentImmediately();

  // Next time TimeUntilSend is called with no bytes in flight, the tokens
  // should be refilled and there should be no delay.
  CheckPacketIsSentImmediately(HAS_RETRANSMITTABLE_DATA, 0, false);
  // Send 10 packets, and verify that they are not paced.
  for (int i = 0; i < kInitialBurstPackets - 1; ++i) {
    CheckPacketIsSentImmediately();
  }

  // The first packet was a "make up", then we sent two packets "into the
  // future", so the delay should be 2ms.
  CheckPacketIsSentImmediately();
  CheckPacketIsSentImmediately();
  CheckPacketIsDelayed(QuicTime::Delta::FromMilliseconds(2));
}

TEST_F(PacingSenderTest, FastSending) {
  // Ensure the pacing sender paces, even when the inter-packet spacing is less
  // than the pacing granularity.
  InitPacingRate(10,
                 QuicBandwidth::FromBytesAndTimeDelta(
                     2 * kMaxPacketSize, QuicTime::Delta::FromMilliseconds(1)));

  EXPECT_CALL(*mock_sender_, GetCongestionWindow())
      .WillOnce(Return(10 * kDefaultTCPMSS));
  // Update the RTT and verify that the first 10 packets aren't paced.
  UpdateRtt();

  // Send 10 packets, and verify that they are not paced.
  for (int i = 0; i < kInitialBurstPackets; ++i) {
    CheckPacketIsSentImmediately();
  }

  // The first packet was a "make up", then we sent two packets "into the
  // future", since it's 2 packets/ms, so the delay should be 1.5ms.
  CheckPacketIsSentImmediately();
  CheckPacketIsSentImmediately();
  CheckPacketIsSentImmediately();
  CheckPacketIsDelayed(QuicTime::Delta::FromMicroseconds(1500));

  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
  CheckPacketIsSentImmediately();

  // Next time TimeUntilSend is called with no bytes in flight, the tokens
  // should be refilled and there should be no delay.
  CheckPacketIsSentImmediately(HAS_RETRANSMITTABLE_DATA, 0, false);
  for (int i = 0; i < kInitialBurstPackets - 1; ++i) {
    CheckPacketIsSentImmediately();
  }

  // The first packet was a "make up", then we sent two packets "into the
  // future", so the delay should be 1.5ms.
  CheckPacketIsSentImmediately();
  CheckPacketIsSentImmediately();
  CheckPacketIsSentImmediately();
  CheckPacketIsDelayed(QuicTime::Delta::FromMicroseconds(1500));
}

TEST_F(PacingSenderTest, NoBurstEnteringRecovery) {
  // Configure pacing rate of 1 packet per 1 ms with no burst tokens.
  InitPacingRate(0, QuicBandwidth::FromBytesAndTimeDelta(
                        kMaxPacketSize, QuicTime::Delta::FromMilliseconds(1)));
  // Sending a packet will set burst tokens.
  CheckPacketIsSentImmediately();

  // Losing a packet will set clear burst tokens.
  SendAlgorithmInterface::CongestionVector lost_packets;
  lost_packets.push_back(std::make_pair(1, kMaxPacketSize));
  SendAlgorithmInterface::CongestionVector empty;
  EXPECT_CALL(*mock_sender_,
              OnCongestionEvent(true, kMaxPacketSize, _, empty, lost_packets));
  pacing_sender_->OnCongestionEvent(true, kMaxPacketSize, clock_.Now(), empty,
                                    lost_packets);
  // One packet is sent immediately, because of 1ms pacing granularity.
  CheckPacketIsSentImmediately();
  // Ensure packets are immediately paced.
  EXPECT_CALL(*mock_sender_, TimeUntilSend(clock_.Now(), kDefaultTCPMSS))
      .WillOnce(Return(zero_time_));
  // Verify the next packet is paced and delayed 2ms due to granularity.
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(2),
            pacing_sender_->TimeUntilSend(clock_.Now(), kDefaultTCPMSS));
  CheckPacketIsDelayed(QuicTime::Delta::FromMilliseconds(2));
}

TEST_F(PacingSenderTest, NoBurstInRecovery) {
  // Configure pacing rate of 1 packet per 1 ms with no burst tokens.
  InitPacingRate(0, QuicBandwidth::FromBytesAndTimeDelta(
                        kMaxPacketSize, QuicTime::Delta::FromMilliseconds(1)));

  UpdateRtt();

  // Ensure only one packet is sent immediately and the rest are paced.
  CheckPacketIsSentImmediately(HAS_RETRANSMITTABLE_DATA, 0, true);
  CheckPacketIsSentImmediately();
  CheckPacketIsDelayed(QuicTime::Delta::FromMilliseconds(2));
}

}  // namespace test
}  // namespace net
