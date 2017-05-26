// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/quic_flow_controller.h"

#include <memory>

#include "net/quic/platform/api/quic_str_cat.h"
#include "net/quic/platform/api/quic_test.h"
#include "net/quic/test_tools/quic_connection_peer.h"
#include "net/quic/test_tools/quic_flow_controller_peer.h"
#include "net/quic/test_tools/quic_sent_packet_manager_peer.h"
#include "net/quic/test_tools/quic_test_utils.h"

using testing::_;

namespace net {
namespace test {

// Receive window auto-tuning uses RTT in its logic.
const int64_t kRtt = 100;

class MockFlowController : public QuicFlowControllerInterface {
 public:
  MockFlowController() {}
  ~MockFlowController() override {}

  MOCK_METHOD1(EnsureWindowAtLeast, void(QuicByteCount));

 private:
  DISALLOW_COPY_AND_ASSIGN(MockFlowController);
};

class QuicFlowControllerTest : public QuicTest {
 public:
  QuicFlowControllerTest()
      : stream_id_(1234),
        send_window_(kInitialSessionFlowControlWindowForTest),
        receive_window_(kInitialSessionFlowControlWindowForTest),
        connection_(&helper_, &alarm_factory_, Perspective::IS_CLIENT) {}

  void Initialize() {
    flow_controller_.reset(new QuicFlowController(
        &connection_, stream_id_, Perspective::IS_CLIENT, send_window_,
        receive_window_, false, &session_flow_controller_));
  }

 protected:
  QuicStreamId stream_id_;
  QuicByteCount send_window_;
  QuicByteCount receive_window_;
  std::unique_ptr<QuicFlowController> flow_controller_;
  MockQuicConnectionHelper helper_;
  MockAlarmFactory alarm_factory_;
  MockQuicConnection connection_;
  MockFlowController session_flow_controller_;
};

TEST_F(QuicFlowControllerTest, SendingBytes) {
  Initialize();

  EXPECT_FALSE(flow_controller_->IsBlocked());
  EXPECT_FALSE(flow_controller_->FlowControlViolation());
  EXPECT_EQ(send_window_, flow_controller_->SendWindowSize());

  // Send some bytes, but not enough to block.
  flow_controller_->AddBytesSent(send_window_ / 2);
  EXPECT_FALSE(flow_controller_->IsBlocked());
  EXPECT_EQ(send_window_ / 2, flow_controller_->SendWindowSize());

  // Send enough bytes to block.
  flow_controller_->AddBytesSent(send_window_ / 2);
  EXPECT_TRUE(flow_controller_->IsBlocked());
  EXPECT_EQ(0u, flow_controller_->SendWindowSize());

  // BLOCKED frame should get sent.
  EXPECT_CALL(connection_, SendBlocked(stream_id_)).Times(1);
  flow_controller_->MaybeSendBlocked();

  // Update the send window, and verify this has unblocked.
  EXPECT_TRUE(flow_controller_->UpdateSendWindowOffset(2 * send_window_));
  EXPECT_FALSE(flow_controller_->IsBlocked());
  EXPECT_EQ(send_window_, flow_controller_->SendWindowSize());

  // Updating with a smaller offset doesn't change anything.
  EXPECT_FALSE(flow_controller_->UpdateSendWindowOffset(send_window_ / 10));
  EXPECT_EQ(send_window_, flow_controller_->SendWindowSize());

  // Try to send more bytes, violating flow control.
  EXPECT_CALL(connection_,
              CloseConnection(QUIC_FLOW_CONTROL_SENT_TOO_MUCH_DATA, _, _));
  EXPECT_QUIC_BUG(
      flow_controller_->AddBytesSent(send_window_ * 10),
      QuicStrCat("Trying to send an extra ", send_window_ * 10, " bytes"));
  EXPECT_TRUE(flow_controller_->IsBlocked());
  EXPECT_EQ(0u, flow_controller_->SendWindowSize());
}

TEST_F(QuicFlowControllerTest, ReceivingBytes) {
  Initialize();

  EXPECT_FALSE(flow_controller_->IsBlocked());
  EXPECT_FALSE(flow_controller_->FlowControlViolation());
  EXPECT_EQ(kInitialSessionFlowControlWindowForTest,
            QuicFlowControllerPeer::ReceiveWindowSize(flow_controller_.get()));

  // Receive some bytes, updating highest received offset, but not enough to
  // fill flow control receive window.
  EXPECT_TRUE(
      flow_controller_->UpdateHighestReceivedOffset(1 + receive_window_ / 2));
  EXPECT_FALSE(flow_controller_->FlowControlViolation());
  EXPECT_EQ((receive_window_ / 2) - 1,
            QuicFlowControllerPeer::ReceiveWindowSize(flow_controller_.get()));

  // Consume enough bytes to send a WINDOW_UPDATE frame.
  EXPECT_CALL(connection_, SendWindowUpdate(stream_id_, ::testing::_)).Times(1);

  flow_controller_->AddBytesConsumed(1 + receive_window_ / 2);

  // Result is that once again we have a fully open receive window.
  EXPECT_FALSE(flow_controller_->FlowControlViolation());
  EXPECT_EQ(kInitialSessionFlowControlWindowForTest,
            QuicFlowControllerPeer::ReceiveWindowSize(flow_controller_.get()));
}

TEST_F(QuicFlowControllerTest, OnlySendBlockedFrameOncePerOffset) {
  Initialize();

  // Test that we don't send duplicate BLOCKED frames. We should only send one
  // BLOCKED frame at a given send window offset.
  EXPECT_FALSE(flow_controller_->IsBlocked());
  EXPECT_FALSE(flow_controller_->FlowControlViolation());
  EXPECT_EQ(send_window_, flow_controller_->SendWindowSize());

  // Send enough bytes to block.
  flow_controller_->AddBytesSent(send_window_);
  EXPECT_TRUE(flow_controller_->IsBlocked());
  EXPECT_EQ(0u, flow_controller_->SendWindowSize());

  // Expect that 2 BLOCKED frames should get sent in total.
  EXPECT_CALL(connection_, SendBlocked(stream_id_)).Times(2);

  // BLOCKED frame should get sent.
  flow_controller_->MaybeSendBlocked();

  // BLOCKED frame should not get sent again until our send offset changes.
  flow_controller_->MaybeSendBlocked();
  flow_controller_->MaybeSendBlocked();
  flow_controller_->MaybeSendBlocked();
  flow_controller_->MaybeSendBlocked();
  flow_controller_->MaybeSendBlocked();

  // Update the send window, then send enough bytes to block again.
  EXPECT_TRUE(flow_controller_->UpdateSendWindowOffset(2 * send_window_));
  EXPECT_FALSE(flow_controller_->IsBlocked());
  EXPECT_EQ(send_window_, flow_controller_->SendWindowSize());
  flow_controller_->AddBytesSent(send_window_);
  EXPECT_TRUE(flow_controller_->IsBlocked());
  EXPECT_EQ(0u, flow_controller_->SendWindowSize());

  // BLOCKED frame should get sent as send offset has changed.
  flow_controller_->MaybeSendBlocked();
}

TEST_F(QuicFlowControllerTest, ReceivingBytesFastIncreasesFlowWindow) {
  // This test will generate two WINDOW_UPDATE frames.
  EXPECT_CALL(connection_, SendWindowUpdate(stream_id_, ::testing::_)).Times(1);

  Initialize();
  flow_controller_->set_auto_tune_receive_window(true);

  // Make sure clock is inititialized.
  connection_.AdvanceTime(QuicTime::Delta::FromMilliseconds(1));

  QuicSentPacketManager* manager =
      QuicConnectionPeer::GetSentPacketManager(&connection_);

  RttStats* rtt_stats = const_cast<RttStats*>(manager->GetRttStats());
  rtt_stats->UpdateRtt(QuicTime::Delta::FromMilliseconds(kRtt),
                       QuicTime::Delta::Zero(), QuicTime::Zero());

  EXPECT_FALSE(flow_controller_->IsBlocked());
  EXPECT_FALSE(flow_controller_->FlowControlViolation());
  EXPECT_EQ(kInitialSessionFlowControlWindowForTest,
            QuicFlowControllerPeer::ReceiveWindowSize(flow_controller_.get()));

  QuicByteCount threshold =
      QuicFlowControllerPeer::WindowUpdateThreshold(flow_controller_.get());

  QuicStreamOffset receive_offset = threshold + 1;
  // Receive some bytes, updating highest received offset, but not enough to
  // fill flow control receive window.
  EXPECT_TRUE(flow_controller_->UpdateHighestReceivedOffset(receive_offset));
  EXPECT_FALSE(flow_controller_->FlowControlViolation());
  EXPECT_EQ(kInitialSessionFlowControlWindowForTest - receive_offset,
            QuicFlowControllerPeer::ReceiveWindowSize(flow_controller_.get()));
  EXPECT_CALL(
      session_flow_controller_,
      EnsureWindowAtLeast(kInitialSessionFlowControlWindowForTest * 2 * 1.5));

  // Consume enough bytes to send a WINDOW_UPDATE frame.
  flow_controller_->AddBytesConsumed(threshold + 1);
  // Result is that once again we have a fully open receive window.
  EXPECT_FALSE(flow_controller_->FlowControlViolation());
  EXPECT_EQ(2 * kInitialSessionFlowControlWindowForTest,
            QuicFlowControllerPeer::ReceiveWindowSize(flow_controller_.get()));

  connection_.AdvanceTime(QuicTime::Delta::FromMilliseconds(2 * kRtt - 1));
  receive_offset += threshold + 1;
  EXPECT_TRUE(flow_controller_->UpdateHighestReceivedOffset(receive_offset));
  flow_controller_->AddBytesConsumed(threshold + 1);
  EXPECT_FALSE(flow_controller_->FlowControlViolation());
  QuicByteCount new_threshold =
      QuicFlowControllerPeer::WindowUpdateThreshold(flow_controller_.get());
  EXPECT_GT(new_threshold, threshold);
}

TEST_F(QuicFlowControllerTest, ReceivingBytesFastNoAutoTune) {
  // This test will generate two WINDOW_UPDATE frames.
  EXPECT_CALL(connection_, SendWindowUpdate(stream_id_, ::testing::_)).Times(2);

  Initialize();
  flow_controller_->set_auto_tune_receive_window(false);

  // Make sure clock is inititialized.
  connection_.AdvanceTime(QuicTime::Delta::FromMilliseconds(1));

  QuicSentPacketManager* manager =
      QuicConnectionPeer::GetSentPacketManager(&connection_);

  RttStats* rtt_stats = const_cast<RttStats*>(manager->GetRttStats());
  rtt_stats->UpdateRtt(QuicTime::Delta::FromMilliseconds(kRtt),
                       QuicTime::Delta::Zero(), QuicTime::Zero());

  EXPECT_FALSE(flow_controller_->IsBlocked());
  EXPECT_FALSE(flow_controller_->FlowControlViolation());
  EXPECT_EQ(kInitialSessionFlowControlWindowForTest,
            QuicFlowControllerPeer::ReceiveWindowSize(flow_controller_.get()));

  QuicByteCount threshold =
      QuicFlowControllerPeer::WindowUpdateThreshold(flow_controller_.get());

  QuicStreamOffset receive_offset = threshold + 1;
  // Receive some bytes, updating highest received offset, but not enough to
  // fill flow control receive window.
  EXPECT_TRUE(flow_controller_->UpdateHighestReceivedOffset(receive_offset));
  EXPECT_FALSE(flow_controller_->FlowControlViolation());
  EXPECT_EQ(kInitialSessionFlowControlWindowForTest - receive_offset,
            QuicFlowControllerPeer::ReceiveWindowSize(flow_controller_.get()));

  // Consume enough bytes to send a WINDOW_UPDATE frame.
  flow_controller_->AddBytesConsumed(threshold + 1);
  // Result is that once again we have a fully open receive window.
  EXPECT_FALSE(flow_controller_->FlowControlViolation());
  EXPECT_EQ(kInitialSessionFlowControlWindowForTest,
            QuicFlowControllerPeer::ReceiveWindowSize(flow_controller_.get()));

  // Move time forward, but by less than two RTTs.  Then receive and consume
  // some more, forcing a second WINDOW_UPDATE with an increased max window
  // size.
  connection_.AdvanceTime(QuicTime::Delta::FromMilliseconds(2 * kRtt - 1));
  receive_offset += threshold + 1;
  EXPECT_TRUE(flow_controller_->UpdateHighestReceivedOffset(receive_offset));
  flow_controller_->AddBytesConsumed(threshold + 1);
  EXPECT_FALSE(flow_controller_->FlowControlViolation());
  QuicByteCount new_threshold =
      QuicFlowControllerPeer::WindowUpdateThreshold(flow_controller_.get());
  EXPECT_EQ(new_threshold, threshold);
}

TEST_F(QuicFlowControllerTest, ReceivingBytesNormalStableFlowWindow) {
  // This test will generate two WINDOW_UPDATE frames.
  EXPECT_CALL(connection_, SendWindowUpdate(stream_id_, ::testing::_)).Times(1);

  Initialize();
  flow_controller_->set_auto_tune_receive_window(true);

  // Make sure clock is inititialized.
  connection_.AdvanceTime(QuicTime::Delta::FromMilliseconds(1));

  QuicSentPacketManager* manager =
      QuicConnectionPeer::GetSentPacketManager(&connection_);
  RttStats* rtt_stats = const_cast<RttStats*>(manager->GetRttStats());
  rtt_stats->UpdateRtt(QuicTime::Delta::FromMilliseconds(kRtt),
                       QuicTime::Delta::Zero(), QuicTime::Zero());

  EXPECT_FALSE(flow_controller_->IsBlocked());
  EXPECT_FALSE(flow_controller_->FlowControlViolation());
  EXPECT_EQ(kInitialSessionFlowControlWindowForTest,
            QuicFlowControllerPeer::ReceiveWindowSize(flow_controller_.get()));

  QuicByteCount threshold =
      QuicFlowControllerPeer::WindowUpdateThreshold(flow_controller_.get());

  QuicStreamOffset receive_offset = threshold + 1;
  // Receive some bytes, updating highest received offset, but not enough to
  // fill flow control receive window.
  EXPECT_TRUE(flow_controller_->UpdateHighestReceivedOffset(receive_offset));
  EXPECT_FALSE(flow_controller_->FlowControlViolation());
  EXPECT_EQ(kInitialSessionFlowControlWindowForTest - receive_offset,
            QuicFlowControllerPeer::ReceiveWindowSize(flow_controller_.get()));
  EXPECT_CALL(
      session_flow_controller_,
      EnsureWindowAtLeast(kInitialSessionFlowControlWindowForTest * 2 * 1.5));
  flow_controller_->AddBytesConsumed(threshold + 1);

  // Result is that once again we have a fully open receive window.
  EXPECT_FALSE(flow_controller_->FlowControlViolation());
  EXPECT_EQ(2 * kInitialSessionFlowControlWindowForTest,
            QuicFlowControllerPeer::ReceiveWindowSize(flow_controller_.get()));

  // Move time forward, but by more than two RTTs.  Then receive and consume
  // some more, forcing a second WINDOW_UPDATE with unchanged max window size.
  connection_.AdvanceTime(QuicTime::Delta::FromMilliseconds(2 * kRtt + 1));

  receive_offset += threshold + 1;
  EXPECT_TRUE(flow_controller_->UpdateHighestReceivedOffset(receive_offset));

  flow_controller_->AddBytesConsumed(threshold + 1);
  EXPECT_FALSE(flow_controller_->FlowControlViolation());

  QuicByteCount new_threshold =
      QuicFlowControllerPeer::WindowUpdateThreshold(flow_controller_.get());
  EXPECT_EQ(new_threshold, 2 * threshold);
}

TEST_F(QuicFlowControllerTest, ReceivingBytesNormalNoAutoTune) {
  // This test will generate two WINDOW_UPDATE frames.
  EXPECT_CALL(connection_, SendWindowUpdate(stream_id_, ::testing::_)).Times(2);

  Initialize();
  flow_controller_->set_auto_tune_receive_window(false);

  // Make sure clock is inititialized.
  connection_.AdvanceTime(QuicTime::Delta::FromMilliseconds(1));

  QuicSentPacketManager* manager =
      QuicConnectionPeer::GetSentPacketManager(&connection_);
  RttStats* rtt_stats = const_cast<RttStats*>(manager->GetRttStats());
  rtt_stats->UpdateRtt(QuicTime::Delta::FromMilliseconds(kRtt),
                       QuicTime::Delta::Zero(), QuicTime::Zero());

  EXPECT_FALSE(flow_controller_->IsBlocked());
  EXPECT_FALSE(flow_controller_->FlowControlViolation());
  EXPECT_EQ(kInitialSessionFlowControlWindowForTest,
            QuicFlowControllerPeer::ReceiveWindowSize(flow_controller_.get()));

  QuicByteCount threshold =
      QuicFlowControllerPeer::WindowUpdateThreshold(flow_controller_.get());

  QuicStreamOffset receive_offset = threshold + 1;
  // Receive some bytes, updating highest received offset, but not enough to
  // fill flow control receive window.
  EXPECT_TRUE(flow_controller_->UpdateHighestReceivedOffset(receive_offset));
  EXPECT_FALSE(flow_controller_->FlowControlViolation());
  EXPECT_EQ(kInitialSessionFlowControlWindowForTest - receive_offset,
            QuicFlowControllerPeer::ReceiveWindowSize(flow_controller_.get()));

  flow_controller_->AddBytesConsumed(threshold + 1);

  // Result is that once again we have a fully open receive window.
  EXPECT_FALSE(flow_controller_->FlowControlViolation());
  EXPECT_EQ(kInitialSessionFlowControlWindowForTest,
            QuicFlowControllerPeer::ReceiveWindowSize(flow_controller_.get()));

  // Move time forward, but by more than two RTTs.  Then receive and consume
  // some more, forcing a second WINDOW_UPDATE with unchanged max window size.
  connection_.AdvanceTime(QuicTime::Delta::FromMilliseconds(2 * kRtt + 1));

  receive_offset += threshold + 1;
  EXPECT_TRUE(flow_controller_->UpdateHighestReceivedOffset(receive_offset));

  flow_controller_->AddBytesConsumed(threshold + 1);
  EXPECT_FALSE(flow_controller_->FlowControlViolation());

  QuicByteCount new_threshold =
      QuicFlowControllerPeer::WindowUpdateThreshold(flow_controller_.get());

  EXPECT_EQ(new_threshold, threshold);
}

}  // namespace test
}  // namespace net
