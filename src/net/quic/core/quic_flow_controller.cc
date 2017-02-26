// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/quic_flow_controller.h"

#include <cstdint>

#include "net/quic/core/quic_connection.h"
#include "net/quic/core/quic_packets.h"
#include "net/quic/platform/api/quic_bug_tracker.h"
#include "net/quic/platform/api/quic_logging.h"
#include "net/quic/platform/api/quic_str_cat.h"

namespace net {

#define ENDPOINT \
  (perspective_ == Perspective::IS_SERVER ? "Server: " : "Client: ")

QuicFlowController::QuicFlowController(
    QuicConnection* connection,
    QuicStreamId id,
    Perspective perspective,
    QuicStreamOffset send_window_offset,
    QuicStreamOffset receive_window_offset,
    bool should_auto_tune_receive_window,
    QuicFlowControllerInterface* session_flow_controller)
    : connection_(connection),
      id_(id),
      perspective_(perspective),
      bytes_sent_(0),
      send_window_offset_(send_window_offset),
      bytes_consumed_(0),
      highest_received_byte_offset_(0),
      receive_window_offset_(receive_window_offset),
      receive_window_size_(receive_window_offset),
      auto_tune_receive_window_(should_auto_tune_receive_window),
      session_flow_controller_(session_flow_controller),
      last_blocked_send_window_offset_(0),
      prev_window_update_time_(QuicTime::Zero()) {
  receive_window_size_limit_ = (id_ == kConnectionLevelId)
                                   ? kSessionReceiveWindowLimit
                                   : kStreamReceiveWindowLimit;
  DCHECK_LE(receive_window_size_, receive_window_size_limit_);

  QUIC_DVLOG(1) << ENDPOINT << "Created flow controller for stream " << id_
                << ", setting initial receive window offset to: "
                << receive_window_offset_
                << ", max receive window to: " << receive_window_size_
                << ", max receive window limit to: "
                << receive_window_size_limit_
                << ", setting send window offset to: " << send_window_offset_;
}

void QuicFlowController::AddBytesConsumed(QuicByteCount bytes_consumed) {
  bytes_consumed_ += bytes_consumed;
  QUIC_DVLOG(1) << ENDPOINT << "Stream " << id_ << " consumed "
                << bytes_consumed_ << " bytes.";

  MaybeSendWindowUpdate();
}

bool QuicFlowController::UpdateHighestReceivedOffset(
    QuicStreamOffset new_offset) {
  // Only update if offset has increased.
  if (new_offset <= highest_received_byte_offset_) {
    return false;
  }

  QUIC_DVLOG(1) << ENDPOINT << "Stream " << id_
                << " highest byte offset increased from "
                << highest_received_byte_offset_ << " to " << new_offset;
  highest_received_byte_offset_ = new_offset;
  return true;
}

void QuicFlowController::AddBytesSent(QuicByteCount bytes_sent) {
  if (bytes_sent_ + bytes_sent > send_window_offset_) {
    QUIC_BUG << ENDPOINT << "Stream " << id_ << " Trying to send an extra "
             << bytes_sent << " bytes, when bytes_sent = " << bytes_sent_
             << ", and send_window_offset_ = " << send_window_offset_;
    bytes_sent_ = send_window_offset_;

    // This is an error on our side, close the connection as soon as possible.
    connection_->CloseConnection(
        QUIC_FLOW_CONTROL_SENT_TOO_MUCH_DATA,
        QuicStrCat(send_window_offset_ - (bytes_sent_ + bytes_sent),
                   "bytes over send window offset"),
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return;
  }

  bytes_sent_ += bytes_sent;
  QUIC_DVLOG(1) << ENDPOINT << "Stream " << id_ << " sent " << bytes_sent_
                << " bytes.";
}

bool QuicFlowController::FlowControlViolation() {
  if (highest_received_byte_offset_ > receive_window_offset_) {
    QUIC_DLOG(INFO) << ENDPOINT << "Flow control violation on stream " << id_
                    << ", receive window offset: " << receive_window_offset_
                    << ", highest received byte offset: "
                    << highest_received_byte_offset_;
    return true;
  }
  return false;
}

void QuicFlowController::MaybeIncreaseMaxWindowSize() {
  // Core of receive window auto tuning.  This method should be called before a
  // WINDOW_UPDATE frame is sent.  Ideally, window updates should occur close to
  // once per RTT.  If a window update happens much faster than RTT, it implies
  // that the flow control window is imposing a bottleneck.  To prevent this,
  // this method will increase the receive window size (subject to a reasonable
  // upper bound).  For simplicity this algorithm is deliberately asymmetric, in
  // that it may increase window size but never decreases.

  // Keep track of timing between successive window updates.
  QuicTime now = connection_->clock()->ApproximateNow();
  QuicTime prev = prev_window_update_time_;
  prev_window_update_time_ = now;
  if (!prev.IsInitialized()) {
    QUIC_DVLOG(1) << ENDPOINT << "first window update for stream " << id_;
    return;
  }

  if (!auto_tune_receive_window_) {
    return;
  }

  // Get outbound RTT.
  QuicTime::Delta rtt =
      connection_->sent_packet_manager().GetRttStats()->smoothed_rtt();
  if (rtt.IsZero()) {
    QUIC_DVLOG(1) << ENDPOINT << "rtt zero for stream " << id_;
    return;
  }

  // Now we can compare timing of window updates with RTT.
  QuicTime::Delta since_last = now - prev;
  QuicTime::Delta two_rtt = 2 * rtt;

  if (since_last >= two_rtt) {
    // If interval between window updates is sufficiently large, there
    // is no need to increase receive_window_size_.
    return;
  }
  QuicByteCount old_window = receive_window_size_;
  IncreaseWindowSize();

  if (receive_window_size_ > old_window) {
    QUIC_DVLOG(1) << ENDPOINT << "New max window increase for stream " << id_
                  << " after " << since_last.ToMicroseconds()
                  << " us, and RTT is " << rtt.ToMicroseconds()
                  << "us. max wndw: " << receive_window_size_;
    if (session_flow_controller_ != nullptr) {
      session_flow_controller_->EnsureWindowAtLeast(
          kSessionFlowControlMultiplier * receive_window_size_);
    }
  } else {
    // TODO(ckrasic) - add a varz to track this (?).
    QUIC_LOG_FIRST_N(INFO, 1) << ENDPOINT << "Max window at limit for stream "
                              << id_ << " after " << since_last.ToMicroseconds()
                              << " us, and RTT is " << rtt.ToMicroseconds()
                              << "us. Limit size: " << receive_window_size_;
  }
}

void QuicFlowController::IncreaseWindowSize() {
  receive_window_size_ *= 2;
  receive_window_size_ =
      std::min(receive_window_size_, receive_window_size_limit_);
}

QuicByteCount QuicFlowController::WindowUpdateThreshold() {
  return receive_window_size_ / 2;
}

void QuicFlowController::MaybeSendWindowUpdate() {
  // Send WindowUpdate to increase receive window if
  // (receive window offset - consumed bytes) < (max window / 2).
  // This is behaviour copied from SPDY.
  DCHECK_LE(bytes_consumed_, receive_window_offset_);
  QuicStreamOffset available_window = receive_window_offset_ - bytes_consumed_;
  QuicByteCount threshold = WindowUpdateThreshold();

  if (available_window >= threshold) {
    QUIC_DVLOG(1) << ENDPOINT << "Not sending WindowUpdate for stream " << id_
                  << ", available window: " << available_window
                  << " >= threshold: " << threshold;
    return;
  }

  MaybeIncreaseMaxWindowSize();
  SendWindowUpdate(available_window);
}

void QuicFlowController::SendWindowUpdate(QuicStreamOffset available_window) {
  // Update our receive window.
  receive_window_offset_ += (receive_window_size_ - available_window);

  QUIC_DVLOG(1) << ENDPOINT << "Sending WindowUpdate frame for stream " << id_
                << ", consumed bytes: " << bytes_consumed_
                << ", available window: " << available_window
                << ", and threshold: " << WindowUpdateThreshold()
                << ", and receive window size: " << receive_window_size_
                << ". New receive window offset is: " << receive_window_offset_;

  // Inform the peer of our new receive window.
  connection_->SendWindowUpdate(id_, receive_window_offset_);
}

void QuicFlowController::MaybeSendBlocked() {
  if (SendWindowSize() == 0 &&
      last_blocked_send_window_offset_ < send_window_offset_) {
    QUIC_DLOG(INFO) << ENDPOINT << "Stream " << id_
                    << " is flow control blocked. "
                    << "Send window: " << SendWindowSize()
                    << ", bytes sent: " << bytes_sent_
                    << ", send limit: " << send_window_offset_;
    // The entire send_window has been consumed, we are now flow control
    // blocked.
    connection_->SendBlocked(id_);

    // Keep track of when we last sent a BLOCKED frame so that we only send one
    // at a given send offset.
    last_blocked_send_window_offset_ = send_window_offset_;
  }
}

bool QuicFlowController::UpdateSendWindowOffset(
    QuicStreamOffset new_send_window_offset) {
  // Only update if send window has increased.
  if (new_send_window_offset <= send_window_offset_) {
    return false;
  }

  QUIC_DVLOG(1) << ENDPOINT << "UpdateSendWindowOffset for stream " << id_
                << " with new offset " << new_send_window_offset
                << " current offset: " << send_window_offset_
                << " bytes_sent: " << bytes_sent_;

  const bool blocked = IsBlocked();
  send_window_offset_ = new_send_window_offset;
  return blocked;
}

void QuicFlowController::EnsureWindowAtLeast(QuicByteCount window_size) {
  if (receive_window_size_limit_ >= window_size) {
    return;
  }

  QuicStreamOffset available_window = receive_window_offset_ - bytes_consumed_;
  IncreaseWindowSize();
  SendWindowUpdate(available_window);
}

bool QuicFlowController::IsBlocked() const {
  return SendWindowSize() == 0;
}

uint64_t QuicFlowController::SendWindowSize() const {
  if (bytes_sent_ > send_window_offset_) {
    return 0;
  }
  return send_window_offset_ - bytes_sent_;
}

void QuicFlowController::UpdateReceiveWindowSize(QuicStreamOffset size) {
  DCHECK_LE(size, receive_window_size_limit_);
  QUIC_DVLOG(1) << ENDPOINT << "UpdateReceiveWindowSize for stream " << id_
                << ": " << size;
  if (receive_window_size_ != receive_window_offset_) {
    QUIC_BUG << "receive_window_size_:" << receive_window_size_
             << " != receive_window_offset:" << receive_window_offset_;
    return;
  }
  receive_window_size_ = size;
  receive_window_offset_ = size;
}

}  // namespace net
