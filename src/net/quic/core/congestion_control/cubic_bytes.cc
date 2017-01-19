// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/congestion_control/cubic_bytes.h"

#include <algorithm>
#include <cmath>
#include <cstdint>

#include "net/quic/core/quic_flags.h"
#include "net/quic/core/quic_packets.h"
#include "net/quic/platform/api/quic_logging.h"

namespace net {

namespace {

// Constants based on TCP defaults.
// The following constants are in 2^10 fractions of a second instead of ms to
// allow a 10 shift right to divide.
const int kCubeScale = 40;  // 1024*1024^3 (first 1024 is from 0.100^3)
                            // where 0.100 is 100 ms which is the scaling
                            // round trip time.
const int kCubeCongestionWindowScale = 410;
// The cube factor for packets in bytes.
const uint64_t kCubeFactor =
    (UINT64_C(1) << kCubeScale) / kCubeCongestionWindowScale / kDefaultTCPMSS;

const uint32_t kDefaultNumConnections = 2;
const float kBeta = 0.7f;  // Default Cubic backoff factor.
// Additional backoff factor when loss occurs in the concave part of the Cubic
// curve. This additional backoff factor is expected to give up bandwidth to
// new concurrent flows and speed up convergence.
const float kBetaLastMax = 0.85f;

}  // namespace

CubicBytes::CubicBytes(const QuicClock* clock)
    : clock_(clock),
      num_connections_(kDefaultNumConnections),
      epoch_(QuicTime::Zero()),
      last_update_time_(QuicTime::Zero()),
      fix_convex_mode_(false),
      fix_cubic_quantization_(false),
      fix_beta_last_max_(false) {
  Reset();
}

void CubicBytes::SetNumConnections(int num_connections) {
  num_connections_ = num_connections;
}

float CubicBytes::Alpha() const {
  // TCPFriendly alpha is described in Section 3.3 of the CUBIC paper. Note that
  // beta here is a cwnd multiplier, and is equal to 1-beta from the paper.
  // We derive the equivalent alpha for an N-connection emulation as:
  const float beta = Beta();
  return 3 * num_connections_ * num_connections_ * (1 - beta) / (1 + beta);
}

float CubicBytes::Beta() const {
  // kNConnectionBeta is the backoff factor after loss for our N-connection
  // emulation, which emulates the effective backoff of an ensemble of N
  // TCP-Reno connections on a single loss event. The effective multiplier is
  // computed as:
  return (num_connections_ - 1 + kBeta) / num_connections_;
}

float CubicBytes::BetaLastMax() const {
  // BetaLastMax is the additional backoff factor after loss for our
  // N-connection emulation, which emulates the additional backoff of
  // an ensemble of N TCP-Reno connections on a single loss event. The
  // effective multiplier is computed as:
  return fix_beta_last_max_
             ? (num_connections_ - 1 + kBetaLastMax) / num_connections_
             : kBetaLastMax;
}

void CubicBytes::Reset() {
  epoch_ = QuicTime::Zero();             // Reset time.
  last_update_time_ = QuicTime::Zero();  // Reset time.
  last_congestion_window_ = 0;
  last_max_congestion_window_ = 0;
  acked_bytes_count_ = 0;
  estimated_tcp_congestion_window_ = 0;
  origin_point_congestion_window_ = 0;
  time_to_origin_point_ = 0;
  last_target_congestion_window_ = 0;
  fix_convex_mode_ = false;
}

void CubicBytes::SetFixConvexMode(bool fix_convex_mode) {
  fix_convex_mode_ = fix_convex_mode;
}

void CubicBytes::SetFixCubicQuantization(bool fix_cubic_quantization) {
  fix_cubic_quantization_ = fix_cubic_quantization;
}

void CubicBytes::SetFixBetaLastMax(bool fix_beta_last_max) {
  fix_beta_last_max_ = fix_beta_last_max;
}

void CubicBytes::OnApplicationLimited() {
  // When sender is not using the available congestion window, the window does
  // not grow. But to be RTT-independent, Cubic assumes that the sender has been
  // using the entire window during the time since the beginning of the current
  // "epoch" (the end of the last loss recovery period). Since
  // application-limited periods break this assumption, we reset the epoch when
  // in such a period. This reset effectively freezes congestion window growth
  // through application-limited periods and allows Cubic growth to continue
  // when the entire window is being used.
  epoch_ = QuicTime::Zero();
}

QuicByteCount CubicBytes::CongestionWindowAfterPacketLoss(
    QuicByteCount current_congestion_window) {
  // Since bytes-mode Reno mode slightly under-estimates the cwnd, we
  // may never reach precisely the last cwnd over the course of an
  // RTT.  Do not interpret a slight under-estimation as competing traffic.
  const QuicByteCount last_window_delta =
      fix_beta_last_max_ ? kDefaultTCPMSS : 0;
  if (current_congestion_window + last_window_delta <
      last_max_congestion_window_) {
    // We never reached the old max, so assume we are competing with
    // another flow. Use our extra back off factor to allow the other
    // flow to go up.
    last_max_congestion_window_ =
        static_cast<int>(BetaLastMax() * current_congestion_window);
  } else {
    last_max_congestion_window_ = current_congestion_window;
  }
  epoch_ = QuicTime::Zero();  // Reset time.
  return static_cast<int>(current_congestion_window * Beta());
}

QuicByteCount CubicBytes::CongestionWindowAfterAck(
    QuicByteCount acked_bytes,
    QuicByteCount current_congestion_window,
    QuicTime::Delta delay_min,
    QuicTime event_time) {
  acked_bytes_count_ += acked_bytes;
  QuicTime current_time = FLAGS_quic_reloadable_flag_quic_use_event_time
                              ? event_time
                              : clock_->ApproximateNow();

  // Cubic is "independent" of RTT, the update is limited by the time elapsed.
  if (last_congestion_window_ == current_congestion_window &&
      (current_time - last_update_time_ <= MaxCubicTimeInterval())) {
    return std::max(last_target_congestion_window_,
                    estimated_tcp_congestion_window_);
  }
  last_congestion_window_ = current_congestion_window;
  last_update_time_ = current_time;

  if (!epoch_.IsInitialized()) {
    // First ACK after a loss event.
    QUIC_DVLOG(1) << "Start of epoch";
    epoch_ = current_time;             // Start of epoch.
    acked_bytes_count_ = acked_bytes;  // Reset count.
    // Reset estimated_tcp_congestion_window_ to be in sync with cubic.
    estimated_tcp_congestion_window_ = current_congestion_window;
    if (last_max_congestion_window_ <= current_congestion_window) {
      time_to_origin_point_ = 0;
      origin_point_congestion_window_ = current_congestion_window;
    } else {
      time_to_origin_point_ = static_cast<uint32_t>(
          cbrt(kCubeFactor *
               (last_max_congestion_window_ - current_congestion_window)));
      origin_point_congestion_window_ = last_max_congestion_window_;
    }
  }
  // Change the time unit from microseconds to 2^10 fractions per second. Take
  // the round trip time in account. This is done to allow us to use shift as a
  // divide operator.
  int64_t elapsed_time =
      ((current_time + delay_min - epoch_).ToMicroseconds() << 10) /
      kNumMicrosPerSecond;

  int64_t offset = time_to_origin_point_ - elapsed_time;
  if (fix_convex_mode_) {
    // Right-shifts of negative, signed numbers have
    // implementation-dependent behavior.  In the fix, force the
    // offset to be positive, as is done in the kernel.
    const int64_t positive_offset =
        std::abs(time_to_origin_point_ - elapsed_time);
    offset = positive_offset;
  }
  QuicByteCount delta_congestion_window =
      fix_cubic_quantization_
          ? (kCubeCongestionWindowScale * offset * offset * offset *
             kDefaultTCPMSS) >>
                kCubeScale
          : ((kCubeCongestionWindowScale * offset * offset * offset) >>
             kCubeScale) *
                kDefaultTCPMSS;

  const bool add_delta = elapsed_time > time_to_origin_point_;
  DCHECK(add_delta ||
         (origin_point_congestion_window_ > delta_congestion_window));
  QuicByteCount target_congestion_window =
      (fix_convex_mode_ && add_delta)
          ? origin_point_congestion_window_ + delta_congestion_window
          : origin_point_congestion_window_ - delta_congestion_window;
  // Limit the CWND increase to half the acked bytes.
  target_congestion_window =
      std::min(target_congestion_window,
               current_congestion_window + acked_bytes_count_ / 2);

  DCHECK_LT(0u, estimated_tcp_congestion_window_);
  // Increase the window by approximately Alpha * 1 MSS of bytes every
  // time we ack an estimated tcp window of bytes.  For small
  // congestion windows (less than 25), the formula below will
  // increase slightly slower than linearly per estimated tcp window
  // of bytes.
  estimated_tcp_congestion_window_ += acked_bytes_count_ *
                                      (Alpha() * kDefaultTCPMSS) /
                                      estimated_tcp_congestion_window_;
  acked_bytes_count_ = 0;

  // We have a new cubic congestion window.
  last_target_congestion_window_ = target_congestion_window;

  // Compute target congestion_window based on cubic target and estimated TCP
  // congestion_window, use highest (fastest).
  if (target_congestion_window < estimated_tcp_congestion_window_) {
    target_congestion_window = estimated_tcp_congestion_window_;
  }

  QUIC_DVLOG(1) << "Final target congestion_window: "
                << target_congestion_window;
  return target_congestion_window;
}

}  // namespace net
