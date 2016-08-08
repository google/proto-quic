// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// A send algorithm that adds pacing on top of an another send algorithm.
// It uses the underlying sender's pacing rate to schedule packets.
// It also takes into consideration the expected granularity of the underlying
// alarm to ensure that alarms are not set too aggressively, and err towards
// sending packets too early instead of too late.

#ifndef NET_QUIC_CONGESTION_CONTROL_PACING_SENDER_H_
#define NET_QUIC_CONGESTION_CONTROL_PACING_SENDER_H_

#include <stdint.h>

#include <map>
#include <memory>

#include "base/macros.h"
#include "net/quic/core/congestion_control/send_algorithm_interface.h"
#include "net/quic/core/quic_bandwidth.h"
#include "net/quic/core/quic_config.h"
#include "net/quic/core/quic_protocol.h"
#include "net/quic/core/quic_time.h"

namespace net {

class NET_EXPORT_PRIVATE PacingSender : public SendAlgorithmInterface {
 public:
  PacingSender();
  ~PacingSender() override;

  void SetMaxPacingRate(QuicBandwidth max_pacing_rate);
  // Sets the underlying sender. Takes ownership of |sender| if |owns_sender| is
  // true.
  void SetSender(SendAlgorithmInterface* sender, bool owns_sender);

  // SendAlgorithmInterface methods.
  void SetFromConfig(const QuicConfig& config,
                     Perspective perspective) override;
  void ResumeConnectionState(
      const CachedNetworkParameters& cached_network_params,
      bool max_bandwidth_resumption) override;
  void SetNumEmulatedConnections(int num_connections) override;
  void OnCongestionEvent(bool rtt_updated,
                         QuicByteCount bytes_in_flight,
                         const CongestionVector& acked_packets,
                         const CongestionVector& lost_packets) override;
  bool OnPacketSent(QuicTime sent_time,
                    QuicByteCount bytes_in_flight,
                    QuicPacketNumber packet_number,
                    QuicByteCount bytes,
                    HasRetransmittableData is_retransmittable) override;
  void OnRetransmissionTimeout(bool packets_retransmitted) override;
  void OnConnectionMigration() override;
  QuicTime::Delta TimeUntilSend(QuicTime now,
                                QuicByteCount bytes_in_flight) const override;
  QuicBandwidth PacingRate(QuicByteCount bytes_in_flight) const override;
  QuicBandwidth BandwidthEstimate() const override;
  QuicTime::Delta RetransmissionDelay() const override;
  QuicByteCount GetCongestionWindow() const override;
  bool InSlowStart() const override;
  bool InRecovery() const override;
  QuicByteCount GetSlowStartThreshold() const override;
  CongestionControlType GetCongestionControlType() const override;
  // End implementation of SendAlgorithmInterface.

 private:
  // Underlying sender. Owned if |owns_sender_| is true.
  SendAlgorithmInterface* sender_;
  // If not QuicBandidth::Zero, the maximum rate the PacingSender will use.
  QuicBandwidth max_pacing_rate_;

  // Number of unpaced packets to be sent before packets are delayed.
  uint32_t burst_tokens_;
  // Send time of the last packet considered delayed.
  QuicTime last_delayed_packet_sent_time_;
  QuicTime ideal_next_packet_send_time_;  // When can the next packet be sent.
  mutable bool was_last_send_delayed_;  // True when the last send was delayed.
  bool owns_sender_;                    // True if PacingSender owns |sender_|.

  DISALLOW_COPY_AND_ASSIGN(PacingSender);
};

}  // namespace net

#endif  // NET_QUIC_CONGESTION_CONTROL_PACING_SENDER_H_
