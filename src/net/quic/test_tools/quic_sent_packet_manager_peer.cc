// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/test_tools/quic_sent_packet_manager_peer.h"

#include "base/stl_util.h"
#include "net/quic/core/congestion_control/loss_detection_interface.h"
#include "net/quic/core/congestion_control/send_algorithm_interface.h"
#include "net/quic/core/quic_flags.h"
#include "net/quic/core/quic_packets.h"
#include "net/quic/core/quic_sent_packet_manager.h"

namespace net {
namespace test {

// static
size_t QuicSentPacketManagerPeer::GetMaxTailLossProbes(
    QuicSentPacketManager* sent_packet_manager) {
  return sent_packet_manager->max_tail_loss_probes_;
}

// static
void QuicSentPacketManagerPeer::SetMaxTailLossProbes(
    QuicSentPacketManager* sent_packet_manager,
    size_t max_tail_loss_probes) {
  sent_packet_manager->max_tail_loss_probes_ = max_tail_loss_probes;
}

// static
bool QuicSentPacketManagerPeer::GetEnableHalfRttTailLossProbe(
    QuicSentPacketManager* sent_packet_manager) {
  return sent_packet_manager->enable_half_rtt_tail_loss_probe_;
}

// static
bool QuicSentPacketManagerPeer::GetUseNewRto(
    QuicSentPacketManager* sent_packet_manager) {
  return sent_packet_manager->use_new_rto_;
}

// static
bool QuicSentPacketManagerPeer::GetUndoRetransmits(
    QuicSentPacketManager* sent_packet_manager) {
  return sent_packet_manager->undo_pending_retransmits_;
}

// static
void QuicSentPacketManagerPeer::SetPerspective(
    QuicSentPacketManager* sent_packet_manager,
    Perspective perspective) {
  sent_packet_manager->perspective_ = perspective;
}

// static
SendAlgorithmInterface* QuicSentPacketManagerPeer::GetSendAlgorithm(
    const QuicSentPacketManager& sent_packet_manager) {
  return sent_packet_manager.send_algorithm_.get();
}

// static
void QuicSentPacketManagerPeer::SetSendAlgorithm(
    QuicSentPacketManager* sent_packet_manager,
    SendAlgorithmInterface* send_algorithm) {
  sent_packet_manager->SetSendAlgorithm(send_algorithm);
}

// static
const LossDetectionInterface* QuicSentPacketManagerPeer::GetLossAlgorithm(
    QuicSentPacketManager* sent_packet_manager) {
  return sent_packet_manager->loss_algorithm_;
}

// static
void QuicSentPacketManagerPeer::SetLossAlgorithm(
    QuicSentPacketManager* sent_packet_manager,
    LossDetectionInterface* loss_detector) {
  sent_packet_manager->loss_algorithm_ = loss_detector;
}

// static
bool QuicSentPacketManagerPeer::HasPendingPackets(
    const QuicSentPacketManager* sent_packet_manager) {
  return sent_packet_manager->unacked_packets_.HasInFlightPackets();
}

// static
QuicTime QuicSentPacketManagerPeer::GetSentTime(
    const QuicSentPacketManager* sent_packet_manager,
    QuicPacketNumber packet_number) {
  DCHECK(sent_packet_manager->unacked_packets_.IsUnacked(packet_number));

  return sent_packet_manager->unacked_packets_.GetTransmissionInfo(
                                                  packet_number)
      .sent_time;
}

// static
bool QuicSentPacketManagerPeer::IsRetransmission(
    QuicSentPacketManager* sent_packet_manager,
    QuicPacketNumber packet_number) {
  DCHECK(HasRetransmittableFrames(sent_packet_manager, packet_number));
  if (!HasRetransmittableFrames(sent_packet_manager, packet_number)) {
    return false;
  }
  for (auto transmission_info : sent_packet_manager->unacked_packets_) {
    if (transmission_info.retransmission == packet_number) {
      return true;
    }
  }
  return false;
}

// static
void QuicSentPacketManagerPeer::MarkForRetransmission(
    QuicSentPacketManager* sent_packet_manager,
    QuicPacketNumber packet_number,
    TransmissionType transmission_type) {
  sent_packet_manager->MarkForRetransmission(packet_number, transmission_type);
}

// static
QuicTime::Delta QuicSentPacketManagerPeer::GetRetransmissionDelay(
    const QuicSentPacketManager* sent_packet_manager) {
  return sent_packet_manager->GetRetransmissionDelay();
}

// static
bool QuicSentPacketManagerPeer::HasUnackedCryptoPackets(
    const QuicSentPacketManager* sent_packet_manager) {
  return sent_packet_manager->unacked_packets_.HasPendingCryptoPackets();
}

// static
size_t QuicSentPacketManagerPeer::GetNumRetransmittablePackets(
    const QuicSentPacketManager* sent_packet_manager) {
  size_t num_unacked_packets = 0;
  for (QuicUnackedPacketMap::const_iterator it =
           sent_packet_manager->unacked_packets_.begin();
       it != sent_packet_manager->unacked_packets_.end(); ++it) {
    if (!it->retransmittable_frames.empty()) {
      ++num_unacked_packets;
    }
  }
  return num_unacked_packets;
}

// static
QuicByteCount QuicSentPacketManagerPeer::GetBytesInFlight(
    const QuicSentPacketManager* sent_packet_manager) {
  return sent_packet_manager->unacked_packets_.bytes_in_flight();
}

// static
QuicSentPacketManager::NetworkChangeVisitor*
QuicSentPacketManagerPeer::GetNetworkChangeVisitor(
    const QuicSentPacketManager* sent_packet_manager) {
  return sent_packet_manager->network_change_visitor_;
}

// static
void QuicSentPacketManagerPeer::SetConsecutiveRtoCount(
    QuicSentPacketManager* sent_packet_manager,
    size_t count) {
  sent_packet_manager->consecutive_rto_count_ = count;
}

// static
void QuicSentPacketManagerPeer::SetConsecutiveTlpCount(
    QuicSentPacketManager* sent_packet_manager,
    size_t count) {
  sent_packet_manager->consecutive_tlp_count_ = count;
}

// static
QuicSustainedBandwidthRecorder& QuicSentPacketManagerPeer::GetBandwidthRecorder(
    QuicSentPacketManager* sent_packet_manager) {
  return sent_packet_manager->sustained_bandwidth_recorder_;
}

// static
bool QuicSentPacketManagerPeer::UsingPacing(
    const QuicSentPacketManager* sent_packet_manager) {
  return sent_packet_manager->using_pacing_;
}

// static
bool QuicSentPacketManagerPeer::IsUnacked(
    QuicSentPacketManager* sent_packet_manager,
    QuicPacketNumber packet_number) {
  return sent_packet_manager->unacked_packets_.IsUnacked(packet_number);
}

// static
bool QuicSentPacketManagerPeer::HasRetransmittableFrames(
    QuicSentPacketManager* sent_packet_manager,
    QuicPacketNumber packet_number) {
  return sent_packet_manager->unacked_packets_.HasRetransmittableFrames(
      packet_number);
}

// static
QuicUnackedPacketMap* QuicSentPacketManagerPeer::GetUnackedPacketMap(
    QuicSentPacketManager* sent_packet_manager) {
  return &sent_packet_manager->unacked_packets_;
}

}  // namespace test
}  // namespace net
