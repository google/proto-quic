// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/test_tools/quic_packet_creator_peer.h"

#include "net/quic/quic_packet_creator.h"

namespace net {
namespace test {

// static
bool QuicPacketCreatorPeer::SendVersionInPacket(QuicPacketCreator* creator) {
  return creator->send_version_in_packet_;
}

// static
bool QuicPacketCreatorPeer::SendPathIdInPacket(QuicPacketCreator* creator) {
  return creator->send_path_id_in_packet_;
}

// static
void QuicPacketCreatorPeer::SetSendVersionInPacket(
    QuicPacketCreator* creator,
    bool send_version_in_packet) {
  creator->send_version_in_packet_ = send_version_in_packet;
}

// static
void QuicPacketCreatorPeer::SetSendPathIdInPacket(QuicPacketCreator* creator,
                                                  bool send_path_id_in_packet) {
  creator->send_path_id_in_packet_ = send_path_id_in_packet;
}

// static
void QuicPacketCreatorPeer::SetPacketNumberLength(
    QuicPacketCreator* creator,
    QuicPacketNumberLength packet_number_length) {
  creator->packet_.packet_number_length = packet_number_length;
}

// static
void QuicPacketCreatorPeer::SetNextPacketNumberLength(
    QuicPacketCreator* creator,
    QuicPacketNumberLength next_packet_number_length) {
  creator->next_packet_number_length_ = next_packet_number_length;
}

// static
QuicPacketNumberLength QuicPacketCreatorPeer::NextPacketNumberLength(
    QuicPacketCreator* creator) {
  return creator->next_packet_number_length_;
}

// static
QuicPacketNumberLength QuicPacketCreatorPeer::GetPacketNumberLength(
    QuicPacketCreator* creator) {
  return creator->packet_.packet_number_length;
}

void QuicPacketCreatorPeer::SetPacketNumber(QuicPacketCreator* creator,
                                            QuicPacketNumber s) {
  creator->packet_.packet_number = s;
}

// static
void QuicPacketCreatorPeer::FillPacketHeader(QuicPacketCreator* creator,
                                             QuicPacketHeader* header) {
  creator->FillPacketHeader(header);
}

// static
void QuicPacketCreatorPeer::CreateStreamFrame(QuicPacketCreator* creator,
                                              QuicStreamId id,
                                              QuicIOVector iov,
                                              size_t iov_offset,
                                              QuicStreamOffset offset,
                                              bool fin,
                                              QuicFrame* frame) {
  creator->CreateStreamFrame(id, iov, iov_offset, offset, fin, frame);
}

// static
SerializedPacket QuicPacketCreatorPeer::SerializeAllFrames(
    QuicPacketCreator* creator,
    const QuicFrames& frames,
    char* buffer,
    size_t buffer_len) {
  DCHECK(creator->queued_frames_.empty());
  DCHECK(!frames.empty());
  for (const QuicFrame& frame : frames) {
    bool success = creator->AddFrame(frame, false);
    DCHECK(success);
  }
  creator->SerializePacket(buffer, buffer_len);
  SerializedPacket packet = creator->packet_;
  // The caller takes ownership of the QuicEncryptedPacket.
  creator->packet_.encrypted_buffer = nullptr;
  DCHECK(packet.retransmittable_frames.empty());
  return packet;
}

// static
EncryptionLevel QuicPacketCreatorPeer::GetEncryptionLevel(
    QuicPacketCreator* creator) {
  return creator->packet_.encryption_level;
}

// static
QuicPathId QuicPacketCreatorPeer::GetCurrentPath(QuicPacketCreator* creator) {
  return creator->packet_.path_id;
}

}  // namespace test
}  // namespace net
