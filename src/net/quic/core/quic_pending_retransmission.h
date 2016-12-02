// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_CORE_QUIC_PENDING_RETRANSMISSION_H_
#define NET_QUIC_CORE_QUIC_PENDING_RETRANSMISSION_H_

#include "net/quic/core/frames/quic_frame.h"
#include "net/quic/core/quic_types.h"

namespace net {

// Struct to store the pending retransmission information.
struct NET_EXPORT_PRIVATE QuicPendingRetransmission {
  QuicPendingRetransmission(QuicPathId path_id,
                            QuicPacketNumber packet_number,
                            TransmissionType transmission_type,
                            const QuicFrames& retransmittable_frames,
                            bool has_crypto_handshake,
                            int num_padding_bytes,
                            EncryptionLevel encryption_level,
                            QuicPacketNumberLength packet_number_length)
      : packet_number(packet_number),
        retransmittable_frames(retransmittable_frames),
        transmission_type(transmission_type),
        path_id(path_id),
        has_crypto_handshake(has_crypto_handshake),
        num_padding_bytes(num_padding_bytes),
        encryption_level(encryption_level),
        packet_number_length(packet_number_length) {}

  QuicPacketNumber packet_number;
  const QuicFrames& retransmittable_frames;
  TransmissionType transmission_type;
  QuicPathId path_id;
  bool has_crypto_handshake;
  int num_padding_bytes;
  EncryptionLevel encryption_level;
  QuicPacketNumberLength packet_number_length;
};

}  // namespace net

#endif  // NET_QUIC_CORE_QUIC_PENDING_RETRANSMISSION_H_
