// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_TEST_TOOLS_QUIC_PACKET_CREATOR_PEER_H_
#define NET_QUIC_TEST_TOOLS_QUIC_PACKET_CREATOR_PEER_H_

#include <stddef.h>

#include "base/macros.h"
#include "net/quic/core/quic_protocol.h"

namespace net {
class QuicPacketCreator;

namespace test {

class QuicPacketCreatorPeer {
 public:
  static bool SendVersionInPacket(QuicPacketCreator* creator);
  static bool SendPathIdInPacket(QuicPacketCreator* creator);

  static void SetSendVersionInPacket(QuicPacketCreator* creator,
                                     bool send_version_in_packet);
  static void SetSendPathIdInPacket(QuicPacketCreator* creator,
                                    bool send_path_id_in_packet);
  static void SetPacketNumberLength(
      QuicPacketCreator* creator,
      QuicPacketNumberLength packet_number_length);
  static QuicPacketNumberLength GetPacketNumberLength(
      QuicPacketCreator* creator);
  static void SetPacketNumber(QuicPacketCreator* creator, QuicPacketNumber s);
  static void FillPacketHeader(QuicPacketCreator* creator,
                               QuicPacketHeader* header);
  static void CreateStreamFrame(QuicPacketCreator* creator,
                                QuicStreamId id,
                                QuicIOVector iov,
                                size_t iov_offset,
                                QuicStreamOffset offset,
                                bool fin,
                                QuicFrame* frame);
  static SerializedPacket SerializeAllFrames(QuicPacketCreator* creator,
                                             const QuicFrames& frames,
                                             char* buffer,
                                             size_t buffer_len);
  static EncryptionLevel GetEncryptionLevel(QuicPacketCreator* creator);
  static QuicPathId GetCurrentPath(QuicPacketCreator* creator);

 private:
  DISALLOW_COPY_AND_ASSIGN(QuicPacketCreatorPeer);
};

}  // namespace test

}  // namespace net

#endif  // NET_QUIC_TEST_TOOLS_QUIC_PACKET_CREATOR_PEER_H_
