// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_TEST_TOOLS_RELIABLE_QUIC_STREAM_PEER_H_
#define NET_QUIC_TEST_TOOLS_RELIABLE_QUIC_STREAM_PEER_H_

#include <stdint.h>

#include "base/macros.h"
#include "base/strings/string_piece.h"
#include "net/quic/quic_protocol.h"

namespace net {

class ReliableQuicStream;

namespace test {

class ReliableQuicStreamPeer {
 public:
  static void SetWriteSideClosed(bool value, ReliableQuicStream* stream);
  static void SetStreamBytesWritten(QuicStreamOffset stream_bytes_written,
                                    ReliableQuicStream* stream);
  static bool read_side_closed(ReliableQuicStream* stream);
  static void CloseReadSide(ReliableQuicStream* stream);

  static bool FinSent(ReliableQuicStream* stream);
  static bool FinReceived(ReliableQuicStream* stream);
  static bool RstSent(ReliableQuicStream* stream);
  static bool RstReceived(ReliableQuicStream* stream);

  static bool ReadSideClosed(ReliableQuicStream* stream);
  static bool WriteSideClosed(ReliableQuicStream* stream);

  static uint32_t SizeOfQueuedData(ReliableQuicStream* stream);

  static bool StreamContributesToConnectionFlowControl(
      ReliableQuicStream* stream);

  static void WriteOrBufferData(
      ReliableQuicStream* stream,
      base::StringPiece data,
      bool fin,
      QuicAckListenerInterface* ack_notifier_delegate);

 private:
  DISALLOW_COPY_AND_ASSIGN(ReliableQuicStreamPeer);
};

}  // namespace test
}  // namespace net

#endif  // NET_QUIC_TEST_TOOLS_RELIABLE_QUIC_STREAM_PEER_H_
