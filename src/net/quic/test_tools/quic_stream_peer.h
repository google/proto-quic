// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_TEST_TOOLS_QUIC_STREAM_PEER_H_
#define NET_QUIC_TEST_TOOLS_QUIC_STREAM_PEER_H_

#include <stdint.h>

#include "base/macros.h"
#include "base/strings/string_piece.h"
#include "net/quic/core/quic_packets.h"
#include "net/quic/core/quic_stream_sequencer.h"

namespace net {

class QuicStream;

namespace test {

class QuicStreamPeer {
 public:
  static void SetWriteSideClosed(bool value, QuicStream* stream);
  static void SetStreamBytesWritten(QuicStreamOffset stream_bytes_written,
                                    QuicStream* stream);
  static bool read_side_closed(QuicStream* stream);
  static void CloseReadSide(QuicStream* stream);

  static bool FinSent(QuicStream* stream);
  static bool FinReceived(QuicStream* stream);
  static bool RstSent(QuicStream* stream);
  static bool RstReceived(QuicStream* stream);

  static bool ReadSideClosed(QuicStream* stream);
  static bool WriteSideClosed(QuicStream* stream);

  static uint32_t SizeOfQueuedData(QuicStream* stream);

  static bool StreamContributesToConnectionFlowControl(QuicStream* stream);

  static void WriteOrBufferData(
      QuicStream* stream,
      base::StringPiece data,
      bool fin,
      QuicAckListenerInterface* ack_notifier_delegate);

  static net::QuicStreamSequencer* sequencer(QuicStream* stream);

 private:
  DISALLOW_COPY_AND_ASSIGN(QuicStreamPeer);
};

}  // namespace test
}  // namespace net

#endif  // NET_QUIC_TEST_TOOLS_QUIC_STREAM_PEER_H_
