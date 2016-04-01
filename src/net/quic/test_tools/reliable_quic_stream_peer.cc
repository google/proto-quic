// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/test_tools/reliable_quic_stream_peer.h"

#include <list>

#include "net/quic/reliable_quic_stream.h"

using base::StringPiece;

namespace net {
namespace test {

// static
void ReliableQuicStreamPeer::SetWriteSideClosed(bool value,
                                                ReliableQuicStream* stream) {
  stream->write_side_closed_ = value;
}

// static
void ReliableQuicStreamPeer::SetStreamBytesWritten(
    QuicStreamOffset stream_bytes_written,
    ReliableQuicStream* stream) {
  stream->stream_bytes_written_ = stream_bytes_written;
}

// static
bool ReliableQuicStreamPeer::read_side_closed(ReliableQuicStream* stream) {
  return stream->read_side_closed();
}

// static
void ReliableQuicStreamPeer::CloseReadSide(ReliableQuicStream* stream) {
  stream->CloseReadSide();
}

// static
bool ReliableQuicStreamPeer::FinSent(ReliableQuicStream* stream) {
  return stream->fin_sent_;
}

// static
bool ReliableQuicStreamPeer::FinReceived(ReliableQuicStream* stream) {
  return stream->fin_received_;
}

// static
bool ReliableQuicStreamPeer::RstSent(ReliableQuicStream* stream) {
  return stream->rst_sent_;
}

// static
bool ReliableQuicStreamPeer::RstReceived(ReliableQuicStream* stream) {
  return stream->rst_received_;
}

// static
bool ReliableQuicStreamPeer::ReadSideClosed(ReliableQuicStream* stream) {
  return stream->read_side_closed_;
}

// static
bool ReliableQuicStreamPeer::WriteSideClosed(ReliableQuicStream* stream) {
  return stream->write_side_closed_;
}

// static
uint32_t ReliableQuicStreamPeer::SizeOfQueuedData(ReliableQuicStream* stream) {
  uint32_t total = 0;
  std::list<ReliableQuicStream::PendingData>::iterator it =
      stream->queued_data_.begin();
  while (it != stream->queued_data_.end()) {
    total += it->data.size();
    ++it;
  }
  return total;
}

// static
bool ReliableQuicStreamPeer::StreamContributesToConnectionFlowControl(
    ReliableQuicStream* stream) {
  return stream->stream_contributes_to_connection_flow_control_;
}

// static
void ReliableQuicStreamPeer::WriteOrBufferData(
    ReliableQuicStream* stream,
    StringPiece data,
    bool fin,
    QuicAckListenerInterface* ack_notifier_delegate) {
  stream->WriteOrBufferData(data, fin, ack_notifier_delegate);
}

}  // namespace test
}  // namespace net
