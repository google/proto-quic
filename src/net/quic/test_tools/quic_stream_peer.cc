// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/test_tools/quic_stream_peer.h"

#include <list>

#include "net/quic/core/quic_stream.h"

using base::StringPiece;

namespace net {
namespace test {

// static
void QuicStreamPeer::SetWriteSideClosed(bool value, QuicStream* stream) {
  stream->write_side_closed_ = value;
}

// static
void QuicStreamPeer::SetStreamBytesWritten(
    QuicStreamOffset stream_bytes_written,
    QuicStream* stream) {
  stream->stream_bytes_written_ = stream_bytes_written;
}

// static
bool QuicStreamPeer::read_side_closed(QuicStream* stream) {
  return stream->read_side_closed();
}

// static
void QuicStreamPeer::CloseReadSide(QuicStream* stream) {
  stream->CloseReadSide();
}

// static
bool QuicStreamPeer::FinSent(QuicStream* stream) {
  return stream->fin_sent_;
}

// static
bool QuicStreamPeer::RstSent(QuicStream* stream) {
  return stream->rst_sent_;
}

// static
uint32_t QuicStreamPeer::SizeOfQueuedData(QuicStream* stream) {
  uint32_t total = 0;
  std::list<QuicStream::PendingData>::iterator it =
      stream->queued_data_.begin();
  while (it != stream->queued_data_.end()) {
    total += it->data.size();
    ++it;
  }
  return total;
}

// static
bool QuicStreamPeer::StreamContributesToConnectionFlowControl(
    QuicStream* stream) {
  return stream->stream_contributes_to_connection_flow_control_;
}

// static
void QuicStreamPeer::WriteOrBufferData(
    QuicStream* stream,
    StringPiece data,
    bool fin,
    QuicReferenceCountedPointer<QuicAckListenerInterface> ack_listener) {
  stream->WriteOrBufferData(data, fin, std::move(ack_listener));
}

// static
QuicStreamSequencer* QuicStreamPeer::sequencer(QuicStream* stream) {
  return &(stream->sequencer_);
}

// static
QuicSession* QuicStreamPeer::session(QuicStream* stream) {
  return stream->session();
}

}  // namespace test
}  // namespace net
