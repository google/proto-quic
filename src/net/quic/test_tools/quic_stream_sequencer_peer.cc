// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/test_tools/quic_stream_sequencer_peer.h"

#include "net/quic/quic_stream_sequencer.h"

using std::map;
using std::string;

namespace net {
namespace test {

// static
size_t QuicStreamSequencerPeer::GetNumBufferedBytes(
    QuicStreamSequencer* sequencer) {
  return sequencer->buffered_frames_.BytesBuffered();
}

// static
QuicStreamOffset QuicStreamSequencerPeer::GetCloseOffset(
    QuicStreamSequencer* sequencer) {
  return sequencer->close_offset_;
}

}  // namespace test
}  // namespace net
