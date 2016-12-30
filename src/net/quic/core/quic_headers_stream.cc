// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/quic_headers_stream.h"

#include "net/quic/core/quic_flags.h"
#include "net/quic/core/quic_spdy_session.h"

namespace net {

QuicHeadersStream::QuicHeadersStream(QuicSpdySession* session)
    : QuicStream(kHeadersStreamId, session), spdy_session_(session) {
  // The headers stream is exempt from connection level flow control.
  DisableConnectionFlowControlForThisStream();
}

QuicHeadersStream::~QuicHeadersStream() {}

void QuicHeadersStream::OnDataAvailable() {
  char buffer[1024];
  struct iovec iov;
  QuicTime timestamp(QuicTime::Zero());
  while (true) {
    iov.iov_base = buffer;
    iov.iov_len = arraysize(buffer);
    if (!sequencer()->GetReadableRegion(&iov, &timestamp)) {
      // No more data to read.
      break;
    }
    if (spdy_session_->ProcessHeaderData(iov, timestamp) != iov.iov_len) {
      // Error processing data.
      return;
    }
    sequencer()->MarkConsumed(iov.iov_len);
    MaybeReleaseSequencerBuffer();
  }
}

void QuicHeadersStream::MaybeReleaseSequencerBuffer() {
  if (FLAGS_quic_reloadable_flag_quic_headers_stream_release_sequencer_buffer &&
      spdy_session_->ShouldReleaseHeadersStreamSequencerBuffer()) {
    sequencer()->ReleaseBufferIfEmpty();
  }
}

}  // namespace net
