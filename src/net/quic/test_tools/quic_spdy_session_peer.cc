// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/test_tools/quic_spdy_session_peer.h"

#include "net/quic/core/quic_spdy_session.h"

namespace net {
namespace test {

// static
QuicHeadersStream* QuicSpdySessionPeer::GetHeadersStream(
    QuicSpdySession* session) {
  return session->headers_stream_.get();
}

// static
void QuicSpdySessionPeer::SetHeadersStream(QuicSpdySession* session,
                                           QuicHeadersStream* headers_stream) {
  session->headers_stream_.reset(headers_stream);
  session->static_streams()[headers_stream->id()] = headers_stream;
}

// static
void QuicSpdySessionPeer::SetForceHolBlocking(QuicSpdySession* session,
                                              bool value) {
  session->force_hol_blocking_ = value;
}

// static
const SpdyFramer& QuicSpdySessionPeer::GetSpdyFramer(
    QuicSpdySession* session) {
  return session->spdy_framer_;
}

void QuicSpdySessionPeer::SetHpackEncoderDebugVisitor(
    QuicSpdySession* session,
    std::unique_ptr<QuicHpackDebugVisitor> visitor) {
  session->SetHpackEncoderDebugVisitor(std::move(visitor));
}

void QuicSpdySessionPeer::SetHpackDecoderDebugVisitor(
    QuicSpdySession* session,
    std::unique_ptr<QuicHpackDebugVisitor> visitor) {
  session->SetHpackDecoderDebugVisitor(std::move(visitor));
}

void QuicSpdySessionPeer::SetMaxUncompressedHeaderBytes(
    QuicSpdySession* session,
    size_t set_max_uncompressed_header_bytes) {
  session->set_max_uncompressed_header_bytes(set_max_uncompressed_header_bytes);
}

// static
size_t QuicSpdySessionPeer::WriteHeadersImpl(
    QuicSpdySession* session,
    QuicStreamId id,
    SpdyHeaderBlock headers,
    bool fin,
    SpdyPriority priority,
    QuicReferenceCountedPointer<QuicAckListenerInterface> ack_listener) {
  return session->WriteHeadersImpl(id, std::move(headers), fin, priority,
                                   std::move(ack_listener));
}

}  // namespace test
}  // namespace net
