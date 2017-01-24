// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/test_tools/quic_session_peer.h"

#include "net/quic/core/quic_session.h"
#include "net/quic/core/quic_stream.h"
#include "net/quic/platform/api/quic_map_util.h"

namespace net {
namespace test {

// static
QuicStreamId QuicSessionPeer::GetNextOutgoingStreamId(QuicSession* session) {
  return session->GetNextOutgoingStreamId();
}

// static
void QuicSessionPeer::SetNextOutgoingStreamId(QuicSession* session,
                                              QuicStreamId id) {
  session->next_outgoing_stream_id_ = id;
}

// static
void QuicSessionPeer::SetMaxOpenIncomingStreams(QuicSession* session,
                                                uint32_t max_streams) {
  session->max_open_incoming_streams_ = max_streams;
}

// static
void QuicSessionPeer::SetMaxOpenOutgoingStreams(QuicSession* session,
                                                uint32_t max_streams) {
  session->max_open_outgoing_streams_ = max_streams;
}

// static
QuicCryptoStream* QuicSessionPeer::GetCryptoStream(QuicSession* session) {
  return session->GetCryptoStream();
}

// static
QuicWriteBlockedList* QuicSessionPeer::GetWriteBlockedStreams(
    QuicSession* session) {
  return &session->write_blocked_streams_;
}

// static
QuicStream* QuicSessionPeer::GetOrCreateDynamicStream(QuicSession* session,
                                                      QuicStreamId stream_id) {
  return session->GetOrCreateDynamicStream(stream_id);
}

// static
std::map<QuicStreamId, QuicStreamOffset>&
QuicSessionPeer::GetLocallyClosedStreamsHighestOffset(QuicSession* session) {
  return session->locally_closed_streams_highest_offset_;
}

// static
QuicSession::StaticStreamMap& QuicSessionPeer::static_streams(
    QuicSession* session) {
  return session->static_streams();
}

// static
QuicSession::DynamicStreamMap& QuicSessionPeer::dynamic_streams(
    QuicSession* session) {
  return session->dynamic_streams();
}

// static
std::unordered_set<QuicStreamId>* QuicSessionPeer::GetDrainingStreams(
    QuicSession* session) {
  return &session->draining_streams_;
}

// static
void QuicSessionPeer::ActivateStream(QuicSession* session,
                                     std::unique_ptr<QuicStream> stream) {
  return session->ActivateStream(std::move(stream));
}

// static
bool QuicSessionPeer::IsStreamClosed(QuicSession* session, QuicStreamId id) {
  DCHECK_NE(0u, id);
  return session->IsClosedStream(id);
}

// static
bool QuicSessionPeer::IsStreamCreated(QuicSession* session, QuicStreamId id) {
  DCHECK_NE(0u, id);
  return QuicContainsKey(session->dynamic_streams(), id);
}

// static
bool QuicSessionPeer::IsStreamAvailable(QuicSession* session, QuicStreamId id) {
  DCHECK_NE(0u, id);
  return QuicContainsKey(session->available_streams_, id);
}

// static
bool QuicSessionPeer::IsStreamUncreated(QuicSession* session, QuicStreamId id) {
  DCHECK_NE(0u, id);
  if (id % 2 == session->next_outgoing_stream_id_ % 2) {
    // locally-created stream.
    return id >= session->next_outgoing_stream_id_;
  } else {
    // peer-created stream.
    return id > session->largest_peer_created_stream_id_;
  }
}

}  // namespace test
}  // namespace net
