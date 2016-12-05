// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/quic_spdy_session.h"

#include <utility>

#include "net/quic/core/quic_bug_tracker.h"
#include "net/quic/core/quic_headers_stream.h"

using base::StringPiece;
using std::string;

namespace net {

QuicSpdySession::QuicSpdySession(QuicConnection* connection,
                                 QuicSession::Visitor* visitor,
                                 const QuicConfig& config)
    : QuicSession(connection, visitor, config),
      force_hol_blocking_(false),
      server_push_enabled_(false) {}

QuicSpdySession::~QuicSpdySession() {
  // Set the streams' session pointers in closed and dynamic stream lists
  // to null to avoid subsequent use of this session.
  for (auto& stream : *closed_streams()) {
    static_cast<QuicSpdyStream*>(stream.get())->ClearSession();
  }
  for (auto const& kv : dynamic_streams()) {
    static_cast<QuicSpdyStream*>(kv.second.get())->ClearSession();
  }
}

void QuicSpdySession::Initialize() {
  QuicSession::Initialize();

  if (perspective() == Perspective::IS_SERVER) {
    set_largest_peer_created_stream_id(kHeadersStreamId);
  } else {
    QuicStreamId headers_stream_id = GetNextOutgoingStreamId();
    DCHECK_EQ(headers_stream_id, kHeadersStreamId);
  }

  headers_stream_.reset(new QuicHeadersStream(this));
  DCHECK_EQ(kHeadersStreamId, headers_stream_->id());
  static_streams()[kHeadersStreamId] = headers_stream_.get();
}

void QuicSpdySession::OnStreamHeadersPriority(QuicStreamId stream_id,
                                              SpdyPriority priority) {
  QuicSpdyStream* stream = GetSpdyDataStream(stream_id);
  if (!stream) {
    // It's quite possible to receive headers after a stream has been reset.
    return;
  }
  stream->OnStreamHeadersPriority(priority);
}

void QuicSpdySession::OnStreamHeaderList(QuicStreamId stream_id,
                                         bool fin,
                                         size_t frame_len,
                                         const QuicHeaderList& header_list) {
  QuicSpdyStream* stream = GetSpdyDataStream(stream_id);
  if (!stream) {
    // It's quite possible to receive headers after a stream has been reset.
    return;
  }
  stream->OnStreamHeaderList(fin, frame_len, header_list);
}

size_t QuicSpdySession::WriteHeaders(
    QuicStreamId id,
    SpdyHeaderBlock headers,
    bool fin,
    SpdyPriority priority,
    QuicAckListenerInterface* ack_notifier_delegate) {
  return headers_stream_->WriteHeaders(id, std::move(headers), fin, priority,
                                       ack_notifier_delegate);
}

void QuicSpdySession::OnHeadersHeadOfLineBlocking(QuicTime::Delta delta) {
  // Implemented in Chromium for stats tracking.
}

void QuicSpdySession::RegisterStreamPriority(QuicStreamId id,
                                             SpdyPriority priority) {
  write_blocked_streams()->RegisterStream(id, priority);
}

void QuicSpdySession::UnregisterStreamPriority(QuicStreamId id) {
  write_blocked_streams()->UnregisterStream(id);
}

void QuicSpdySession::UpdateStreamPriority(QuicStreamId id,
                                           SpdyPriority new_priority) {
  write_blocked_streams()->UpdateStreamPriority(id, new_priority);
}

QuicSpdyStream* QuicSpdySession::GetSpdyDataStream(
    const QuicStreamId stream_id) {
  return static_cast<QuicSpdyStream*>(GetOrCreateDynamicStream(stream_id));
}

void QuicSpdySession::OnPromiseHeaderList(QuicStreamId stream_id,
                                          QuicStreamId promised_stream_id,
                                          size_t frame_len,
                                          const QuicHeaderList& header_list) {
  string error = "OnPromiseHeaderList should be overriden in client code.";
  QUIC_BUG << error;
  connection()->CloseConnection(QUIC_INTERNAL_ERROR, error,
                                ConnectionCloseBehavior::SILENT_CLOSE);
}

void QuicSpdySession::OnConfigNegotiated() {
  QuicSession::OnConfigNegotiated();
  if (config()->HasClientSentConnectionOption(kDHDT, perspective())) {
    headers_stream_->DisableHpackDynamicTable();
  }
  const QuicVersion version = connection()->version();
  if (FLAGS_quic_enable_force_hol_blocking && version > QUIC_VERSION_35 &&
      config()->ForceHolBlocking(perspective())) {
    force_hol_blocking_ = true;
    // Since all streams are tunneled through the headers stream, it
    // is important that headers stream never flow control blocks.
    // Otherwise, busy-loop behaviour can ensue where data streams
    // data try repeatedly to write data not realizing that the
    // tunnel through the headers stream is blocked.
    headers_stream_->flow_controller()->UpdateReceiveWindowSize(
        kStreamReceiveWindowLimit);
    headers_stream_->flow_controller()->UpdateSendWindowOffset(
        kStreamReceiveWindowLimit);
  }

  if (version > QUIC_VERSION_34) {
    server_push_enabled_ = FLAGS_quic_enable_server_push_by_default;
  }
}

void QuicSpdySession::OnStreamFrameData(QuicStreamId stream_id,
                                        const char* data,
                                        size_t len,
                                        bool fin) {
  QuicSpdyStream* stream = GetSpdyDataStream(stream_id);
  if (stream == nullptr) {
    return;
  }
  const QuicStreamOffset offset =
      stream->flow_controller()->highest_received_byte_offset();
  const QuicStreamFrame frame(stream_id, fin, offset, StringPiece(data, len));
  DVLOG(1) << "De-encapsulating DATA frame for stream " << stream_id
           << " offset " << offset << " len " << len << " fin " << fin;
  OnStreamFrame(frame);
}

bool QuicSpdySession::ShouldReleaseHeadersStreamSequencerBuffer() {
  return false;
}

}  // namespace net
