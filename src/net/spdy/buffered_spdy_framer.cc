// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/buffered_spdy_framer.h"

#include <utility>

#include "base/logging.h"
#include "base/strings/string_util.h"

namespace net {

namespace {

// GOAWAY frame debug data is only buffered up to this many bytes.
size_t kGoAwayDebugDataMaxSize = 1024;

// Initial and maximum sizes for header block buffer.
size_t kHeaderBufferInitialSize = 8 * 1024;
size_t kHeaderBufferMaxSize = 256 * 1024;

}  // namespace

SpdyMajorVersion NextProtoToSpdyMajorVersion(NextProto next_proto) {
  switch (next_proto) {
    case kProtoSPDY31:
      return SPDY3;
    case kProtoHTTP2:
      return HTTP2;
    case kProtoUnknown:
    case kProtoHTTP11:
    case kProtoQUIC1SPDY3:
      break;
  }
  NOTREACHED();
  return HTTP2;
}

BufferedSpdyFramer::BufferedSpdyFramer(SpdyMajorVersion version)
    : spdy_framer_(version),
      visitor_(NULL),
      header_buffer_valid_(false),
      header_stream_id_(SpdyFramer::kInvalidStream),
      frames_received_(0) {}

BufferedSpdyFramer::~BufferedSpdyFramer() {
}

void BufferedSpdyFramer::set_visitor(
    BufferedSpdyFramerVisitorInterface* visitor) {
  visitor_ = visitor;
  spdy_framer_.set_visitor(this);
}

void BufferedSpdyFramer::set_debug_visitor(
    SpdyFramerDebugVisitorInterface* debug_visitor) {
  spdy_framer_.set_debug_visitor(debug_visitor);
}

void BufferedSpdyFramer::OnError(SpdyFramer* spdy_framer) {
  DCHECK(spdy_framer);
  visitor_->OnError(spdy_framer->error_code());
}

void BufferedSpdyFramer::OnSynStream(SpdyStreamId stream_id,
                                     SpdyStreamId associated_stream_id,
                                     SpdyPriority priority,
                                     bool fin,
                                     bool unidirectional) {
  frames_received_++;
  DCHECK(!control_frame_fields_.get());
  control_frame_fields_.reset(new ControlFrameFields());
  control_frame_fields_->type = SYN_STREAM;
  control_frame_fields_->stream_id = stream_id;
  control_frame_fields_->associated_stream_id = associated_stream_id;
  control_frame_fields_->priority = priority;
  control_frame_fields_->fin = fin;
  control_frame_fields_->unidirectional = unidirectional;

  InitHeaderStreaming(stream_id);
}

void BufferedSpdyFramer::OnHeaders(SpdyStreamId stream_id,
                                   bool has_priority,
                                   int weight,
                                   SpdyStreamId parent_stream_id,
                                   bool exclusive,
                                   bool fin,
                                   bool end) {
  frames_received_++;
  DCHECK(!control_frame_fields_.get());
  control_frame_fields_.reset(new ControlFrameFields());
  control_frame_fields_->type = HEADERS;
  control_frame_fields_->stream_id = stream_id;
  control_frame_fields_->has_priority = has_priority;
  if (control_frame_fields_->has_priority) {
    control_frame_fields_->weight = weight;
    control_frame_fields_->parent_stream_id = parent_stream_id;
    control_frame_fields_->exclusive = exclusive;
  }
  control_frame_fields_->fin = fin;

  InitHeaderStreaming(stream_id);
}

void BufferedSpdyFramer::OnSynReply(SpdyStreamId stream_id,
                                    bool fin) {
  frames_received_++;
  DCHECK(!control_frame_fields_.get());
  control_frame_fields_.reset(new ControlFrameFields());
  control_frame_fields_->type = SYN_REPLY;
  control_frame_fields_->stream_id = stream_id;
  control_frame_fields_->fin = fin;

  InitHeaderStreaming(stream_id);
}

bool BufferedSpdyFramer::OnControlFrameHeaderData(SpdyStreamId stream_id,
                                                  const char* header_data,
                                                  size_t len) {
  CHECK_EQ(header_stream_id_, stream_id);

  if (len == 0) {
    // Indicates end-of-header-block.
    CHECK(header_buffer_valid_);

    SpdyHeaderBlock headers;
    if (!spdy_framer_.ParseHeaderBlockInBuffer(
            header_buffer_.data(), header_buffer_.size(), &headers)) {
      visitor_->OnStreamError(
          stream_id, "Could not parse Spdy Control Frame Header.");
      return false;
    }
    DCHECK(control_frame_fields_.get());
    switch (control_frame_fields_->type) {
      case SYN_STREAM:
        visitor_->OnSynStream(control_frame_fields_->stream_id,
                              control_frame_fields_->associated_stream_id,
                              control_frame_fields_->priority,
                              control_frame_fields_->fin,
                              control_frame_fields_->unidirectional,
                              headers);
        break;
      case SYN_REPLY:
        visitor_->OnSynReply(control_frame_fields_->stream_id,
                             control_frame_fields_->fin,
                             headers);
        break;
      case HEADERS:
        visitor_->OnHeaders(control_frame_fields_->stream_id,
                            control_frame_fields_->has_priority,
                            control_frame_fields_->weight,
                            control_frame_fields_->parent_stream_id,
                            control_frame_fields_->exclusive,
                            control_frame_fields_->fin, headers);
        break;
      case PUSH_PROMISE:
        DCHECK_LT(SPDY3, protocol_version());
        visitor_->OnPushPromise(control_frame_fields_->stream_id,
                                control_frame_fields_->promised_stream_id,
                                headers);
        break;
      default:
        DCHECK(false) << "Unexpect control frame type: "
                      << control_frame_fields_->type;
        break;
    }
    control_frame_fields_.reset(NULL);
    return true;
  }

  const size_t new_size = header_buffer_.size() + len;
  if (new_size > kHeaderBufferMaxSize) {
    header_buffer_valid_ = false;
    visitor_->OnStreamError(stream_id, "Received too much header data.");
    return false;
  }

  if (new_size > header_buffer_.capacity()) {
    // Grow |header_buffer_| exponentially to reduce memory allocations and
    // copies.
    size_t new_capacity = std::max(new_size, kHeaderBufferInitialSize);
    new_capacity = std::max(new_capacity, 2 * header_buffer_.capacity());
    new_capacity = std::min(new_capacity, kHeaderBufferMaxSize);
    header_buffer_.reserve(new_capacity);
  }
  header_buffer_.append(header_data, len);
  return true;
}

void BufferedSpdyFramer::OnDataFrameHeader(SpdyStreamId stream_id,
                                           size_t length,
                                           bool fin) {
  frames_received_++;
  header_stream_id_ = stream_id;
  visitor_->OnDataFrameHeader(stream_id, length, fin);
}

void BufferedSpdyFramer::OnStreamFrameData(SpdyStreamId stream_id,
                                           const char* data,
                                           size_t len) {
  visitor_->OnStreamFrameData(stream_id, data, len);
}

void BufferedSpdyFramer::OnStreamEnd(SpdyStreamId stream_id) {
  visitor_->OnStreamEnd(stream_id);
}

void BufferedSpdyFramer::OnStreamPadding(SpdyStreamId stream_id, size_t len) {
  visitor_->OnStreamPadding(stream_id, len);
}

SpdyHeadersHandlerInterface* BufferedSpdyFramer::OnHeaderFrameStart(
    SpdyStreamId stream_id) {
  coalescer_.reset(new HeaderCoalescer(protocol_version()));
  return coalescer_.get();
}

void BufferedSpdyFramer::OnHeaderFrameEnd(SpdyStreamId stream_id,
                                          bool end_headers) {
  if (coalescer_->error_seen()) {
    visitor_->OnStreamError(stream_id,
                            "Could not parse Spdy Control Frame Header.");
    return;
  }
  DCHECK(control_frame_fields_.get());
  switch (control_frame_fields_->type) {
    case SYN_STREAM:
      visitor_->OnSynStream(
          control_frame_fields_->stream_id,
          control_frame_fields_->associated_stream_id,
          control_frame_fields_->priority, control_frame_fields_->fin,
          control_frame_fields_->unidirectional, coalescer_->headers());
      break;
    case SYN_REPLY:
      visitor_->OnSynReply(control_frame_fields_->stream_id,
                           control_frame_fields_->fin, coalescer_->headers());
      break;
    case HEADERS:
      visitor_->OnHeaders(control_frame_fields_->stream_id,
                          control_frame_fields_->has_priority,
                          control_frame_fields_->weight,
                          control_frame_fields_->parent_stream_id,
                          control_frame_fields_->exclusive,
                          control_frame_fields_->fin, coalescer_->headers());
      break;
    case PUSH_PROMISE:
      DCHECK_LT(SPDY3, protocol_version());
      visitor_->OnPushPromise(control_frame_fields_->stream_id,
                              control_frame_fields_->promised_stream_id,
                              coalescer_->headers());
      break;
    default:
      DCHECK(false) << "Unexpect control frame type: "
                    << control_frame_fields_->type;
      break;
  }
  control_frame_fields_.reset(NULL);
}

void BufferedSpdyFramer::OnSettings(bool clear_persisted) {
  visitor_->OnSettings(clear_persisted);
}

void BufferedSpdyFramer::OnSetting(SpdySettingsIds id,
                                   uint8_t flags,
                                   uint32_t value) {
  visitor_->OnSetting(id, flags, value);
}

void BufferedSpdyFramer::OnSettingsAck() {
  visitor_->OnSettingsAck();
}

void BufferedSpdyFramer::OnSettingsEnd() {
  visitor_->OnSettingsEnd();
}

void BufferedSpdyFramer::OnPing(SpdyPingId unique_id, bool is_ack) {
  visitor_->OnPing(unique_id, is_ack);
}

void BufferedSpdyFramer::OnRstStream(SpdyStreamId stream_id,
                                     SpdyRstStreamStatus status) {
  visitor_->OnRstStream(stream_id, status);
}
void BufferedSpdyFramer::OnGoAway(SpdyStreamId last_accepted_stream_id,
                                  SpdyGoAwayStatus status) {
  DCHECK(!goaway_fields_);
  goaway_fields_.reset(new GoAwayFields());
  goaway_fields_->last_accepted_stream_id = last_accepted_stream_id;
  goaway_fields_->status = status;
}

bool BufferedSpdyFramer::OnGoAwayFrameData(const char* goaway_data,
                                           size_t len) {
  if (len > 0) {
    if (goaway_fields_->debug_data.size() < kGoAwayDebugDataMaxSize) {
      goaway_fields_->debug_data.append(
          goaway_data, std::min(len, kGoAwayDebugDataMaxSize -
                                         goaway_fields_->debug_data.size()));
    }
    return true;
  }
  visitor_->OnGoAway(goaway_fields_->last_accepted_stream_id,
                     goaway_fields_->status, goaway_fields_->debug_data);
  goaway_fields_.reset();
  return true;
}

void BufferedSpdyFramer::OnWindowUpdate(SpdyStreamId stream_id,
                                        int delta_window_size) {
  visitor_->OnWindowUpdate(stream_id, delta_window_size);
}

void BufferedSpdyFramer::OnPushPromise(SpdyStreamId stream_id,
                                       SpdyStreamId promised_stream_id,
                                       bool end) {
  DCHECK_LT(SPDY3, protocol_version());
  frames_received_++;
  DCHECK(!control_frame_fields_.get());
  control_frame_fields_.reset(new ControlFrameFields());
  control_frame_fields_->type = PUSH_PROMISE;
  control_frame_fields_->stream_id = stream_id;
  control_frame_fields_->promised_stream_id = promised_stream_id;

  InitHeaderStreaming(stream_id);
}

void BufferedSpdyFramer::OnAltSvc(
    SpdyStreamId stream_id,
    base::StringPiece origin,
    const SpdyAltSvcWireFormat::AlternativeServiceVector& altsvc_vector) {
  visitor_->OnAltSvc(stream_id, origin, altsvc_vector);
}

void BufferedSpdyFramer::OnContinuation(SpdyStreamId stream_id, bool end) {
}

bool BufferedSpdyFramer::OnUnknownFrame(SpdyStreamId stream_id,
                                        int frame_type) {
  return visitor_->OnUnknownFrame(stream_id, frame_type);
}

SpdyMajorVersion BufferedSpdyFramer::protocol_version() {
  return spdy_framer_.protocol_version();
}

size_t BufferedSpdyFramer::ProcessInput(const char* data, size_t len) {
  return spdy_framer_.ProcessInput(data, len);
}

void BufferedSpdyFramer::Reset() {
  spdy_framer_.Reset();
}

SpdyFramer::SpdyError BufferedSpdyFramer::error_code() const {
  return spdy_framer_.error_code();
}

SpdyFramer::SpdyState BufferedSpdyFramer::state() const {
  return spdy_framer_.state();
}

bool BufferedSpdyFramer::MessageFullyRead() {
  return state() == SpdyFramer::SPDY_FRAME_COMPLETE;
}

bool BufferedSpdyFramer::HasError() {
  return spdy_framer_.HasError();
}

// TODO(jgraettinger): Eliminate uses of this method (prefer
// SpdySynStreamIR).
SpdySerializedFrame* BufferedSpdyFramer::CreateSynStream(
    SpdyStreamId stream_id,
    SpdyStreamId associated_stream_id,
    SpdyPriority priority,
    SpdyControlFlags flags,
    SpdyHeaderBlock headers) {
  SpdySynStreamIR syn_stream(stream_id, std::move(headers));
  syn_stream.set_associated_to_stream_id(associated_stream_id);
  syn_stream.set_priority(priority);
  syn_stream.set_fin((flags & CONTROL_FLAG_FIN) != 0);
  syn_stream.set_unidirectional((flags & CONTROL_FLAG_UNIDIRECTIONAL) != 0);
  return new SpdySerializedFrame(spdy_framer_.SerializeSynStream(syn_stream));
}

// TODO(jgraettinger): Eliminate uses of this method (prefer
// SpdySynReplyIR).
SpdySerializedFrame* BufferedSpdyFramer::CreateSynReply(
    SpdyStreamId stream_id,
    SpdyControlFlags flags,
    SpdyHeaderBlock headers) {
  SpdySynReplyIR syn_reply(stream_id, std::move(headers));
  syn_reply.set_fin(flags & CONTROL_FLAG_FIN);
  return new SpdySerializedFrame(spdy_framer_.SerializeSynReply(syn_reply));
}

// TODO(jgraettinger): Eliminate uses of this method (prefer
// SpdyRstStreamIR).
SpdySerializedFrame* BufferedSpdyFramer::CreateRstStream(
    SpdyStreamId stream_id,
    SpdyRstStreamStatus status) const {
  SpdyRstStreamIR rst_ir(stream_id, status);
  return new SpdySerializedFrame(spdy_framer_.SerializeRstStream(rst_ir));
}

// TODO(jgraettinger): Eliminate uses of this method (prefer
// SpdySettingsIR).
SpdySerializedFrame* BufferedSpdyFramer::CreateSettings(
    const SettingsMap& values) const {
  SpdySettingsIR settings_ir;
  for (SettingsMap::const_iterator it = values.begin();
       it != values.end();
       ++it) {
    settings_ir.AddSetting(
        it->first,
        (it->second.first & SETTINGS_FLAG_PLEASE_PERSIST) != 0,
        (it->second.first & SETTINGS_FLAG_PERSISTED) != 0,
        it->second.second);
  }
  return new SpdySerializedFrame(spdy_framer_.SerializeSettings(settings_ir));
}

// TODO(jgraettinger): Eliminate uses of this method (prefer SpdyPingIR).
SpdySerializedFrame* BufferedSpdyFramer::CreatePingFrame(SpdyPingId unique_id,
                                                         bool is_ack) const {
  SpdyPingIR ping_ir(unique_id);
  ping_ir.set_is_ack(is_ack);
  return new SpdySerializedFrame(spdy_framer_.SerializePing(ping_ir));
}

// TODO(jgraettinger): Eliminate uses of this method (prefer SpdyGoAwayIR).
SpdySerializedFrame* BufferedSpdyFramer::CreateGoAway(
    SpdyStreamId last_accepted_stream_id,
    SpdyGoAwayStatus status,
    base::StringPiece debug_data) const {
  SpdyGoAwayIR go_ir(last_accepted_stream_id, status, debug_data);
  return new SpdySerializedFrame(spdy_framer_.SerializeGoAway(go_ir));
}

// TODO(jgraettinger): Eliminate uses of this method (prefer SpdyHeadersIR).
SpdySerializedFrame* BufferedSpdyFramer::CreateHeaders(
    SpdyStreamId stream_id,
    SpdyControlFlags flags,
    int weight,
    SpdyHeaderBlock headers) {
  SpdyHeadersIR headers_ir(stream_id, std::move(headers));
  headers_ir.set_fin((flags & CONTROL_FLAG_FIN) != 0);
  if (flags & HEADERS_FLAG_PRIORITY) {
    headers_ir.set_has_priority(true);
    headers_ir.set_weight(weight);
  }
  return new SpdySerializedFrame(spdy_framer_.SerializeHeaders(headers_ir));
}

// TODO(jgraettinger): Eliminate uses of this method (prefer
// SpdyWindowUpdateIR).
SpdySerializedFrame* BufferedSpdyFramer::CreateWindowUpdate(
    SpdyStreamId stream_id,
    uint32_t delta_window_size) const {
  SpdyWindowUpdateIR update_ir(stream_id, delta_window_size);
  return new SpdySerializedFrame(spdy_framer_.SerializeWindowUpdate(update_ir));
}

// TODO(jgraettinger): Eliminate uses of this method (prefer SpdyDataIR).
SpdySerializedFrame* BufferedSpdyFramer::CreateDataFrame(SpdyStreamId stream_id,
                                                         const char* data,
                                                         uint32_t len,
                                                         SpdyDataFlags flags) {
  SpdyDataIR data_ir(stream_id,
                     base::StringPiece(data, len));
  data_ir.set_fin((flags & DATA_FLAG_FIN) != 0);
  return new SpdySerializedFrame(spdy_framer_.SerializeData(data_ir));
}

// TODO(jgraettinger): Eliminate uses of this method (prefer SpdyPushPromiseIR).
SpdySerializedFrame* BufferedSpdyFramer::CreatePushPromise(
    SpdyStreamId stream_id,
    SpdyStreamId promised_stream_id,
    SpdyHeaderBlock headers) {
  SpdyPushPromiseIR push_promise_ir(stream_id, promised_stream_id,
                                    std::move(headers));
  return new SpdySerializedFrame(
      spdy_framer_.SerializePushPromise(push_promise_ir));
}

SpdyPriority BufferedSpdyFramer::GetHighestPriority() const {
  return spdy_framer_.GetHighestPriority();
}

void BufferedSpdyFramer::InitHeaderStreaming(SpdyStreamId stream_id) {
  header_buffer_.clear();
  header_buffer_valid_ = true;
  header_stream_id_ = stream_id;
  DCHECK_NE(header_stream_id_, SpdyFramer::kInvalidStream);
}

}  // namespace net
