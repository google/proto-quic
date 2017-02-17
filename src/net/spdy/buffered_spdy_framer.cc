// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/buffered_spdy_framer.h"

#include <algorithm>
#include <utility>

#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "base/strings/string_util.h"
#include "net/spdy/platform/api/spdy_estimate_memory_usage.h"

namespace net {

namespace {

// GOAWAY frame debug data is only buffered up to this many bytes.
size_t kGoAwayDebugDataMaxSize = 1024;

}  // namespace

BufferedSpdyFramer::BufferedSpdyFramer()
    : spdy_framer_(SpdyFramer::ENABLE_COMPRESSION),
      visitor_(NULL),
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
  visitor_->OnError(spdy_framer->spdy_framer_error());
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

  DCHECK_NE(stream_id, SpdyFramer::kInvalidStream);
}

void BufferedSpdyFramer::OnDataFrameHeader(SpdyStreamId stream_id,
                                           size_t length,
                                           bool fin) {
  frames_received_++;
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
  coalescer_.reset(new HeaderCoalescer());
  return coalescer_.get();
}

void BufferedSpdyFramer::OnHeaderFrameEnd(SpdyStreamId stream_id,
                                          bool end_headers) {
  if (coalescer_->error_seen()) {
    visitor_->OnStreamError(stream_id,
                            "Could not parse Spdy Control Frame Header.");
    control_frame_fields_.reset();
    return;
  }
  DCHECK(control_frame_fields_.get());
  switch (control_frame_fields_->type) {
    case HEADERS:
      visitor_->OnHeaders(
          control_frame_fields_->stream_id, control_frame_fields_->has_priority,
          control_frame_fields_->weight,
          control_frame_fields_->parent_stream_id,
          control_frame_fields_->exclusive, control_frame_fields_->fin,
          coalescer_->release_headers());
      break;
    case PUSH_PROMISE:
      visitor_->OnPushPromise(control_frame_fields_->stream_id,
                              control_frame_fields_->promised_stream_id,
                              coalescer_->release_headers());
      break;
    default:
      DCHECK(false) << "Unexpect control frame type: "
                    << control_frame_fields_->type;
      break;
  }
  control_frame_fields_.reset(NULL);
}

void BufferedSpdyFramer::OnSettings(bool clear_persisted) {
  visitor_->OnSettings();
}

void BufferedSpdyFramer::OnSetting(SpdySettingsIds id, uint32_t value) {
  visitor_->OnSetting(id, value);
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
                                     SpdyErrorCode error_code) {
  visitor_->OnRstStream(stream_id, error_code);
}
void BufferedSpdyFramer::OnGoAway(SpdyStreamId last_accepted_stream_id,
                                  SpdyErrorCode error_code) {
  DCHECK(!goaway_fields_);
  goaway_fields_.reset(new GoAwayFields());
  goaway_fields_->last_accepted_stream_id = last_accepted_stream_id;
  goaway_fields_->error_code = error_code;
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
                     goaway_fields_->error_code, goaway_fields_->debug_data);
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
  frames_received_++;
  DCHECK(!control_frame_fields_.get());
  control_frame_fields_.reset(new ControlFrameFields());
  control_frame_fields_->type = PUSH_PROMISE;
  control_frame_fields_->stream_id = stream_id;
  control_frame_fields_->promised_stream_id = promised_stream_id;

  DCHECK_NE(stream_id, SpdyFramer::kInvalidStream);
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
                                        uint8_t frame_type) {
  return visitor_->OnUnknownFrame(stream_id, frame_type);
}

size_t BufferedSpdyFramer::ProcessInput(const char* data, size_t len) {
  return spdy_framer_.ProcessInput(data, len);
}

void BufferedSpdyFramer::UpdateHeaderDecoderTableSize(uint32_t value) {
  spdy_framer_.UpdateHeaderDecoderTableSize(value);
}

void BufferedSpdyFramer::Reset() {
  spdy_framer_.Reset();
}

SpdyFramer::SpdyFramerError BufferedSpdyFramer::spdy_framer_error() const {
  return spdy_framer_.spdy_framer_error();
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
// SpdyRstStreamIR).
std::unique_ptr<SpdySerializedFrame> BufferedSpdyFramer::CreateRstStream(
    SpdyStreamId stream_id,
    SpdyErrorCode error_code) const {
  SpdyRstStreamIR rst_ir(stream_id, error_code);
  return base::MakeUnique<SpdySerializedFrame>(
      spdy_framer_.SerializeRstStream(rst_ir));
}

// TODO(jgraettinger): Eliminate uses of this method (prefer
// SpdySettingsIR).
std::unique_ptr<SpdySerializedFrame> BufferedSpdyFramer::CreateSettings(
    const SettingsMap& values) const {
  SpdySettingsIR settings_ir;
  for (SettingsMap::const_iterator it = values.begin(); it != values.end();
       ++it) {
    settings_ir.AddSetting(it->first, it->second);
  }
  return base::MakeUnique<SpdySerializedFrame>(
      spdy_framer_.SerializeSettings(settings_ir));
}

// TODO(jgraettinger): Eliminate uses of this method (prefer SpdyPingIR).
std::unique_ptr<SpdySerializedFrame> BufferedSpdyFramer::CreatePingFrame(
    SpdyPingId unique_id,
    bool is_ack) const {
  SpdyPingIR ping_ir(unique_id);
  ping_ir.set_is_ack(is_ack);
  return base::MakeUnique<SpdySerializedFrame>(
      spdy_framer_.SerializePing(ping_ir));
}

// TODO(jgraettinger): Eliminate uses of this method (prefer
// SpdyWindowUpdateIR).
std::unique_ptr<SpdySerializedFrame> BufferedSpdyFramer::CreateWindowUpdate(
    SpdyStreamId stream_id,
    uint32_t delta_window_size) const {
  SpdyWindowUpdateIR update_ir(stream_id, delta_window_size);
  return base::MakeUnique<SpdySerializedFrame>(
      spdy_framer_.SerializeWindowUpdate(update_ir));
}

// TODO(jgraettinger): Eliminate uses of this method (prefer SpdyDataIR).
std::unique_ptr<SpdySerializedFrame> BufferedSpdyFramer::CreateDataFrame(
    SpdyStreamId stream_id,
    const char* data,
    uint32_t len,
    SpdyDataFlags flags) {
  SpdyDataIR data_ir(stream_id,
                     base::StringPiece(data, len));
  data_ir.set_fin((flags & DATA_FLAG_FIN) != 0);
  return base::MakeUnique<SpdySerializedFrame>(
      spdy_framer_.SerializeData(data_ir));
}

// TODO(jgraettinger): Eliminate uses of this method (prefer
// SpdyPriorityIR).
std::unique_ptr<SpdySerializedFrame> BufferedSpdyFramer::CreatePriority(
    SpdyStreamId stream_id,
    SpdyStreamId dependency_id,
    int weight,
    bool exclusive) const {
  SpdyPriorityIR priority_ir(stream_id, dependency_id, weight, exclusive);
  return base::MakeUnique<SpdySerializedFrame>(
      spdy_framer_.SerializePriority(priority_ir));
}

SpdyPriority BufferedSpdyFramer::GetHighestPriority() const {
  return spdy_framer_.GetHighestPriority();
}

size_t BufferedSpdyFramer::EstimateMemoryUsage() const {
  return SpdyEstimateMemoryUsage(spdy_framer_) +
         SpdyEstimateMemoryUsage(coalescer_) +
         SpdyEstimateMemoryUsage(control_frame_fields_) +
         SpdyEstimateMemoryUsage(goaway_fields_);
}

size_t BufferedSpdyFramer::GoAwayFields::EstimateMemoryUsage() const {
  return SpdyEstimateMemoryUsage(debug_data);
}

}  // namespace net
