// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/core/spdy_framer_decoder_adapter.h"

#include <memory>
#include <utility>

#include "base/format_macros.h"
#include "base/logging.h"
#include "net/spdy/platform/api/spdy_estimate_memory_usage.h"
#include "net/spdy/platform/api/spdy_ptr_util.h"
#include "net/spdy/platform/api/spdy_string_utils.h"

#if defined(COMPILER_GCC)
#define PRETTY_THIS SpdyStringPrintf("%s@%p ", __PRETTY_FUNCTION__, this)
#elif defined(COMPILER_MSVC)
#define PRETTY_THIS SpdyStringPrintf("%s@%p ", __FUNCSIG__, this)
#else
#define PRETTY_THIS SpdyStringPrintf("%s@%p ", __func__, this)
#endif

namespace net {

SpdyFramerDecoderAdapter::SpdyFramerDecoderAdapter() {
  DVLOG(1) << PRETTY_THIS;
}

SpdyFramerDecoderAdapter::~SpdyFramerDecoderAdapter() {
  DVLOG(1) << PRETTY_THIS;
}

void SpdyFramerDecoderAdapter::set_visitor(
    SpdyFramerVisitorInterface* visitor) {
  visitor_ = visitor;
}

void SpdyFramerDecoderAdapter::set_debug_visitor(
    SpdyFramerDebugVisitorInterface* debug_visitor) {
  debug_visitor_ = debug_visitor;
}

void SpdyFramerDecoderAdapter::set_process_single_input_frame(bool v) {
  process_single_input_frame_ = v;
}

void SpdyFramerVisitorAdapter::OnError(SpdyFramer* framer) {
  visitor_->OnError(framer_);
}

void SpdyFramerVisitorAdapter::OnCommonHeader(SpdyStreamId stream_id,
                                              size_t length,
                                              uint8_t type,
                                              uint8_t flags) {
  visitor_->OnCommonHeader(stream_id, length, type, flags);
}

void SpdyFramerVisitorAdapter::OnDataFrameHeader(SpdyStreamId stream_id,
                                                 size_t length,
                                                 bool fin) {
  visitor_->OnDataFrameHeader(stream_id, length, fin);
}

void SpdyFramerVisitorAdapter::OnStreamFrameData(SpdyStreamId stream_id,
                                                 const char* data,
                                                 size_t len) {
  visitor_->OnStreamFrameData(stream_id, data, len);
}

void SpdyFramerVisitorAdapter::OnStreamEnd(SpdyStreamId stream_id) {
  visitor_->OnStreamEnd(stream_id);
}

void SpdyFramerVisitorAdapter::OnStreamPadding(SpdyStreamId stream_id,
                                               size_t len) {
  visitor_->OnStreamPadding(stream_id, len);
}

SpdyHeadersHandlerInterface* SpdyFramerVisitorAdapter::OnHeaderFrameStart(
    SpdyStreamId stream_id) {
  return visitor_->OnHeaderFrameStart(stream_id);
}

void SpdyFramerVisitorAdapter::OnHeaderFrameEnd(SpdyStreamId stream_id,
                                                bool end_headers) {
  visitor_->OnHeaderFrameEnd(stream_id, end_headers);
}

void SpdyFramerVisitorAdapter::OnRstStream(SpdyStreamId stream_id,
                                           SpdyErrorCode error_code) {
  visitor_->OnRstStream(stream_id, error_code);
}

void SpdyFramerVisitorAdapter::OnSetting(SpdySettingsIds id,
                                         uint32_t value) {
  visitor_->OnSetting(id, value);
}

void SpdyFramerVisitorAdapter::OnPing(SpdyPingId unique_id, bool is_ack) {
  visitor_->OnPing(unique_id, is_ack);
}

void SpdyFramerVisitorAdapter::OnSettings(bool clear_persisted) {
  visitor_->OnSettings(clear_persisted);
}

void SpdyFramerVisitorAdapter::OnSettingsAck() {
  visitor_->OnSettingsAck();
}

void SpdyFramerVisitorAdapter::OnSettingsEnd() {
  visitor_->OnSettingsEnd();
}

void SpdyFramerVisitorAdapter::OnGoAway(SpdyStreamId last_accepted_stream_id,
                                        SpdyErrorCode error_code) {
  visitor_->OnGoAway(last_accepted_stream_id, error_code);
}

void SpdyFramerVisitorAdapter::OnHeaders(SpdyStreamId stream_id,
                                         bool has_priority,
                                         int weight,
                                         SpdyStreamId parent_stream_id,
                                         bool exclusive,
                                         bool fin,
                                         bool end) {
  visitor_->OnHeaders(stream_id, has_priority, weight, parent_stream_id,
                      exclusive, fin, end);
}

void SpdyFramerVisitorAdapter::OnWindowUpdate(SpdyStreamId stream_id,
                                              int delta_window_size) {
  visitor_->OnWindowUpdate(stream_id, delta_window_size);
}

bool SpdyFramerVisitorAdapter::OnGoAwayFrameData(const char* goaway_data,
                                                 size_t len) {
  return visitor_->OnGoAwayFrameData(goaway_data, len);
}

void SpdyFramerVisitorAdapter::OnPushPromise(SpdyStreamId stream_id,
                                             SpdyStreamId promised_stream_id,
                                             bool end) {
  visitor_->OnPushPromise(stream_id, promised_stream_id, end);
}

void SpdyFramerVisitorAdapter::OnContinuation(SpdyStreamId stream_id,
                                              bool end) {
  visitor_->OnContinuation(stream_id, end);
}

void SpdyFramerVisitorAdapter::OnPriority(SpdyStreamId stream_id,
                                          SpdyStreamId parent_id,
                                          int weight,
                                          bool exclusive) {
  visitor_->OnPriority(stream_id, parent_id, weight, exclusive);
}

void SpdyFramerVisitorAdapter::OnAltSvc(
    SpdyStreamId stream_id,
    SpdyStringPiece origin,
    const SpdyAltSvcWireFormat::AlternativeServiceVector& altsvc_vector) {
  visitor_->OnAltSvc(stream_id, origin, altsvc_vector);
}

bool SpdyFramerVisitorAdapter::OnUnknownFrame(SpdyStreamId stream_id,
                                              uint8_t frame_type) {
  return visitor_->OnUnknownFrame(stream_id, frame_type);
}

}  // namespace net
