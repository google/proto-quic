// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/core/spdy_protocol.h"

#include <ostream>

#include "net/spdy/core/spdy_bug_tracker.h"

namespace net {

const char* const kHttp2ConnectionHeaderPrefix =
    "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

std::ostream& operator<<(std::ostream& out, SpdySettingsIds id) {
  return out << static_cast<uint16_t>(id);
}

std::ostream& operator<<(std::ostream& out, SpdyFrameType frame_type) {
  return out << SerializeFrameType(frame_type);
}

SpdyPriority ClampSpdy3Priority(SpdyPriority priority) {
  if (priority < kV3HighestPriority) {
    SPDY_BUG << "Invalid priority: " << static_cast<int>(priority);
    return kV3HighestPriority;
  }
  if (priority > kV3LowestPriority) {
    SPDY_BUG << "Invalid priority: " << static_cast<int>(priority);
    return kV3LowestPriority;
  }
  return priority;
}

int ClampHttp2Weight(int weight) {
  if (weight < kHttp2MinStreamWeight) {
    SPDY_BUG << "Invalid weight: " << weight;
    return kHttp2MinStreamWeight;
  }
  if (weight > kHttp2MaxStreamWeight) {
    SPDY_BUG << "Invalid weight: " << weight;
    return kHttp2MaxStreamWeight;
  }
  return weight;
}

int Spdy3PriorityToHttp2Weight(SpdyPriority priority) {
  priority = ClampSpdy3Priority(priority);
  const float kSteps = 255.9f / 7.f;
  return static_cast<int>(kSteps * (7.f - priority)) + 1;
}

SpdyPriority Http2WeightToSpdy3Priority(int weight) {
  weight = ClampHttp2Weight(weight);
  const float kSteps = 255.9f / 7.f;
  return static_cast<SpdyPriority>(7.f - (weight - 1) / kSteps);
}

bool IsDefinedFrameType(uint8_t frame_type_field) {
  return frame_type_field <= SerializeFrameType(SpdyFrameType::MAX_FRAME_TYPE);
}

SpdyFrameType ParseFrameType(uint8_t frame_type_field) {
  SPDY_BUG_IF(!IsDefinedFrameType(frame_type_field))
      << "Frame type not defined: " << static_cast<int>(frame_type_field);
  return static_cast<SpdyFrameType>(frame_type_field);
}

uint8_t SerializeFrameType(SpdyFrameType frame_type) {
  return static_cast<uint8_t>(frame_type);
}

bool IsValidHTTP2FrameStreamId(SpdyStreamId current_frame_stream_id,
                               SpdyFrameType frame_type_field) {
  if (current_frame_stream_id == 0) {
    switch (frame_type_field) {
      case SpdyFrameType::DATA:
      case SpdyFrameType::HEADERS:
      case SpdyFrameType::PRIORITY:
      case SpdyFrameType::RST_STREAM:
      case SpdyFrameType::CONTINUATION:
      case SpdyFrameType::PUSH_PROMISE:
        // These frame types must specify a stream
        return false;
      default:
        return true;
    }
  } else {
    switch (frame_type_field) {
      case SpdyFrameType::GOAWAY:
      case SpdyFrameType::SETTINGS:
      case SpdyFrameType::PING:
        // These frame types must not specify a stream
        return false;
      default:
        return true;
    }
  }
}

const char* FrameTypeToString(SpdyFrameType frame_type) {
  switch (frame_type) {
    case SpdyFrameType::DATA:
      return "DATA";
    case SpdyFrameType::RST_STREAM:
      return "RST_STREAM";
    case SpdyFrameType::SETTINGS:
      return "SETTINGS";
    case SpdyFrameType::PING:
      return "PING";
    case SpdyFrameType::GOAWAY:
      return "GOAWAY";
    case SpdyFrameType::HEADERS:
      return "HEADERS";
    case SpdyFrameType::WINDOW_UPDATE:
      return "WINDOW_UPDATE";
    case SpdyFrameType::PUSH_PROMISE:
      return "PUSH_PROMISE";
    case SpdyFrameType::CONTINUATION:
      return "CONTINUATION";
    case SpdyFrameType::PRIORITY:
      return "PRIORITY";
    case SpdyFrameType::ALTSVC:
      return "ALTSVC";
    case SpdyFrameType::EXTENSION:
      return "EXTENSION (unspecified)";
  }
  return "UNKNOWN_FRAME_TYPE";
}

bool ParseSettingsId(uint16_t wire_setting_id, SpdySettingsIds* setting_id) {
  if (wire_setting_id < SETTINGS_MIN || wire_setting_id > SETTINGS_MAX) {
    return false;
  }

  *setting_id = static_cast<SpdySettingsIds>(wire_setting_id);
  return true;
}

bool SettingsIdToString(SpdySettingsIds id, const char** settings_id_string) {
  switch (id) {
    case SETTINGS_HEADER_TABLE_SIZE:
      *settings_id_string = "SETTINGS_HEADER_TABLE_SIZE";
      return true;
    case SETTINGS_ENABLE_PUSH:
      *settings_id_string = "SETTINGS_ENABLE_PUSH";
      return true;
    case SETTINGS_MAX_CONCURRENT_STREAMS:
      *settings_id_string = "SETTINGS_MAX_CONCURRENT_STREAMS";
      return true;
    case SETTINGS_INITIAL_WINDOW_SIZE:
      *settings_id_string = "SETTINGS_INITIAL_WINDOW_SIZE";
      return true;
    case SETTINGS_MAX_FRAME_SIZE:
      *settings_id_string = "SETTINGS_MAX_FRAME_SIZE";
      return true;
    case SETTINGS_MAX_HEADER_LIST_SIZE:
      *settings_id_string = "SETTINGS_MAX_HEADER_LIST_SIZE";
      return true;
  }

  *settings_id_string = "SETTINGS_UNKNOWN";
  return false;
}

SpdyErrorCode ParseErrorCode(uint32_t wire_error_code) {
  if (wire_error_code > ERROR_CODE_MAX) {
    return ERROR_CODE_INTERNAL_ERROR;
  }

  return static_cast<SpdyErrorCode>(wire_error_code);
}

const char* ErrorCodeToString(SpdyErrorCode error_code) {
  switch (error_code) {
    case ERROR_CODE_NO_ERROR:
      return "NO_ERROR";
    case ERROR_CODE_PROTOCOL_ERROR:
      return "PROTOCOL_ERROR";
    case ERROR_CODE_INTERNAL_ERROR:
      return "INTERNAL_ERROR";
    case ERROR_CODE_FLOW_CONTROL_ERROR:
      return "FLOW_CONTROL_ERROR";
    case ERROR_CODE_SETTINGS_TIMEOUT:
      return "SETTINGS_TIMEOUT";
    case ERROR_CODE_STREAM_CLOSED:
      return "STREAM_CLOSED";
    case ERROR_CODE_FRAME_SIZE_ERROR:
      return "FRAME_SIZE_ERROR";
    case ERROR_CODE_REFUSED_STREAM:
      return "REFUSED_STREAM";
    case ERROR_CODE_CANCEL:
      return "CANCEL";
    case ERROR_CODE_COMPRESSION_ERROR:
      return "COMPRESSION_ERROR";
    case ERROR_CODE_CONNECT_ERROR:
      return "CONNECT_ERROR";
    case ERROR_CODE_ENHANCE_YOUR_CALM:
      return "ENHANCE_YOUR_CALM";
    case ERROR_CODE_INADEQUATE_SECURITY:
      return "INADEQUATE_SECURITY";
    case ERROR_CODE_HTTP_1_1_REQUIRED:
      return "HTTP_1_1_REQUIRED";
  }
  return "UNKNOWN_ERROR_CODE";
}

const char* const kHttp2Npn = "h2";

bool SpdyFrameIR::fin() const {
  return false;
}

int SpdyFrameIR::flow_control_window_consumed() const {
  return 0;
}

bool SpdyFrameWithFinIR::fin() const {
  return fin_;
}

SpdyFrameWithHeaderBlockIR::SpdyFrameWithHeaderBlockIR(
    SpdyStreamId stream_id,
    SpdyHeaderBlock header_block)
    : SpdyFrameWithFinIR(stream_id), header_block_(std::move(header_block)) {}

SpdyFrameWithHeaderBlockIR::~SpdyFrameWithHeaderBlockIR() {}

SpdyDataIR::SpdyDataIR(SpdyStreamId stream_id, SpdyStringPiece data)
    : SpdyFrameWithFinIR(stream_id),
      data_(nullptr),
      data_len_(0),
      padded_(false),
      padding_payload_len_(0) {
  SetDataDeep(data);
}

SpdyDataIR::SpdyDataIR(SpdyStreamId stream_id, const char* data)
    : SpdyDataIR(stream_id, SpdyStringPiece(data)) {}

SpdyDataIR::SpdyDataIR(SpdyStreamId stream_id, SpdyString data)
    : SpdyFrameWithFinIR(stream_id),
      data_store_(SpdyMakeUnique<SpdyString>(std::move(data))),
      data_(data_store_->data()),
      data_len_(data_store_->size()),
      padded_(false),
      padding_payload_len_(0) {}

SpdyDataIR::SpdyDataIR(SpdyStreamId stream_id)
    : SpdyFrameWithFinIR(stream_id),
      data_(nullptr),
      data_len_(0),
      padded_(false),
      padding_payload_len_(0) {}

SpdyDataIR::~SpdyDataIR() {}

void SpdyDataIR::Visit(SpdyFrameVisitor* visitor) const {
  return visitor->VisitData(*this);
}

SpdyFrameType SpdyDataIR::frame_type() const {
  return SpdyFrameType::DATA;
}

int SpdyDataIR::flow_control_window_consumed() const {
  return padded() ? 1 + padding_payload_len() + data_len() : data_len();
}

SpdyRstStreamIR::SpdyRstStreamIR(SpdyStreamId stream_id,
                                 SpdyErrorCode error_code)
    : SpdyFrameIR(stream_id) {
  set_error_code(error_code);
}

SpdyRstStreamIR::~SpdyRstStreamIR() {}

void SpdyRstStreamIR::Visit(SpdyFrameVisitor* visitor) const {
  return visitor->VisitRstStream(*this);
}

SpdyFrameType SpdyRstStreamIR::frame_type() const {
  return SpdyFrameType::RST_STREAM;
}

SpdySettingsIR::SpdySettingsIR() : is_ack_(false) {}

SpdySettingsIR::~SpdySettingsIR() {}

void SpdySettingsIR::Visit(SpdyFrameVisitor* visitor) const {
  return visitor->VisitSettings(*this);
}

SpdyFrameType SpdySettingsIR::frame_type() const {
  return SpdyFrameType::SETTINGS;
}

void SpdyPingIR::Visit(SpdyFrameVisitor* visitor) const {
  return visitor->VisitPing(*this);
}

SpdyFrameType SpdyPingIR::frame_type() const {
  return SpdyFrameType::PING;
}

SpdyGoAwayIR::SpdyGoAwayIR(SpdyStreamId last_good_stream_id,
                           SpdyErrorCode error_code,
                           SpdyStringPiece description)
    : description_(description) {
  set_last_good_stream_id(last_good_stream_id);
  set_error_code(error_code);
}

SpdyGoAwayIR::SpdyGoAwayIR(SpdyStreamId last_good_stream_id,
                           SpdyErrorCode error_code,
                           const char* description)
    : SpdyGoAwayIR(last_good_stream_id,
                   error_code,
                   SpdyStringPiece(description)) {}

SpdyGoAwayIR::SpdyGoAwayIR(SpdyStreamId last_good_stream_id,
                           SpdyErrorCode error_code,
                           SpdyString description)
    : description_store_(std::move(description)),
      description_(description_store_) {
  set_last_good_stream_id(last_good_stream_id);
  set_error_code(error_code);
}

SpdyGoAwayIR::~SpdyGoAwayIR() {}

void SpdyGoAwayIR::Visit(SpdyFrameVisitor* visitor) const {
  return visitor->VisitGoAway(*this);
}

SpdyFrameType SpdyGoAwayIR::frame_type() const {
  return SpdyFrameType::GOAWAY;
}

SpdyContinuationIR::SpdyContinuationIR(SpdyStreamId stream_id)
    : SpdyFrameIR(stream_id), end_headers_(false) {
  encoding_ = SpdyMakeUnique<SpdyString>();
}

SpdyContinuationIR::~SpdyContinuationIR() {}

void SpdyContinuationIR::Visit(SpdyFrameVisitor* visitor) const {
  return visitor->VisitContinuation(*this);
}

SpdyFrameType SpdyContinuationIR::frame_type() const {
  return SpdyFrameType::CONTINUATION;
}

void SpdyHeadersIR::Visit(SpdyFrameVisitor* visitor) const {
  return visitor->VisitHeaders(*this);
}

SpdyFrameType SpdyHeadersIR::frame_type() const {
  return SpdyFrameType::HEADERS;
}

void SpdyWindowUpdateIR::Visit(SpdyFrameVisitor* visitor) const {
  return visitor->VisitWindowUpdate(*this);
}

SpdyFrameType SpdyWindowUpdateIR::frame_type() const {
  return SpdyFrameType::WINDOW_UPDATE;
}

void SpdyPushPromiseIR::Visit(SpdyFrameVisitor* visitor) const {
  return visitor->VisitPushPromise(*this);
}

SpdyFrameType SpdyPushPromiseIR::frame_type() const {
  return SpdyFrameType::PUSH_PROMISE;
}

SpdyAltSvcIR::SpdyAltSvcIR(SpdyStreamId stream_id) : SpdyFrameIR(stream_id) {}

SpdyAltSvcIR::~SpdyAltSvcIR() {}

void SpdyAltSvcIR::Visit(SpdyFrameVisitor* visitor) const {
  return visitor->VisitAltSvc(*this);
}

SpdyFrameType SpdyAltSvcIR::frame_type() const {
  return SpdyFrameType::ALTSVC;
}

void SpdyPriorityIR::Visit(SpdyFrameVisitor* visitor) const {
  return visitor->VisitPriority(*this);
}

SpdyFrameType SpdyPriorityIR::frame_type() const {
  return SpdyFrameType::PRIORITY;
}

void SpdyUnknownIR::Visit(SpdyFrameVisitor* visitor) const {
  return visitor->VisitUnknown(*this);
}

SpdyFrameType SpdyUnknownIR::frame_type() const {
  return static_cast<SpdyFrameType>(type());
}

int SpdyUnknownIR::flow_control_window_consumed() const {
  if (frame_type() == SpdyFrameType::DATA) {
    return payload_.size();
  } else {
    return 0;
  }
}

}  // namespace net
