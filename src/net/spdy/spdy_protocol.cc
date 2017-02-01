// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/spdy_protocol.h"

#include "base/memory/ptr_util.h"
#include "net/spdy/spdy_bug_tracker.h"

namespace net {

const char* const kHttp2ConnectionHeaderPrefix =
    "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

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

bool IsDefinedFrameType(int frame_type_field) {
  return frame_type_field >= MIN_FRAME_TYPE &&
         frame_type_field <= MAX_FRAME_TYPE;
}

SpdyFrameType ParseFrameType(int frame_type_field) {
  SPDY_BUG_IF(!IsDefinedFrameType(frame_type_field))
      << "Frame type not defined: " << static_cast<int>(frame_type_field);
  return static_cast<SpdyFrameType>(frame_type_field);
}

bool IsValidHTTP2FrameStreamId(SpdyStreamId current_frame_stream_id,
                               SpdyFrameType frame_type_field) {
  if (current_frame_stream_id == 0) {
    switch (frame_type_field) {
      case DATA:
      case HEADERS:
      case PRIORITY:
      case RST_STREAM:
      case CONTINUATION:
      case PUSH_PROMISE:
        // These frame types must specify a stream
        return false;
      default:
        return true;
    }
  } else {
    switch (frame_type_field) {
      case GOAWAY:
      case SETTINGS:
      case PING:
        // These frame types must not specify a stream
        return false;
      default:
        return true;
    }
  }
}

bool ParseSettingsId(int wire_setting_id, SpdySettingsIds* setting_id) {
  // HEADER_TABLE_SIZE is the first defined setting id.
  if (wire_setting_id < SETTINGS_MIN) {
    return false;
  }

  // MAX_HEADER_LIST_SIZE is the last defined setting id.
  if (wire_setting_id > SETTINGS_MAX) {
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

SpdyRstStreamStatus ParseRstStreamStatus(int rst_stream_status_field) {
  if (rst_stream_status_field < RST_STREAM_MIN ||
      rst_stream_status_field > RST_STREAM_MAX) {
    return RST_STREAM_INTERNAL_ERROR;
  }

  return static_cast<SpdyRstStreamStatus>(rst_stream_status_field);
}

SpdyGoAwayStatus ParseGoAwayStatus(int goaway_status_field) {
  if (goaway_status_field < GOAWAY_MIN || goaway_status_field > GOAWAY_MAX) {
    return GOAWAY_INTERNAL_ERROR;
  }

  return static_cast<SpdyGoAwayStatus>(goaway_status_field);
}

const char* const kHttp2Npn = "h2";

SpdyFrameWithHeaderBlockIR::SpdyFrameWithHeaderBlockIR(
    SpdyStreamId stream_id,
    SpdyHeaderBlock header_block)
    : SpdyFrameWithFinIR(stream_id), header_block_(std::move(header_block)) {}

SpdyFrameWithHeaderBlockIR::~SpdyFrameWithHeaderBlockIR() {}

SpdyDataIR::SpdyDataIR(SpdyStreamId stream_id, base::StringPiece data)
    : SpdyFrameWithFinIR(stream_id),
      data_(nullptr),
      data_len_(0),
      padded_(false),
      padding_payload_len_(0) {
  SetDataDeep(data);
}

SpdyDataIR::SpdyDataIR(SpdyStreamId stream_id, const char* data)
    : SpdyDataIR(stream_id, base::StringPiece(data)) {}

SpdyDataIR::SpdyDataIR(SpdyStreamId stream_id, std::string data)
    : SpdyFrameWithFinIR(stream_id),
      data_store_(base::MakeUnique<std::string>(std::move(data))),
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

SpdyRstStreamIR::SpdyRstStreamIR(SpdyStreamId stream_id,
                                 SpdyRstStreamStatus status)
    : SpdyFrameWithStreamIdIR(stream_id) {
  set_status(status);
}

SpdyRstStreamIR::~SpdyRstStreamIR() {}

void SpdyRstStreamIR::Visit(SpdyFrameVisitor* visitor) const {
  return visitor->VisitRstStream(*this);
}

SpdySettingsIR::SpdySettingsIR() : is_ack_(false) {}

SpdySettingsIR::~SpdySettingsIR() {}

void SpdySettingsIR::Visit(SpdyFrameVisitor* visitor) const {
  return visitor->VisitSettings(*this);
}

void SpdyPingIR::Visit(SpdyFrameVisitor* visitor) const {
  return visitor->VisitPing(*this);
}

SpdyGoAwayIR::SpdyGoAwayIR(SpdyStreamId last_good_stream_id,
                           SpdyGoAwayStatus status,
                           base::StringPiece description)
    : description_(description) {
      set_last_good_stream_id(last_good_stream_id);
  set_status(status);
}

SpdyGoAwayIR::SpdyGoAwayIR(SpdyStreamId last_good_stream_id,
                           SpdyGoAwayStatus status,
                           const char* description)
    : SpdyGoAwayIR(last_good_stream_id,
                   status,
                   base::StringPiece(description)) {}

SpdyGoAwayIR::SpdyGoAwayIR(SpdyStreamId last_good_stream_id,
                           SpdyGoAwayStatus status,
                           std::string description)
    : description_store_(std::move(description)),
      description_(description_store_) {
  set_last_good_stream_id(last_good_stream_id);
  set_status(status);
}

SpdyGoAwayIR::~SpdyGoAwayIR() {}

SpdyContinuationIR::SpdyContinuationIR(SpdyStreamId stream_id)
    : SpdyFrameWithStreamIdIR(stream_id), end_headers_(false) {
  encoding_ = base::MakeUnique<std::string>();
}

SpdyContinuationIR::~SpdyContinuationIR() {}

void SpdyGoAwayIR::Visit(SpdyFrameVisitor* visitor) const {
  return visitor->VisitGoAway(*this);
}

void SpdyHeadersIR::Visit(SpdyFrameVisitor* visitor) const {
  return visitor->VisitHeaders(*this);
}

void SpdyWindowUpdateIR::Visit(SpdyFrameVisitor* visitor) const {
  return visitor->VisitWindowUpdate(*this);
}

void SpdyBlockedIR::Visit(SpdyFrameVisitor* visitor) const {
  return visitor->VisitBlocked(*this);
}

void SpdyPushPromiseIR::Visit(SpdyFrameVisitor* visitor) const {
  return visitor->VisitPushPromise(*this);
}

void SpdyContinuationIR::Visit(SpdyFrameVisitor* visitor) const {
  return visitor->VisitContinuation(*this);
}

SpdyAltSvcIR::SpdyAltSvcIR(SpdyStreamId stream_id)
    : SpdyFrameWithStreamIdIR(stream_id) {
}

SpdyAltSvcIR::~SpdyAltSvcIR() {
}

void SpdyAltSvcIR::Visit(SpdyFrameVisitor* visitor) const {
  return visitor->VisitAltSvc(*this);
}

void SpdyPriorityIR::Visit(SpdyFrameVisitor* visitor) const {
  return visitor->VisitPriority(*this);
}

}  // namespace net
