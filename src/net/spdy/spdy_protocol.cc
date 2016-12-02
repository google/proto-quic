// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/spdy_protocol.h"

#include "base/memory/ptr_util.h"
#include "net/spdy/spdy_bug_tracker.h"

namespace net {

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

bool SpdyConstants::IsValidFrameType(int frame_type_field) {
  // Check for recognized extensions.
  if (frame_type_field == SerializeFrameType(ALTSVC) ||
      frame_type_field == SerializeFrameType(BLOCKED)) {
    return true;
  }

  // DATA is the first valid frame.
  if (frame_type_field < SerializeFrameType(DATA)) {
    return false;
  }

  // CONTINUATION is the last valid frame.
  if (frame_type_field > SerializeFrameType(CONTINUATION)) {
    return false;
  }

  return true;
}

SpdyFrameType SpdyConstants::ParseFrameType(int frame_type_field) {
  switch (frame_type_field) {
    case 0:
      return DATA;
    case 1:
      return HEADERS;
    case 2:
      return PRIORITY;
    case 3:
      return RST_STREAM;
    case 4:
      return SETTINGS;
    case 5:
      return PUSH_PROMISE;
    case 6:
      return PING;
    case 7:
      return GOAWAY;
    case 8:
      return WINDOW_UPDATE;
    case 9:
      return CONTINUATION;
    case 10:
      return ALTSVC;
    case 11:
      return BLOCKED;
  }
  SPDY_BUG << "Unhandled frame type " << frame_type_field;
  return DATA;
}

int SpdyConstants::SerializeFrameType(SpdyFrameType frame_type) {
  switch (frame_type) {
    case DATA:
      return kDataFrameType;
    case HEADERS:
      return 1;
    case PRIORITY:
      return 2;
    case RST_STREAM:
      return 3;
    case SETTINGS:
      return 4;
    case PUSH_PROMISE:
      return 5;
    case PING:
      return 6;
    case GOAWAY:
      return 7;
    case WINDOW_UPDATE:
      return 8;
    case CONTINUATION:
      return 9;
    // ALTSVC and BLOCKED are extensions.
    case ALTSVC:
      return 10;
    case BLOCKED:
      return 11;
    default:
      SPDY_BUG << "Serializing unhandled frame type " << frame_type;
      return -1;
  }
}

bool SpdyConstants::IsValidHTTP2FrameStreamId(
    SpdyStreamId current_frame_stream_id,
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

bool SpdyConstants::IsValidSettingId(int setting_id_field) {
  // HEADER_TABLE_SIZE is the first valid setting id.
  if (setting_id_field < SerializeSettingId(SETTINGS_HEADER_TABLE_SIZE)) {
    return false;
  }

  // MAX_HEADER_LIST_SIZE is the last valid setting id.
  if (setting_id_field > SerializeSettingId(SETTINGS_MAX_HEADER_LIST_SIZE)) {
    return false;
  }

  return true;
}

SpdySettingsIds SpdyConstants::ParseSettingId(int setting_id_field) {
  switch (setting_id_field) {
    case 1:
      return SETTINGS_HEADER_TABLE_SIZE;
    case 2:
      return SETTINGS_ENABLE_PUSH;
    case 3:
      return SETTINGS_MAX_CONCURRENT_STREAMS;
    case 4:
      return SETTINGS_INITIAL_WINDOW_SIZE;
    case 5:
      return SETTINGS_MAX_FRAME_SIZE;
    case 6:
      return SETTINGS_MAX_HEADER_LIST_SIZE;
  }
  SPDY_BUG << "Unhandled setting ID " << setting_id_field;
  return SETTINGS_UPLOAD_BANDWIDTH;
}

int SpdyConstants::SerializeSettingId(SpdySettingsIds id) {
  switch (id) {
    case SETTINGS_HEADER_TABLE_SIZE:
      return 1;
    case SETTINGS_ENABLE_PUSH:
      return 2;
    case SETTINGS_MAX_CONCURRENT_STREAMS:
      return 3;
    case SETTINGS_INITIAL_WINDOW_SIZE:
      return 4;
    case SETTINGS_MAX_FRAME_SIZE:
      return 5;
    case SETTINGS_MAX_HEADER_LIST_SIZE:
      return 6;
    default:
      SPDY_BUG << "Serializing unhandled setting id " << id;
      return -1;
  }
}

bool SpdyConstants::IsValidRstStreamStatus(int rst_stream_status_field) {
  // NO_ERROR is the first valid status code.
  if (rst_stream_status_field < SerializeRstStreamStatus(RST_STREAM_NO_ERROR)) {
    return false;
  }

  // TODO(hkhalil): Omit COMPRESSION_ERROR and SETTINGS_TIMEOUT
  /*
  // This works because GOAWAY and RST_STREAM share a namespace.
  if (rst_stream_status_field ==
  SerializeGoAwayStatus(version, GOAWAY_COMPRESSION_ERROR) ||
  rst_stream_status_field ==
  SerializeGoAwayStatus(version, GOAWAY_SETTINGS_TIMEOUT)) {
  return false;
  }
  */

  // HTTP_1_1_REQUIRED is the last valid status code.
  if (rst_stream_status_field >
      SerializeRstStreamStatus(RST_STREAM_HTTP_1_1_REQUIRED)) {
    return false;
  }

  return true;
}

SpdyRstStreamStatus SpdyConstants::ParseRstStreamStatus(
    int rst_stream_status_field) {
  switch (rst_stream_status_field) {
    case 0:
      return RST_STREAM_NO_ERROR;
    case 1:
      return RST_STREAM_PROTOCOL_ERROR;
    case 2:
      return RST_STREAM_INTERNAL_ERROR;
    case 3:
      return RST_STREAM_FLOW_CONTROL_ERROR;
    case 5:
      return RST_STREAM_STREAM_CLOSED;
    case 6:
      return RST_STREAM_FRAME_SIZE_ERROR;
    case 7:
      return RST_STREAM_REFUSED_STREAM;
    case 8:
      return RST_STREAM_CANCEL;
    case 10:
      return RST_STREAM_CONNECT_ERROR;
    case 11:
      return RST_STREAM_ENHANCE_YOUR_CALM;
    case 12:
      return RST_STREAM_INADEQUATE_SECURITY;
    case 13:
      return RST_STREAM_HTTP_1_1_REQUIRED;
  }

  SPDY_BUG << "Invalid RST_STREAM status " << rst_stream_status_field;
  return RST_STREAM_PROTOCOL_ERROR;
}

int SpdyConstants::SerializeRstStreamStatus(
    SpdyRstStreamStatus rst_stream_status) {
  switch (rst_stream_status) {
    case RST_STREAM_NO_ERROR:
      return 0;
    case RST_STREAM_PROTOCOL_ERROR:
      return 1;
    case RST_STREAM_INTERNAL_ERROR:
      return 2;
    case RST_STREAM_FLOW_CONTROL_ERROR:
      return 3;
    case RST_STREAM_STREAM_CLOSED:
      return 5;
    case RST_STREAM_FRAME_SIZE_ERROR:
      return 6;
    case RST_STREAM_REFUSED_STREAM:
      return 7;
    case RST_STREAM_CANCEL:
      return 8;
    case RST_STREAM_CONNECT_ERROR:
      return 10;
    case RST_STREAM_ENHANCE_YOUR_CALM:
      return 11;
    case RST_STREAM_INADEQUATE_SECURITY:
      return 12;
    case RST_STREAM_HTTP_1_1_REQUIRED:
      return 13;
    default:
      SPDY_BUG << "Unhandled RST_STREAM status " << rst_stream_status;
      return -1;
  }
}

bool SpdyConstants::IsValidGoAwayStatus(int goaway_status_field) {
  // GOAWAY_NO_ERROR is the first valid status.
  if (goaway_status_field < SerializeGoAwayStatus(GOAWAY_NO_ERROR)) {
    return false;
  }

  // GOAWAY_HTTP_1_1_REQUIRED is the last valid status.
  if (goaway_status_field > SerializeGoAwayStatus(GOAWAY_HTTP_1_1_REQUIRED)) {
    return false;
  }

  return true;
}

SpdyGoAwayStatus SpdyConstants::ParseGoAwayStatus(int goaway_status_field) {
  switch (goaway_status_field) {
    case 0:
      return GOAWAY_NO_ERROR;
    case 1:
      return GOAWAY_PROTOCOL_ERROR;
    case 2:
      return GOAWAY_INTERNAL_ERROR;
    case 3:
      return GOAWAY_FLOW_CONTROL_ERROR;
    case 4:
      return GOAWAY_SETTINGS_TIMEOUT;
    case 5:
      return GOAWAY_STREAM_CLOSED;
    case 6:
      return GOAWAY_FRAME_SIZE_ERROR;
    case 7:
      return GOAWAY_REFUSED_STREAM;
    case 8:
      return GOAWAY_CANCEL;
    case 9:
      return GOAWAY_COMPRESSION_ERROR;
    case 10:
      return GOAWAY_CONNECT_ERROR;
    case 11:
      return GOAWAY_ENHANCE_YOUR_CALM;
    case 12:
      return GOAWAY_INADEQUATE_SECURITY;
    case 13:
      return GOAWAY_HTTP_1_1_REQUIRED;
  }

  SPDY_BUG << "Unhandled GOAWAY status " << goaway_status_field;
  return GOAWAY_PROTOCOL_ERROR;
}

int SpdyConstants::SerializeGoAwayStatus(SpdyGoAwayStatus status) {
  switch (status) {
    case GOAWAY_NO_ERROR:
      return 0;
    case GOAWAY_PROTOCOL_ERROR:
      return 1;
    case GOAWAY_INTERNAL_ERROR:
      return 2;
    case GOAWAY_FLOW_CONTROL_ERROR:
      return 3;
    case GOAWAY_SETTINGS_TIMEOUT:
      return 4;
    case GOAWAY_STREAM_CLOSED:
      return 5;
    case GOAWAY_FRAME_SIZE_ERROR:
      return 6;
    case GOAWAY_REFUSED_STREAM:
      return 7;
    case GOAWAY_CANCEL:
      return 8;
    case GOAWAY_COMPRESSION_ERROR:
      return 9;
    case GOAWAY_CONNECT_ERROR:
      return 10;
    case GOAWAY_ENHANCE_YOUR_CALM:
      return 11;
    case GOAWAY_INADEQUATE_SECURITY:
      return 12;
    case GOAWAY_HTTP_1_1_REQUIRED:
      return 13;
    default:
      SPDY_BUG << "Serializing unhandled GOAWAY status " << status;
      return -1;
  }
}

const int SpdyConstants::kDataFrameType = 0;

const size_t SpdyConstants::kFrameHeaderSize = 9;

const size_t SpdyConstants::kDataFrameMinimumSize = kFrameHeaderSize;

const size_t SpdyConstants::kMaxFrameSizeLimit =
    kSpdyMaxFrameSizeLimit + kFrameHeaderSize;

const size_t SpdyConstants::kSizeOfSizeField = sizeof(uint32_t);

const size_t SpdyConstants::kPerHeaderOverhead = 32;

const int32_t SpdyConstants::kInitialStreamWindowSize = 64 * 1024 - 1;

const int32_t SpdyConstants::kInitialSessionWindowSize = 64 * 1024 - 1;

const char SpdyConstants::kHttp2Npn[] = "h2";

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

SpdySettingsIR::SpdySettingsIR()
    : clear_settings_(false),
      is_ack_(false) {}

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
