// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/http2_frame_decoder_adapter.h"

// Logging policy: If an error in the input is detected, VLOG(n) is used so that
// the option exists to debug the situation. Otherwise, this code mostly uses
// DVLOG so that the logging does not slow down production code when things are
// working OK.

#include <stddef.h>

#include <cstdint>
#include <cstring>
#include <string>
#include <utility>

#include "base/logging.h"
#include "base/optional.h"
#include "base/strings/string_piece.h"
#include "base/sys_byteorder.h"
#include "net/http2/decoder/decode_buffer.h"
#include "net/http2/decoder/decode_status.h"
#include "net/http2/decoder/http2_frame_decoder.h"
#include "net/http2/decoder/http2_frame_decoder_listener.h"
#include "net/http2/http2_constants.h"
#include "net/http2/http2_structures.h"
#include "net/spdy/hpack/hpack_decoder_interface.h"
#include "net/spdy/hpack/hpack_header_table.h"
#include "net/spdy/platform/api/spdy_estimate_memory_usage.h"
#include "net/spdy/spdy_alt_svc_wire_format.h"
#include "net/spdy/spdy_bug_tracker.h"
#include "net/spdy/spdy_frame_builder.h"
#include "net/spdy/spdy_header_block.h"
#include "net/spdy/spdy_headers_handler_interface.h"
#include "net/spdy/spdy_protocol.h"

using std::string;

namespace net {

namespace {

const bool kHasPriorityFields = true;
const bool kNotHasPriorityFields = false;

const Http2FrameType kFrameTypeBlocked = Http2FrameType(11);

bool IsPaddable(Http2FrameType type) {
  return type == Http2FrameType::DATA || type == Http2FrameType::HEADERS ||
         type == Http2FrameType::PUSH_PROMISE;
}

SpdyFrameType ToSpdyFrameType(Http2FrameType type) {
  return ParseFrameType(static_cast<uint8_t>(type));
}

uint64_t ToSpdyPingId(const Http2PingFields& ping) {
  uint64_t v;
  std::memcpy(&v, ping.opaque_data, Http2PingFields::EncodedSize());
  return base::NetToHost64(v);
}

// Overwrites the fields of the header with invalid values, for the purpose
// of identifying reading of unset fields. Only takes effect for debug builds.
// In Address Sanatizer builds, it also marks the fields as un-readable.
void CorruptFrameHeader(Http2FrameHeader* header) {
#ifndef NDEBUG
  // Beyond a valid payload length, which is 2^24 - 1.
  header->payload_length = 0x1010dead;
  // An unsupported frame type.
  header->type = Http2FrameType(0x80);
  DCHECK(!IsSupportedHttp2FrameType(header->type));
  // Frame flag bits that aren't used by any supported frame type.
  header->flags = Http2FrameFlag(0xd2);
  // A stream id with the reserved high-bit (R in the RFC) set.
  // 2129510127 when the high-bit is cleared.
  header->stream_id = 0xfeedbeef;
#endif
}

class Http2DecoderAdapter : public SpdyFramerDecoderAdapter,
                            public Http2FrameDecoderListener {
  typedef SpdyFramer::SpdyState SpdyState;
  typedef SpdyFramer::SpdyFramerError SpdyFramerError;

 public:
  explicit Http2DecoderAdapter(SpdyFramer* outer_framer)
      : SpdyFramerDecoderAdapter(), outer_framer_(outer_framer) {
    DVLOG(1) << "Http2DecoderAdapter ctor, outer_framer=" << outer_framer;
    ResetInternal();
  }
  ~Http2DecoderAdapter() override {}

  // ===========================================================================
  // Implementations of the pure virtual methods from SpdyFramerDecoderAdapter;
  // the other virtual methods of SpdyFramerDecoderAdapter have satsifactory
  // default implementations.

  // Passes the call on to the HPACK decoder.
  void SetDecoderHeaderTableDebugVisitor(
      std::unique_ptr<HpackHeaderTable::DebugVisitorInterface> visitor)
      override {
    GetHpackDecoder()->SetHeaderTableDebugVisitor(std::move(visitor));
  }

  size_t ProcessInput(const char* data, size_t len) override {
    size_t limit = outer_framer_->recv_frame_size_limit();
    frame_decoder_->set_maximum_payload_size(limit);

    size_t total_processed = 0;
    while (len > 0 && spdy_state_ != SpdyFramer::SPDY_ERROR) {
      // Process one at a time so that we update the adapter's internal
      // state appropriately.
      const size_t processed = ProcessInputFrame(data, len);

      // We had some data, and weren't in an error state, so should have
      // processed/consumed at least one byte of it, even if we then ended up
      // in an error state.
      DCHECK(processed > 0) << "processed=" << processed
                            << "   spdy_state_=" << spdy_state_
                            << "   spdy_framer_error_=" << spdy_framer_error_;

      data += processed;
      len -= processed;
      total_processed += processed;
      if (process_single_input_frame() || processed == 0) {
        break;
      }
    }
    return total_processed;
  }

  void Reset() override { ResetInternal(); }

  SpdyState state() const override { return spdy_state_; }

  SpdyFramerError spdy_framer_error() const override {
    return spdy_framer_error_;
  }

  bool probable_http_response() const override {
    return latched_probable_http_response_;
  }

  size_t EstimateMemoryUsage() const override {
    // Skip |frame_decoder_|, |frame_header_| and |hpack_first_frame_header_| as
    // they don't allocate.
    return SpdyEstimateMemoryUsage(alt_svc_origin_) +
           SpdyEstimateMemoryUsage(alt_svc_value_);
  }
  // ===========================================================================
  // Implementations of the methods declared by Http2FrameDecoderListener.

  // Called once the common frame header has been decoded for any frame.
  // This function is largely based on SpdyFramer::ValidateFrameHeader
  // and some parts of SpdyFramer::ProcessCommonHeader.
  bool OnFrameHeader(const Http2FrameHeader& header) override {
    DVLOG(1) << "OnFrameHeader: " << header;
    decoded_frame_header_ = true;
    if (!latched_probable_http_response_) {
      latched_probable_http_response_ = header.IsProbableHttpResponse();
    }
    const uint8_t raw_frame_type = static_cast<uint8_t>(header.type);
    visitor()->OnCommonHeader(header.stream_id, header.payload_length,
                              raw_frame_type, header.flags);
    if (!IsSupportedHttp2FrameType(header.type) &&
        header.type != kFrameTypeBlocked) {
      // In HTTP2 we ignore unknown frame types for extensibility, as long as
      // the rest of the control frame header is valid.
      // We rely on the visitor to check validity of stream_id.
      bool valid_stream =
          visitor()->OnUnknownFrame(header.stream_id, raw_frame_type);
      if (has_expected_frame_type_ && header.type != expected_frame_type_) {
        // Report an unexpected frame error and close the connection if we
        // expect a known frame type (probably CONTINUATION) and receive an
        // unknown frame.
        VLOG(1) << "The framer was expecting to receive a "
                << expected_frame_type_
                << " frame, but instead received an unknown frame of type "
                << header.type;
        SetSpdyErrorAndNotify(SpdyFramerError::SPDY_UNEXPECTED_FRAME);
        return false;
      } else if (!valid_stream) {
        // Report an invalid frame error if the stream_id is not valid.
        VLOG(1) << "Unknown control frame type " << header.type
                << " received on invalid stream " << header.stream_id;
        SetSpdyErrorAndNotify(SpdyFramerError::SPDY_INVALID_CONTROL_FRAME);
        return false;
      } else {
        DVLOG(1) << "Ignoring unknown frame type " << header.type;
        return true;
      }
    }

    SpdyFrameType frame_type = ToSpdyFrameType(header.type);
    if (!IsValidHTTP2FrameStreamId(header.stream_id, frame_type)) {
      VLOG(1) << "The framer received an invalid streamID of "
              << header.stream_id << " for a frame of type " << header.type;
      SetSpdyErrorAndNotify(SpdyFramerError::SPDY_INVALID_STREAM_ID);
      return false;
    }

    if (has_expected_frame_type_ && header.type != expected_frame_type_) {
      VLOG(1) << "Expected frame type " << expected_frame_type_ << ", not "
              << header.type;
      SetSpdyErrorAndNotify(SpdyFramerError::SPDY_UNEXPECTED_FRAME);
      return false;
    }

    if (!has_expected_frame_type_ &&
        header.type == Http2FrameType::CONTINUATION) {
      VLOG(1) << "Got CONTINUATION frame when not expected.";
      SetSpdyErrorAndNotify(SpdyFramerError::SPDY_UNEXPECTED_FRAME);
      return false;
    }

    if (header.type == Http2FrameType::DATA) {
      // For some reason SpdyFramer still rejects invalid DATA frame flags.
      uint8_t valid_flags =
          Http2FrameFlag::FLAG_PADDED | Http2FrameFlag::FLAG_END_STREAM;
      if (header.HasAnyFlags(~valid_flags)) {
        SetSpdyErrorAndNotify(SpdyFramerError::SPDY_INVALID_DATA_FRAME_FLAGS);
        return false;
      }
    }

    return true;
  }

  void OnDataStart(const Http2FrameHeader& header) override {
    DVLOG(1) << "OnDataStart: " << header;

    if (IsOkToStartFrame(header) && HasRequiredStreamId(header)) {
      frame_header_ = header;
      has_frame_header_ = true;
      visitor()->OnDataFrameHeader(header.stream_id, header.payload_length,
                                   header.IsEndStream());
    }
  }

  void OnDataPayload(const char* data, size_t len) override {
    DVLOG(1) << "OnDataPayload: len=" << len;
    DCHECK(has_frame_header_);
    DCHECK_EQ(frame_header_.type, Http2FrameType::DATA);
    visitor()->OnStreamFrameData(frame_header().stream_id, data, len);
  }

  void OnDataEnd() override {
    DVLOG(1) << "OnDataEnd";
    DCHECK(has_frame_header_);
    DCHECK_EQ(frame_header_.type, Http2FrameType::DATA);
    if (frame_header().IsEndStream()) {
      visitor()->OnStreamEnd(frame_header().stream_id);
    }
    opt_pad_length_.reset();
  }

  void OnHeadersStart(const Http2FrameHeader& header) override {
    DVLOG(1) << "OnHeadersStart: " << header;
    if (IsOkToStartFrame(header) && HasRequiredStreamId(header)) {
      frame_header_ = header;
      has_frame_header_ = true;
      if (header.HasPriority()) {
        // Once we've got the priority fields, then we can report the arrival
        // of this HEADERS frame.
        on_headers_called_ = false;
        return;
      }
      on_headers_called_ = true;
      ReportReceiveCompressedFrame(header);
      visitor()->OnHeaders(header.stream_id, kNotHasPriorityFields,
                           0,      // priority
                           0,      // parent_stream_id
                           false,  // exclusive
                           header.IsEndStream(), header.IsEndHeaders());
      CommonStartHpackBlock();
    }
  }

  void OnHeadersPriority(const Http2PriorityFields& priority) override {
    DVLOG(1) << "OnHeadersPriority: " << priority;
    DCHECK(has_frame_header_);
    DCHECK_EQ(frame_type(), Http2FrameType::HEADERS) << frame_header_;
    DCHECK(frame_header_.HasPriority());
    DCHECK(!on_headers_called_);
    on_headers_called_ = true;
    ReportReceiveCompressedFrame(frame_header_);
    visitor()->OnHeaders(frame_header_.stream_id, kHasPriorityFields,
                         priority.weight, priority.stream_dependency,
                         priority.is_exclusive, frame_header_.IsEndStream(),
                         frame_header_.IsEndHeaders());
    CommonStartHpackBlock();
  }

  void OnHpackFragment(const char* data, size_t len) override {
    DVLOG(1) << "OnHpackFragment: len=" << len;
    on_hpack_fragment_called_ = true;
    if (!GetHpackDecoder()->HandleControlFrameHeadersData(data, len)) {
      SetSpdyErrorAndNotify(SpdyFramerError::SPDY_DECOMPRESS_FAILURE);
      return;
    }
  }

  void OnHeadersEnd() override {
    DVLOG(1) << "OnHeadersEnd";
    CommonHpackFragmentEnd();
    opt_pad_length_.reset();
  }

  void OnPriorityFrame(const Http2FrameHeader& header,
                       const Http2PriorityFields& priority) override {
    DVLOG(1) << "OnPriorityFrame: " << header << "; priority: " << priority;
    if (IsOkToStartFrame(header) && HasRequiredStreamId(header)) {
      visitor()->OnPriority(header.stream_id, priority.stream_dependency,
                            priority.weight, priority.is_exclusive);
    }
  }

  void OnContinuationStart(const Http2FrameHeader& header) override {
    DVLOG(1) << "OnContinuationStart: " << header;
    if (IsOkToStartFrame(header) && HasRequiredStreamId(header)) {
      DCHECK(has_hpack_first_frame_header_);
      if (header.stream_id != hpack_first_frame_header_.stream_id) {
        SetSpdyErrorAndNotify(SpdyFramerError::SPDY_UNEXPECTED_FRAME);
        return;
      }
      frame_header_ = header;
      has_frame_header_ = true;
      ReportReceiveCompressedFrame(header);
      visitor()->OnContinuation(header.stream_id, header.IsEndHeaders());
    }
  }

  void OnContinuationEnd() override {
    DVLOG(1) << "OnContinuationEnd";
    CommonHpackFragmentEnd();
  }

  void OnPadLength(size_t trailing_length) override {
    DVLOG(1) << "OnPadLength: " << trailing_length;
    opt_pad_length_ = trailing_length;
    if (frame_header_.type == Http2FrameType::DATA) {
      visitor()->OnStreamPadding(stream_id(), 1);
    } else if (frame_header_.type == Http2FrameType::HEADERS) {
      CHECK_LT(trailing_length, 256u);
    }
  }

  void OnPadding(const char* padding, size_t skipped_length) override {
    DVLOG(1) << "OnPadding: " << skipped_length;
    if (frame_header_.type == Http2FrameType::DATA) {
      visitor()->OnStreamPadding(stream_id(), skipped_length);
    } else {
      MaybeAnnounceEmptyFirstHpackFragment();
    }
  }

  void OnRstStream(const Http2FrameHeader& header,
                   Http2ErrorCode http2_error_code) override {
    DVLOG(1) << "OnRstStream: " << header << "; code=" << http2_error_code;
    if (IsOkToStartFrame(header) && HasRequiredStreamId(header)) {
      SpdyErrorCode error_code =
          ParseErrorCode(static_cast<uint32_t>(http2_error_code));
      visitor()->OnRstStream(header.stream_id, error_code);
    }
  }

  void OnSettingsStart(const Http2FrameHeader& header) override {
    DVLOG(1) << "OnSettingsStart: " << header;
    if (IsOkToStartFrame(header) && HasRequiredStreamIdZero(header)) {
      frame_header_ = header;
      has_frame_header_ = true;
      visitor()->OnSettings(0);
    }
  }

  void OnSetting(const Http2SettingFields& setting_fields) override {
    DVLOG(1) << "OnSetting: " << setting_fields;
    SpdySettingsIds setting_id;
    if (!ParseSettingsId(static_cast<uint16_t>(setting_fields.parameter),
                         &setting_id)) {
      DVLOG(1) << "Ignoring invalid setting id: " << setting_fields;
      return;
    }
    visitor()->OnSetting(setting_id, setting_fields.value);
  }

  void OnSettingsEnd() override {
    DVLOG(1) << "OnSettingsEnd";
    visitor()->OnSettingsEnd();
  }

  void OnSettingsAck(const Http2FrameHeader& header) override {
    DVLOG(1) << "OnSettingsAck: " << header;
    if (IsOkToStartFrame(header) && HasRequiredStreamIdZero(header)) {
      visitor()->OnSettingsAck();
    }
  }

  void OnPushPromiseStart(const Http2FrameHeader& header,
                          const Http2PushPromiseFields& promise,
                          size_t total_padding_length) override {
    DVLOG(1) << "OnPushPromiseStart: " << header << "; promise: " << promise
             << "; total_padding_length: " << total_padding_length;
    if (IsOkToStartFrame(header) && HasRequiredStreamId(header)) {
      if (promise.promised_stream_id == 0) {
        SetSpdyErrorAndNotify(SpdyFramerError::SPDY_INVALID_CONTROL_FRAME);
        return;
      }
      frame_header_ = header;
      has_frame_header_ = true;
      ReportReceiveCompressedFrame(header);
      visitor()->OnPushPromise(header.stream_id, promise.promised_stream_id,
                               header.IsEndHeaders());
      CommonStartHpackBlock();
    }
  }

  void OnPushPromiseEnd() override {
    DVLOG(1) << "OnPushPromiseEnd";
    CommonHpackFragmentEnd();
    opt_pad_length_.reset();
  }

  void OnPing(const Http2FrameHeader& header,
              const Http2PingFields& ping) override {
    DVLOG(1) << "OnPing: " << header << "; ping: " << ping;
    if (IsOkToStartFrame(header) && HasRequiredStreamIdZero(header)) {
      visitor()->OnPing(ToSpdyPingId(ping), false);
    }
  }

  void OnPingAck(const Http2FrameHeader& header,
                 const Http2PingFields& ping) override {
    DVLOG(1) << "OnPingAck: " << header << "; ping: " << ping;
    if (IsOkToStartFrame(header) && HasRequiredStreamIdZero(header)) {
      visitor()->OnPing(ToSpdyPingId(ping), true);
    }
  }

  void OnGoAwayStart(const Http2FrameHeader& header,
                     const Http2GoAwayFields& goaway) override {
    DVLOG(1) << "OnGoAwayStart: " << header << "; goaway: " << goaway;
    if (IsOkToStartFrame(header) && HasRequiredStreamIdZero(header)) {
      frame_header_ = header;
      has_frame_header_ = true;
      SpdyErrorCode error_code =
          ParseErrorCode(static_cast<uint32_t>(goaway.error_code));
      visitor()->OnGoAway(goaway.last_stream_id, error_code);
    }
  }

  void OnGoAwayOpaqueData(const char* data, size_t len) override {
    DVLOG(1) << "OnGoAwayOpaqueData: len=" << len;
    visitor()->OnGoAwayFrameData(data, len);
  }

  void OnGoAwayEnd() override {
    DVLOG(1) << "OnGoAwayEnd";
    visitor()->OnGoAwayFrameData(nullptr, 0);
  }

  void OnWindowUpdate(const Http2FrameHeader& header,
                      uint32_t increment) override {
    DVLOG(1) << "OnWindowUpdate: " << header << "; increment=" << increment;
    if (IsOkToStartFrame(header)) {
      visitor()->OnWindowUpdate(header.stream_id, increment);
    }
  }

  // Per RFC7838, an ALTSVC frame on stream 0 with origin_length == 0, or one on
  // a stream other than stream 0 with origin_length != 0 MUST be ignored.  All
  // frames are decoded by Http2DecoderAdapter, and it is left to the consumer
  // (listener) to implement this behavior.
  void OnAltSvcStart(const Http2FrameHeader& header,
                     size_t origin_length,
                     size_t value_length) override {
    DVLOG(1) << "OnAltSvcStart: " << header
             << "; origin_length: " << origin_length
             << "; value_length: " << value_length;
    if (!IsOkToStartFrame(header)) {
      return;
    }
    frame_header_ = header;
    has_frame_header_ = true;
    alt_svc_origin_.clear();
    alt_svc_value_.clear();
  }

  void OnAltSvcOriginData(const char* data, size_t len) override {
    DVLOG(1) << "OnAltSvcOriginData: len=" << len;
    alt_svc_origin_.append(data, len);
  }

  // Called when decoding the Alt-Svc-Field-Value of an ALTSVC;
  // the field is uninterpreted.
  void OnAltSvcValueData(const char* data, size_t len) override {
    DVLOG(1) << "OnAltSvcValueData: len=" << len;
    alt_svc_value_.append(data, len);
  }

  void OnAltSvcEnd() override {
    DVLOG(1) << "OnAltSvcEnd: origin.size(): " << alt_svc_origin_.size()
             << "; value.size(): " << alt_svc_value_.size();
    SpdyAltSvcWireFormat::AlternativeServiceVector altsvc_vector;
    if (!SpdyAltSvcWireFormat::ParseHeaderFieldValue(alt_svc_value_,
                                                     &altsvc_vector)) {
      DLOG(ERROR) << "SpdyAltSvcWireFormat::ParseHeaderFieldValue failed.";
      SetSpdyErrorAndNotify(SpdyFramerError::SPDY_INVALID_CONTROL_FRAME);
      return;
    }
    visitor()->OnAltSvc(frame_header_.stream_id, alt_svc_origin_,
                        altsvc_vector);
    // We assume that ALTSVC frames are rare, so get rid of the storage.
    alt_svc_origin_.clear();
    alt_svc_origin_.shrink_to_fit();
    alt_svc_value_.clear();
    alt_svc_value_.shrink_to_fit();
  }

  // Except for BLOCKED frames, all other unknown frames are
  // effectively dropped.
  void OnUnknownStart(const Http2FrameHeader& header) override {
    DVLOG(1) << "OnUnknownStart: " << header;
    if (IsOkToStartFrame(header)) {
      if (header.type == kFrameTypeBlocked) {
        visitor()->OnBlocked(header.stream_id);
      }
    }
  }

  void OnUnknownPayload(const char* data, size_t len) override {
    DVLOG(1) << "OnUnknownPayload: len=" << len;
  }

  void OnUnknownEnd() override { DVLOG(1) << "OnUnknownEnd"; }

  void OnPaddingTooLong(const Http2FrameHeader& header,
                        size_t missing_length) override {
    DVLOG(1) << "OnPaddingTooLong: " << header
             << "; missing_length: " << missing_length;
    if (header.type == Http2FrameType::DATA) {
      if (header.payload_length == 0) {
        DCHECK_EQ(1u, missing_length);
        SetSpdyErrorAndNotify(SpdyFramerError::SPDY_INVALID_DATA_FRAME_FLAGS);
        return;
      }
      visitor()->OnStreamPadding(header.stream_id, 1);
    }
    SetSpdyErrorAndNotify(SpdyFramerError::SPDY_INVALID_PADDING);
  }

  void OnFrameSizeError(const Http2FrameHeader& header) override {
    DVLOG(1) << "OnFrameSizeError: " << header;
    size_t recv_limit = outer_framer_->recv_frame_size_limit();
    if (header.payload_length > recv_limit) {
      SetSpdyErrorAndNotify(SpdyFramerError::SPDY_OVERSIZED_PAYLOAD);
      return;
    }
    if (header.type != Http2FrameType::DATA &&
        header.payload_length > recv_limit) {
      SetSpdyErrorAndNotify(SpdyFramerError::SPDY_CONTROL_PAYLOAD_TOO_LARGE);
      return;
    }
    switch (header.type) {
      case Http2FrameType::GOAWAY:
      case Http2FrameType::ALTSVC:
        SetSpdyErrorAndNotify(SpdyFramerError::SPDY_INVALID_CONTROL_FRAME);
        break;
      default:
        SetSpdyErrorAndNotify(SpdyFramerError::SPDY_INVALID_CONTROL_FRAME_SIZE);
    }
  }

 private:
  // Decodes the input up to the next frame boundary (i.e. at most one frame),
  // stopping early if an error is detected.
  size_t ProcessInputFrame(const char* data, size_t len) {
    DCHECK_NE(spdy_state_, SpdyState::SPDY_ERROR);
    DecodeBuffer db(data, len);
    DecodeStatus status = frame_decoder_->DecodeFrame(&db);
    if (spdy_state_ != SpdyFramer::SPDY_ERROR) {
      DetermineSpdyState(status);
    } else {
      VLOG(1) << "ProcessInputFrame spdy_framer_error_="
              << SpdyFramer::SpdyFramerErrorToString(spdy_framer_error_);
      if (spdy_framer_error_ == SpdyFramerError::SPDY_INVALID_PADDING &&
          has_frame_header_ && frame_type() != Http2FrameType::DATA) {
        // spdy_framer_test checks that all of the available frame payload
        // has been consumed, so do that.
        size_t total = remaining_total_payload();
        if (total <= frame_header().payload_length) {
          size_t avail = db.MinLengthRemaining(total);
          VLOG(1) << "Skipping past " << avail << " bytes, of " << total
                  << " total remaining in the frame's payload.";
          db.AdvanceCursor(avail);
        } else {
          SPDY_BUG << "Total remaining (" << total
                   << ") should not be greater than the payload length; "
                   << frame_header();
        }
      }
    }
    return db.Offset();
  }

  // After decoding, determine the next SpdyState. Only called if the current
  // state is NOT SpdyState::SPDY_ERROR (i.e. if none of the callback methods
  // detected an error condition), because otherwise we assume that the callback
  // method has set spdy_framer_error_ appropriately.
  void DetermineSpdyState(DecodeStatus status) {
    DCHECK_EQ(spdy_framer_error_, SpdyFramer::SPDY_NO_ERROR);
    DCHECK(!HasError()) << spdy_framer_error_;
    switch (status) {
      case DecodeStatus::kDecodeDone:
        DVLOG(1) << "ProcessInputFrame -> DecodeStatus::kDecodeDone";
        ResetBetweenFrames();
        break;
      case DecodeStatus::kDecodeInProgress:
        DVLOG(1) << "ProcessInputFrame -> DecodeStatus::kDecodeInProgress";
        if (decoded_frame_header_) {
          if (IsDiscardingPayload()) {
            set_spdy_state(SpdyState::SPDY_IGNORE_REMAINING_PAYLOAD);
          } else if (has_frame_header_ &&
                     frame_type() == Http2FrameType::DATA) {
            if (IsReadingPaddingLength()) {
              set_spdy_state(SpdyState::SPDY_READ_DATA_FRAME_PADDING_LENGTH);
            } else if (IsSkippingPadding()) {
              set_spdy_state(SpdyState::SPDY_CONSUME_PADDING);
            } else {
              set_spdy_state(SpdyState::SPDY_FORWARD_STREAM_FRAME);
            }
          } else {
            set_spdy_state(SpdyState::SPDY_CONTROL_FRAME_PAYLOAD);
          }
        } else {
          set_spdy_state(SpdyState::SPDY_READING_COMMON_HEADER);
        }
        break;
      case DecodeStatus::kDecodeError:
        VLOG(1) << "ProcessInputFrame -> DecodeStatus::kDecodeError";
        if (IsDiscardingPayload()) {
          if (remaining_total_payload() == 0) {
            // Push the Http2FrameDecoder out of state kDiscardPayload now
            // since doing so requires no input.
            DecodeBuffer tmp("", 0);
            DecodeStatus status = frame_decoder_->DecodeFrame(&tmp);
            if (status != DecodeStatus::kDecodeDone) {
              SPDY_BUG << "Expected to be done decoding the frame, not "
                       << status;
              SetSpdyErrorAndNotify(SpdyFramer::SPDY_INTERNAL_FRAMER_ERROR);
            } else if (spdy_framer_error_ != SpdyFramer::SPDY_NO_ERROR) {
              SPDY_BUG << "Expected to have no error, not "
                       << SpdyFramer::SpdyFramerErrorToString(
                              spdy_framer_error_);
            } else {
              ResetBetweenFrames();
            }
          } else {
            set_spdy_state(SpdyState::SPDY_IGNORE_REMAINING_PAYLOAD);
          }
        } else {
          SetSpdyErrorAndNotify(SpdyFramer::SPDY_INVALID_CONTROL_FRAME);
        }
        break;
    }
  }

  void ResetBetweenFrames() {
    CorruptFrameHeader(&frame_header_);
    decoded_frame_header_ = false;
    has_frame_header_ = false;
    set_spdy_state(SpdyState::SPDY_READY_FOR_FRAME);
  }

  // ResetInternal is called from the constructor, and during tests, but not
  // otherwise (i.e. not between every frame).
  void ResetInternal() {
    set_spdy_state(SpdyState::SPDY_READY_FOR_FRAME);
    spdy_framer_error_ = SpdyFramerError::SPDY_NO_ERROR;

    decoded_frame_header_ = false;
    has_frame_header_ = false;
    on_headers_called_ = false;
    on_hpack_fragment_called_ = false;
    latched_probable_http_response_ = false;
    has_expected_frame_type_ = false;

    CorruptFrameHeader(&frame_header_);
    CorruptFrameHeader(&hpack_first_frame_header_);

    frame_decoder_.reset(new Http2FrameDecoder(this));
  }

  void set_spdy_state(SpdyState v) {
    DVLOG(2) << "set_spdy_state(" << SpdyFramer::StateToString(v) << ")";
    spdy_state_ = v;
  }

  void SetSpdyErrorAndNotify(SpdyFramerError error) {
    if (HasError()) {
      DCHECK_EQ(spdy_state_, SpdyState::SPDY_ERROR);
    } else {
      VLOG(2) << "SetSpdyErrorAndNotify("
              << SpdyFramer::SpdyFramerErrorToString(error) << ")";
      DCHECK_NE(error, SpdyFramerError::SPDY_NO_ERROR);
      spdy_framer_error_ = error;
      set_spdy_state(SpdyState::SPDY_ERROR);
      frame_decoder_->set_listener(&no_op_listener_);
      visitor()->OnError(outer_framer_);
    }
  }

  bool HasError() const {
    if (spdy_state_ == SpdyState::SPDY_ERROR) {
      DCHECK_NE(spdy_framer_error(), SpdyFramerError::SPDY_NO_ERROR);
      return true;
    } else {
      DCHECK_EQ(spdy_framer_error(), SpdyFramerError::SPDY_NO_ERROR);
      return false;
    }
  }

  const Http2FrameHeader& frame_header() const {
    DCHECK(has_frame_header_);
    return frame_header_;
  }

  uint32_t stream_id() const { return frame_header().stream_id; }

  Http2FrameType frame_type() const { return frame_header().type; }

  size_t remaining_total_payload() const {
    DCHECK(has_frame_header_);
    size_t remaining = frame_decoder_->remaining_payload();
    if (IsPaddable(frame_type()) && frame_header_.IsPadded()) {
      remaining += frame_decoder_->remaining_padding();
    }
    return remaining;
  }

  bool IsReadingPaddingLength() {
    bool result = frame_header_.IsPadded() && !opt_pad_length_;
    DVLOG(2) << "Http2DecoderAdapter::IsReadingPaddingLength: " << result;
    return result;
  }
  bool IsSkippingPadding() {
    bool result = frame_header_.IsPadded() && opt_pad_length_ &&
                  frame_decoder_->remaining_payload() == 0 &&
                  frame_decoder_->remaining_padding() > 0;
    DVLOG(2) << "Http2DecoderAdapter::IsSkippingPadding: " << result;
    return result;
  }
  bool IsDiscardingPayload() {
    bool result =
        decoded_frame_header_ && frame_decoder_->IsDiscardingPayload();
    DVLOG(2) << "Http2DecoderAdapter::IsDiscardingPayload: " << result;
    return result;
  }
  // Called from OnXyz or OnXyzStart methods to decide whether it is OK to
  // handle the callback.
  bool IsOkToStartFrame(const Http2FrameHeader& header) {
    DVLOG(3) << "IsOkToStartFrame";
    if (HasError()) {
      VLOG(2) << "HasError()";
      return false;
    }
    DCHECK(!has_frame_header_);
    if (has_expected_frame_type_ && header.type != expected_frame_type_) {
      VLOG(1) << "Expected frame type " << expected_frame_type_ << ", not "
              << header.type;
      SetSpdyErrorAndNotify(SpdyFramerError::SPDY_UNEXPECTED_FRAME);
      return false;
    }

    return true;
  }

  bool HasRequiredStreamId(uint32_t stream_id) {
    DVLOG(3) << "HasRequiredStreamId: " << stream_id;
    if (HasError()) {
      VLOG(2) << "HasError()";
      return false;
    }
    if (stream_id != 0) {
      return true;
    }
    VLOG(1) << "Stream Id is required, but zero provided";
    SetSpdyErrorAndNotify(SpdyFramerError::SPDY_INVALID_STREAM_ID);
    return false;
  }

  bool HasRequiredStreamId(const Http2FrameHeader& header) {
    return HasRequiredStreamId(header.stream_id);
  }

  bool HasRequiredStreamIdZero(uint32_t stream_id) {
    DVLOG(3) << "HasRequiredStreamIdZero: " << stream_id;
    if (HasError()) {
      VLOG(2) << "HasError()";
      return false;
    }
    if (stream_id == 0) {
      return true;
    }
    VLOG(1) << "Stream Id was not zero, as required: " << stream_id;
    SetSpdyErrorAndNotify(SpdyFramerError::SPDY_INVALID_STREAM_ID);
    return false;
  }

  bool HasRequiredStreamIdZero(const Http2FrameHeader& header) {
    return HasRequiredStreamIdZero(header.stream_id);
  }

  void ReportReceiveCompressedFrame(const Http2FrameHeader& header) {
    if (debug_visitor() != nullptr) {
      size_t total = header.payload_length + Http2FrameHeader::EncodedSize();
      debug_visitor()->OnReceiveCompressedFrame(
          header.stream_id, ToSpdyFrameType(header.type), total);
    }
  }

  HpackDecoderInterface* GetHpackDecoder() {
    if (hpack_decoder_ == nullptr) {
      hpack_decoder_ = outer_framer_->GetHpackDecoderForAdapter();
    }
    return hpack_decoder_;
  }

  void CommonStartHpackBlock() {
    DVLOG(1) << "CommonStartHpackBlock";
    DCHECK(!has_hpack_first_frame_header_);
    if (!frame_header_.IsEndHeaders()) {
      hpack_first_frame_header_ = frame_header_;
      has_hpack_first_frame_header_ = true;
    } else {
      CorruptFrameHeader(&hpack_first_frame_header_);
    }
    on_hpack_fragment_called_ = false;
    SpdyHeadersHandlerInterface* handler =
        visitor()->OnHeaderFrameStart(stream_id());
    if (handler == nullptr) {
      SPDY_BUG << "visitor_->OnHeaderFrameStart returned nullptr";
      SetSpdyErrorAndNotify(SpdyFramerError::SPDY_INTERNAL_FRAMER_ERROR);
      return;
    }
    GetHpackDecoder()->HandleControlFrameHeadersStart(handler);
  }

  // SpdyFramer calls HandleControlFrameHeadersData even if there are zero
  // fragment bytes in the first frame, so do the same.
  void MaybeAnnounceEmptyFirstHpackFragment() {
    if (!on_hpack_fragment_called_) {
      OnHpackFragment(nullptr, 0);
      DCHECK(on_hpack_fragment_called_);
    }
  }

  void CommonHpackFragmentEnd() {
    DVLOG(1) << "CommonHpackFragmentEnd: stream_id=" << stream_id();
    if (HasError()) {
      VLOG(1) << "HasError(), returning";
      return;
    }
    DCHECK(has_frame_header_);
    MaybeAnnounceEmptyFirstHpackFragment();
    if (frame_header_.IsEndHeaders()) {
      DCHECK_EQ(has_hpack_first_frame_header_,
                frame_type() == Http2FrameType::CONTINUATION)
          << frame_header();
      has_expected_frame_type_ = false;
      if (GetHpackDecoder()->HandleControlFrameHeadersComplete(nullptr)) {
        visitor()->OnHeaderFrameEnd(stream_id(), true);
      } else {
        SetSpdyErrorAndNotify(SpdyFramerError::SPDY_DECOMPRESS_FAILURE);
        return;
      }
      const Http2FrameHeader& first =
          frame_type() == Http2FrameType::CONTINUATION
              ? hpack_first_frame_header_
              : frame_header_;
      if (first.type == Http2FrameType::HEADERS && first.IsEndStream()) {
        visitor()->OnStreamEnd(first.stream_id);
      }
      hpack_decoder_ = nullptr;
      has_hpack_first_frame_header_ = false;
      CorruptFrameHeader(&hpack_first_frame_header_);
    } else {
      DCHECK(has_hpack_first_frame_header_);
      has_expected_frame_type_ = true;
      expected_frame_type_ = Http2FrameType::CONTINUATION;
    }
  }

  // The SpdyFramer that created this Http2FrameDecoderAdapter.
  SpdyFramer* const outer_framer_;

  // The HPACK decoder that we're using for the HPACK block that is currently
  // being decoded. Cleared at the end of the block. Owned by the SpdyFramer.
  HpackDecoderInterface* hpack_decoder_ = nullptr;

  // The HTTP/2 frame decoder. Accessed via a unique_ptr to allow replacement
  // (e.g. in tests) when Reset() is called.
  std::unique_ptr<Http2FrameDecoder> frame_decoder_;

  // The most recently decoded frame header; invalid after we reached the end
  // of that frame.
  Http2FrameHeader frame_header_;

  // If decoding an HPACK block that is split across multiple frames, this holds
  // the frame header of the HEADERS or PUSH_PROMISE that started the block.
  Http2FrameHeader hpack_first_frame_header_;

  // Amount of trailing padding. Currently used just as an indicator of whether
  // OnPadLength has been called.
  base::Optional<size_t> opt_pad_length_;

  // Temporary buffers for the AltSvc fields.
  string alt_svc_origin_;
  string alt_svc_value_;

  // Listener used if we transition to an error state; the listener ignores all
  // the callbacks.
  Http2FrameDecoderNoOpListener no_op_listener_;

  // Next frame type expected. Currently only used for CONTINUATION frames,
  // but could be used for detecting whether the first frame is a SETTINGS
  // frame.
  // TODO(jamessyng): Provide means to indicate that decoder should require
  // SETTINGS frame as the first frame.
  Http2FrameType expected_frame_type_;

  // Attempt to duplicate the SpdyState and SpdyFramerError values that
  // SpdyFramer sets. Values determined by getting tests to pass.
  SpdyState spdy_state_;
  SpdyFramerError spdy_framer_error_;

  // Has OnFrameHeader been called?
  bool decoded_frame_header_ = false;

  // Have we recorded an Http2FrameHeader for the current frame?
  // We only do so if the decoder will make multiple callbacks for
  // the frame; for example, for PING frames we don't make record
  // the frame header, but for ALTSVC we do.
  bool has_frame_header_ = false;

  // Have we recorded an Http2FrameHeader for the current HPACK block?
  // True only for multi-frame HPACK blocks.
  bool has_hpack_first_frame_header_ = false;

  // Has OnHeaders() already been called for current HEADERS block? Only
  // meaningful between OnHeadersStart and OnHeadersPriority.
  bool on_headers_called_;

  // Has OnHpackFragment() already been called for current HPACK block?
  // SpdyFramer will pass an empty buffer to the HPACK decoder if a HEADERS
  // or PUSH_PROMISE has no HPACK data in it (e.g. a HEADERS frame with only
  // padding). Detect that condition and replicate the behavior using this
  // field.
  bool on_hpack_fragment_called_;

  // Have we seen a frame header that appears to be an HTTP/1 response?
  bool latched_probable_http_response_ = false;

  // Is expected_frame_type_ set?
  bool has_expected_frame_type_ = false;
};

}  // namespace

std::unique_ptr<SpdyFramerDecoderAdapter> CreateHttp2FrameDecoderAdapter(
    SpdyFramer* outer_framer) {
  return std::unique_ptr<SpdyFramerDecoderAdapter>(
      new Http2DecoderAdapter(outer_framer));
}

}  // namespace net
