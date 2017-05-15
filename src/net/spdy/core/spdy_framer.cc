// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/core/spdy_framer.h"

#include <string.h>

#include <algorithm>
#include <cctype>
#include <ios>
#include <iterator>
#include <list>
#include <new>
#include <vector>

#include "base/lazy_instance.h"
#include "base/logging.h"
#include "base/metrics/histogram_macros.h"
#include "base/strings/string_util.h"
#include "net/quic/platform/api/quic_flags.h"
#include "net/spdy/chromium/spdy_flags.h"
#include "net/spdy/core/hpack/hpack_constants.h"
#include "net/spdy/core/hpack/hpack_decoder.h"
#include "net/spdy/core/hpack/hpack_decoder3.h"
#include "net/spdy/core/http2_frame_decoder_adapter.h"
#include "net/spdy/core/spdy_bitmasks.h"
#include "net/spdy/core/spdy_bug_tracker.h"
#include "net/spdy/core/spdy_frame_builder.h"
#include "net/spdy/core/spdy_frame_reader.h"
#include "net/spdy/core/spdy_framer_decoder_adapter.h"
#include "net/spdy/platform/api/spdy_estimate_memory_usage.h"
#include "net/spdy/platform/api/spdy_ptr_util.h"
#include "net/spdy/platform/api/spdy_string_utils.h"

using std::vector;

namespace net {

namespace {

// Pack parent stream ID and exclusive flag into the format used by HTTP/2
// headers and priority frames.
uint32_t PackStreamDependencyValues(bool exclusive,
                                    SpdyStreamId parent_stream_id) {
  // Make sure the highest-order bit in the parent stream id is zeroed out.
  uint32_t parent = parent_stream_id & 0x7fffffff;
  // Set the one-bit exclusivity flag.
  uint32_t e_bit = exclusive ? 0x80000000 : 0;
  return parent | e_bit;
}

// Unpack parent stream ID and exclusive flag from the format used by HTTP/2
// headers and priority frames.
void UnpackStreamDependencyValues(uint32_t packed,
                                  bool* exclusive,
                                  SpdyStreamId* parent_stream_id) {
  *exclusive = (packed >> 31) != 0;
  // Zero out the highest-order bit to get the parent stream id.
  *parent_stream_id = packed & 0x7fffffff;
}

// Creates a SpdyFramerDecoderAdapter if flags indicate that one should be
// used. This code is isolated to hopefully make merging into Chromium easier.
std::unique_ptr<SpdyFramerDecoderAdapter> DecoderAdapterFactory(
    SpdyFramer* outer) {
  if (FLAGS_chromium_http2_flag_spdy_use_http2_frame_decoder_adapter) {
    DVLOG(1) << "Creating Http2FrameDecoderAdapter.";
    return CreateHttp2FrameDecoderAdapter(outer);
  }

  return nullptr;
}

// Used to indicate no flags in a HTTP2 flags field.
const uint8_t kNoFlags = 0;

// Wire sizes of priority payloads.
const size_t kPriorityDependencyPayloadSize = 4;
const size_t kPriorityWeightPayloadSize = 1;

// Wire size of pad length field.
const size_t kPadLengthFieldSize = 1;

}  // namespace

const SpdyStreamId SpdyFramer::kInvalidStream = static_cast<SpdyStreamId>(-1);
const size_t SpdyFramer::kHeaderDataChunkMaxSize = 1024;
// Even though the length field is 24 bits, we keep this 16 kB
// limit on control frame size for legacy reasons and to
// mitigate DOS attacks.
const size_t SpdyFramer::kMaxControlFrameSize = (1 << 14) - 1;
const size_t SpdyFramer::kMaxDataPayloadSendSize = 1 << 14;
// The size of the control frame buffer. Must be >= the minimum size of the
// largest control frame.
const size_t SpdyFramer::kControlFrameBufferSize = 19;
const size_t SpdyFramer::kOneSettingParameterSize = 6;

#ifdef DEBUG_SPDY_STATE_CHANGES
#define CHANGE_STATE(newstate)                                  \
  do {                                                          \
    DVLOG(1) << "Changing state from: "                         \
             << StateToString(state_)                           \
             << " to " << StateToString(newstate) << "\n";      \
    DCHECK(state_ != SPDY_ERROR);                               \
    DCHECK_EQ(previous_state_, state_);                         \
    previous_state_ = state_;                                   \
    state_ = newstate;                                          \
  } while (false)
#else
#define CHANGE_STATE(newstate)                                  \
  do {                                                          \
    DCHECK(state_ != SPDY_ERROR);                               \
    DCHECK_EQ(previous_state_, state_);                         \
    previous_state_ = state_;                                   \
    state_ = newstate;                                          \
  } while (false)
#endif

bool SpdyFramerVisitorInterface::OnGoAwayFrameData(const char* goaway_data,
                                                   size_t len) {
  return true;
}

SpdyFramer::SpdyFramer(SpdyFramer::DecoderAdapterFactoryFn adapter_factory,
                       CompressionOption option)
    : current_frame_buffer_(kControlFrameBufferSize),
      expect_continuation_(0),
      visitor_(nullptr),
      extension_(nullptr),
      debug_visitor_(nullptr),
      header_handler_(nullptr),
      compression_option_(option),
      probable_http_response_(false),
      end_stream_when_done_(false) {
  static_assert(
      kMaxControlFrameSize <= kSpdyInitialFrameSizeLimit + kFrameHeaderSize,
      "Our send limit should be at most our receive limit");
  Reset();

  if (adapter_factory != nullptr) {
    decoder_adapter_ = adapter_factory(this);
  }
}

SpdyFramer::SpdyFramer(CompressionOption option)
    : SpdyFramer(&DecoderAdapterFactory, option) {}

SpdyFramer::~SpdyFramer() {}

void SpdyFramer::Reset() {
  if (decoder_adapter_ != nullptr) {
    decoder_adapter_->Reset();
  }
  state_ = SPDY_READY_FOR_FRAME;
  previous_state_ = SPDY_READY_FOR_FRAME;
  spdy_framer_error_ = SPDY_NO_ERROR;
  remaining_data_length_ = 0;
  remaining_control_header_ = 0;
  current_frame_buffer_.Rewind();
  current_frame_type_ = SpdyFrameType::DATA;
  current_frame_flags_ = 0;
  current_frame_length_ = 0;
  current_frame_stream_id_ = kInvalidStream;
  settings_scratch_.Reset();
  altsvc_scratch_.reset();
  remaining_padding_payload_length_ = 0;
}

void SpdyFramer::set_visitor(SpdyFramerVisitorInterface* visitor) {
  if (decoder_adapter_ != nullptr) {
    decoder_adapter_->set_visitor(visitor);
  }
  visitor_ = visitor;
}

void SpdyFramer::set_extension_visitor(ExtensionVisitorInterface* extension) {
  if (decoder_adapter_ != nullptr) {
    decoder_adapter_->set_extension_visitor(extension);
  }
  extension_ = extension;
}

void SpdyFramer::set_debug_visitor(
    SpdyFramerDebugVisitorInterface* debug_visitor) {
  if (decoder_adapter_ != nullptr) {
    decoder_adapter_->set_debug_visitor(debug_visitor);
  }
  debug_visitor_ = debug_visitor;
}

void SpdyFramer::set_process_single_input_frame(bool v) {
  if (decoder_adapter_ != nullptr) {
    decoder_adapter_->set_process_single_input_frame(v);
  }
  process_single_input_frame_ = v;
}

bool SpdyFramer::probable_http_response() const {
  if (decoder_adapter_) {
    return decoder_adapter_->probable_http_response();
  }
  return probable_http_response_;
}

SpdyFramer::SpdyFramerError SpdyFramer::spdy_framer_error() const {
  if (decoder_adapter_ != nullptr) {
    return decoder_adapter_->spdy_framer_error();
  }
  return spdy_framer_error_;
}

SpdyFramer::SpdyState SpdyFramer::state() const {
  if (decoder_adapter_ != nullptr) {
    return decoder_adapter_->state();
  }
  return state_;
}

size_t SpdyFramer::GetDataFrameMinimumSize() const {
  return kDataFrameMinimumSize;
}

// Size, in bytes, of the control frame header.
size_t SpdyFramer::GetFrameHeaderSize() const {
  return kFrameHeaderSize;
}

size_t SpdyFramer::GetRstStreamSize() const {
  // Size, in bytes, of a RST_STREAM frame.
  // Calculated as:
  // frame prefix + 4 (status code)
  return GetFrameHeaderSize() + 4;
}

size_t SpdyFramer::GetSettingsMinimumSize() const {
  // Size, in bytes, of a SETTINGS frame not including the IDs and values
  // from the variable-length value block.
  return GetFrameHeaderSize();
}

size_t SpdyFramer::GetPingSize() const {
  // Size, in bytes, of this PING frame.
  // Calculated as:
  // control frame header + 8 (id)
  return GetFrameHeaderSize() + 8;
}

size_t SpdyFramer::GetGoAwayMinimumSize() const {
  // Size, in bytes, of this GOAWAY frame. Calculated as:
  // Control frame header + last stream id (4 bytes) + error code (4 bytes).
  return GetFrameHeaderSize() + 8;
}

size_t SpdyFramer::GetHeadersMinimumSize() const {
  // Size, in bytes, of a HEADERS frame not including the variable-length
  // header block.
  return GetFrameHeaderSize();
}

size_t SpdyFramer::GetWindowUpdateSize() const {
  // Size, in bytes, of a WINDOW_UPDATE frame.
  // Calculated as:
  // frame prefix + 4 (delta)
  return GetFrameHeaderSize() + 4;
}

size_t SpdyFramer::GetPushPromiseMinimumSize() const {
  // Size, in bytes, of a PUSH_PROMISE frame, sans the embedded header block.
  // Calculated as frame prefix + 4 (promised stream id)
  return GetFrameHeaderSize() + 4;
}

size_t SpdyFramer::GetContinuationMinimumSize() const {
  // Size, in bytes, of a CONTINUATION frame not including the variable-length
  // headers fragments.
  return GetFrameHeaderSize();
}

size_t SpdyFramer::GetAltSvcMinimumSize() const {
  // Size, in bytes, of an ALTSVC frame not including the Field-Value and
  // (optional) Origin fields, both of which can vary in length.  Note that
  // this gives a lower bound on the frame size rather than a true minimum;
  // the actual frame should always be larger than this.
  // Calculated as frame prefix + 2 (origin_len).
  return GetFrameHeaderSize() + 2;
}

size_t SpdyFramer::GetPrioritySize() const {
  // Size, in bytes, of a PRIORITY frame.
  return GetFrameHeaderSize() + kPriorityDependencyPayloadSize +
         kPriorityWeightPayloadSize;
}

size_t SpdyFramer::GetFrameMinimumSize() const {
  return GetFrameHeaderSize();
}

size_t SpdyFramer::GetFrameMaximumSize() const {
  return send_frame_size_limit_ + kFrameHeaderSize;
}

size_t SpdyFramer::GetDataFrameMaximumPayload() const {
  return std::min(kMaxDataPayloadSendSize,
                  GetFrameMaximumSize() - GetDataFrameMinimumSize());
}

const char* SpdyFramer::StateToString(int state) {
  switch (state) {
    case SPDY_ERROR:
      return "ERROR";
    case SPDY_FRAME_COMPLETE:
      return "FRAME_COMPLETE";
    case SPDY_READY_FOR_FRAME:
      return "READY_FOR_FRAME";
    case SPDY_READING_COMMON_HEADER:
      return "READING_COMMON_HEADER";
    case SPDY_CONTROL_FRAME_PAYLOAD:
      return "CONTROL_FRAME_PAYLOAD";
    case SPDY_READ_DATA_FRAME_PADDING_LENGTH:
      return "SPDY_READ_DATA_FRAME_PADDING_LENGTH";
    case SPDY_CONSUME_PADDING:
      return "SPDY_CONSUME_PADDING";
    case SPDY_IGNORE_REMAINING_PAYLOAD:
      return "IGNORE_REMAINING_PAYLOAD";
    case SPDY_FORWARD_STREAM_FRAME:
      return "FORWARD_STREAM_FRAME";
    case SPDY_CONTROL_FRAME_BEFORE_HEADER_BLOCK:
      return "SPDY_CONTROL_FRAME_BEFORE_HEADER_BLOCK";
    case SPDY_CONTROL_FRAME_HEADER_BLOCK:
      return "SPDY_CONTROL_FRAME_HEADER_BLOCK";
    case SPDY_GOAWAY_FRAME_PAYLOAD:
      return "SPDY_GOAWAY_FRAME_PAYLOAD";
    case SPDY_SETTINGS_FRAME_HEADER:
      return "SPDY_SETTINGS_FRAME_HEADER";
    case SPDY_SETTINGS_FRAME_PAYLOAD:
      return "SPDY_SETTINGS_FRAME_PAYLOAD";
    case SPDY_ALTSVC_FRAME_PAYLOAD:
      return "SPDY_ALTSVC_FRAME_PAYLOAD";
  }
  return "UNKNOWN_STATE";
}

void SpdyFramer::set_error(SpdyFramerError error) {
  DCHECK(visitor_);
  spdy_framer_error_ = error;
  // These values will usually get reset once we come to the end
  // of a header block, but if we run into an error that
  // might not happen, so reset them here.
  expect_continuation_ = 0;
  end_stream_when_done_ = false;

  CHANGE_STATE(SPDY_ERROR);
  visitor_->OnError(this);
}

const char* SpdyFramer::SpdyFramerErrorToString(
    SpdyFramerError spdy_framer_error) {
  switch (spdy_framer_error) {
    case SPDY_NO_ERROR:
      return "NO_ERROR";
    case SPDY_INVALID_STREAM_ID:
      return "INVALID_STREAM_ID";
    case SPDY_INVALID_CONTROL_FRAME:
      return "INVALID_CONTROL_FRAME";
    case SPDY_CONTROL_PAYLOAD_TOO_LARGE:
      return "CONTROL_PAYLOAD_TOO_LARGE";
    case SPDY_ZLIB_INIT_FAILURE:
      return "ZLIB_INIT_FAILURE";
    case SPDY_UNSUPPORTED_VERSION:
      return "UNSUPPORTED_VERSION";
    case SPDY_DECOMPRESS_FAILURE:
      return "DECOMPRESS_FAILURE";
    case SPDY_COMPRESS_FAILURE:
      return "COMPRESS_FAILURE";
    case SPDY_GOAWAY_FRAME_CORRUPT:
      return "GOAWAY_FRAME_CORRUPT";
    case SPDY_RST_STREAM_FRAME_CORRUPT:
      return "RST_STREAM_FRAME_CORRUPT";
    case SPDY_INVALID_PADDING:
      return "INVALID_PADDING";
    case SPDY_INVALID_DATA_FRAME_FLAGS:
      return "INVALID_DATA_FRAME_FLAGS";
    case SPDY_INVALID_CONTROL_FRAME_FLAGS:
      return "INVALID_CONTROL_FRAME_FLAGS";
    case SPDY_UNEXPECTED_FRAME:
      return "UNEXPECTED_FRAME";
    case SPDY_INTERNAL_FRAMER_ERROR:
      return "INTERNAL_FRAMER_ERROR";
    case SPDY_INVALID_CONTROL_FRAME_SIZE:
      return "INVALID_CONTROL_FRAME_SIZE";
    case SPDY_OVERSIZED_PAYLOAD:
      return "OVERSIZED_PAYLOAD";
    case LAST_ERROR:
      return "UNKNOWN_ERROR";
  }
  return "UNKNOWN_ERROR";
}

size_t SpdyFramer::ProcessInput(const char* data, size_t len) {
  DCHECK(visitor_);
  DCHECK(data);

  if (decoder_adapter_ != nullptr) {
    return decoder_adapter_->ProcessInput(data, len);
  }
  const size_t original_len = len;
  do {
    previous_state_ = state_;
    switch (state_) {
      case SPDY_ERROR:
        goto bottom;

      case SPDY_FRAME_COMPLETE:
        // Should not enter in this state.
        DCHECK_LT(len, original_len);
        Reset();
        if (len > 0 && !process_single_input_frame_) {
          CHANGE_STATE(SPDY_READING_COMMON_HEADER);
        }
        break;

      case SPDY_READY_FOR_FRAME:
        if (len > 0) {
          CHANGE_STATE(SPDY_READING_COMMON_HEADER);
        }
        break;

      case SPDY_READING_COMMON_HEADER: {
        size_t bytes_read = ProcessCommonHeader(data, len);
        len -= bytes_read;
        data += bytes_read;
        break;
      }

      case SPDY_CONTROL_FRAME_BEFORE_HEADER_BLOCK: {
        // Control frames that contain header blocks
        // (HEADERS, PUSH_PROMISE, CONTINUATION)
        // take a special path through the state machine - they
        // will go:
        //   1. SPDY_CONTROL_FRAME_BEFORE_HEADER_BLOCK
        //   2. SPDY_CONTROL_FRAME_HEADER_BLOCK
        int bytes_read = ProcessControlFrameBeforeHeaderBlock(data, len);
        len -= bytes_read;
        data += bytes_read;
        break;
      }

      case SPDY_SETTINGS_FRAME_HEADER: {
        int bytes_read = ProcessSettingsFrameHeader(data, len);
        len -= bytes_read;
        data += bytes_read;
        break;
      }

      case SPDY_SETTINGS_FRAME_PAYLOAD: {
        int bytes_read = ProcessSettingsFramePayload(data, len);
        len -= bytes_read;
        data += bytes_read;
        break;
      }

      case SPDY_CONTROL_FRAME_HEADER_BLOCK: {
        int bytes_read = ProcessControlFrameHeaderBlock(data, len);
        len -= bytes_read;
        data += bytes_read;
        break;
      }

      case SPDY_GOAWAY_FRAME_PAYLOAD: {
        size_t bytes_read = ProcessGoAwayFramePayload(data, len);
        len -= bytes_read;
        data += bytes_read;
        break;
      }

      case SPDY_ALTSVC_FRAME_PAYLOAD: {
        size_t bytes_read = ProcessAltSvcFramePayload(data, len);
        len -= bytes_read;
        data += bytes_read;
        break;
      }

      case SPDY_CONTROL_FRAME_PAYLOAD: {
        size_t bytes_read = ProcessControlFramePayload(data, len);
        len -= bytes_read;
        data += bytes_read;
        break;
      }

      case SPDY_READ_DATA_FRAME_PADDING_LENGTH: {
        size_t bytes_read = ProcessDataFramePaddingLength(data, len);
        len -= bytes_read;
        data += bytes_read;
        break;
      }

      case SPDY_CONSUME_PADDING: {
        size_t bytes_read = ProcessFramePadding(data, len);
        len -= bytes_read;
        data += bytes_read;
        break;
      }

      case SPDY_IGNORE_REMAINING_PAYLOAD: {
        size_t bytes_read = ProcessIgnoredControlFramePayload(/*data,*/ len);
        len -= bytes_read;
        data += bytes_read;
        break;
      }

      case SPDY_FORWARD_STREAM_FRAME: {
        size_t bytes_read = ProcessDataFramePayload(data, len);
        len -= bytes_read;
        data += bytes_read;
        break;
      }

      case SPDY_EXTENSION_FRAME_PAYLOAD: {
        size_t bytes_read = ProcessExtensionFramePayload(data, len);
        len -= bytes_read;
        data += bytes_read;
        break;
      }

      default:
        SPDY_BUG << "Invalid value for framer state: " << state_;
        // This ensures that we don't infinite-loop if state_ gets an
        // invalid value somehow, such as due to a SpdyFramer getting deleted
        // from a callback it calls.
        goto bottom;
    }
  } while (state_ != previous_state_);
 bottom:
  DCHECK(len == 0 || state_ == SPDY_ERROR || process_single_input_frame_)
      << "len: " << len << " state: " << state_
      << " process single input frame: " << process_single_input_frame_;
  if (current_frame_buffer_.len() == 0 && remaining_data_length_ == 0 &&
      remaining_control_header_ == 0) {
    DCHECK(state_ == SPDY_READY_FOR_FRAME || state_ == SPDY_ERROR)
        << "State: " << StateToString(state_);
  }

  return original_len - len;
}

SpdyFramer::CharBuffer::CharBuffer(size_t capacity)
    : buffer_(new char[capacity]), capacity_(capacity), len_(0) {}
SpdyFramer::CharBuffer::~CharBuffer() {}

void SpdyFramer::CharBuffer::CopyFrom(const char* data, size_t size) {
  DCHECK_GE(capacity_, len_ + size);
  memcpy(buffer_.get() + len_, data, size);
  len_ += size;
}

void SpdyFramer::CharBuffer::Rewind() {
  len_ = 0;
}

size_t SpdyFramer::CharBuffer::EstimateMemoryUsage() const {
  return capacity_;
}

SpdyFramer::SpdySettingsScratch::SpdySettingsScratch()
    : buffer(8), last_setting_id(-1) {}

void SpdyFramer::SpdySettingsScratch::Reset() {
  buffer.Rewind();
  last_setting_id = -1;
}

size_t SpdyFramer::SpdySettingsScratch::EstimateMemoryUsage() const {
  return SpdyEstimateMemoryUsage(buffer);
}

SpdyFrameType SpdyFramer::ValidateFrameHeader(bool is_control_frame,
                                              uint8_t frame_type_field,
                                              size_t payload_length_field) {
  if (!IsDefinedFrameType(frame_type_field)) {
    if (expect_continuation_) {
      // Report an unexpected frame error and close the connection
      // if we expect a continuation and receive an unknown frame.
      DLOG(ERROR) << "The framer was expecting to receive a CONTINUATION "
                  << "frame, but instead received an unknown frame of type "
                  << SpdyStringPrintf("%x", frame_type_field);
      set_error(SPDY_UNEXPECTED_FRAME);
      return SpdyFrameType::DATA;
    }
    if (extension_ != nullptr) {
      if (extension_->OnFrameHeader(current_frame_stream_id_,
                                    payload_length_field, frame_type_field,
                                    current_frame_flags_)) {
        return SpdyFrameType::EXTENSION;
      }
    }
    // We ignore unknown frame types for extensibility, as long as
    // the rest of the control frame header is valid.
    // We rely on the visitor to check validity of current_frame_stream_id_.
    bool valid_stream =
        visitor_->OnUnknownFrame(current_frame_stream_id_, frame_type_field);
    if (!valid_stream) {
      // Report an invalid frame error and close the stream if the
      // stream_id is not valid.
      DLOG(WARNING) << "Unknown control frame type "
                    << SpdyStringPrintf("%x", frame_type_field)
                    << " received on invalid stream "
                    << current_frame_stream_id_;
      set_error(SPDY_INVALID_CONTROL_FRAME);
    } else {
      DVLOG(1) << "Ignoring unknown frame type.";
      CHANGE_STATE(SPDY_IGNORE_REMAINING_PAYLOAD);
    }
    return SpdyFrameType::DATA;
  }

  SpdyFrameType frame_type = ParseFrameType(frame_type_field);

  if (!IsValidHTTP2FrameStreamId(current_frame_stream_id_, frame_type)) {
    DLOG(ERROR) << "The framer received an invalid streamID of "
                << current_frame_stream_id_ << " for a frame of type "
                << FrameTypeToString(frame_type);
    set_error(SPDY_INVALID_STREAM_ID);
    return frame_type;
  }

  // Ensure that we see a CONTINUATION frame iff we expect to.
  if ((frame_type == SpdyFrameType::CONTINUATION) !=
      (expect_continuation_ != 0)) {
    if (expect_continuation_ != 0) {
      DLOG(ERROR) << "The framer was expecting to receive a CONTINUATION "
                  << "frame, but instead received a frame of type "
                  << FrameTypeToString(frame_type);
    } else {
      DLOG(ERROR) << "The framer received an unexpected CONTINUATION frame.";
    }
    set_error(SPDY_UNEXPECTED_FRAME);
    return frame_type;
  }

  if (payload_length_field > recv_frame_size_limit_) {
    set_error(SPDY_OVERSIZED_PAYLOAD);
  }

  return frame_type;
}

size_t SpdyFramer::ProcessCommonHeader(const char* data, size_t len) {
  // This should only be called when we're in the SPDY_READING_COMMON_HEADER
  // state.
  DCHECK_EQ(state_, SPDY_READING_COMMON_HEADER);

  size_t original_len = len;

  // Update current frame buffer as needed.
  if (current_frame_buffer_.len() < GetFrameHeaderSize()) {
    size_t bytes_desired = GetFrameHeaderSize() - current_frame_buffer_.len();
    UpdateCurrentFrameBuffer(&data, &len, bytes_desired);
  }

  if (current_frame_buffer_.len() < GetFrameHeaderSize()) {
    // Not enough information to do anything meaningful.
    return original_len - len;
  }

  SpdyFrameReader reader(current_frame_buffer_.data(),
                         current_frame_buffer_.len());
  bool is_control_frame = false;

  uint32_t length_field = 0;
  bool successful_read = reader.ReadUInt24(&length_field);
  DCHECK(successful_read);

  uint8_t control_frame_type_field = 0;
  successful_read = reader.ReadUInt8(&control_frame_type_field);
  DCHECK(successful_read);
  // We check control_frame_type_field's validity in
  // ValidateFrameHeader().
  is_control_frame =
      control_frame_type_field != SerializeFrameType(SpdyFrameType::DATA);

  current_frame_length_ = length_field + GetFrameHeaderSize();

  successful_read = reader.ReadUInt8(&current_frame_flags_);
  DCHECK(successful_read);

  successful_read = reader.ReadUInt31(&current_frame_stream_id_);
  DCHECK(successful_read);

  remaining_data_length_ = current_frame_length_ - reader.GetBytesConsumed();

  DCHECK_EQ(GetFrameHeaderSize(), reader.GetBytesConsumed());
  DCHECK_EQ(current_frame_length_,
            remaining_data_length_ + reader.GetBytesConsumed());

  // This is just a sanity check for help debugging early frame errors.
  // The strncmp for 5 is safe because we only hit this point if we
  // have kMinCommonHeader (8) bytes
  if (remaining_data_length_ > 1000000u &&
      strncmp(current_frame_buffer_.data(), "HTTP/", 5) == 0) {
    LOG(WARNING) << "Unexpected HTTP response to HTTP2 request";
    probable_http_response_ = true;
  }

  // If we're here, then we have the common header all received.
  visitor_->OnCommonHeader(current_frame_stream_id_, remaining_data_length_,
                           control_frame_type_field, current_frame_flags_);

  current_frame_type_ = ValidateFrameHeader(
      is_control_frame, control_frame_type_field, remaining_data_length_);

  if (state_ == SPDY_ERROR || state_ == SPDY_IGNORE_REMAINING_PAYLOAD) {
    return original_len - len;
  }

  if (!is_control_frame) {
    uint8_t valid_data_flags = DATA_FLAG_FIN | DATA_FLAG_PADDED;

    if (current_frame_flags_ & ~valid_data_flags) {
      set_error(SPDY_INVALID_DATA_FRAME_FLAGS);
    } else {
      visitor_->OnDataFrameHeader(current_frame_stream_id_,
                                  remaining_data_length_,
                                  current_frame_flags_ & DATA_FLAG_FIN);
      if (remaining_data_length_ > 0) {
        CHANGE_STATE(SPDY_READ_DATA_FRAME_PADDING_LENGTH);
      } else {
        // Empty data frame.
        if (current_frame_flags_ & DATA_FLAG_FIN) {
          visitor_->OnStreamEnd(current_frame_stream_id_);
        }
        CHANGE_STATE(SPDY_FRAME_COMPLETE);
      }
    }
  } else {
    ProcessControlFrameHeader();
  }

  return original_len - len;
}

void SpdyFramer::ProcessControlFrameHeader() {
  DCHECK_EQ(SPDY_NO_ERROR, spdy_framer_error_);
  DCHECK_LE(GetFrameHeaderSize(), current_frame_buffer_.len());

  // Do some sanity checking on the control frame sizes and flags.
  switch (current_frame_type_) {
    case SpdyFrameType::RST_STREAM:
      if (current_frame_length_ != GetRstStreamSize()) {
        set_error(SPDY_INVALID_CONTROL_FRAME_SIZE);
      } else if (current_frame_flags_ != 0) {
        VLOG(1) << "Undefined frame flags for RST_STREAM frame: " << std::hex
                << static_cast<int>(current_frame_flags_);
        current_frame_flags_ = 0;
      }
      break;
    case SpdyFrameType::SETTINGS: {
      // Make sure that we have an integral number of 8-byte key/value pairs.
      // Size of each key/value pair in bytes.
      if (current_frame_length_ < GetSettingsMinimumSize() ||
          (current_frame_length_ - GetFrameHeaderSize()) %
                  kOneSettingParameterSize !=
              0) {
        DLOG(WARNING) << "Invalid length for SETTINGS frame: "
                      << current_frame_length_;
        set_error(SPDY_INVALID_CONTROL_FRAME_SIZE);
      } else if (current_frame_flags_ & SETTINGS_FLAG_ACK &&
                 current_frame_length_ > GetSettingsMinimumSize()) {
        set_error(SPDY_INVALID_CONTROL_FRAME_SIZE);
      } else if (current_frame_flags_ & ~SETTINGS_FLAG_ACK) {
        VLOG(1) << "Undefined frame flags for SETTINGS frame: " << std::hex
                << static_cast<int>(current_frame_flags_);
        current_frame_flags_ &= SETTINGS_FLAG_ACK;
      }
      break;
    }
    case SpdyFrameType::PING:
      if (current_frame_length_ != GetPingSize()) {
        set_error(SPDY_INVALID_CONTROL_FRAME_SIZE);
      } else {
        if (current_frame_flags_ & ~PING_FLAG_ACK) {
          VLOG(1) << "Undefined frame flags for PING frame: " << std::hex
                  << static_cast<int>(current_frame_flags_);
          current_frame_flags_ &= PING_FLAG_ACK;
        }
      }
      break;
    case SpdyFrameType::GOAWAY: {
      // For HTTP/2, optional opaque data may be appended to the
      // GOAWAY frame, thus there is only a minimal length restriction.
      if (current_frame_length_ < GetGoAwayMinimumSize()) {
        set_error(SPDY_INVALID_CONTROL_FRAME);
      } else if (current_frame_flags_ != 0) {
        VLOG(1) << "Undefined frame flags for GOAWAY frame: " << std::hex
                << static_cast<int>(current_frame_flags_);
        current_frame_flags_ = 0;
      }
      break;
    }
    case SpdyFrameType::HEADERS: {
      size_t min_size = GetHeadersMinimumSize();
      if (current_frame_flags_ & HEADERS_FLAG_PRIORITY) {
        min_size += 4;
      }
      if (current_frame_length_ < min_size) {
        // TODO(mlavan): check here for HEADERS with no payload?
        // (not allowed in HTTP2)
        set_error(SPDY_INVALID_CONTROL_FRAME);
      } else if (current_frame_flags_ &
                 ~(CONTROL_FLAG_FIN | HEADERS_FLAG_PRIORITY |
                   HEADERS_FLAG_END_HEADERS | HEADERS_FLAG_PADDED)) {
        VLOG(1) << "Undefined frame flags for HEADERS frame: " << std::hex
                << static_cast<int>(current_frame_flags_);
        current_frame_flags_ &=
            (CONTROL_FLAG_FIN | HEADERS_FLAG_PRIORITY |
             HEADERS_FLAG_END_HEADERS | HEADERS_FLAG_PADDED);
      }
      break;
    }
    case SpdyFrameType::WINDOW_UPDATE:
      if (current_frame_length_ != GetWindowUpdateSize()) {
        set_error(SPDY_INVALID_CONTROL_FRAME_SIZE);
      } else if (current_frame_flags_ != 0) {
        VLOG(1) << "Undefined frame flags for WINDOW_UPDATE frame: " << std::hex
                << static_cast<int>(current_frame_flags_);
        current_frame_flags_ = 0;
      }
      break;
    case SpdyFrameType::PUSH_PROMISE:
      if (current_frame_length_ < GetPushPromiseMinimumSize()) {
        set_error(SPDY_INVALID_CONTROL_FRAME);
      } else if (current_frame_flags_ &
                 ~(PUSH_PROMISE_FLAG_END_PUSH_PROMISE | HEADERS_FLAG_PADDED)) {
        VLOG(1) << "Undefined frame flags for PUSH_PROMISE frame: " << std::hex
                << static_cast<int>(current_frame_flags_);
        current_frame_flags_ &=
            (PUSH_PROMISE_FLAG_END_PUSH_PROMISE | HEADERS_FLAG_PADDED);
      }
      break;
    case SpdyFrameType::CONTINUATION:
      if (current_frame_length_ < GetContinuationMinimumSize()) {
        set_error(SPDY_INVALID_CONTROL_FRAME);
      } else if (current_frame_flags_ & ~HEADERS_FLAG_END_HEADERS) {
        VLOG(1) << "Undefined frame flags for CONTINUATION frame: " << std::hex
                << static_cast<int>(current_frame_flags_);
        current_frame_flags_ &= HEADERS_FLAG_END_HEADERS;
      }
      break;
    case SpdyFrameType::ALTSVC:
      if (current_frame_length_ <= GetAltSvcMinimumSize()) {
        set_error(SPDY_INVALID_CONTROL_FRAME);
      } else if (current_frame_flags_ != 0) {
        VLOG(1) << "Undefined frame flags for ALTSVC frame: " << std::hex
                << static_cast<int>(current_frame_flags_);
        current_frame_flags_ = 0;
      }
      break;
    case SpdyFrameType::PRIORITY:
      if (current_frame_length_ != GetPrioritySize()) {
        set_error(SPDY_INVALID_CONTROL_FRAME_SIZE);
      } else if (current_frame_flags_ != 0) {
        VLOG(1) << "Undefined frame flags for PRIORITY frame: " << std::hex
                << static_cast<int>(current_frame_flags_);
        current_frame_flags_ = 0;
      }
      break;
    case SpdyFrameType::EXTENSION:
      // No particular requirements on frames handled by the registered
      // extension.
      break;
    default:
      LOG(WARNING) << "Valid control frame with unhandled type: "
                   << SerializeFrameType(current_frame_type_);
      // This branch should be unreachable because of the frame type bounds
      // check above. However, we DLOG(FATAL) here in an effort to painfully
      // club the head of the developer who failed to keep this file in sync
      // with spdy_protocol.h.
      set_error(SPDY_INVALID_CONTROL_FRAME);
      DLOG(FATAL);
      break;
  }

  if (state_ == SPDY_ERROR) {
    return;
  }

  if (current_frame_type_ == SpdyFrameType::GOAWAY) {
    CHANGE_STATE(SPDY_GOAWAY_FRAME_PAYLOAD);
    return;
  }

  if (current_frame_type_ == SpdyFrameType::ALTSVC) {
    CHANGE_STATE(SPDY_ALTSVC_FRAME_PAYLOAD);
    return;
  }
  // Determine the frame size without variable-length data.
  int32_t frame_size_without_variable_data;
  switch (current_frame_type_) {
    case SpdyFrameType::SETTINGS:
      frame_size_without_variable_data = GetSettingsMinimumSize();
      break;
    case SpdyFrameType::HEADERS:
      frame_size_without_variable_data = GetHeadersMinimumSize();
      if (current_frame_flags_ & HEADERS_FLAG_PADDED) {
        frame_size_without_variable_data += kPadLengthFieldSize;
      }
      if (current_frame_flags_ & HEADERS_FLAG_PRIORITY) {
        frame_size_without_variable_data +=
            kPriorityDependencyPayloadSize + kPriorityWeightPayloadSize;
      }
      break;
    case SpdyFrameType::PUSH_PROMISE:
      frame_size_without_variable_data = GetPushPromiseMinimumSize();
      if (current_frame_flags_ & PUSH_PROMISE_FLAG_PADDED) {
        frame_size_without_variable_data += kPadLengthFieldSize;
      }
      break;
    case SpdyFrameType::CONTINUATION:
      frame_size_without_variable_data = GetContinuationMinimumSize();
      break;
    case SpdyFrameType::EXTENSION:
      frame_size_without_variable_data = GetFrameHeaderSize();
      break;
    default:
      frame_size_without_variable_data = -1;
      break;
  }

  if ((frame_size_without_variable_data == -1) &&
      (current_frame_length_ > kControlFrameBufferSize)) {
    // We should already be in an error state. Double-check.
    DCHECK_EQ(SPDY_ERROR, state_);
    if (state_ != SPDY_ERROR) {
      SPDY_BUG << "Control frame buffer too small for fixed-length frame.";
      set_error(SPDY_CONTROL_PAYLOAD_TOO_LARGE);
    }
    return;
  }

  if (frame_size_without_variable_data > 0) {
    // We have a control frame with variable-size data. We need to parse the
    // remainder of the control frame's header before we can parse the payload.
    // The start of the payload varies with the control frame type.
    DCHECK_GE(frame_size_without_variable_data,
              static_cast<int32_t>(current_frame_buffer_.len()));
    remaining_control_header_ =
        frame_size_without_variable_data - current_frame_buffer_.len();

    if (current_frame_type_ == SpdyFrameType::SETTINGS) {
      CHANGE_STATE(SPDY_SETTINGS_FRAME_HEADER);
    } else if (current_frame_type_ == SpdyFrameType::EXTENSION) {
      CHANGE_STATE(SPDY_EXTENSION_FRAME_PAYLOAD);
    } else {
      CHANGE_STATE(SPDY_CONTROL_FRAME_BEFORE_HEADER_BLOCK);
    }
    return;
  }

  CHANGE_STATE(SPDY_CONTROL_FRAME_PAYLOAD);
}

size_t SpdyFramer::UpdateCurrentFrameBuffer(const char** data,
                                            size_t* len,
                                            size_t max_bytes) {
  size_t bytes_to_read = std::min(*len, max_bytes);
  if (bytes_to_read > 0) {
    current_frame_buffer_.CopyFrom(*data, bytes_to_read);
    *data += bytes_to_read;
    *len -= bytes_to_read;
  }
  return bytes_to_read;
}

size_t SpdyFramer::GetSerializedLength(const SpdyHeaderBlock* headers) {
  const size_t num_name_value_pairs_size = sizeof(uint32_t);
  const size_t length_of_name_size = num_name_value_pairs_size;
  const size_t length_of_value_size = num_name_value_pairs_size;

  size_t total_length = num_name_value_pairs_size;
  for (const auto& header : *headers) {
    // We add space for the length of the name and the length of the value as
    // well as the length of the name and the length of the value.
    total_length += length_of_name_size + header.first.size() +
                    length_of_value_size + header.second.size();
  }
  return total_length;
}

size_t SpdyFramer::ProcessControlFrameBeforeHeaderBlock(const char* data,
                                                        size_t len) {
  DCHECK_EQ(SPDY_CONTROL_FRAME_BEFORE_HEADER_BLOCK, state_);
  const size_t original_len = len;

  if (remaining_control_header_ > 0) {
    size_t bytes_read =
        UpdateCurrentFrameBuffer(&data, &len, remaining_control_header_);
    remaining_control_header_ -= bytes_read;
    remaining_data_length_ -= bytes_read;
  }

  if (remaining_control_header_ == 0) {
    SpdyFrameReader reader(current_frame_buffer_.data(),
                           current_frame_buffer_.len());
    reader.Seek(GetFrameHeaderSize());  // Seek past frame header.

    switch (current_frame_type_) {
      case SpdyFrameType::HEADERS: {
        bool successful_read = true;
        if (current_frame_stream_id_ == 0) {
          set_error(SPDY_INVALID_CONTROL_FRAME);
          return original_len - len;
        }
        if (!(current_frame_flags_ & HEADERS_FLAG_END_HEADERS) &&
            current_frame_type_ == SpdyFrameType::HEADERS) {
          expect_continuation_ = current_frame_stream_id_;
          end_stream_when_done_ = current_frame_flags_ & CONTROL_FLAG_FIN;
        }
        if (current_frame_flags_ & HEADERS_FLAG_PADDED) {
          uint8_t pad_payload_len = 0;
          DCHECK_EQ(remaining_padding_payload_length_, 0u);
          successful_read = reader.ReadUInt8(&pad_payload_len);
          DCHECK(successful_read);
          remaining_padding_payload_length_ = pad_payload_len;
        }
        const bool has_priority =
            (current_frame_flags_ & HEADERS_FLAG_PRIORITY) != 0;
        int weight = 0;
        uint32_t parent_stream_id = 0;
        bool exclusive = false;
        if (has_priority) {
          uint32_t stream_dependency;
          successful_read = reader.ReadUInt32(&stream_dependency);
          DCHECK(successful_read);
          UnpackStreamDependencyValues(stream_dependency, &exclusive,
                                       &parent_stream_id);

          uint8_t serialized_weight = 0;
          successful_read = reader.ReadUInt8(&serialized_weight);
          if (successful_read) {
            // Per RFC 7540 section 6.3, serialized weight value is actual
            // value - 1.
            weight = serialized_weight + 1;
          }
        }
        DCHECK(reader.IsDoneReading());
        if (debug_visitor_) {
          debug_visitor_->OnReceiveCompressedFrame(current_frame_stream_id_,
                                                   current_frame_type_,
                                                   current_frame_length_);
        }
        visitor_->OnHeaders(current_frame_stream_id_,
                            (current_frame_flags_ & HEADERS_FLAG_PRIORITY) != 0,
                            weight, parent_stream_id, exclusive,
                            (current_frame_flags_ & CONTROL_FLAG_FIN) != 0,
                            expect_continuation_ == 0);
        }
        break;
        case SpdyFrameType::PUSH_PROMISE: {
          if (current_frame_stream_id_ == 0) {
            set_error(SPDY_INVALID_CONTROL_FRAME);
            return original_len - len;
          }
          bool successful_read = true;
          if (current_frame_flags_ & PUSH_PROMISE_FLAG_PADDED) {
            DCHECK_EQ(remaining_padding_payload_length_, 0u);
            uint8_t pad_payload_len = 0;
            successful_read = reader.ReadUInt8(&pad_payload_len);
            DCHECK(successful_read);
            remaining_padding_payload_length_ = pad_payload_len;
          }
        }
        {
          SpdyStreamId promised_stream_id = kInvalidStream;
          bool successful_read = reader.ReadUInt31(&promised_stream_id);
          DCHECK(successful_read);
          DCHECK(reader.IsDoneReading());
          if (promised_stream_id == 0) {
            set_error(SPDY_INVALID_CONTROL_FRAME);
            return original_len - len;
          }
          if (!(current_frame_flags_ & PUSH_PROMISE_FLAG_END_PUSH_PROMISE)) {
            expect_continuation_ = current_frame_stream_id_;
          }
          if (debug_visitor_) {
            debug_visitor_->OnReceiveCompressedFrame(
                current_frame_stream_id_,
                current_frame_type_,
                current_frame_length_);
          }
          visitor_->OnPushPromise(current_frame_stream_id_,
                                  promised_stream_id,
                                  (current_frame_flags_ &
                                   PUSH_PROMISE_FLAG_END_PUSH_PROMISE) != 0);
        }
        break;
        case SpdyFrameType::CONTINUATION: {
          // Check to make sure the stream id of the current frame is
          // the same as that of the preceding frame.
          // If we're at this point we should already know that
          // expect_continuation_ != 0, so this doubles as a check
          // that current_frame_stream_id != 0.
          if (current_frame_stream_id_ != expect_continuation_) {
            set_error(SPDY_UNEXPECTED_FRAME);
            return original_len - len;
          }
          if (current_frame_flags_ & HEADERS_FLAG_END_HEADERS) {
            expect_continuation_ = 0;
          }
          if (debug_visitor_) {
            debug_visitor_->OnReceiveCompressedFrame(
                current_frame_stream_id_,
                current_frame_type_,
                current_frame_length_);
          }
          visitor_->OnContinuation(current_frame_stream_id_,
                                   (current_frame_flags_ &
                                    HEADERS_FLAG_END_HEADERS) != 0);
        }
        break;
      default:
#ifndef NDEBUG
        LOG(FATAL) << "Invalid control frame type: " << current_frame_type_;
#else
        set_error(SPDY_INVALID_CONTROL_FRAME);
        return original_len - len;
#endif
    }

    if (current_frame_type_ != SpdyFrameType::CONTINUATION) {
      header_handler_ = visitor_->OnHeaderFrameStart(current_frame_stream_id_);
      if (header_handler_ == nullptr) {
        SPDY_BUG << "visitor_->OnHeaderFrameStart returned nullptr";
        set_error(SPDY_INTERNAL_FRAMER_ERROR);
        return original_len - len;
      }
      GetHpackDecoder()->HandleControlFrameHeadersStart(header_handler_);
    }
    CHANGE_STATE(SPDY_CONTROL_FRAME_HEADER_BLOCK);
  }
  return original_len - len;
}

// Does not buffer the control payload. Instead, either passes directly to the
// visitor or decompresses and then passes directly to the visitor.
size_t SpdyFramer::ProcessControlFrameHeaderBlock(const char* data,
                                                  size_t data_len) {
  DCHECK_EQ(SPDY_CONTROL_FRAME_HEADER_BLOCK, state_);

  bool processed_successfully = true;
  if (current_frame_type_ != SpdyFrameType::HEADERS &&
      current_frame_type_ != SpdyFrameType::PUSH_PROMISE &&
      current_frame_type_ != SpdyFrameType::CONTINUATION) {
    SPDY_BUG << "Unhandled frame type in ProcessControlFrameHeaderBlock.";
  }

  if (remaining_padding_payload_length_ > remaining_data_length_) {
    set_error(SPDY_INVALID_PADDING);
    return data_len;
  }

  size_t process_bytes = std::min(
      data_len, remaining_data_length_ - remaining_padding_payload_length_);
  if (!GetHpackDecoder()->HandleControlFrameHeadersData(data, process_bytes)) {
    // TODO(jgraettinger): Finer-grained HPACK error codes.
    set_error(SPDY_DECOMPRESS_FAILURE);
    processed_successfully = false;
  }
  remaining_data_length_ -= process_bytes;

  // Handle the case that there is no futher data in this frame.
  if (remaining_data_length_ == remaining_padding_payload_length_ &&
      processed_successfully) {
    if (expect_continuation_ == 0) {
      size_t compressed_len = 0;
      if (GetHpackDecoder()->HandleControlFrameHeadersComplete(
              &compressed_len)) {
        visitor_->OnHeaderFrameEnd(current_frame_stream_id_, true);
        if (state_ == SPDY_ERROR) {
          return data_len;
        }
      } else {
        set_error(SPDY_DECOMPRESS_FAILURE);
        processed_successfully = false;
      }
    }
    if (processed_successfully) {
      CHANGE_STATE(SPDY_CONSUME_PADDING);
    }
  }

  // Handle error.
  if (!processed_successfully) {
    return data_len;
  }

  // Return amount processed.
  return process_bytes;
}

size_t SpdyFramer::ProcessSettingsFrameHeader(const char* data, size_t len) {
  // TODO(birenroy): Remove this state when removing SPDY3. I think it only
  // exists to read the number of settings in the frame for SPDY3. This value
  // is never parsed or used.
  size_t bytes_read = 0;
  if (remaining_control_header_ > 0) {
    bytes_read =
        UpdateCurrentFrameBuffer(&data, &len, remaining_control_header_);
    remaining_control_header_ -= bytes_read;
    remaining_data_length_ -= bytes_read;
  }
  if (remaining_control_header_ == 0) {
    if (current_frame_flags_ & SETTINGS_FLAG_ACK) {
      visitor_->OnSettingsAck();
      CHANGE_STATE(SPDY_FRAME_COMPLETE);
    } else {
      visitor_->OnSettings(current_frame_flags_ &
                           SETTINGS_FLAG_CLEAR_PREVIOUSLY_PERSISTED_SETTINGS);
      CHANGE_STATE(SPDY_SETTINGS_FRAME_PAYLOAD);
    }
  }
  return bytes_read;
}

size_t SpdyFramer::ProcessSettingsFramePayload(const char* data,
                                               size_t data_len) {
  DCHECK_EQ(SPDY_SETTINGS_FRAME_PAYLOAD, state_);
  DCHECK_EQ(SpdyFrameType::SETTINGS, current_frame_type_);
  size_t unprocessed_bytes = std::min(data_len, remaining_data_length_);
  size_t processed_bytes = 0;

  // Loop over our incoming data.
  while (unprocessed_bytes > 0) {
    // Process up to one setting at a time.
    size_t processing =
        std::min(unprocessed_bytes,
                 kOneSettingParameterSize - settings_scratch_.buffer.len());

    // Check if we have a complete setting in our input.
    if (processing == kOneSettingParameterSize) {
      // Parse the setting directly out of the input without buffering.
      if (!ProcessSetting(data + processed_bytes)) {
        set_error(SPDY_INVALID_CONTROL_FRAME);
        return processed_bytes;
      }
    } else {
      // Continue updating settings_scratch_.setting_buf.
      settings_scratch_.buffer.CopyFrom(data + processed_bytes, processing);

      // Check if we have a complete setting buffered.
      if (settings_scratch_.buffer.len() == kOneSettingParameterSize) {
        if (!ProcessSetting(settings_scratch_.buffer.data())) {
          set_error(SPDY_INVALID_CONTROL_FRAME);
          return processed_bytes;
        }
        // Rewind settings buffer for our next setting.
        settings_scratch_.buffer.Rewind();
      }
    }

    // Iterate.
    unprocessed_bytes -= processing;
    processed_bytes += processing;
  }

  // Check if we're done handling this SETTINGS frame.
  remaining_data_length_ -= processed_bytes;
  if (remaining_data_length_ == 0) {
    visitor_->OnSettingsEnd();
    CHANGE_STATE(SPDY_FRAME_COMPLETE);
  }

  return processed_bytes;
}

bool SpdyFramer::ProcessSetting(const char* data) {
  // Extract fields.
  // Maintain behavior of old SPDY 2 bug with byte ordering of flags/id.
  uint16_t id_field =
      base::NetToHost16(*(reinterpret_cast<const uint16_t*>(data)));
  uint32_t value =
      base::NetToHost32(*(reinterpret_cast<const uint32_t*>(data + 2)));

  // Validate id.
  SpdySettingsIds setting_id;
  if (!ParseSettingsId(id_field, &setting_id)) {
    if (extension_ == nullptr) {
      DLOG(WARNING) << "Unknown SETTINGS ID: " << id_field;
    } else {
      extension_->OnSetting(id_field, value);
    }
    // Ignore unknown settings for extensibility.
    return true;
  }

  // Validation succeeded. Pass on to visitor.
  visitor_->OnSetting(setting_id, value);
  return true;
}

size_t SpdyFramer::ProcessControlFramePayload(const char* data, size_t len) {
  size_t original_len = len;
  size_t bytes_read =
      UpdateCurrentFrameBuffer(&data, &len, remaining_data_length_);
  remaining_data_length_ -= bytes_read;
  if (remaining_data_length_ == 0) {
    SpdyFrameReader reader(current_frame_buffer_.data(),
                           current_frame_buffer_.len());
    reader.Seek(GetFrameHeaderSize());  // Skip frame header.

    // Use frame-specific handlers.
    switch (current_frame_type_) {
      case SpdyFrameType::RST_STREAM: {
        uint32_t error_code = ERROR_CODE_NO_ERROR;
        bool successful_read = reader.ReadUInt32(&error_code);
        DCHECK(successful_read);
        DCHECK(reader.IsDoneReading());
        visitor_->OnRstStream(current_frame_stream_id_,
                              ParseErrorCode(error_code));
      } break;
      case SpdyFrameType::PING: {
        SpdyPingId id = 0;
        bool is_ack = current_frame_flags_ & PING_FLAG_ACK;
        bool successful_read = true;
        successful_read = reader.ReadUInt64(&id);
        DCHECK(successful_read);
        DCHECK(reader.IsDoneReading());
        visitor_->OnPing(id, is_ack);
      } break;
      case SpdyFrameType::WINDOW_UPDATE: {
        uint32_t delta_window_size = 0;
        bool successful_read = true;
        successful_read = reader.ReadUInt32(&delta_window_size);
        DCHECK(successful_read);
        DCHECK(reader.IsDoneReading());
        visitor_->OnWindowUpdate(current_frame_stream_id_, delta_window_size);
      } break;
      case SpdyFrameType::PRIORITY: {
        uint32_t stream_dependency;
        uint32_t parent_stream_id;
        bool exclusive;
        uint8_t serialized_weight;
        bool successful_read = reader.ReadUInt32(&stream_dependency);
        DCHECK(successful_read);
        UnpackStreamDependencyValues(stream_dependency, &exclusive,
                                     &parent_stream_id);

        successful_read = reader.ReadUInt8(&serialized_weight);
        DCHECK(successful_read);
        DCHECK(reader.IsDoneReading());
        // Per RFC 7540 section 6.3, serialized weight value is
        // actual value - 1.
        int weight = serialized_weight + 1;
        visitor_->OnPriority(current_frame_stream_id_, parent_stream_id, weight,
                             exclusive);
      } break;
      case SpdyFrameType::EXTENSION:
        if (extension_ == nullptr) {
          SPDY_BUG << "Reached EXTENSION frame processing with a null "
                   << "extension!";
          break;
        }
        extension_->OnFramePayload(current_frame_buffer_.data(),
                                   current_frame_buffer_.len());
        break;
      default:
        // Unreachable.
        LOG(FATAL) << "Unhandled control frame " << current_frame_type_;
    }

    CHANGE_STATE(SPDY_IGNORE_REMAINING_PAYLOAD);
  }
  return original_len - len;
}

size_t SpdyFramer::ProcessGoAwayFramePayload(const char* data, size_t len) {
  if (len == 0) {
    return 0;
  }
  // Clamp to the actual remaining payload.
  if (len > remaining_data_length_) {
    len = remaining_data_length_;
  }
  size_t original_len = len;

  // Check if we had already read enough bytes to parse the GOAWAY header.
  const size_t header_size = GetGoAwayMinimumSize();
  size_t unread_header_bytes = header_size - current_frame_buffer_.len();
  bool already_parsed_header = (unread_header_bytes == 0);
  if (!already_parsed_header) {
    // Buffer the new GOAWAY header bytes we got.
    UpdateCurrentFrameBuffer(&data, &len, unread_header_bytes);

    // Do we have enough to parse the constant size GOAWAY header?
    if (current_frame_buffer_.len() == header_size) {
      // Parse out the last good stream id.
      SpdyFrameReader reader(current_frame_buffer_.data(),
                             current_frame_buffer_.len());
      reader.Seek(GetFrameHeaderSize());  // Seek past frame header.
      bool successful_read = reader.ReadUInt31(&current_frame_stream_id_);
      DCHECK(successful_read);

      // Parse status code.
      uint32_t error_code = ERROR_CODE_NO_ERROR;
      successful_read = reader.ReadUInt32(&error_code);
      DCHECK(successful_read);
      // Finished parsing the GOAWAY header, call frame handler.
      visitor_->OnGoAway(current_frame_stream_id_, ParseErrorCode(error_code));
    }
  }

  // Handle remaining data as opaque.
  bool processed_successfully = true;
  if (len > 0) {
    processed_successfully = visitor_->OnGoAwayFrameData(data, len);
  }
  remaining_data_length_ -= original_len;
  if (!processed_successfully) {
    set_error(SPDY_GOAWAY_FRAME_CORRUPT);
  } else if (remaining_data_length_ == 0) {
    // Signal that there is not more opaque data.
    visitor_->OnGoAwayFrameData(nullptr, 0);
    CHANGE_STATE(SPDY_FRAME_COMPLETE);
  }
  return original_len;
}

size_t SpdyFramer::ProcessAltSvcFramePayload(const char* data, size_t len) {
  if (len == 0) {
    return 0;
  }

  // Clamp to the actual remaining payload.
  len = std::min(len, remaining_data_length_);

  if (altsvc_scratch_ == nullptr) {
    size_t capacity = current_frame_length_ - GetFrameHeaderSize();
    altsvc_scratch_ = SpdyMakeUnique<CharBuffer>(capacity);
  }
  altsvc_scratch_->CopyFrom(data, len);
  remaining_data_length_ -= len;
  if (remaining_data_length_ > 0) {
    return len;
  }

  SpdyFrameReader reader(altsvc_scratch_->data(), altsvc_scratch_->len());
  SpdyStringPiece origin;
  bool successful_read = reader.ReadStringPiece16(&origin);
  if (!successful_read) {
    set_error(SPDY_INVALID_CONTROL_FRAME);
    return 0;
  }
  SpdyStringPiece value(altsvc_scratch_->data() + reader.GetBytesConsumed(),
                        altsvc_scratch_->len() - reader.GetBytesConsumed());

  SpdyAltSvcWireFormat::AlternativeServiceVector altsvc_vector;
  bool success =
      SpdyAltSvcWireFormat::ParseHeaderFieldValue(value, &altsvc_vector);
  if (!success) {
    set_error(SPDY_INVALID_CONTROL_FRAME);
    return 0;
  }

  visitor_->OnAltSvc(current_frame_stream_id_, origin, altsvc_vector);
  CHANGE_STATE(SPDY_FRAME_COMPLETE);
  return len;
}

size_t SpdyFramer::ProcessDataFramePaddingLength(const char* data, size_t len) {
  DCHECK_EQ(SPDY_READ_DATA_FRAME_PADDING_LENGTH, state_);
  DCHECK_EQ(0u, remaining_padding_payload_length_);
  DCHECK_EQ(SpdyFrameType::DATA, current_frame_type_);

  size_t original_len = len;
  if (current_frame_flags_ & DATA_FLAG_PADDED) {
    if (len != 0) {
      if (remaining_data_length_ < kPadLengthFieldSize) {
        set_error(SPDY_INVALID_DATA_FRAME_FLAGS);
        return 0;
      }

      static_assert(kPadLengthFieldSize == 1,
                    "Unexpected pad length field size.");
      remaining_padding_payload_length_ =
          *reinterpret_cast<const uint8_t*>(data);
      ++data;
      --len;
      --remaining_data_length_;
      visitor_->OnStreamPadding(current_frame_stream_id_, kPadLengthFieldSize);
    } else {
      // We don't have the data available for parsing the pad length field. Keep
      // waiting.
      return 0;
    }
  }

  if (remaining_padding_payload_length_ > remaining_data_length_) {
    set_error(SPDY_INVALID_PADDING);
    return 0;
  }

  CHANGE_STATE(SPDY_FORWARD_STREAM_FRAME);
  return original_len - len;
}

size_t SpdyFramer::ProcessFramePadding(const char* data, size_t len) {
  DCHECK_EQ(SPDY_CONSUME_PADDING, state_);

  size_t original_len = len;
  if (remaining_padding_payload_length_ > 0) {
    DCHECK_EQ(remaining_padding_payload_length_, remaining_data_length_);
    size_t amount_to_discard = std::min(remaining_padding_payload_length_, len);
    if (current_frame_type_ == SpdyFrameType::DATA && amount_to_discard > 0) {
      visitor_->OnStreamPadding(current_frame_stream_id_, amount_to_discard);
    }
    data += amount_to_discard;
    len -= amount_to_discard;
    remaining_padding_payload_length_ -= amount_to_discard;
    remaining_data_length_ -= amount_to_discard;
  }

  if (remaining_data_length_ == 0) {
    // If the FIN flag is set, or this ends a header block which set FIN,
    // inform the visitor of EOF via a 0-length data frame.
    if (expect_continuation_ == 0 &&
        ((current_frame_flags_ & CONTROL_FLAG_FIN) != 0 ||
         end_stream_when_done_)) {
      end_stream_when_done_ = false;
      visitor_->OnStreamEnd(current_frame_stream_id_);
    }
    CHANGE_STATE(SPDY_FRAME_COMPLETE);
  }
  return original_len - len;
}

size_t SpdyFramer::ProcessDataFramePayload(const char* data, size_t len) {
  size_t original_len = len;
  if (remaining_data_length_ - remaining_padding_payload_length_ > 0) {
    size_t amount_to_forward = std::min(
        remaining_data_length_ - remaining_padding_payload_length_, len);
    if (amount_to_forward && state_ != SPDY_IGNORE_REMAINING_PAYLOAD) {
      // Only inform the visitor if there is data.
      if (amount_to_forward) {
        visitor_->OnStreamFrameData(current_frame_stream_id_, data,
                                    amount_to_forward);
      }
    }
    data += amount_to_forward;
    len -= amount_to_forward;
    remaining_data_length_ -= amount_to_forward;
  }

  if (remaining_data_length_ == remaining_padding_payload_length_) {
    CHANGE_STATE(SPDY_CONSUME_PADDING);
  }
  return original_len - len;
}

size_t SpdyFramer::ProcessExtensionFramePayload(const char* data, size_t len) {
  DCHECK_EQ(SPDY_EXTENSION_FRAME_PAYLOAD, state_);
  DCHECK(extension_ != nullptr);
  size_t original_len = len;
  if (remaining_data_length_ > 0) {
    size_t amount_to_forward = std::min(remaining_data_length_, len);
    if (amount_to_forward && state_ != SPDY_IGNORE_REMAINING_PAYLOAD) {
      // Only inform the visitor if there is data.
      extension_->OnFramePayload(data, amount_to_forward);
    }
    remaining_data_length_ -= amount_to_forward;
    len -= amount_to_forward;
  }

  if (remaining_data_length_ == 0) {
    CHANGE_STATE(SPDY_FRAME_COMPLETE);
  }
  return original_len - len;
}

size_t SpdyFramer::ProcessIgnoredControlFramePayload(/*const char* data,*/
                                                     size_t len) {
  size_t original_len = len;
  if (remaining_data_length_ > 0) {
    size_t amount_to_ignore = std::min(remaining_data_length_, len);
    len -= amount_to_ignore;
    remaining_data_length_ -= amount_to_ignore;
  }

  if (remaining_data_length_ == 0) {
    CHANGE_STATE(SPDY_FRAME_COMPLETE);
  }
  return original_len - len;
}

SpdyFramer::SpdyFrameIterator::SpdyFrameIterator(SpdyFramer* framer)
    : framer_(framer),
      is_first_frame_(true),
      has_next_frame_(true),
      debug_total_size_(0) {}

SpdyFramer::SpdyFrameIterator::~SpdyFrameIterator() {}

size_t SpdyFramer::SpdyFrameIterator::NextFrame(ZeroCopyOutputBuffer* output) {
  const SpdyFrameIR* frame_ir = GetIR();
  if (frame_ir == nullptr) {
    LOG(WARNING) << "frame_ir doesn't exist.";
    return false;
  }
  if (!has_next_frame_) {
    SPDY_BUG << "SpdyFramer::SpdyFrameIterator::NextFrame called without "
             << "a next frame.";
    return false;
  }

  size_t size_without_block = is_first_frame_
                                  ? GetFrameSizeSansBlock()
                                  : framer_->GetContinuationMinimumSize();
  auto encoding = SpdyMakeUnique<SpdyString>();
  encoder_->Next(kMaxControlFrameSize - size_without_block, encoding.get());
  has_next_frame_ = encoder_->HasNext();

  if (framer_->debug_visitor_ != nullptr) {
    debug_total_size_ += size_without_block;
    debug_total_size_ += encoding->size();
    if (!has_next_frame_) {
      auto* header_block_frame_ir =
          static_cast<const SpdyFrameWithHeaderBlockIR*>(frame_ir);
      // TODO(birenroy) are these (here and below) still necessary?
      // HTTP2 uses HPACK for header compression. However, continue to
      // use GetSerializedLength() for an apples-to-apples comparision of
      // compression performance between HPACK and SPDY w/ deflate.
      size_t debug_payload_len =
          framer_->GetSerializedLength(&header_block_frame_ir->header_block());
      framer_->debug_visitor_->OnSendCompressedFrame(
          frame_ir->stream_id(), frame_ir->frame_type(), debug_payload_len,
          debug_total_size_);
    }
  }

  framer_->SetIsLastFrame(!has_next_frame_);
  const size_t free_bytes_before = output->BytesFree();
  bool ok = false;
  if (is_first_frame_) {
    is_first_frame_ = false;
    ok = SerializeGivenEncoding(*encoding, output);
  } else {
    SpdyContinuationIR continuation_ir(frame_ir->stream_id());
    continuation_ir.take_encoding(std::move(encoding));
    ok = framer_->SerializeContinuation(continuation_ir, output);
  }
  return ok ? free_bytes_before - output->BytesFree() : 0;
}

bool SpdyFramer::SpdyFrameIterator::HasNextFrame() const {
  return has_next_frame_;
}

SpdyFramer::SpdyHeaderFrameIterator::SpdyHeaderFrameIterator(
    SpdyFramer* framer,
    std::unique_ptr<const SpdyHeadersIR> headers_ir)
    : SpdyFrameIterator(framer), headers_ir_(std::move(headers_ir)) {
  SetEncoder(headers_ir_.get());
  GetFramer()->SetOverwriteLastFrame(true);
}

SpdyFramer::SpdyHeaderFrameIterator::~SpdyHeaderFrameIterator() {}

const SpdyFrameIR* SpdyFramer::SpdyHeaderFrameIterator::GetIR() const {
  return headers_ir_.get();
}

size_t SpdyFramer::SpdyHeaderFrameIterator::GetFrameSizeSansBlock() const {
  return GetFramer()->GetHeaderFrameSizeSansBlock(*headers_ir_);
}

bool SpdyFramer::SpdyHeaderFrameIterator::SerializeGivenEncoding(
    const SpdyString& encoding,
    ZeroCopyOutputBuffer* output) const {
  return GetFramer()->SerializeHeadersGivenEncoding(*headers_ir_, encoding,
                                                    output);
}

SpdyFramer::SpdyPushPromiseFrameIterator::SpdyPushPromiseFrameIterator(
    SpdyFramer* framer,
    std::unique_ptr<const SpdyPushPromiseIR> push_promise_ir)
    : SpdyFrameIterator(framer), push_promise_ir_(std::move(push_promise_ir)) {
  SetEncoder(push_promise_ir_.get());
  GetFramer()->SetOverwriteLastFrame(true);
}

SpdyFramer::SpdyPushPromiseFrameIterator::~SpdyPushPromiseFrameIterator() {}

const SpdyFrameIR* SpdyFramer::SpdyPushPromiseFrameIterator::GetIR() const {
  return push_promise_ir_.get();
}

size_t SpdyFramer::SpdyPushPromiseFrameIterator::GetFrameSizeSansBlock() const {
  return GetFramer()->GetPushPromiseFrameSizeSansBlock(*push_promise_ir_);
}

bool SpdyFramer::SpdyPushPromiseFrameIterator::SerializeGivenEncoding(
    const SpdyString& encoding,
    ZeroCopyOutputBuffer* output) const {
  return GetFramer()->SerializePushPromiseGivenEncoding(*push_promise_ir_,
                                                        encoding, output);
}

SpdyFramer::SpdyControlFrameIterator::SpdyControlFrameIterator(
    SpdyFramer* framer,
    std::unique_ptr<const SpdyFrameIR> frame_ir)
    : framer_(framer), frame_ir_(std::move(frame_ir)) {}

SpdyFramer::SpdyControlFrameIterator::~SpdyControlFrameIterator() {}

size_t SpdyFramer::SpdyControlFrameIterator::NextFrame(
    ZeroCopyOutputBuffer* output) {
  size_t size_written = framer_->SerializeFrame(*frame_ir_, output);
  has_next_frame_ = false;
  return size_written;
}

bool SpdyFramer::SpdyControlFrameIterator::HasNextFrame() const {
  return has_next_frame_;
}

const SpdyFrameIR* SpdyFramer::SpdyControlFrameIterator::GetIR() const {
  return frame_ir_.get();
}

// TODO(yasong): remove all the static_casts.
std::unique_ptr<SpdyFrameSequence> SpdyFramer::CreateIterator(
    SpdyFramer* framer,
    std::unique_ptr<const SpdyFrameIR> frame_ir) {
  std::unique_ptr<SpdyFrameSequence> result = nullptr;
  switch (frame_ir->frame_type()) {
    case SpdyFrameType::HEADERS: {
      result = SpdyMakeUnique<SpdyHeaderFrameIterator>(
          framer, SpdyWrapUnique(
                      static_cast<const SpdyHeadersIR*>(frame_ir.release())));
      break;
    }
    case SpdyFrameType::PUSH_PROMISE: {
      result = SpdyMakeUnique<SpdyPushPromiseFrameIterator>(
          framer, SpdyWrapUnique(static_cast<const SpdyPushPromiseIR*>(
                      frame_ir.release())));
      break;
    }
    case SpdyFrameType::DATA: {
      DVLOG(1) << "Serialize a stream end DATA frame for VTL";
      // FALLTHROUGH_INTENDED
    }
    default: {
      result =
          SpdyMakeUnique<SpdyControlFrameIterator>(framer, std::move(frame_ir));
    }
  }
  return result;
}

void SpdyFramer::SerializeDataBuilderHelper(const SpdyDataIR& data_ir,
                                            uint8_t* flags,
                                            int* num_padding_fields,
                                            size_t* size_with_padding) const {
  if (data_ir.fin()) {
    *flags = DATA_FLAG_FIN;
  }

  if (data_ir.padded()) {
    *flags = *flags | DATA_FLAG_PADDED;
    ++*num_padding_fields;
  }

  *size_with_padding = *num_padding_fields + data_ir.data_len() +
                       data_ir.padding_payload_len() +
                       GetDataFrameMinimumSize();
}

SpdySerializedFrame SpdyFramer::SerializeData(const SpdyDataIR& data_ir) const {
  uint8_t flags = DATA_FLAG_NONE;
  int num_padding_fields = 0;
  size_t size_with_padding = 0;
  SerializeDataBuilderHelper(data_ir, &flags, &num_padding_fields,
                             &size_with_padding);

  SpdyFrameBuilder builder(size_with_padding);
  builder.BeginNewFrame(*this, SpdyFrameType::DATA, flags, data_ir.stream_id());
  if (data_ir.padded()) {
    builder.WriteUInt8(data_ir.padding_payload_len() & 0xff);
  }
  builder.WriteBytes(data_ir.data(), data_ir.data_len());
  if (data_ir.padding_payload_len() > 0) {
    SpdyString padding(data_ir.padding_payload_len(), 0);
    builder.WriteBytes(padding.data(), padding.length());
  }
  DCHECK_EQ(size_with_padding, builder.length());
  return builder.take();
}

void SpdyFramer::SerializeDataFrameHeaderWithPaddingLengthFieldBuilderHelper(
    const SpdyDataIR& data_ir,
    uint8_t* flags,
    size_t* frame_size,
    size_t* num_padding_fields) const {
  *flags = DATA_FLAG_NONE;
  if (data_ir.fin()) {
    *flags = DATA_FLAG_FIN;
  }

  *frame_size = GetDataFrameMinimumSize();
  if (data_ir.padded()) {
    *flags = *flags | DATA_FLAG_PADDED;
    ++(*num_padding_fields);
    *frame_size = *frame_size + *num_padding_fields;
  }
}

SpdySerializedFrame SpdyFramer::SerializeDataFrameHeaderWithPaddingLengthField(
    const SpdyDataIR& data_ir) const {
  uint8_t flags = DATA_FLAG_NONE;
  size_t frame_size = 0;
  size_t num_padding_fields = 0;
  SerializeDataFrameHeaderWithPaddingLengthFieldBuilderHelper(
      data_ir, &flags, &frame_size, &num_padding_fields);

  SpdyFrameBuilder builder(frame_size);
  builder.BeginNewFrame(
      *this, SpdyFrameType::DATA, flags, data_ir.stream_id(),
      num_padding_fields + data_ir.data_len() + data_ir.padding_payload_len());
  if (data_ir.padded()) {
    builder.WriteUInt8(data_ir.padding_payload_len() & 0xff);
  }
  DCHECK_EQ(frame_size, builder.length());
  return builder.take();
}

SpdySerializedFrame SpdyFramer::SerializeRstStream(
    const SpdyRstStreamIR& rst_stream) const {
  size_t expected_length = GetRstStreamSize();
  SpdyFrameBuilder builder(expected_length);

  builder.BeginNewFrame(*this, SpdyFrameType::RST_STREAM, 0,
                        rst_stream.stream_id());

  builder.WriteUInt32(rst_stream.error_code());

  DCHECK_EQ(expected_length, builder.length());
  return builder.take();
}

void SpdyFramer::SerializeSettingsBuilderHelper(const SpdySettingsIR& settings,
                                                uint8_t* flags,
                                                const SettingsMap* values,
                                                size_t* size) const {
  if (settings.is_ack()) {
    *flags = *flags | SETTINGS_FLAG_ACK;
  }
  *size =
      GetSettingsMinimumSize() + (values->size() * kOneSettingParameterSize);
}

SpdySerializedFrame SpdyFramer::SerializeSettings(
    const SpdySettingsIR& settings) const {
  uint8_t flags = 0;
  // Size, in bytes, of this SETTINGS frame.
  size_t size = 0;
  const SettingsMap* values = &(settings.values());
  SerializeSettingsBuilderHelper(settings, &flags, values, &size);
  SpdyFrameBuilder builder(size);
  builder.BeginNewFrame(*this, SpdyFrameType::SETTINGS, flags, 0);

  // If this is an ACK, payload should be empty.
  if (settings.is_ack()) {
    return builder.take();
  }

  DCHECK_EQ(GetSettingsMinimumSize(), builder.length());
  for (SettingsMap::const_iterator it = values->begin(); it != values->end();
       ++it) {
    int setting_id = it->first;
    DCHECK_GE(setting_id, 0);
    builder.WriteUInt16(static_cast<uint16_t>(setting_id));
    builder.WriteUInt32(it->second);
  }
  DCHECK_EQ(size, builder.length());
  return builder.take();
}

SpdySerializedFrame SpdyFramer::SerializePing(const SpdyPingIR& ping) const {
  SpdyFrameBuilder builder(GetPingSize());
  uint8_t flags = 0;
  if (ping.is_ack()) {
    flags |= PING_FLAG_ACK;
  }
  builder.BeginNewFrame(*this, SpdyFrameType::PING, flags, 0);
  builder.WriteUInt64(ping.id());
  DCHECK_EQ(GetPingSize(), builder.length());
  return builder.take();
}

SpdySerializedFrame SpdyFramer::SerializeGoAway(
    const SpdyGoAwayIR& goaway) const {
  // Compute the output buffer size, take opaque data into account.
  size_t expected_length = GetGoAwayMinimumSize();
  expected_length += goaway.description().size();
  SpdyFrameBuilder builder(expected_length);

  // Serialize the GOAWAY frame.
  builder.BeginNewFrame(*this, SpdyFrameType::GOAWAY, 0, 0);

  // GOAWAY frames specify the last good stream id.
  builder.WriteUInt32(goaway.last_good_stream_id());

  // GOAWAY frames also specify the error code.
  builder.WriteUInt32(goaway.error_code());

  // GOAWAY frames may also specify opaque data.
  if (!goaway.description().empty()) {
    builder.WriteBytes(goaway.description().data(),
                       goaway.description().size());
  }

  DCHECK_EQ(expected_length, builder.length());
  return builder.take();
}

void SpdyFramer::SerializeHeadersBuilderHelper(const SpdyHeadersIR& headers,
                                               uint8_t* flags,
                                               size_t* size,
                                               SpdyString* hpack_encoding,
                                               int* weight,
                                               size_t* length_field) {
  if (headers.fin()) {
    *flags = *flags | CONTROL_FLAG_FIN;
  }
  // This will get overwritten if we overflow into a CONTINUATION frame.
  *flags = *flags | HEADERS_FLAG_END_HEADERS;
  if (headers.has_priority()) {
    *flags = *flags | HEADERS_FLAG_PRIORITY;
  }
  if (headers.padded()) {
    *flags = *flags | HEADERS_FLAG_PADDED;
  }

  *size = GetHeadersMinimumSize();

  if (headers.padded()) {
    *size = *size + kPadLengthFieldSize;
    *size = *size + headers.padding_payload_len();
  }

  if (headers.has_priority()) {
    *weight = ClampHttp2Weight(headers.weight());
    *size = *size + 5;
  }

  GetHpackEncoder()->EncodeHeaderSet(headers.header_block(), hpack_encoding);
  *size = *size + hpack_encoding->size();
  if (*size > kMaxControlFrameSize) {
    *size = *size + GetNumberRequiredContinuationFrames(*size) *
                        GetContinuationMinimumSize();
    *flags = *flags & ~HEADERS_FLAG_END_HEADERS;
  }
  // Compute frame length field.
  if (headers.padded()) {
    *length_field = *length_field + 1;  // Padding length field.
  }
  if (headers.has_priority()) {
    *length_field = *length_field + 4;  // Dependency field.
    *length_field = *length_field + 1;  // Weight field.
  }
  *length_field = *length_field + headers.padding_payload_len();
  *length_field = *length_field + hpack_encoding->size();
  // If the HEADERS frame with payload would exceed the max frame size, then
  // WritePayloadWithContinuation() will serialize CONTINUATION frames as
  // necessary.
  *length_field =
      std::min(*length_field, kMaxControlFrameSize - GetFrameHeaderSize());
}

SpdySerializedFrame SpdyFramer::SerializeHeaders(const SpdyHeadersIR& headers) {
  uint8_t flags = 0;
  // The size of this frame, including padding (if there is any) and
  // variable-length header block.
  size_t size = 0;
  SpdyString hpack_encoding;
  int weight = 0;
  size_t length_field = 0;
  SerializeHeadersBuilderHelper(headers, &flags, &size, &hpack_encoding,
                                &weight, &length_field);

  SpdyFrameBuilder builder(size);
  builder.BeginNewFrame(*this, SpdyFrameType::HEADERS, flags,
                        headers.stream_id(), length_field);

  DCHECK_EQ(GetHeadersMinimumSize(), builder.length());

  int padding_payload_len = 0;
  if (headers.padded()) {
    builder.WriteUInt8(headers.padding_payload_len());
    padding_payload_len = headers.padding_payload_len();
  }
  if (headers.has_priority()) {
    builder.WriteUInt32(PackStreamDependencyValues(headers.exclusive(),
                                                   headers.parent_stream_id()));
    // Per RFC 7540 section 6.3, serialized weight value is actual value - 1.
    builder.WriteUInt8(weight - 1);
  }
  WritePayloadWithContinuation(&builder, hpack_encoding, headers.stream_id(),
                               SpdyFrameType::HEADERS, padding_payload_len);

  if (debug_visitor_) {
    // HTTP2 uses HPACK for header compression. However, continue to
    // use GetSerializedLength() for an apples-to-apples comparision of
    // compression performance between HPACK and SPDY w/ deflate.
    const size_t payload_len = GetSerializedLength(&(headers.header_block()));
    debug_visitor_->OnSendCompressedFrame(headers.stream_id(),
                                          SpdyFrameType::HEADERS, payload_len,
                                          builder.length());
  }

  return builder.take();
}

SpdySerializedFrame SpdyFramer::SerializeWindowUpdate(
    const SpdyWindowUpdateIR& window_update) const {
  SpdyFrameBuilder builder(GetWindowUpdateSize());
  builder.BeginNewFrame(*this, SpdyFrameType::WINDOW_UPDATE, kNoFlags,
                        window_update.stream_id());
  builder.WriteUInt32(window_update.delta());
  DCHECK_EQ(GetWindowUpdateSize(), builder.length());
  return builder.take();
}

void SpdyFramer::SerializePushPromiseBuilderHelper(
    const SpdyPushPromiseIR& push_promise,
    uint8_t* flags,
    SpdyString* hpack_encoding,
    size_t* size) {
  *flags = 0;
  // This will get overwritten if we overflow into a CONTINUATION frame.
  *flags = *flags | PUSH_PROMISE_FLAG_END_PUSH_PROMISE;
  // The size of this frame, including variable-length name-value block.
  *size = GetPushPromiseMinimumSize();

  if (push_promise.padded()) {
    *flags = *flags | PUSH_PROMISE_FLAG_PADDED;
    *size = *size + kPadLengthFieldSize;
    *size = *size + push_promise.padding_payload_len();
  }

  GetHpackEncoder()->EncodeHeaderSet(push_promise.header_block(),
                                     hpack_encoding);
  *size = *size + hpack_encoding->size();
  if (*size > kMaxControlFrameSize) {
    *size = *size + GetNumberRequiredContinuationFrames(*size) *
                        GetContinuationMinimumSize();
    *flags = *flags & ~PUSH_PROMISE_FLAG_END_PUSH_PROMISE;
  }
}

SpdySerializedFrame SpdyFramer::SerializePushPromise(
    const SpdyPushPromiseIR& push_promise) {
  uint8_t flags = 0;
  size_t size = 0;
  SpdyString hpack_encoding;
  SerializePushPromiseBuilderHelper(push_promise, &flags, &hpack_encoding,
                                    &size);

  SpdyFrameBuilder builder(size);
  size_t length = std::min(size, kMaxControlFrameSize) - GetFrameHeaderSize();
  builder.BeginNewFrame(*this, SpdyFrameType::PUSH_PROMISE, flags,
                        push_promise.stream_id(), length);
  int padding_payload_len = 0;
  if (push_promise.padded()) {
    builder.WriteUInt8(push_promise.padding_payload_len());
    builder.WriteUInt32(push_promise.promised_stream_id());
    DCHECK_EQ(GetPushPromiseMinimumSize() + kPadLengthFieldSize,
              builder.length());

    padding_payload_len = push_promise.padding_payload_len();
  } else {
    builder.WriteUInt32(push_promise.promised_stream_id());
    DCHECK_EQ(GetPushPromiseMinimumSize(), builder.length());
  }

  WritePayloadWithContinuation(
      &builder, hpack_encoding, push_promise.stream_id(),
      SpdyFrameType::PUSH_PROMISE, padding_payload_len);

  if (debug_visitor_) {
    // HTTP2 uses HPACK for header compression. However, continue to
    // use GetSerializedLength() for an apples-to-apples comparision of
    // compression performance between HPACK and SPDY w/ deflate.
    const size_t payload_len =
        GetSerializedLength(&(push_promise.header_block()));
    debug_visitor_->OnSendCompressedFrame(push_promise.stream_id(),
                                          SpdyFrameType::PUSH_PROMISE,
                                          payload_len, builder.length());
  }

  return builder.take();
}

bool SpdyFramer::SerializeHeadersGivenEncoding(
    const SpdyHeadersIR& headers,
    const SpdyString& encoding,
    ZeroCopyOutputBuffer* output) const {
  size_t frame_size = GetHeaderFrameSizeSansBlock(headers) + encoding.size();
  SpdyFrameBuilder builder(frame_size, output);
  bool ret = builder.BeginNewFrame(
      *this, SpdyFrameType::HEADERS, SerializeHeaderFrameFlags(headers),
      headers.stream_id(), frame_size - GetFrameHeaderSize());
  DCHECK_EQ(GetFrameHeaderSize(), builder.length());

  if (ret && headers.padded()) {
    ret &= builder.WriteUInt8(headers.padding_payload_len());
  }

  if (ret && headers.has_priority()) {
    int weight = ClampHttp2Weight(headers.weight());
    ret &= builder.WriteUInt32(PackStreamDependencyValues(
        headers.exclusive(), headers.parent_stream_id()));
    // Per RFC 7540 section 6.3, serialized weight value is actual value - 1.
    ret &= builder.WriteUInt8(weight - 1);
  }

  if (ret) {
    ret &= builder.WriteBytes(encoding.data(), encoding.size());
  }

  if (ret && headers.padding_payload_len() > 0) {
    SpdyString padding(headers.padding_payload_len(), 0);
    ret &= builder.WriteBytes(padding.data(), padding.length());
  }

  if (!ret) {
    DLOG(WARNING) << "Failed to build HEADERS. Not enough space in output";
  }
  return ret;
}

SpdySerializedFrame SpdyFramer::SerializeContinuation(
    const SpdyContinuationIR& continuation) const {
  const SpdyString& encoding = continuation.encoding();
  size_t frame_size = GetContinuationMinimumSize() + encoding.size();
  SpdyFrameBuilder builder(frame_size);
  uint8_t flags = ((overwrite_last_frame_ && is_last_frame_) ||
                   (!overwrite_last_frame_ && continuation.end_headers()))
                      ? HEADERS_FLAG_END_HEADERS
                      : 0;
  builder.BeginNewFrame(*this, SpdyFrameType::CONTINUATION, flags,
                        continuation.stream_id());
  DCHECK_EQ(GetFrameHeaderSize(), builder.length());

  builder.WriteBytes(encoding.data(), encoding.size());
  return builder.take();
}

void SpdyFramer::SerializeAltSvcBuilderHelper(const SpdyAltSvcIR& altsvc_ir,
                                              SpdyString* value,
                                              size_t* size) const {
  *size = GetAltSvcMinimumSize();
  *size = *size + altsvc_ir.origin().length();
  *value = SpdyAltSvcWireFormat::SerializeHeaderFieldValue(
      altsvc_ir.altsvc_vector());
  *size = *size + value->length();
}

SpdySerializedFrame SpdyFramer::SerializeAltSvc(const SpdyAltSvcIR& altsvc_ir) {
  SpdyString value;
  size_t size = 0;
  SerializeAltSvcBuilderHelper(altsvc_ir, &value, &size);
  SpdyFrameBuilder builder(size);
  builder.BeginNewFrame(*this, SpdyFrameType::ALTSVC, kNoFlags,
                        altsvc_ir.stream_id());

  builder.WriteUInt16(altsvc_ir.origin().length());
  builder.WriteBytes(altsvc_ir.origin().data(), altsvc_ir.origin().length());
  builder.WriteBytes(value.data(), value.length());
  DCHECK_LT(GetAltSvcMinimumSize(), builder.length());
  return builder.take();
}

SpdySerializedFrame SpdyFramer::SerializePriority(
    const SpdyPriorityIR& priority) const {
  size_t size = GetPrioritySize();

  SpdyFrameBuilder builder(size);
  builder.BeginNewFrame(*this, SpdyFrameType::PRIORITY, kNoFlags,
                        priority.stream_id());

  builder.WriteUInt32(PackStreamDependencyValues(priority.exclusive(),
                                                 priority.parent_stream_id()));
  // Per RFC 7540 section 6.3, serialized weight value is actual value - 1.
  builder.WriteUInt8(priority.weight() - 1);
  DCHECK_EQ(GetPrioritySize(), builder.length());
  return builder.take();
}

namespace {

class FrameSerializationVisitor : public SpdyFrameVisitor {
 public:
  explicit FrameSerializationVisitor(SpdyFramer* framer)
      : framer_(framer), frame_() {}
  ~FrameSerializationVisitor() override {}

  SpdySerializedFrame ReleaseSerializedFrame() { return std::move(frame_); }

  void VisitData(const SpdyDataIR& data) override {
    frame_ = framer_->SerializeData(data);
  }
  void VisitRstStream(const SpdyRstStreamIR& rst_stream) override {
    frame_ = framer_->SerializeRstStream(rst_stream);
  }
  void VisitSettings(const SpdySettingsIR& settings) override {
    frame_ = framer_->SerializeSettings(settings);
  }
  void VisitPing(const SpdyPingIR& ping) override {
    frame_ = framer_->SerializePing(ping);
  }
  void VisitGoAway(const SpdyGoAwayIR& goaway) override {
    frame_ = framer_->SerializeGoAway(goaway);
  }
  void VisitHeaders(const SpdyHeadersIR& headers) override {
    frame_ = framer_->SerializeHeaders(headers);
  }
  void VisitWindowUpdate(const SpdyWindowUpdateIR& window_update) override {
    frame_ = framer_->SerializeWindowUpdate(window_update);
  }
  void VisitPushPromise(const SpdyPushPromiseIR& push_promise) override {
    frame_ = framer_->SerializePushPromise(push_promise);
  }
  void VisitContinuation(const SpdyContinuationIR& continuation) override {
    frame_ = framer_->SerializeContinuation(continuation);
  }
  void VisitAltSvc(const SpdyAltSvcIR& altsvc) override {
    frame_ = framer_->SerializeAltSvc(altsvc);
  }
  void VisitPriority(const SpdyPriorityIR& priority) override {
    frame_ = framer_->SerializePriority(priority);
  }

 private:
  SpdyFramer* framer_;
  SpdySerializedFrame frame_;
};

// TODO(diannahu): Use also in frame serialization.
class FlagsSerializationVisitor : public SpdyFrameVisitor {
 public:
  void VisitData(const SpdyDataIR& data) override {
    flags_ = DATA_FLAG_NONE;
    if (data.fin()) {
      flags_ |= DATA_FLAG_FIN;
    }
    if (data.padded()) {
      flags_ |= DATA_FLAG_PADDED;
    }
  }

  void VisitRstStream(const SpdyRstStreamIR& rst_stream) override {
    flags_ = kNoFlags;
  }

  void VisitSettings(const SpdySettingsIR& settings) override {
    flags_ = kNoFlags;
    if (settings.is_ack()) {
      flags_ |= SETTINGS_FLAG_ACK;
    }
  }

  void VisitPing(const SpdyPingIR& ping) override {
    flags_ = kNoFlags;
    if (ping.is_ack()) {
      flags_ |= PING_FLAG_ACK;
    }
  }

  void VisitGoAway(const SpdyGoAwayIR& goaway) override { flags_ = kNoFlags; }

  // TODO(diannahu): The END_HEADERS flag is incorrect for HEADERS that require
  //     CONTINUATION frames.
  void VisitHeaders(const SpdyHeadersIR& headers) override {
    flags_ = HEADERS_FLAG_END_HEADERS;
    if (headers.fin()) {
      flags_ |= CONTROL_FLAG_FIN;
    }
    if (headers.padded()) {
      flags_ |= HEADERS_FLAG_PADDED;
    }
    if (headers.has_priority()) {
      flags_ |= HEADERS_FLAG_PRIORITY;
    }
  }

  void VisitWindowUpdate(const SpdyWindowUpdateIR& window_update) override {
    flags_ = kNoFlags;
  }

  // TODO(diannahu): The END_PUSH_PROMISE flag is incorrect for PUSH_PROMISEs
  //     that require CONTINUATION frames.
  void VisitPushPromise(const SpdyPushPromiseIR& push_promise) override {
    flags_ = PUSH_PROMISE_FLAG_END_PUSH_PROMISE;
    if (push_promise.padded()) {
      flags_ |= PUSH_PROMISE_FLAG_PADDED;
    }
  }

  // TODO(diannahu): The END_HEADERS flag is incorrect for CONTINUATIONs that
  //     require CONTINUATION frames.
  void VisitContinuation(const SpdyContinuationIR& continuation) override {
    flags_ = HEADERS_FLAG_END_HEADERS;
  }

  void VisitAltSvc(const SpdyAltSvcIR& altsvc) override { flags_ = kNoFlags; }

  void VisitPriority(const SpdyPriorityIR& priority) override {
    flags_ = kNoFlags;
  }

  uint8_t flags() const { return flags_; }

 private:
  uint8_t flags_ = kNoFlags;
};

}  // namespace

SpdySerializedFrame SpdyFramer::SerializeFrame(const SpdyFrameIR& frame) {
  FrameSerializationVisitor visitor(this);
  frame.Visit(&visitor);
  return visitor.ReleaseSerializedFrame();
}

uint8_t SpdyFramer::GetSerializedFlags(const SpdyFrameIR& frame) {
  FlagsSerializationVisitor visitor;
  frame.Visit(&visitor);
  return visitor.flags();
}

bool SpdyFramer::SerializeData(const SpdyDataIR& data_ir,
                               ZeroCopyOutputBuffer* output) const {
  uint8_t flags = DATA_FLAG_NONE;
  int num_padding_fields = 0;
  size_t size_with_padding = 0;
  SerializeDataBuilderHelper(data_ir, &flags, &num_padding_fields,
                             &size_with_padding);
  SpdyFrameBuilder builder(size_with_padding, output);

  bool ok = builder.BeginNewFrame(*this, SpdyFrameType::DATA, flags,
                                  data_ir.stream_id());

  if (data_ir.padded()) {
    ok = ok && builder.WriteUInt8(data_ir.padding_payload_len() & 0xff);
  }

  ok = ok && builder.WriteBytes(data_ir.data(), data_ir.data_len());
  if (data_ir.padding_payload_len() > 0) {
    SpdyString padding;
    padding = SpdyString(data_ir.padding_payload_len(), 0);
    ok = ok && builder.WriteBytes(padding.data(), padding.length());
  }
  DCHECK_EQ(size_with_padding, builder.length());
  return ok;
}

bool SpdyFramer::SerializeDataFrameHeaderWithPaddingLengthField(
    const SpdyDataIR& data_ir,
    ZeroCopyOutputBuffer* output) const {
  uint8_t flags = DATA_FLAG_NONE;
  size_t frame_size = 0;
  size_t num_padding_fields = 0;
  SerializeDataFrameHeaderWithPaddingLengthFieldBuilderHelper(
      data_ir, &flags, &frame_size, &num_padding_fields);

  SpdyFrameBuilder builder(frame_size, output);
  bool ok = true;
  ok = ok && builder.BeginNewFrame(*this, SpdyFrameType::DATA, flags,
                                   data_ir.stream_id(),
                                   num_padding_fields + data_ir.data_len() +
                                       data_ir.padding_payload_len());
  if (data_ir.padded()) {
    ok = ok && builder.WriteUInt8(data_ir.padding_payload_len() & 0xff);
  }
  DCHECK_EQ(frame_size, builder.length());
  return ok;
}

bool SpdyFramer::SerializeRstStream(const SpdyRstStreamIR& rst_stream,
                                    ZeroCopyOutputBuffer* output) const {
  size_t expected_length = GetRstStreamSize();
  SpdyFrameBuilder builder(expected_length, output);
  bool ok = builder.BeginNewFrame(*this, SpdyFrameType::RST_STREAM, 0,
                                  rst_stream.stream_id());
  ok = ok && builder.WriteUInt32(rst_stream.error_code());

  DCHECK_EQ(expected_length, builder.length());
  return ok;
}

bool SpdyFramer::SerializeSettings(const SpdySettingsIR& settings,
                                   ZeroCopyOutputBuffer* output) const {
  uint8_t flags = 0;
  // Size, in bytes, of this SETTINGS frame.
  size_t size = 0;
  const SettingsMap* values = &(settings.values());
  SerializeSettingsBuilderHelper(settings, &flags, values, &size);
  SpdyFrameBuilder builder(size, output);
  bool ok = builder.BeginNewFrame(*this, SpdyFrameType::SETTINGS, flags, 0);

  // If this is an ACK, payload should be empty.
  if (settings.is_ack()) {
    return ok;
  }

  DCHECK_EQ(GetSettingsMinimumSize(), builder.length());
  for (SettingsMap::const_iterator it = values->begin(); it != values->end();
       ++it) {
    int setting_id = it->first;
    DCHECK_GE(setting_id, 0);
    ok = ok && builder.WriteUInt16(static_cast<uint16_t>(setting_id)) &&
         builder.WriteUInt32(it->second);
  }
  DCHECK_EQ(size, builder.length());
  return ok;
}

bool SpdyFramer::SerializePing(const SpdyPingIR& ping,
                               ZeroCopyOutputBuffer* output) const {
  SpdyFrameBuilder builder(GetPingSize(), output);
  uint8_t flags = 0;
  if (ping.is_ack()) {
    flags |= PING_FLAG_ACK;
  }
  bool ok = builder.BeginNewFrame(*this, SpdyFrameType::PING, flags, 0);
  ok = ok && builder.WriteUInt64(ping.id());
  DCHECK_EQ(GetPingSize(), builder.length());
  return ok;
}

bool SpdyFramer::SerializeGoAway(const SpdyGoAwayIR& goaway,
                                 ZeroCopyOutputBuffer* output) const {
  // Compute the output buffer size, take opaque data into account.
  size_t expected_length = GetGoAwayMinimumSize();
  expected_length += goaway.description().size();
  SpdyFrameBuilder builder(expected_length, output);

  // Serialize the GOAWAY frame.
  bool ok = builder.BeginNewFrame(*this, SpdyFrameType::GOAWAY, 0, 0);

  // GOAWAY frames specify the last good stream id.
  ok = ok && builder.WriteUInt32(goaway.last_good_stream_id()) &&
       // GOAWAY frames also specify the error status code.
       builder.WriteUInt32(goaway.error_code());

  // GOAWAY frames may also specify opaque data.
  if (!goaway.description().empty()) {
    ok = ok && builder.WriteBytes(goaway.description().data(),
                                  goaway.description().size());
  }

  DCHECK_EQ(expected_length, builder.length());
  return ok;
}

bool SpdyFramer::SerializeHeaders(const SpdyHeadersIR& headers,
                                  ZeroCopyOutputBuffer* output) {
  uint8_t flags = 0;
  // The size of this frame, including padding (if there is any) and
  // variable-length header block.
  size_t size = 0;
  SpdyString hpack_encoding;
  int weight = 0;
  size_t length_field = 0;
  SerializeHeadersBuilderHelper(headers, &flags, &size, &hpack_encoding,
                                &weight, &length_field);

  bool ok = true;
  SpdyFrameBuilder builder(size, output);
  ok = ok && builder.BeginNewFrame(*this, SpdyFrameType::HEADERS, flags,
                                   headers.stream_id(), length_field);
  DCHECK_EQ(GetHeadersMinimumSize(), builder.length());

  int padding_payload_len = 0;
  if (headers.padded()) {
    ok = ok && builder.WriteUInt8(headers.padding_payload_len());
    padding_payload_len = headers.padding_payload_len();
  }
  if (headers.has_priority()) {
    ok = ok &&
         builder.WriteUInt32(PackStreamDependencyValues(
             headers.exclusive(), headers.parent_stream_id())) &&
         // Per RFC 7540 section 6.3, serialized weight value is weight - 1.
         builder.WriteUInt8(weight - 1);
  }
  ok = ok && WritePayloadWithContinuation(
                 &builder, hpack_encoding, headers.stream_id(),
                 SpdyFrameType::HEADERS, padding_payload_len);

  if (debug_visitor_) {
    // HTTP2 uses HPACK for header compression. However, continue to
    // use GetSerializedLength() for an apples-to-apples comparision of
    // compression performance between HPACK and SPDY w/ deflate.
    const size_t payload_len = GetSerializedLength(&(headers.header_block()));
    debug_visitor_->OnSendCompressedFrame(headers.stream_id(),
                                          SpdyFrameType::HEADERS, payload_len,
                                          builder.length());
  }

  return ok;
}

bool SpdyFramer::SerializeWindowUpdate(const SpdyWindowUpdateIR& window_update,
                                       ZeroCopyOutputBuffer* output) const {
  SpdyFrameBuilder builder(GetWindowUpdateSize(), output);
  bool ok = builder.BeginNewFrame(*this, SpdyFrameType::WINDOW_UPDATE, kNoFlags,
                                  window_update.stream_id());
  ok = ok && builder.WriteUInt32(window_update.delta());
  DCHECK_EQ(GetWindowUpdateSize(), builder.length());
  return ok;
}

bool SpdyFramer::SerializePushPromise(const SpdyPushPromiseIR& push_promise,
                                      ZeroCopyOutputBuffer* output) {
  uint8_t flags = 0;
  size_t size = 0;
  SpdyString hpack_encoding;
  SerializePushPromiseBuilderHelper(push_promise, &flags, &hpack_encoding,
                                    &size);

  bool ok = true;
  SpdyFrameBuilder builder(size, output);
  size_t length = std::min(size, kMaxControlFrameSize) - GetFrameHeaderSize();
  ok = builder.BeginNewFrame(*this, SpdyFrameType::PUSH_PROMISE, flags,
                             push_promise.stream_id(), length);

  int padding_payload_len = 0;
  if (push_promise.padded()) {
    ok = ok && builder.WriteUInt8(push_promise.padding_payload_len()) &&
         builder.WriteUInt32(push_promise.promised_stream_id());
    DCHECK_EQ(GetPushPromiseMinimumSize() + kPadLengthFieldSize,
              builder.length());

    padding_payload_len = push_promise.padding_payload_len();
  } else {
    ok = ok && builder.WriteUInt32(push_promise.promised_stream_id());
    DCHECK_EQ(GetPushPromiseMinimumSize(), builder.length());
  }

  ok = ok && WritePayloadWithContinuation(
                 &builder, hpack_encoding, push_promise.stream_id(),
                 SpdyFrameType::PUSH_PROMISE, padding_payload_len);

  if (debug_visitor_) {
    // HTTP2 uses HPACK for header compression. However, continue to
    // use GetSerializedLength() for an apples-to-apples comparision of
    // compression performance between HPACK and SPDY w/ deflate.
    const size_t payload_len =
        GetSerializedLength(&(push_promise.header_block()));
    debug_visitor_->OnSendCompressedFrame(push_promise.stream_id(),
                                          SpdyFrameType::PUSH_PROMISE,
                                          payload_len, builder.length());
  }

  return ok;
}

bool SpdyFramer::SerializePushPromiseGivenEncoding(
    const SpdyPushPromiseIR& push_promise,
    const SpdyString& encoding,
    ZeroCopyOutputBuffer* output) const {
  size_t const frame_size =
      GetPushPromiseFrameSizeSansBlock(push_promise) + encoding.size();
  SpdyFrameBuilder builder(frame_size, output);
  bool ok = builder.BeginNewFrame(*this, SpdyFrameType::PUSH_PROMISE,
                                  SerializePushPromiseFrameFlags(push_promise),
                                  push_promise.stream_id(),
                                  frame_size - GetFrameHeaderSize());

  if (push_promise.padded()) {
    ok = ok && builder.WriteUInt8(push_promise.padding_payload_len());
  }
  ok = ok && builder.WriteUInt32(push_promise.promised_stream_id()) &&
       builder.WriteBytes(encoding.data(), encoding.size());
  if (ok && push_promise.padding_payload_len() > 0) {
    SpdyString padding(push_promise.padding_payload_len(), 0);
    ok = builder.WriteBytes(padding.data(), padding.length());
  }

  DLOG_IF(ERROR, !ok) << "Failed to write PUSH_PROMISE encoding, not enough "
                      << "space in output";
  return ok;
}

bool SpdyFramer::SerializeContinuation(const SpdyContinuationIR& continuation,
                                       ZeroCopyOutputBuffer* output) const {
  const SpdyString& encoding = continuation.encoding();
  size_t frame_size = GetContinuationMinimumSize() + encoding.size();
  SpdyFrameBuilder builder(frame_size, output);
  uint8_t flags = ((overwrite_last_frame_ && is_last_frame_) ||
                   (!overwrite_last_frame_ && continuation.end_headers()))
                      ? HEADERS_FLAG_END_HEADERS
                      : 0;
  bool ok = builder.BeginNewFrame(*this, SpdyFrameType::CONTINUATION, flags,
                                  continuation.stream_id(),
                                  frame_size - GetFrameHeaderSize());
  DCHECK_EQ(GetFrameHeaderSize(), builder.length());

  ok = ok && builder.WriteBytes(encoding.data(), encoding.size());
  return ok;
}

bool SpdyFramer::SerializeAltSvc(const SpdyAltSvcIR& altsvc_ir,
                                 ZeroCopyOutputBuffer* output) {
  SpdyString value;
  size_t size = 0;
  SerializeAltSvcBuilderHelper(altsvc_ir, &value, &size);
  SpdyFrameBuilder builder(size, output);
  bool ok = builder.BeginNewFrame(*this, SpdyFrameType::ALTSVC, kNoFlags,
                                  altsvc_ir.stream_id()) &&
            builder.WriteUInt16(altsvc_ir.origin().length()) &&
            builder.WriteBytes(altsvc_ir.origin().data(),
                               altsvc_ir.origin().length()) &&
            builder.WriteBytes(value.data(), value.length());
  DCHECK_LT(GetAltSvcMinimumSize(), builder.length());
  return ok;
}

bool SpdyFramer::SerializePriority(const SpdyPriorityIR& priority,
                                   ZeroCopyOutputBuffer* output) const {
  size_t size = GetPrioritySize();

  SpdyFrameBuilder builder(size, output);
  bool ok = builder.BeginNewFrame(*this, SpdyFrameType::PRIORITY, kNoFlags,
                                  priority.stream_id());
  ok = ok &&
       builder.WriteUInt32(PackStreamDependencyValues(
           priority.exclusive(), priority.parent_stream_id())) &&
       // Per RFC 7540 section 6.3, serialized weight value is actual value - 1.
       builder.WriteUInt8(priority.weight() - 1);
  DCHECK_EQ(GetPrioritySize(), builder.length());
  return ok;
}

namespace {

class FrameSerializationVisitorWithOutput : public SpdyFrameVisitor {
 public:
  explicit FrameSerializationVisitorWithOutput(SpdyFramer* framer,
                                               ZeroCopyOutputBuffer* output)
      : framer_(framer), output_(output), result_(false) {}
  ~FrameSerializationVisitorWithOutput() override {}

  size_t Result() { return result_; }

  void VisitData(const SpdyDataIR& data) override {
    result_ = framer_->SerializeData(data, output_);
  }
  void VisitRstStream(const SpdyRstStreamIR& rst_stream) override {
    result_ = framer_->SerializeRstStream(rst_stream, output_);
  }
  void VisitSettings(const SpdySettingsIR& settings) override {
    result_ = framer_->SerializeSettings(settings, output_);
  }
  void VisitPing(const SpdyPingIR& ping) override {
    result_ = framer_->SerializePing(ping, output_);
  }
  void VisitGoAway(const SpdyGoAwayIR& goaway) override {
    result_ = framer_->SerializeGoAway(goaway, output_);
  }
  void VisitHeaders(const SpdyHeadersIR& headers) override {
    result_ = framer_->SerializeHeaders(headers, output_);
  }
  void VisitWindowUpdate(const SpdyWindowUpdateIR& window_update) override {
    result_ = framer_->SerializeWindowUpdate(window_update, output_);
  }
  void VisitPushPromise(const SpdyPushPromiseIR& push_promise) override {
    result_ = framer_->SerializePushPromise(push_promise, output_);
  }
  void VisitContinuation(const SpdyContinuationIR& continuation) override {
    result_ = framer_->SerializeContinuation(continuation, output_);
  }
  void VisitAltSvc(const SpdyAltSvcIR& altsvc) override {
    result_ = framer_->SerializeAltSvc(altsvc, output_);
  }
  void VisitPriority(const SpdyPriorityIR& priority) override {
    result_ = framer_->SerializePriority(priority, output_);
  }

 private:
  SpdyFramer* framer_;
  ZeroCopyOutputBuffer* output_;
  bool result_;
};

}  // namespace

size_t SpdyFramer::SerializeFrame(const SpdyFrameIR& frame,
                                  ZeroCopyOutputBuffer* output) {
  FrameSerializationVisitorWithOutput visitor(this, output);
  size_t free_bytes_before = output->BytesFree();
  frame.Visit(&visitor);
  return visitor.Result() ? free_bytes_before - output->BytesFree() : 0;
}

size_t SpdyFramer::GetNumberRequiredContinuationFrames(size_t size) {
  DCHECK_GT(size, kMaxControlFrameSize);
  size_t overflow = size - kMaxControlFrameSize;
  size_t payload_size = kMaxControlFrameSize - GetContinuationMinimumSize();
  // This is ceiling(overflow/payload_size) using integer arithmetics.
  return (overflow - 1) / payload_size + 1;
}

size_t SpdyFramer::GetHeaderFrameSizeSansBlock(
    const SpdyHeadersIR& header_ir) const {
  size_t min_size = GetFrameHeaderSize();

  if (header_ir.padded()) {
    min_size += 1;
    min_size += header_ir.padding_payload_len();
  }

  if (header_ir.has_priority()) {
    min_size += 5;
  }

  return min_size;
}

size_t SpdyFramer::GetPushPromiseFrameSizeSansBlock(
    const SpdyPushPromiseIR& push_promise_ir) const {
  size_t size = GetPushPromiseMinimumSize();

  if (push_promise_ir.padded()) {
    size += kPadLengthFieldSize + push_promise_ir.padding_payload_len();
  }

  return size;
}

uint8_t SpdyFramer::SerializeHeaderFrameFlags(
    const SpdyHeadersIR& header_ir) const {
  uint8_t flags = 0;
  if (header_ir.fin()) {
    flags |= CONTROL_FLAG_FIN;
  }

  if ((overwrite_last_frame_ && is_last_frame_) ||
      (!overwrite_last_frame_ && header_ir.end_headers())) {
    flags |= HEADERS_FLAG_END_HEADERS;
  }

  if (header_ir.padded()) {
    flags |= HEADERS_FLAG_PADDED;
  }
  if (header_ir.has_priority()) {
    flags |= HEADERS_FLAG_PRIORITY;
  }
  return flags;
}

uint8_t SpdyFramer::SerializePushPromiseFrameFlags(
    const SpdyPushPromiseIR& push_promise_ir) const {
  uint8_t flags = 0;

  if (push_promise_ir.padded()) {
    flags = flags | PUSH_PROMISE_FLAG_PADDED;
  }

  if ((overwrite_last_frame_ && is_last_frame_) ||
      (!overwrite_last_frame_ && push_promise_ir.end_headers())) {
    flags |= PUSH_PROMISE_FLAG_END_PUSH_PROMISE;
  }

  return flags;
}

bool SpdyFramer::WritePayloadWithContinuation(SpdyFrameBuilder* builder,
                                              const SpdyString& hpack_encoding,
                                              SpdyStreamId stream_id,
                                              SpdyFrameType type,
                                              int padding_payload_len) {
  uint8_t end_flag = 0;
  uint8_t flags = 0;
  if (type == SpdyFrameType::HEADERS) {
    end_flag = HEADERS_FLAG_END_HEADERS;
  } else if (type == SpdyFrameType::PUSH_PROMISE) {
    end_flag = PUSH_PROMISE_FLAG_END_PUSH_PROMISE;
  } else {
    DLOG(FATAL) << "CONTINUATION frames cannot be used with frame type "
                << FrameTypeToString(type);
  }

  // Write all the padding payload and as much of the data payload as possible
  // into the initial frame.
  size_t bytes_remaining = 0;
  bytes_remaining =
      hpack_encoding.size() -
      std::min(hpack_encoding.size(),
               kMaxControlFrameSize - builder->length() - padding_payload_len);
  bool ret = builder->WriteBytes(&hpack_encoding[0],
                                 hpack_encoding.size() - bytes_remaining);
  if (padding_payload_len > 0) {
    SpdyString padding = SpdyString(padding_payload_len, 0);
    ret &= builder->WriteBytes(padding.data(), padding.length());
  }

  // Tack on CONTINUATION frames for the overflow.
  while (bytes_remaining > 0 && ret) {
    size_t bytes_to_write = std::min(
        bytes_remaining, kMaxControlFrameSize - GetContinuationMinimumSize());
    // Write CONTINUATION frame prefix.
    if (bytes_remaining == bytes_to_write) {
      flags |= end_flag;
    }
    ret &= builder->BeginNewFrame(*this, SpdyFrameType::CONTINUATION, flags,
                                  stream_id, bytes_to_write);
    // Write payload fragment.
    ret &= builder->WriteBytes(
        &hpack_encoding[hpack_encoding.size() - bytes_remaining],
        bytes_to_write);
    bytes_remaining -= bytes_to_write;
  }
  return ret;
}

HpackEncoder* SpdyFramer::GetHpackEncoder() {
  if (hpack_encoder_.get() == nullptr) {
    hpack_encoder_ = SpdyMakeUnique<HpackEncoder>(ObtainHpackHuffmanTable());
    if (!compression_enabled()) {
      hpack_encoder_->DisableCompression();
    }
  }
  return hpack_encoder_.get();
}

HpackDecoderInterface* SpdyFramer::GetHpackDecoder() {
  if (hpack_decoder_.get() == nullptr) {
    if (FLAGS_chromium_http2_flag_spdy_use_hpack_decoder3) {
      hpack_decoder_ = SpdyMakeUnique<HpackDecoder3>();
    } else {
      hpack_decoder_ = SpdyMakeUnique<HpackDecoder>();
    }
  }
  return hpack_decoder_.get();
}

void SpdyFramer::SetDecoderHeaderTableDebugVisitor(
    std::unique_ptr<HpackHeaderTable::DebugVisitorInterface> visitor) {
  if (decoder_adapter_ != nullptr) {
    decoder_adapter_->SetDecoderHeaderTableDebugVisitor(std::move(visitor));
  } else {
    GetHpackDecoder()->SetHeaderTableDebugVisitor(std::move(visitor));
  }
}

void SpdyFramer::SetEncoderHeaderTableDebugVisitor(
    std::unique_ptr<HpackHeaderTable::DebugVisitorInterface> visitor) {
  GetHpackEncoder()->SetHeaderTableDebugVisitor(std::move(visitor));
}

size_t SpdyFramer::EstimateMemoryUsage() const {
  return SpdyEstimateMemoryUsage(current_frame_buffer_) +
         SpdyEstimateMemoryUsage(settings_scratch_) +
         SpdyEstimateMemoryUsage(altsvc_scratch_) +
         SpdyEstimateMemoryUsage(hpack_encoder_) +
         SpdyEstimateMemoryUsage(hpack_decoder_) +
         SpdyEstimateMemoryUsage(decoder_adapter_);
}

void SpdyFramer::UpdateHeaderEncoderTableSize(uint32_t value) {
  GetHpackEncoder()->ApplyHeaderTableSizeSetting(value);
}

void SpdyFramer::UpdateHeaderDecoderTableSize(uint32_t value) {
  GetHpackDecoder()->ApplyHeaderTableSizeSetting(value);
}

size_t SpdyFramer::header_encoder_table_size() const {
  if (hpack_encoder_ == nullptr) {
    return kDefaultHeaderTableSizeSetting;
  } else {
    return hpack_encoder_->CurrentHeaderTableSizeSetting();
  }
}

void SpdyFramer::SerializeHeaderBlockWithoutCompression(
    SpdyFrameBuilder* builder,
    const SpdyHeaderBlock& header_block) const {
  // Serialize number of headers.
  builder->WriteUInt32(header_block.size());

  // Serialize each header.
  for (const auto& header : header_block) {
    builder->WriteStringPiece32(base::ToLowerASCII(header.first));
    builder->WriteStringPiece32(header.second);
  }
}

}  // namespace net
