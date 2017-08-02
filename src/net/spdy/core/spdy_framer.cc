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

#include "base/lazy_instance.h"
#include "base/logging.h"
#include "base/metrics/histogram_macros.h"
#include "base/strings/string_util.h"
#include "net/quic/platform/api/quic_flags.h"
#include "net/spdy/core/hpack/hpack_constants.h"
#include "net/spdy/core/hpack/hpack_decoder_adapter.h"
#include "net/spdy/core/http2_frame_decoder_adapter.h"
#include "net/spdy/core/spdy_bitmasks.h"
#include "net/spdy/core/spdy_bug_tracker.h"
#include "net/spdy/core/spdy_frame_builder.h"
#include "net/spdy/core/spdy_frame_reader.h"
#include "net/spdy/core/spdy_framer_decoder_adapter.h"
#include "net/spdy/platform/api/spdy_estimate_memory_usage.h"
#include "net/spdy/platform/api/spdy_ptr_util.h"
#include "net/spdy/platform/api/spdy_string_utils.h"

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

// Used to indicate no flags in a HTTP2 flags field.
const uint8_t kNoFlags = 0;

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

SpdyFramer::SpdyFramer(CompressionOption option)
    : visitor_(nullptr),
      extension_(nullptr),
      debug_visitor_(nullptr),
      header_handler_(nullptr),
      compression_option_(option) {
  static_assert(
      kMaxControlFrameSize <= kSpdyInitialFrameSizeLimit + kFrameHeaderSize,
      "Our send limit should be at most our receive limit");
  decoder_adapter_ = CreateHttp2FrameDecoderAdapter(this);
}

SpdyFramer::~SpdyFramer() {}

void SpdyFramer::Reset() {
  if (decoder_adapter_ != nullptr) {
    decoder_adapter_->Reset();
  } else {
    SPDY_BUG << "Decoder adapter is required to use SpdyFramer!";
  }
}

void SpdyFramer::set_visitor(SpdyFramerVisitorInterface* visitor) {
  if (decoder_adapter_ != nullptr) {
    decoder_adapter_->set_visitor(visitor);
  } else {
    SPDY_BUG << "Decoder adapter is required to use SpdyFramer!";
  }
  visitor_ = visitor;
}

void SpdyFramer::set_extension_visitor(ExtensionVisitorInterface* extension) {
  if (decoder_adapter_ != nullptr) {
    decoder_adapter_->set_extension_visitor(extension);
  } else {
    SPDY_BUG << "Decoder adapter is required to use SpdyFramer!";
  }
  extension_ = extension;
}

void SpdyFramer::set_debug_visitor(
    SpdyFramerDebugVisitorInterface* debug_visitor) {
  if (decoder_adapter_ != nullptr) {
    decoder_adapter_->set_debug_visitor(debug_visitor);
  } else {
    SPDY_BUG << "Decoder adapter is required to use SpdyFramer!";
  }
  debug_visitor_ = debug_visitor;
}

void SpdyFramer::set_process_single_input_frame(bool v) {
  if (decoder_adapter_ != nullptr) {
    decoder_adapter_->set_process_single_input_frame(v);
  } else {
    SPDY_BUG << "Decoder adapter is required to use SpdyFramer!";
  }
}

bool SpdyFramer::probable_http_response() const {
  if (decoder_adapter_) {
    return decoder_adapter_->probable_http_response();
  } else {
    SPDY_BUG << "Decoder adapter is required to use SpdyFramer!";
    return false;
  }
}

SpdyFramer::SpdyFramerError SpdyFramer::spdy_framer_error() const {
  if (decoder_adapter_ != nullptr) {
    return decoder_adapter_->spdy_framer_error();
  } else {
    SPDY_BUG << "Decoder adapter is required to use SpdyFramer!";
    return SpdyFramerError::LAST_ERROR;
  }
}

SpdyFramer::SpdyState SpdyFramer::state() const {
  if (decoder_adapter_ != nullptr) {
    return decoder_adapter_->state();
  } else {
    SPDY_BUG << "Decoder adapter is required to use SpdyFramer!";
    return SpdyState::SPDY_ERROR;
  }
}

size_t SpdyFramer::GetFrameMaximumSize() const {
  return send_frame_size_limit_ + kFrameHeaderSize;
}

size_t SpdyFramer::GetDataFrameMaximumPayload() const {
  return std::min(kMaxDataPayloadSendSize,
                  GetFrameMaximumSize() - kDataFrameMinimumSize);
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
  } else {
    SPDY_BUG << "SpdyFramer::ProcessInput called without decoder_adapter_!";
    return 0;
  }
}

size_t SpdyFramer::GetUncompressedSerializedLength(
    const SpdyHeaderBlock& headers) {
  const size_t num_name_value_pairs_size = sizeof(uint32_t);
  const size_t length_of_name_size = num_name_value_pairs_size;
  const size_t length_of_value_size = num_name_value_pairs_size;

  size_t total_length = num_name_value_pairs_size;
  for (const auto& header : headers) {
    // We add space for the length of the name and the length of the value as
    // well as the length of the name and the length of the value.
    total_length += length_of_name_size + header.first.size() +
                    length_of_value_size + header.second.size();
  }
  return total_length;
}


SpdyFramer::SpdyFrameIterator::SpdyFrameIterator(SpdyFramer* framer)
    : framer_(framer), is_first_frame_(true), has_next_frame_(true) {}

SpdyFramer::SpdyFrameIterator::~SpdyFrameIterator() {}

size_t SpdyFramer::SpdyFrameIterator::NextFrame(ZeroCopyOutputBuffer* output) {
  const SpdyFrameIR& frame_ir = GetIR();
  if (!has_next_frame_) {
    SPDY_BUG << "SpdyFramer::SpdyFrameIterator::NextFrame called without "
             << "a next frame.";
    return false;
  }

  const size_t size_without_block =
      is_first_frame_ ? GetFrameSizeSansBlock() : kContinuationFrameMinimumSize;
  auto encoding = SpdyMakeUnique<SpdyString>();
  encoder_->Next(kMaxControlFrameSize - size_without_block, encoding.get());
  has_next_frame_ = encoder_->HasNext();

  if (framer_->debug_visitor_ != nullptr) {
    const auto& header_block_frame_ir =
        static_cast<const SpdyFrameWithHeaderBlockIR&>(frame_ir);
    const size_t header_list_size = framer_->GetUncompressedSerializedLength(
        header_block_frame_ir.header_block());
    framer_->debug_visitor_->OnSendCompressedFrame(
        frame_ir.stream_id(),
        is_first_frame_ ? frame_ir.frame_type() : SpdyFrameType::CONTINUATION,
        header_list_size, size_without_block + encoding->size());
  }

  framer_->SetIsLastFrame(!has_next_frame_);
  const size_t free_bytes_before = output->BytesFree();
  bool ok = false;
  if (is_first_frame_) {
    is_first_frame_ = false;
    ok = SerializeGivenEncoding(*encoding, output);
  } else {
    SpdyContinuationIR continuation_ir(frame_ir.stream_id());
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

const SpdyFrameIR& SpdyFramer::SpdyHeaderFrameIterator::GetIR() const {
  return *(headers_ir_.get());
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

const SpdyFrameIR& SpdyFramer::SpdyPushPromiseFrameIterator::GetIR() const {
  return *(push_promise_ir_.get());
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

const SpdyFrameIR& SpdyFramer::SpdyControlFrameIterator::GetIR() const {
  return *(frame_ir_.get());
}

// TODO(yasong): remove all the static_casts.
std::unique_ptr<SpdyFrameSequence> SpdyFramer::CreateIterator(
    SpdyFramer* framer,
    std::unique_ptr<const SpdyFrameIR> frame_ir) {
  switch (frame_ir->frame_type()) {
    case SpdyFrameType::HEADERS: {
      return SpdyMakeUnique<SpdyHeaderFrameIterator>(
          framer, SpdyWrapUnique(
                      static_cast<const SpdyHeadersIR*>(frame_ir.release())));
    }
    case SpdyFrameType::PUSH_PROMISE: {
      return SpdyMakeUnique<SpdyPushPromiseFrameIterator>(
          framer, SpdyWrapUnique(static_cast<const SpdyPushPromiseIR*>(
                      frame_ir.release())));
    }
    case SpdyFrameType::DATA: {
      DVLOG(1) << "Serialize a stream end DATA frame for VTL";
      // FALLTHROUGH_INTENDED
    }
    default: {
      return SpdyMakeUnique<SpdyControlFrameIterator>(framer,
                                                      std::move(frame_ir));
    }
  }
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
                       data_ir.padding_payload_len() + kDataFrameMinimumSize;
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

  *frame_size = kDataFrameMinimumSize;
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
  size_t expected_length = kRstStreamFrameSize;
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
      kSettingsFrameMinimumSize + (values->size() * kOneSettingParameterSize);
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

  DCHECK_EQ(kSettingsFrameMinimumSize, builder.length());
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
  SpdyFrameBuilder builder(kPingFrameSize);
  uint8_t flags = 0;
  if (ping.is_ack()) {
    flags |= PING_FLAG_ACK;
  }
  builder.BeginNewFrame(*this, SpdyFrameType::PING, flags, 0);
  builder.WriteUInt64(ping.id());
  DCHECK_EQ(kPingFrameSize, builder.length());
  return builder.take();
}

SpdySerializedFrame SpdyFramer::SerializeGoAway(
    const SpdyGoAwayIR& goaway) const {
  // Compute the output buffer size, take opaque data into account.
  size_t expected_length = kGoawayFrameMinimumSize;
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

  *size = kHeadersFrameMinimumSize;

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
                        kContinuationFrameMinimumSize;
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
      std::min(*length_field, kMaxControlFrameSize - kFrameHeaderSize);
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

  DCHECK_EQ(kHeadersFrameMinimumSize, builder.length());

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
    const size_t header_list_size =
        GetUncompressedSerializedLength(headers.header_block());
    debug_visitor_->OnSendCompressedFrame(headers.stream_id(),
                                          SpdyFrameType::HEADERS,
                                          header_list_size, builder.length());
  }

  return builder.take();
}

SpdySerializedFrame SpdyFramer::SerializeWindowUpdate(
    const SpdyWindowUpdateIR& window_update) const {
  SpdyFrameBuilder builder(kWindowUpdateFrameSize);
  builder.BeginNewFrame(*this, SpdyFrameType::WINDOW_UPDATE, kNoFlags,
                        window_update.stream_id());
  builder.WriteUInt32(window_update.delta());
  DCHECK_EQ(kWindowUpdateFrameSize, builder.length());
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
  *size = kPushPromiseFrameMinimumSize;

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
                        kContinuationFrameMinimumSize;
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
  size_t length = std::min(size, kMaxControlFrameSize) - kFrameHeaderSize;
  builder.BeginNewFrame(*this, SpdyFrameType::PUSH_PROMISE, flags,
                        push_promise.stream_id(), length);
  int padding_payload_len = 0;
  if (push_promise.padded()) {
    builder.WriteUInt8(push_promise.padding_payload_len());
    builder.WriteUInt32(push_promise.promised_stream_id());
    DCHECK_EQ(kPushPromiseFrameMinimumSize + kPadLengthFieldSize,
              builder.length());

    padding_payload_len = push_promise.padding_payload_len();
  } else {
    builder.WriteUInt32(push_promise.promised_stream_id());
    DCHECK_EQ(kPushPromiseFrameMinimumSize, builder.length());
  }

  WritePayloadWithContinuation(
      &builder, hpack_encoding, push_promise.stream_id(),
      SpdyFrameType::PUSH_PROMISE, padding_payload_len);

  if (debug_visitor_) {
    const size_t header_list_size =
        GetUncompressedSerializedLength(push_promise.header_block());
    debug_visitor_->OnSendCompressedFrame(push_promise.stream_id(),
                                          SpdyFrameType::PUSH_PROMISE,
                                          header_list_size, builder.length());
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
      headers.stream_id(), frame_size - kFrameHeaderSize);
  DCHECK_EQ(kFrameHeaderSize, builder.length());

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
  size_t frame_size = kContinuationFrameMinimumSize + encoding.size();
  SpdyFrameBuilder builder(frame_size);
  uint8_t flags = ((overwrite_last_frame_ && is_last_frame_) ||
                   (!overwrite_last_frame_ && continuation.end_headers()))
                      ? HEADERS_FLAG_END_HEADERS
                      : 0;
  builder.BeginNewFrame(*this, SpdyFrameType::CONTINUATION, flags,
                        continuation.stream_id());
  DCHECK_EQ(kFrameHeaderSize, builder.length());

  builder.WriteBytes(encoding.data(), encoding.size());
  return builder.take();
}

void SpdyFramer::SerializeAltSvcBuilderHelper(const SpdyAltSvcIR& altsvc_ir,
                                              SpdyString* value,
                                              size_t* size) const {
  *size = kGetAltSvcFrameMinimumSize;
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
  DCHECK_LT(kGetAltSvcFrameMinimumSize, builder.length());
  return builder.take();
}

SpdySerializedFrame SpdyFramer::SerializePriority(
    const SpdyPriorityIR& priority) const {
  SpdyFrameBuilder builder(kPriorityFrameSize);
  builder.BeginNewFrame(*this, SpdyFrameType::PRIORITY, kNoFlags,
                        priority.stream_id());

  builder.WriteUInt32(PackStreamDependencyValues(priority.exclusive(),
                                                 priority.parent_stream_id()));
  // Per RFC 7540 section 6.3, serialized weight value is actual value - 1.
  builder.WriteUInt8(priority.weight() - 1);
  DCHECK_EQ(kPriorityFrameSize, builder.length());
  return builder.take();
}

SpdySerializedFrame SpdyFramer::SerializeUnknown(
    const SpdyUnknownIR& unknown) const {
  const size_t total_size = kFrameHeaderSize + unknown.payload().size();
  SpdyFrameBuilder builder(total_size);
  builder.BeginNewUncheckedFrame(*this, unknown.type(), unknown.flags(),
                                 unknown.stream_id(), unknown.length());
  builder.WriteBytes(unknown.payload().data(), unknown.payload().size());
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
  void VisitUnknown(const SpdyUnknownIR& unknown) override {
    frame_ = framer_->SerializeUnknown(unknown);
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
  size_t expected_length = kRstStreamFrameSize;
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

  DCHECK_EQ(kSettingsFrameMinimumSize, builder.length());
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
  SpdyFrameBuilder builder(kPingFrameSize, output);
  uint8_t flags = 0;
  if (ping.is_ack()) {
    flags |= PING_FLAG_ACK;
  }
  bool ok = builder.BeginNewFrame(*this, SpdyFrameType::PING, flags, 0);
  ok = ok && builder.WriteUInt64(ping.id());
  DCHECK_EQ(kPingFrameSize, builder.length());
  return ok;
}

bool SpdyFramer::SerializeGoAway(const SpdyGoAwayIR& goaway,
                                 ZeroCopyOutputBuffer* output) const {
  // Compute the output buffer size, take opaque data into account.
  size_t expected_length = kGoawayFrameMinimumSize;
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
  DCHECK_EQ(kHeadersFrameMinimumSize, builder.length());

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
    const size_t header_list_size =
        GetUncompressedSerializedLength(headers.header_block());
    debug_visitor_->OnSendCompressedFrame(headers.stream_id(),
                                          SpdyFrameType::HEADERS,
                                          header_list_size, builder.length());
  }

  return ok;
}

bool SpdyFramer::SerializeWindowUpdate(const SpdyWindowUpdateIR& window_update,
                                       ZeroCopyOutputBuffer* output) const {
  SpdyFrameBuilder builder(kWindowUpdateFrameSize, output);
  bool ok = builder.BeginNewFrame(*this, SpdyFrameType::WINDOW_UPDATE, kNoFlags,
                                  window_update.stream_id());
  ok = ok && builder.WriteUInt32(window_update.delta());
  DCHECK_EQ(kWindowUpdateFrameSize, builder.length());
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
  size_t length = std::min(size, kMaxControlFrameSize) - kFrameHeaderSize;
  ok = builder.BeginNewFrame(*this, SpdyFrameType::PUSH_PROMISE, flags,
                             push_promise.stream_id(), length);

  int padding_payload_len = 0;
  if (push_promise.padded()) {
    ok = ok && builder.WriteUInt8(push_promise.padding_payload_len()) &&
         builder.WriteUInt32(push_promise.promised_stream_id());
    DCHECK_EQ(kPushPromiseFrameMinimumSize + kPadLengthFieldSize,
              builder.length());

    padding_payload_len = push_promise.padding_payload_len();
  } else {
    ok = ok && builder.WriteUInt32(push_promise.promised_stream_id());
    DCHECK_EQ(kPushPromiseFrameMinimumSize, builder.length());
  }

  ok = ok && WritePayloadWithContinuation(
                 &builder, hpack_encoding, push_promise.stream_id(),
                 SpdyFrameType::PUSH_PROMISE, padding_payload_len);

  if (debug_visitor_) {
    const size_t header_list_size =
        GetUncompressedSerializedLength(push_promise.header_block());
    debug_visitor_->OnSendCompressedFrame(push_promise.stream_id(),
                                          SpdyFrameType::PUSH_PROMISE,
                                          header_list_size, builder.length());
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
                                  frame_size - kFrameHeaderSize);

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
  size_t frame_size = kContinuationFrameMinimumSize + encoding.size();
  SpdyFrameBuilder builder(frame_size, output);
  uint8_t flags = ((overwrite_last_frame_ && is_last_frame_) ||
                   (!overwrite_last_frame_ && continuation.end_headers()))
                      ? HEADERS_FLAG_END_HEADERS
                      : 0;
  bool ok = builder.BeginNewFrame(*this, SpdyFrameType::CONTINUATION, flags,
                                  continuation.stream_id(),
                                  frame_size - kFrameHeaderSize);
  DCHECK_EQ(kFrameHeaderSize, builder.length());

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
  DCHECK_LT(kGetAltSvcFrameMinimumSize, builder.length());
  return ok;
}

bool SpdyFramer::SerializePriority(const SpdyPriorityIR& priority,
                                   ZeroCopyOutputBuffer* output) const {
  SpdyFrameBuilder builder(kPriorityFrameSize, output);
  bool ok = builder.BeginNewFrame(*this, SpdyFrameType::PRIORITY, kNoFlags,
                                  priority.stream_id());
  ok = ok &&
       builder.WriteUInt32(PackStreamDependencyValues(
           priority.exclusive(), priority.parent_stream_id())) &&
       // Per RFC 7540 section 6.3, serialized weight value is actual value - 1.
       builder.WriteUInt8(priority.weight() - 1);
  DCHECK_EQ(kPriorityFrameSize, builder.length());
  return ok;
}

bool SpdyFramer::SerializeUnknown(const SpdyUnknownIR& unknown,
                                  ZeroCopyOutputBuffer* output) const {
  const size_t total_size = kFrameHeaderSize + unknown.payload().size();
  SpdyFrameBuilder builder(total_size, output);
  bool ok =
      builder.BeginNewUncheckedFrame(*this, unknown.type(), unknown.flags(),
                                     unknown.stream_id(), unknown.length());
  ok = ok &&
       builder.WriteBytes(unknown.payload().data(), unknown.payload().size());
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
  void VisitUnknown(const SpdyUnknownIR& unknown) override {
    result_ = framer_->SerializeUnknown(unknown, output_);
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
  int payload_size = kMaxControlFrameSize - kContinuationFrameMinimumSize;
  // This is ceiling(overflow/payload_size) using integer arithmetics.
  return (overflow - 1) / payload_size + 1;
}

size_t SpdyFramer::GetHeaderFrameSizeSansBlock(
    const SpdyHeadersIR& header_ir) const {
  size_t min_size = kFrameHeaderSize;

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
  size_t size = kPushPromiseFrameMinimumSize;

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
        bytes_remaining, kMaxControlFrameSize - kContinuationFrameMinimumSize);
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

void SpdyFramer::UpdateHeaderEncoderTableSize(uint32_t value) {
  GetHpackEncoder()->ApplyHeaderTableSizeSetting(value);
}

void SpdyFramer::UpdateHeaderDecoderTableSize(uint32_t value) {
  decoder_adapter_->GetHpackDecoder()->ApplyHeaderTableSizeSetting(value);
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

void SpdyFramer::SetDecoderHeaderTableDebugVisitor(
    std::unique_ptr<HpackHeaderTable::DebugVisitorInterface> visitor) {
  if (decoder_adapter_ != nullptr) {
    decoder_adapter_->SetDecoderHeaderTableDebugVisitor(std::move(visitor));
  } else {
    SPDY_BUG << "SpdyFramer::SetDecoderHeaderTableDebugVisitor called without "
                "decoder_adapter_!";
  }
}

void SpdyFramer::set_max_decode_buffer_size_bytes(
    size_t max_decode_buffer_size_bytes) {
  if (decoder_adapter_ != nullptr) {
    decoder_adapter_->GetHpackDecoder()->set_max_decode_buffer_size_bytes(
        max_decode_buffer_size_bytes);
  } else {
    SPDY_BUG << "SpdyFramer::set_max_decode_buffer_size_bytes called without "
                "decoder_adapter_!";
  }
}

void SpdyFramer::SetEncoderHeaderTableDebugVisitor(
    std::unique_ptr<HpackHeaderTable::DebugVisitorInterface> visitor) {
  GetHpackEncoder()->SetHeaderTableDebugVisitor(std::move(visitor));
}

size_t SpdyFramer::EstimateMemoryUsage() const {
  return SpdyEstimateMemoryUsage(hpack_encoder_) +
         SpdyEstimateMemoryUsage(decoder_adapter_);
}

}  // namespace net
