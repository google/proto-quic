// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/core/hpack/hpack_decoder3.h"

#include <utility>

#include "base/logging.h"
#include "net/http2/decoder/decode_buffer.h"
#include "net/http2/decoder/decode_status.h"
#include "net/spdy/chromium/spdy_flags.h"
#include "net/spdy/platform/api/spdy_estimate_memory_usage.h"

namespace net {
namespace {
const size_t kMaxDecodeBufferSizeBytes = 32 * 1024;  // 32 KB
}  // namespace

HpackDecoder3::HpackDecoder3()
    : hpack_decoder_(&listener_adapter_, kMaxDecodeBufferSizeBytes),
      max_decode_buffer_size_bytes_(kMaxDecodeBufferSizeBytes),
      header_block_started_(false) {}

HpackDecoder3::~HpackDecoder3() {}

void HpackDecoder3::ApplyHeaderTableSizeSetting(size_t size_setting) {
  DVLOG(2) << "HpackDecoder3::ApplyHeaderTableSizeSetting";
  hpack_decoder_.ApplyHeaderTableSizeSetting(size_setting);
}

void HpackDecoder3::HandleControlFrameHeadersStart(
    SpdyHeadersHandlerInterface* handler) {
  DVLOG(2) << "HpackDecoder3::HandleControlFrameHeadersStart";
  DCHECK(!header_block_started_);
  listener_adapter_.set_handler(handler);
}

bool HpackDecoder3::HandleControlFrameHeadersData(const char* headers_data,
                                                  size_t headers_data_length) {
  DVLOG(2) << "HpackDecoder3::HandleControlFrameHeadersData: len="
           << headers_data_length;
  if (!header_block_started_) {
    // Initialize the decoding process here rather than in
    // HandleControlFrameHeadersStart because that method is not always called.
    header_block_started_ = true;
    if (!hpack_decoder_.StartDecodingBlock()) {
      header_block_started_ = false;
      return false;
    }
  }

  // Sometimes we get a call with headers_data==nullptr and
  // headers_data_length==0, in which case we need to avoid creating
  // a DecodeBuffer, which would otherwise complain.
  if (headers_data_length > 0) {
    DCHECK_NE(headers_data, nullptr);
    if (headers_data_length > max_decode_buffer_size_bytes_) {
      DVLOG(1) << "max_decode_buffer_size_bytes_ < headers_data_length: "
               << max_decode_buffer_size_bytes_ << " < " << headers_data_length;
      return false;
    }
    listener_adapter_.AddToTotalHpackBytes(headers_data_length);
    DecodeBuffer db(headers_data, headers_data_length);
    bool ok = hpack_decoder_.DecodeFragment(&db);
    DCHECK(!ok || db.Empty()) << "Remaining=" << db.Remaining();
    return ok;
  }
  return true;
}

// TODO(jamessynge): Determine if compressed_len is needed; it is used to
// produce UUMA stat Net.SpdyHpackDecompressionPercentage, but only for
// SPDY3, not HTTP2.
bool HpackDecoder3::HandleControlFrameHeadersComplete(size_t* compressed_len) {
  DVLOG(2) << "HpackDecoder3::HandleControlFrameHeadersComplete";
  if (compressed_len != nullptr) {
    *compressed_len = listener_adapter_.total_hpack_bytes();
  }
  if (!hpack_decoder_.EndDecodingBlock()) {
    DVLOG(3) << "EndDecodingBlock returned false";
    return false;
  }
  header_block_started_ = false;
  return true;
}

const SpdyHeaderBlock& HpackDecoder3::decoded_block() const {
  return listener_adapter_.decoded_block();
}

void HpackDecoder3::SetHeaderTableDebugVisitor(
    std::unique_ptr<HpackHeaderTable::DebugVisitorInterface> visitor) {
  DVLOG(2) << "HpackDecoder3::SetHeaderTableDebugVisitor";
  if (visitor != nullptr) {
    listener_adapter_.SetHeaderTableDebugVisitor(std::move(visitor));
    hpack_decoder_.set_tables_debug_listener(&listener_adapter_);
  } else {
    hpack_decoder_.set_tables_debug_listener(nullptr);
    listener_adapter_.SetHeaderTableDebugVisitor(nullptr);
  }
}

void HpackDecoder3::set_max_decode_buffer_size_bytes(
    size_t max_decode_buffer_size_bytes) {
  DVLOG(2) << "HpackDecoder3::set_max_decode_buffer_size_bytes";
  max_decode_buffer_size_bytes_ = max_decode_buffer_size_bytes;
  hpack_decoder_.set_max_string_size_bytes(max_decode_buffer_size_bytes);
}

size_t HpackDecoder3::EstimateMemoryUsage() const {
  return SpdyEstimateMemoryUsage(hpack_decoder_);
}

HpackDecoder3::ListenerAdapter::ListenerAdapter() : handler_(nullptr) {}
HpackDecoder3::ListenerAdapter::~ListenerAdapter() {}

void HpackDecoder3::ListenerAdapter::set_handler(
    SpdyHeadersHandlerInterface* handler) {
  handler_ = handler;
}

void HpackDecoder3::ListenerAdapter::SetHeaderTableDebugVisitor(
    std::unique_ptr<HpackHeaderTable::DebugVisitorInterface> visitor) {
  visitor_ = std::move(visitor);
}

void HpackDecoder3::ListenerAdapter::OnHeaderListStart() {
  DVLOG(2) << "HpackDecoder3::ListenerAdapter::OnHeaderListStart";
  total_hpack_bytes_ = 0;
  total_uncompressed_bytes_ = 0;
  decoded_block_.clear();
  if (handler_ != nullptr) {
    handler_->OnHeaderBlockStart();
  }
}

void HpackDecoder3::ListenerAdapter::OnHeader(HpackEntryType entry_type,
                                              const HpackString& name,
                                              const HpackString& value) {
  DVLOG(2) << "HpackDecoder3::ListenerAdapter::OnHeader:\n name: " << name
           << "\n value: " << value;
  total_uncompressed_bytes_ += name.size() + value.size();
  if (handler_ == nullptr) {
    DVLOG(3) << "Adding to decoded_block";
    decoded_block_.AppendValueOrAddHeader(name.ToStringPiece(),
                                          value.ToStringPiece());
  } else {
    DVLOG(3) << "Passing to handler";
    handler_->OnHeader(name.ToStringPiece(), value.ToStringPiece());
  }
}

void HpackDecoder3::ListenerAdapter::OnHeaderListEnd() {
  DVLOG(2) << "HpackDecoder3::ListenerAdapter::OnHeaderListEnd";
  // We don't clear the SpdyHeaderBlock here to allow access to it until the
  // next HPACK block is decoded.
  if (handler_ != nullptr) {
    handler_->OnHeaderBlockEnd(total_uncompressed_bytes_, total_hpack_bytes_);
    handler_ = nullptr;
  }
}

void HpackDecoder3::ListenerAdapter::OnHeaderErrorDetected(
    SpdyStringPiece error_message) {
  VLOG(1) << error_message;
}

int64_t HpackDecoder3::ListenerAdapter::OnEntryInserted(
    const HpackStringPair& sp,
    size_t insert_count) {
  DVLOG(2) << "HpackDecoder3::ListenerAdapter::OnEntryInserted: " << sp
           << ",  insert_count=" << insert_count;
  if (visitor_ == nullptr) {
    return 0;
  }
  HpackEntry entry(sp.name.ToStringPiece(), sp.value.ToStringPiece(),
                   /*is_static*/ false, insert_count);
  int64_t time_added = visitor_->OnNewEntry(entry);
  DVLOG(2) << "HpackDecoder3::ListenerAdapter::OnEntryInserted: time_added="
           << time_added;
  return time_added;
}

void HpackDecoder3::ListenerAdapter::OnUseEntry(const HpackStringPair& sp,
                                                size_t insert_count,
                                                int64_t time_added) {
  DVLOG(2) << "HpackDecoder3::ListenerAdapter::OnUseEntry: " << sp
           << ",  insert_count=" << insert_count
           << ",  time_added=" << time_added;
  if (visitor_ != nullptr) {
    HpackEntry entry(sp.name.ToStringPiece(), sp.value.ToStringPiece(),
                     /*is_static*/ false, insert_count);
    entry.set_time_added(time_added);
    visitor_->OnUseEntry(entry);
  }
}

}  // namespace net
