// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/hpack/hpack_decoder2.h"

#include <list>
#include <utility>

#include "base/logging.h"
#include "base/strings/string_piece.h"
#include "net/http2/decoder/decode_buffer.h"
#include "net/http2/decoder/decode_status.h"
#include "net/spdy/hpack/hpack_entry.h"
#include "net/spdy/platform/api/spdy_estimate_memory_usage.h"

using base::StringPiece;

namespace net {

HpackDecoder2::HpackDecoder2() : hpack_block_decoder_(this) {
  Reset();
}

HpackDecoder2::~HpackDecoder2() {}

void HpackDecoder2::Reset() {
  DVLOG(2) << "HpackDecoder2::Reset";
  handler_ = nullptr;

  hpack_block_decoder_.Reset();
  hpack_block_decoder_.set_listener(this);

  total_hpack_bytes_ = 0;
  total_header_bytes_ = 0;
  size_update_count_ = 0;
  header_seen_ = false;
  in_progress_ = false;
  error_detected_ = false;
  header_block_started_ = false;

  name_.Reset();
  value_.Reset();
}

void HpackDecoder2::SetErrorDetected() {
  if (!error_detected_) {
    DVLOG(2) << "HpackDecoder2::SetErrorDetected";
    hpack_block_decoder_.set_listener(&no_op_listener_);
    error_detected_ = true;
  }
}

void HpackDecoder2::ApplyHeaderTableSizeSetting(size_t size_setting) {
  DVLOG(2) << "HpackDecoder2::ApplyHeaderTableSizeSetting";
  header_table_.SetSettingsHeaderTableSize(size_setting);
}

// If a SpdyHeadersHandlerInterface is provided, the decoder will emit
// headers to it rather than accumulating them in a SpdyHeaderBlock.
void HpackDecoder2::HandleControlFrameHeadersStart(
    SpdyHeadersHandlerInterface* handler) {
  DVLOG(2) << "HpackDecoder2::HandleControlFrameHeadersStart";
  DCHECK(!header_block_started_);
  handler_ = handler;
}

// Called as HPACK block fragments arrive. Returns false
// if an error occurred while decoding the block.
bool HpackDecoder2::HandleControlFrameHeadersData(const char* headers_data,
                                                  size_t headers_data_length) {
  DVLOG(2) << "HpackDecoder2::HandleControlFrameHeadersData: len="
           << headers_data_length;
  if (!header_block_started_) {
    DCHECK_EQ(total_hpack_bytes_, 0u);
    // Clear the SpdyHeaderBlock here rather than in Reset so that it is NOT
    // cleared in HandleControlFrameHeadersComplete, which would be before it
    // could be used.
    decoded_block_.clear();
    header_block_started_ = true;
    if (handler_ != nullptr) {
      handler_->OnHeaderBlockStart();
    }
  }

  // Sometimes we get a call with headers_data==nullptr and
  // headers_data_length==0, in which case we need to avoid creating
  // a DecodeBuffer, which would otherwise complain.
  if (headers_data_length > 0) {
    DCHECK_NE(headers_data, nullptr);
    total_hpack_bytes_ += headers_data_length;
    DecodeBuffer db(headers_data, headers_data_length);
    DecodeStatus status = hpack_block_decoder_.Decode(&db);
    switch (status) {
      case DecodeStatus::kDecodeDone:
        // We've completed the decoding of headers_data, and it ended at the
        // boundary between two HPACK block entries, so name_ and value_ are
        // currently reset.
        DCHECK_EQ(0u, db.Remaining());
        in_progress_ = false;
        break;

      case DecodeStatus::kDecodeInProgress:
        DCHECK_EQ(0u, db.Remaining());
        in_progress_ = true;
        if (!error_detected_) {
          name_.BufferStringIfUnbuffered();
          value_.BufferStringIfUnbuffered();
          EnforceMaxDecodeBufferSize();
        }
        break;

      case DecodeStatus::kDecodeError:
        SetErrorDetected();
        break;
    }
  }
  return !error_detected_;
}

// Called after a HPACK block has been completely delivered via
// HandleControlFrameHeadersData(). Returns false if an error occurred.
// |compressed_len| if non-null will be set to the size of the encoded
// buffered block that was accumulated in HandleControlFrameHeadersData(),
// to support subsequent calculation of compression percentage.
// Discards the handler supplied at the start of decoding the block.
// TODO(jamessynge): Determine if compressed_len is needed; it is used to
// produce UUMA stat Net.SpdyHpackDecompressionPercentage, but only for
// SPDY3, not HTTP2.
bool HpackDecoder2::HandleControlFrameHeadersComplete(size_t* compressed_len) {
  DVLOG(2) << "HpackDecoder2::HandleControlFrameHeadersComplete";
  if (error_detected_ || in_progress_) {
    DVLOG(2) << "error_detected_=" << error_detected_
             << ", in_progress_=" << in_progress_;
    return false;
  }
  if (compressed_len != nullptr) {
    *compressed_len = total_hpack_bytes_;
  }
  if (handler_ != nullptr) {
    handler_->OnHeaderBlockEnd(total_header_bytes_);
  }
  Reset();
  return true;
}

const SpdyHeaderBlock& HpackDecoder2::decoded_block() const {
  return decoded_block_;
}

void HpackDecoder2::SetHeaderTableDebugVisitor(
    std::unique_ptr<HpackHeaderTable::DebugVisitorInterface> visitor) {
  DVLOG(2) << "HpackDecoder2::SetHeaderTableDebugVisitor";
  header_table_.set_debug_visitor(std::move(visitor));
}

void HpackDecoder2::set_max_decode_buffer_size_bytes(
    size_t max_decode_buffer_size_bytes) {
  DVLOG(2) << "HpackDecoder2::set_max_decode_buffer_size_bytes";
  max_decode_buffer_size_bytes_ = max_decode_buffer_size_bytes;
}

size_t HpackDecoder2::EstimateMemoryUsage() const {
  return SpdyEstimateMemoryUsage(header_table_) +
         SpdyEstimateMemoryUsage(decoded_block_) +
         SpdyEstimateMemoryUsage(name_) + SpdyEstimateMemoryUsage(value_);
}

void HpackDecoder2::OnIndexedHeader(size_t index) {
  DVLOG(2) << "HpackDecoder2::OnIndexedHeader: index=" << index;
  DCHECK(!error_detected_);
  const HpackEntry* entry = header_table_.GetByIndex(index);
  if (entry == nullptr) {
    SetErrorDetected();
    return;
  }
  HandleHeaderRepresentation(entry->name(), entry->value());
}

void HpackDecoder2::OnStartLiteralHeader(HpackEntryType entry_type,
                                         size_t maybe_name_index) {
  DVLOG(2) << "HpackDecoder2::OnStartLiteralHeader: entry_type=" << entry_type
           << ",  maybe_name_index=" << maybe_name_index;
  DCHECK(!error_detected_);
  entry_type_ = entry_type;
  if (maybe_name_index > 0) {
    const HpackEntry* entry = header_table_.GetByIndex(maybe_name_index);
    if (entry == nullptr) {
      SetErrorDetected();
      return;
    } else {
      // Non-static entries could be evicted, leaving us with a dangling
      // pointer, so we preemptively copy. This could be avoided if
      // TryAddEntry would copy the strings prior to performing eviction.
      name_.Set(entry->name(), entry->IsStatic());
      name_.BufferStringIfUnbuffered();
    }
  }
}

void HpackDecoder2::OnNameStart(bool huffman_encoded, size_t len) {
  DVLOG(2) << "HpackDecoder2::OnNameStart: huffman_encoded="
           << (huffman_encoded ? "true" : "false") << ",  len=" << len;
  if (len > max_decode_buffer_size_bytes_) {
    DVLOG(1) << "Name length (" << len << ") is longer than permitted ("
             << max_decode_buffer_size_bytes_ << ")";
    SetErrorDetected();
    return;
  }
  name_.OnStart(huffman_encoded, len);
}

void HpackDecoder2::OnNameData(const char* data, size_t len) {
  DVLOG(2) << "HpackDecoder2::OnNameData: len=" << len
           << "\n data: " << StringPiece(data, len);
  if (error_detected_) {
    return;
  }
  if (!name_.OnData(data, len)) {
    SetErrorDetected();
  }
}

void HpackDecoder2::OnNameEnd() {
  DVLOG(2) << "HpackDecoder2::OnNameEnd";
  if (error_detected_) {
    return;
  }
  if (!name_.OnEnd()) {
    SetErrorDetected();
  }
}

void HpackDecoder2::OnValueStart(bool huffman_encoded, size_t len) {
  DVLOG(2) << "HpackDecoder2::OnValueStart: huffman_encoded="
           << (huffman_encoded ? "true" : "false") << ",  len=" << len;
  if (len > max_decode_buffer_size_bytes_) {
    DVLOG(1) << "Value length (" << len << ") is longer than permitted ("
             << max_decode_buffer_size_bytes_ << ")";
    SetErrorDetected();
    return;
  }
  value_.OnStart(huffman_encoded, len);
}

void HpackDecoder2::OnValueData(const char* data, size_t len) {
  DVLOG(2) << "HpackDecoder2::OnValueData: len=" << len
           << "\n data: " << StringPiece(data, len);
  if (error_detected_) {
    return;
  }
  if (!value_.OnData(data, len)) {
    SetErrorDetected();
  }
}

void HpackDecoder2::OnValueEnd() {
  DVLOG(2) << "HpackDecoder2::OnValueEnd";
  if (error_detected_) {
    return;
  }
  if (!value_.OnEnd()) {
    SetErrorDetected();
    return;
  }
  if (EnforceMaxDecodeBufferSize()) {
    // All is well.
    HandleHeaderRepresentation(name_.str(), value_.str());
    if (entry_type_ == HpackEntryType::kIndexedLiteralHeader) {
      header_table_.TryAddEntry(name_.str(), value_.str());
    }
    name_.Reset();
    value_.Reset();
  }
}

void HpackDecoder2::OnDynamicTableSizeUpdate(size_t size) {
  DVLOG(2) << "HpackDecoder2::OnDynamicTableSizeUpdate: size=" << size;
  if (error_detected_) {
    return;
  }
  if (size > header_table_.settings_size_bound()) {
    DVLOG(1) << "Dynamic Table Size Update with too large a size: " << size
             << " > " << header_table_.settings_size_bound();
    SetErrorDetected();
    return;
  }
  if (header_seen_) {
    DVLOG(1) << "Dynamic Table Size Update seen after a Header";
    SetErrorDetected();
    return;
  }
  ++size_update_count_;
  if (size_update_count_ > 2) {
    DVLOG(1) << "Too many (" << size_update_count_
             << ") Dynamic Table Size Updates";
    SetErrorDetected();
    return;
  }
  header_table_.SetMaxSize(size);
  return;
}

bool HpackDecoder2::EnforceMaxDecodeBufferSize() {
  if (!error_detected_) {
    size_t buffered_length = name_.BufferedLength() + value_.BufferedLength();
    DVLOG(2) << "buffered_length=" << buffered_length
             << "; max=" << max_decode_buffer_size_bytes_;
    if (buffered_length > max_decode_buffer_size_bytes_) {
      DVLOG(1) << "Header length (" << buffered_length
               << ") is longer than permitted ("
               << max_decode_buffer_size_bytes_ << ")";
      SetErrorDetected();
    }
  }
  return !error_detected_;
}

void HpackDecoder2::HandleHeaderRepresentation(StringPiece name,
                                               StringPiece value) {
  DVLOG(2) << "HpackDecoder2::HandleHeaderRepresentation:\n name: " << name
           << "\n value: " << value;
  total_header_bytes_ += name.size() + value.size();
  header_seen_ = true;
  if (handler_ == nullptr) {
    DVLOG(3) << "HpackDecoder2::HandleHeaderRepresentation "
             << "adding to decoded_block";
    decoded_block_.AppendValueOrAddHeader(name, value);
  } else {
    DVLOG(3) << "HpackDecoder2::HandleHeaderRepresentation "
             << "passing to handler";
    DCHECK(decoded_block_.empty());
    handler_->OnHeader(name, value);
  }
}

}  // namespace net
