// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SPDY_HPACK_HPACK_DECODER2_H_
#define NET_SPDY_HPACK_HPACK_DECODER2_H_

// HpackDecoder2

// An HpackDecoder decodes header sets as outlined in
// http://tools.ietf.org/html/rfc7541. This implementation uses the
// new HpackBlockDecoder in //net/http2/hpack/

#include <stddef.h>

#include <memory>
#include <string>

#include "base/macros.h"
#include "base/strings/string_piece.h"
#include "net/base/net_export.h"
#include "net/http2/hpack/decoder/hpack_block_decoder.h"
#include "net/http2/hpack/decoder/hpack_decoder_string_buffer.h"
#include "net/http2/hpack/decoder/hpack_entry_decoder_listener.h"
#include "net/http2/hpack/http2_hpack_constants.h"
#include "net/http2/hpack/huffman/http2_hpack_huffman_decoder.h"
#include "net/spdy/hpack/hpack_constants.h"
#include "net/spdy/hpack/hpack_decoder_interface.h"
#include "net/spdy/hpack/hpack_header_table.h"
#include "net/spdy/spdy_header_block.h"
#include "net/spdy/spdy_headers_handler_interface.h"

namespace net {
namespace test {
class HpackDecoder2Peer;
}  // namespace test

class NET_EXPORT_PRIVATE HpackDecoder2 : public HpackDecoderInterface,
                                         HpackEntryDecoderListener {
 public:
  friend test::HpackDecoder2Peer;
  HpackDecoder2();
  ~HpackDecoder2() override;

  // Override the interface methods:

  void ApplyHeaderTableSizeSetting(size_t size_setting) override;
  void HandleControlFrameHeadersStart(
      SpdyHeadersHandlerInterface* handler) override;
  bool HandleControlFrameHeadersData(const char* headers_data,
                                     size_t headers_data_length) override;
  bool HandleControlFrameHeadersComplete(size_t* compressed_len) override;
  const SpdyHeaderBlock& decoded_block() const override;
  void SetHeaderTableDebugVisitor(
      std::unique_ptr<HpackHeaderTable::DebugVisitorInterface> visitor)
      override;
  void set_max_decode_buffer_size_bytes(
      size_t max_decode_buffer_size_bytes) override;
  size_t EstimateMemoryUsage() const override;

 protected:
  // Override the HpackEntryDecoderListener methods:

  void OnIndexedHeader(size_t index) override;
  void OnStartLiteralHeader(HpackEntryType entry_type,
                            size_t maybe_name_index) override;
  void OnNameStart(bool huffman_encoded, size_t len) override;
  void OnNameData(const char* data, size_t len) override;
  void OnNameEnd() override;
  void OnValueStart(bool huffman_encoded, size_t len) override;
  void OnValueData(const char* data, size_t len) override;
  void OnValueEnd() override;
  void OnDynamicTableSizeUpdate(size_t size) override;

 private:
  // Called when a complete header entry has been decoded, with the name and
  // value of the entry. If check_header_order_ is true, confirms that
  // pseudo-headers don't appear after normal headers, else it treats the
  // headers as malformed, as per sections 8.1.2.3. of the HTTP2 specification.
  // Calls handler_->OnHeader() if there is a handler, else adds the header
  // to decoded_block_.
  void HandleHeaderRepresentation(base::StringPiece name,
                                  base::StringPiece value);

  // Reset state in preparation for decoding a new HPACK block. Does not reset
  // the dynamic table.
  void Reset();

  // Called when an error is detected while decoding. Replaces the listener
  // in the HpackBlockDecoder with the no-op listener.
  void SetErrorDetected();

  // Enforce the limit on the maximum size of strings that can be buffered.
  // It happens that this test is made after the strings have been buffered,
  // but that isn't a problem because we don't pass enormous buffers into
  // HandleControlFrameHeadersData.
  bool EnforceMaxDecodeBufferSize();

  HpackHeaderTable header_table_;
  SpdyHeaderBlock decoded_block_;

  // Scratch space for storing decoded literals.
  HpackDecoderStringBuffer name_, value_;

  // If non-NULL, handles decoded headers.
  SpdyHeadersHandlerInterface* handler_;

  HpackEntryDecoderNoOpListener no_op_listener_;

  // Total bytes that have been received as input (i.e. HPACK encoded).
  size_t total_hpack_bytes_;

  // Total bytes of the name and value strings in the current HPACK block.
  size_t total_header_bytes_;

  // How much encoded data this decoder is willing to buffer.
  size_t max_decode_buffer_size_bytes_ = 32 * 1024;  // 32 KB

  HpackBlockDecoder hpack_block_decoder_;

  // Count of Dynamic Table Size Updates seen in the current HPACK block.
  uint32_t size_update_count_;

  // The type of the current header entry (with literals) that is being decoded.
  HpackEntryType entry_type_;

  // Has a header been seen in the current HPACK block?
  bool header_seen_;

  // Did the HpackBlockDecoder stop in the middle of an entry?
  bool in_progress_;

  // Has an error been detected while decoding the HPACK block?
  bool error_detected_;

  // Flag to keep track of having seen the header block start. Needed at the
  // moment because HandleControlFrameHeadersStart won't be called if a handler
  // is not being provided by the caller.
  // TODO(jamessynge): Consider collapsing several of these bools into a single
  // enum representing the state of the decoding process.
  bool header_block_started_;

  DISALLOW_COPY_AND_ASSIGN(HpackDecoder2);
};

}  // namespace net
#endif  // NET_SPDY_HPACK_HPACK_DECODER2_H_
