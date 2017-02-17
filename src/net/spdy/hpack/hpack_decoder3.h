// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SPDY_HPACK_HPACK_DECODER3_H_
#define NET_SPDY_HPACK_HPACK_DECODER3_H_

// HpackDecoder3 implements HpackDecoderInterface, using Http2HpackDecoder to
// decode HPACK blocks into HTTP/2 header lists as outlined in
// http://tools.ietf.org/html/rfc7541.

#include <stddef.h>

#include <memory>

#include "base/macros.h"
#include "base/strings/string_piece.h"
#include "net/base/net_export.h"
#include "net/http2/hpack/decoder/hpack_decoder_listener.h"
#include "net/http2/hpack/decoder/http2_hpack_decoder.h"
#include "net/http2/hpack/hpack_string.h"
#include "net/http2/hpack/http2_hpack_constants.h"
#include "net/spdy/hpack/hpack_decoder_interface.h"
#include "net/spdy/hpack/hpack_header_table.h"
#include "net/spdy/spdy_header_block.h"
#include "net/spdy/spdy_headers_handler_interface.h"

namespace net {
namespace test {
class HpackDecoder3Peer;
}  // namespace test

class NET_EXPORT_PRIVATE HpackDecoder3 : public HpackDecoderInterface {
 public:
  friend test::HpackDecoder3Peer;
  HpackDecoder3();
  ~HpackDecoder3() override;

  // Override the HpackDecoderInterface methods:

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

 private:
  class NET_EXPORT_PRIVATE ListenerAdapter
      : public HpackDecoderListener,
        public HpackDecoderTablesDebugListener {
   public:
    ListenerAdapter();
    ~ListenerAdapter() override;

    // If a SpdyHeadersHandlerInterface is provided, the decoder will emit
    // headers to it rather than accumulating them in a SpdyHeaderBlock.
    // Does not take ownership of the handler, but does use the pointer until
    // the current HPACK block is completely decoded.
    void set_handler(SpdyHeadersHandlerInterface* handler);
    const SpdyHeaderBlock& decoded_block() const { return decoded_block_; }

    void SetHeaderTableDebugVisitor(
        std::unique_ptr<HpackHeaderTable::DebugVisitorInterface> visitor);

    // Override the HpackDecoderListener methods:
    void OnHeaderListStart() override;
    void OnHeader(HpackEntryType entry_type,
                  const HpackString& name,
                  const HpackString& value) override;
    void OnHeaderListEnd() override;
    void OnHeaderErrorDetected(base::StringPiece error_message) override;

    // Override the HpackDecoderTablesDebugListener methods:
    int64_t OnEntryInserted(const HpackStringPair& entry,
                            size_t insert_count) override;
    void OnUseEntry(const HpackStringPair& entry,
                    size_t insert_count,
                    int64_t insert_time) override;

   private:
    // If the caller doesn't provide a handler, the header list is stored in
    // this SpdyHeaderBlock.
    SpdyHeaderBlock decoded_block_;

    // If non-NULL, handles decoded headers. Not owned.
    SpdyHeadersHandlerInterface* handler_;

    // Total bytes of the name and value strings in the current HPACK block.
    size_t total_uncompressed_bytes_;

    // visitor_ is used by a QUIC experiment regarding HPACK; remove
    // when the experiment is done.
    std::unique_ptr<HpackHeaderTable::DebugVisitorInterface> visitor_;
  };

  // Converts calls to HpackDecoderListener into calls to
  // SpdyHeadersHandlerInterface.
  ListenerAdapter listener_adapter_;

  // The actual decoder.
  Http2HpackDecoder hpack_decoder_;

  // Total bytes that have been received as input (i.e. HPACK encoded)
  // in the current HPACK block.
  size_t total_hpack_bytes_;

  // How much encoded data this decoder is willing to buffer.
  size_t max_decode_buffer_size_bytes_;

  // Flag to keep track of having seen the header block start. Needed at the
  // moment because HandleControlFrameHeadersStart won't be called if a handler
  // is not being provided by the caller.
  bool header_block_started_;

  DISALLOW_COPY_AND_ASSIGN(HpackDecoder3);
};

}  // namespace net

#endif  // NET_SPDY_HPACK_HPACK_DECODER3_H_
