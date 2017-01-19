// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_HTTP2_HPACK_DECODER_HPACK_BLOCK_DECODER_H_
#define NET_HTTP2_HPACK_DECODER_HPACK_BLOCK_DECODER_H_

// HpackBlockDecoder decodes an entire HPACK block (or the available portion
// thereof in the DecodeBuffer) into entries, but doesn't include HPACK static
// or dynamic table support, so table indices remain indices at this level.
// Reports the entries to an HpackEntryDecoderListener.

#include <string>

#include "base/logging.h"
#include "base/macros.h"
#include "net/base/net_export.h"
#include "net/http2/decoder/decode_buffer.h"
#include "net/http2/decoder/decode_status.h"
#include "net/http2/hpack/decoder/hpack_entry_decoder.h"
#include "net/http2/hpack/decoder/hpack_entry_decoder_listener.h"

namespace net {

class NET_EXPORT_PRIVATE HpackBlockDecoder {
 public:
  explicit HpackBlockDecoder(HpackEntryDecoderListener* listener)
      : listener_(listener) {
    DCHECK_NE(listener_, nullptr);
  }
  ~HpackBlockDecoder() {}

  // The listener may be changed at any time. The change takes effect on the
  // next entry into the decode loop of the Decode() method below.
  void set_listener(HpackEntryDecoderListener* listener) {
    DCHECK_NE(nullptr, listener);
    listener_ = listener;
  }
  HpackEntryDecoderListener* listener() { return listener_; }

  // Prepares the decoder to start decoding a new HPACK block. Expected
  // to be called from an implementation of Http2FrameDecoderListener's
  // OnHeadersStart or OnPushPromiseStart methods.
  void Reset() {
    DVLOG(2) << "HpackBlockDecoder::Reset";
    before_entry_ = true;
  }

  // Decode the fragment of the HPACK block contained in the decode buffer.
  // Expected to be called from an implementation of Http2FrameDecoderListener's
  // OnHpackFragment method.
  DecodeStatus Decode(DecodeBuffer* db);

  // Is the decoding process between entries (i.e. would the next byte be the
  // first byte of a new HPACK entry)?
  bool before_entry() const { return before_entry_; }

  std::string DebugString() const;

 private:
  HpackEntryDecoder entry_decoder_;
  HpackEntryDecoderListener* listener_;
  bool before_entry_ = true;

  DISALLOW_COPY_AND_ASSIGN(HpackBlockDecoder);
};

NET_EXPORT_PRIVATE std::ostream& operator<<(std::ostream& out,
                                            const HpackBlockDecoder& v);

}  // namespace net

#endif  // NET_HTTP2_HPACK_DECODER_HPACK_BLOCK_DECODER_H_
