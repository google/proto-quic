// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_HTTP2_HPACK_DECODER_HPACK_DECODER_STRING_BUFFER_H_
#define NET_HTTP2_HPACK_DECODER_HPACK_DECODER_STRING_BUFFER_H_

// HpackDecoderStringBuffer helps an HPACK decoder to avoid copies of a string
// literal (name or value) except when necessary (e.g. when split across two
// or more HPACK block fragments).

#include <stddef.h>

#include <ostream>
#include <string>

#include "base/macros.h"
#include "base/strings/string_piece.h"
#include "net/base/net_export.h"
#include "net/http2/hpack/huffman/http2_hpack_huffman_decoder.h"

namespace net {

class NET_EXPORT_PRIVATE HpackDecoderStringBuffer {
 public:
  enum class State : uint8_t { RESET, COLLECTING, COMPLETE };
  enum class Backing : uint8_t { RESET, UNBUFFERED, BUFFERED, STATIC };

  HpackDecoderStringBuffer();
  ~HpackDecoderStringBuffer();

  void Reset();
  void Set(base::StringPiece value, bool is_static);

  // Note that for Huffman encoded strings the length of the string after
  // decoding may be larger (expected), the same or even smaller; the latter
  // are unlikely, but possible if the encoder makes odd choices.
  void OnStart(bool huffman_encoded, size_t len);
  bool OnData(const char* data, size_t len);
  bool OnEnd();
  void BufferStringIfUnbuffered();
  size_t BufferedLength() const;

  base::StringPiece str() const;

  State state_for_testing() const { return state_; }
  Backing backing_for_testing() const { return backing_; }
  void OutputDebugStringTo(std::ostream& out) const;

 private:
  // Storage for the string being buffered, if buffering is necessary
  // (e.g. if Huffman encoded, buffer_ is storage for the decoded string).
  std::string buffer_;

  // The StringPiece to be returned by HpackDecoderStringBuffer::str(). If a
  // string has been collected, but not buffered, value_ points to that string.
  base::StringPiece value_;

  // The decoder to use if the string is Huffman encoded.
  HpackHuffmanDecoder decoder_;

  // Count of bytes not yet passed to OnData.
  size_t remaining_len_ = 0;

  // Is the HPACK string Huffman encoded?
  bool is_huffman_encoded_ = false;

  // State of the string decoding process.
  State state_;

  // Where is the string stored?
  Backing backing_;

  DISALLOW_COPY_AND_ASSIGN(HpackDecoderStringBuffer);
};

NET_EXPORT_PRIVATE std::ostream& operator<<(std::ostream& out,
                                            const HpackDecoderStringBuffer& v);

}  // namespace net

#endif  // NET_HTTP2_HPACK_DECODER_HPACK_DECODER_STRING_BUFFER_H_
