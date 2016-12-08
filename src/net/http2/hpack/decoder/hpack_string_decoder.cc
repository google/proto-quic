// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http2/hpack/decoder/hpack_string_decoder.h"

#include <sstream>

namespace net {

std::string HpackStringDecoder::DebugString() const {
  std::stringstream ss;
  ss << "HpackStringDecoder(state=" << StateToString(state_)
     << ", length=" << length_decoder_.DebugString()
     << ", remaining=" << remaining_
     << ", huffman=" << (huffman_encoded_ ? "true)" : "false)");
  return ss.str();
}

// static
std::string HpackStringDecoder::StateToString(StringDecoderState v) {
  switch (v) {
    case kStartDecodingLength:
      return "kStartDecodingLength";
    case kDecodingString:
      return "kDecodingString";
    case kResumeDecodingLength:
      return "kResumeDecodingLength";
  }
  std::stringstream ss;
  ss << "UNKNOWN_STATE(" << static_cast<uint32_t>(v) << ")";
  return ss.str();
}

std::ostream& operator<<(std::ostream& out, const HpackStringDecoder& v) {
  return out << v.DebugString();
}

}  // namespace net
