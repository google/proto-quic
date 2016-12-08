// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http2/hpack/decoder/hpack_varint_decoder.h"

#include <sstream>

namespace net {

std::string HpackVarintDecoder::DebugString() const {
  std::stringstream ss;
  ss << "HpackVarintDecoder(value=" << value_ << ", offset=" << offset_ << ")";
  return ss.str();
}

DecodeStatus HpackVarintDecoder::StartForTest(uint8_t prefix_value,
                                              uint8_t prefix_mask,
                                              DecodeBuffer* db) {
  return Start(prefix_value, prefix_mask, db);
}

DecodeStatus HpackVarintDecoder::StartExtendedForTest(uint8_t prefix_mask,
                                                      DecodeBuffer* db) {
  return StartExtended(prefix_mask, db);
}

DecodeStatus HpackVarintDecoder::ResumeForTest(DecodeBuffer* db) {
  return Resume(db);
}

std::ostream& operator<<(std::ostream& out, const HpackVarintDecoder& v) {
  return out << v.DebugString();
}

}  // namespace net
