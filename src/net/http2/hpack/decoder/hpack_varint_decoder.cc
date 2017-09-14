// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http2/hpack/decoder/hpack_varint_decoder.h"

#include "net/http2/platform/api/http2_string_utils.h"

namespace net {

Http2String HpackVarintDecoder::DebugString() const {
  return Http2StrCat("HpackVarintDecoder(value=", value_, ", offset=", offset_,
                     ")");
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

}  // namespace net
