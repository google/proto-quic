// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http2/decoder/decode_buffer.h"

namespace net {

bool DecodeBuffer::SlowDecodeUnsignedInt(uint32_t field_size,
                                         uint32_t field_offset,
                                         uint32_t* decode_offset,
                                         uint32_t* value) {
  DCHECK_LT(0u, field_size);
  DCHECK_LE(field_size, 4u);
  DCHECK(decode_offset != nullptr);
  DCHECK_LE(field_offset, *decode_offset);
  const uint32_t next_field_offset = field_offset + field_size;
  if (*decode_offset == field_offset) {
    // Starting to decode field. It is possible we will reach this point
    // twice, once when we've just exhausted the input, and once when
    // resuming decoding with a new input buffer.
    // Clear the field; we do NOT assume that the caller has done so
    // previously.
    *value = 0;
  } else if (*decode_offset >= next_field_offset) {
    // We already decoded this field.
    return true;
  }
  do {
    if (Empty()) {
      return false;  // Not done decoding.
    }
    *value = *value << 8 | DecodeUInt8();
    (*decode_offset)++;
  } while (*decode_offset < next_field_offset);
  return true;
}

bool DecodeBuffer::SlowDecodeUInt8(uint32_t field_offset,
                                   uint32_t* decode_offset,
                                   uint8_t* value) {
  uint32_t tmp = *value;
  const bool done = SlowDecodeUnsignedInt(1 /* field_size */, field_offset,
                                          decode_offset, &tmp);
  *value = tmp & 0xff;
  DCHECK_EQ(tmp, *value);
  return done;
}

bool DecodeBuffer::SlowDecodeUInt16(uint32_t field_offset,
                                    uint32_t* decode_offset,
                                    uint16_t* value) {
  uint32_t tmp = *value;
  const bool done = SlowDecodeUnsignedInt(2 /* field_size */, field_offset,
                                          decode_offset, &tmp);
  *value = tmp & 0xffff;
  DCHECK_EQ(tmp, *value);
  return done;
}

bool DecodeBuffer::SlowDecodeUInt24(uint32_t field_offset,
                                    uint32_t* decode_offset,
                                    uint32_t* value) {
  uint32_t tmp = *value;
  const bool done = SlowDecodeUnsignedInt(3 /* field_size */, field_offset,
                                          decode_offset, &tmp);
  *value = tmp & 0xffffff;
  DCHECK_EQ(tmp, *value);
  return done;
}

bool DecodeBuffer::SlowDecodeUInt31(uint32_t field_offset,
                                    uint32_t* decode_offset,
                                    uint32_t* value) {
  uint32_t tmp = *value;
  const bool done = SlowDecodeUnsignedInt(4 /* field_size */, field_offset,
                                          decode_offset, &tmp);
  *value = tmp & 0x7fffffff;
  DCHECK_EQ(tmp & 0x7fffffff, *value);
  return done;
}

bool DecodeBuffer::SlowDecodeUInt32(uint32_t field_offset,
                                    uint32_t* decode_offset,
                                    uint32_t* value) {
  return SlowDecodeUnsignedInt(4 /* field_size */, field_offset, decode_offset,
                               value);
}

}  // namespace net
