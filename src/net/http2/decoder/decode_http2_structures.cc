// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http2/decoder/decode_http2_structures.h"

#include <string.h>

#include "base/logging.h"
#include "net/http2/decoder/decode_buffer.h"
#include "net/http2/http2_constants.h"

namespace net {

// Http2FrameHeader decoding:

void DoDecode(Http2FrameHeader* out, DecodeBuffer* b) {
  DCHECK_NE(nullptr, out);
  DCHECK_NE(nullptr, b);
  DCHECK_LE(Http2FrameHeader::EncodedSize(), b->Remaining());
  out->payload_length = b->DecodeUInt24();
  out->type = static_cast<Http2FrameType>(b->DecodeUInt8());
  out->flags = static_cast<Http2FrameFlag>(b->DecodeUInt8());
  out->stream_id = b->DecodeUInt31();
}

bool MaybeDecode(Http2FrameHeader* out, DecodeBuffer* b) {
  DCHECK_NE(nullptr, out);
  DCHECK_NE(nullptr, b);
  if (b->Remaining() >= Http2FrameHeader::EncodedSize()) {
    DoDecode(out, b);
    return true;
  }
  return false;
}

bool SlowDecode(Http2FrameHeader* out, DecodeBuffer* b, uint32_t* offset) {
  DCHECK_NE(nullptr, out);
  DCHECK_NE(nullptr, b);
  DCHECK_NE(nullptr, offset);
  DCHECK_GT(Http2FrameHeader::EncodedSize(), *offset);
  if (b->SlowDecodeUInt24(0 /* field_offset */, offset, &out->payload_length) &&
      b->SlowDecodeEnum(1 /* field_size */, 3 /* field_offset */, offset,
                        &out->type) &&
      b->SlowDecodeEnum(1 /* field_size */, 4 /* field_offset */, offset,
                        &out->flags) &&
      b->SlowDecodeUInt31(5 /* field_offset */, offset, &out->stream_id)) {
    DCHECK_EQ(Http2FrameHeader::EncodedSize(), *offset);
    return true;
  }
  DCHECK_GT(Http2FrameHeader::EncodedSize(), *offset);
  return false;
}

// Http2PriorityFields decoding:

void DoDecode(Http2PriorityFields* out, DecodeBuffer* b) {
  DCHECK_NE(nullptr, out);
  DCHECK_NE(nullptr, b);
  DCHECK_LE(Http2PriorityFields::EncodedSize(), b->Remaining());
  uint32_t stream_id_and_flag = b->DecodeUInt32();
  out->stream_dependency = stream_id_and_flag & StreamIdMask();
  if (out->stream_dependency == stream_id_and_flag) {
    out->is_exclusive = false;
  } else {
    out->is_exclusive = true;
  }
  // Note that chars are automatically promoted to ints during arithmetic,
  // so 255 + 1 doesn't end up as zero.
  out->weight = b->DecodeUInt8() + 1;
}

bool MaybeDecode(Http2PriorityFields* out, DecodeBuffer* b) {
  DCHECK_NE(nullptr, out);
  DCHECK_NE(nullptr, b);
  if (b->Remaining() >= Http2PriorityFields::EncodedSize()) {
    DoDecode(out, b);
    return true;
  }
  return false;
}

bool SlowDecode(Http2PriorityFields* out, DecodeBuffer* b, uint32_t* offset) {
  DCHECK_NE(nullptr, out);
  DCHECK_NE(nullptr, b);
  DCHECK_NE(nullptr, offset);
  DCHECK_GT(Http2PriorityFields::EncodedSize(), *offset);
  const uint32_t start_offset = *offset;
  if (b->SlowDecodeUInt32(0 /* field_offset */, offset,
                          &out->stream_dependency) &&
      b->SlowDecodeUnsignedInt(1,  // field_size
                               4,  // field_offset
                               offset, &out->weight)) {
    DCHECK_EQ(Http2PriorityFields::EncodedSize(), *offset);
    if (start_offset < *offset) {
      // First time here. Extract is_exclusive from stream_dependency.
      const uint32_t stream_id_only = out->stream_dependency & StreamIdMask();
      if (out->stream_dependency != stream_id_only) {
        out->stream_dependency = stream_id_only;
        out->is_exclusive = true;
      } else {
        out->is_exclusive = false;
      }
      // Need to add one to the weight field because the encoding is 0-255, but
      // interpreted as 1-256.
      ++(out->weight);
    }
    return true;
  }
  DCHECK_GT(Http2PriorityFields::EncodedSize(), *offset);
  return false;
}

// Http2RstStreamFields decoding:

void DoDecode(Http2RstStreamFields* out, DecodeBuffer* b) {
  DCHECK_NE(nullptr, out);
  DCHECK_NE(nullptr, b);
  DCHECK_LE(Http2RstStreamFields::EncodedSize(), b->Remaining());
  out->error_code = static_cast<Http2ErrorCode>(b->DecodeUInt32());
}

bool MaybeDecode(Http2RstStreamFields* out, DecodeBuffer* b) {
  DCHECK_NE(nullptr, out);
  DCHECK_NE(nullptr, b);
  if (b->Remaining() >= Http2RstStreamFields::EncodedSize()) {
    DoDecode(out, b);
    return true;
  }
  return false;
}

bool SlowDecode(Http2RstStreamFields* out, DecodeBuffer* b, uint32_t* offset) {
  DCHECK_NE(nullptr, out);
  DCHECK_NE(nullptr, b);
  DCHECK_NE(nullptr, offset);
  DCHECK_GT(Http2RstStreamFields::EncodedSize(), *offset);

  if (b->SlowDecodeEnum(4 /* field_size */, 0 /* field_offset */, offset,
                        &out->error_code)) {
    DCHECK_EQ(Http2RstStreamFields::EncodedSize(), *offset);
    return true;
  }
  DCHECK_GT(Http2RstStreamFields::EncodedSize(), *offset);
  return false;
}

// Http2SettingFields decoding:

void DoDecode(Http2SettingFields* out, DecodeBuffer* b) {
  DCHECK_NE(nullptr, out);
  DCHECK_NE(nullptr, b);
  DCHECK_LE(Http2SettingFields::EncodedSize(), b->Remaining());
  out->parameter = static_cast<Http2SettingsParameter>(b->DecodeUInt16());
  out->value = b->DecodeUInt32();
}

bool MaybeDecode(Http2SettingFields* out, DecodeBuffer* b) {
  DCHECK_NE(nullptr, out);
  DCHECK_NE(nullptr, b);
  if (b->Remaining() >= Http2SettingFields::EncodedSize()) {
    DoDecode(out, b);
    return true;
  }
  return false;
}

bool SlowDecode(Http2SettingFields* out, DecodeBuffer* b, uint32_t* offset) {
  DCHECK_NE(nullptr, out);
  DCHECK_NE(nullptr, b);
  DCHECK_NE(nullptr, offset);
  DCHECK_LT(*offset, Http2SettingFields::EncodedSize());

  if (b->SlowDecodeEnum(2 /* field_size */, 0 /* field_offset */, offset,
                        &out->parameter) &&
      b->SlowDecodeUInt32(2 /* field_offset */, offset, &out->value)) {
    DCHECK_EQ(Http2SettingFields::EncodedSize(), *offset);
    return true;
  }
  DCHECK_LT(*offset, Http2SettingFields::EncodedSize());
  return false;
}

// Http2PushPromiseFields decoding:

void DoDecode(Http2PushPromiseFields* out, DecodeBuffer* b) {
  DCHECK_NE(nullptr, out);
  DCHECK_NE(nullptr, b);
  DCHECK_LE(Http2PushPromiseFields::EncodedSize(), b->Remaining());
  out->promised_stream_id = b->DecodeUInt31();
}

bool MaybeDecode(Http2PushPromiseFields* out, DecodeBuffer* b) {
  DCHECK_NE(nullptr, out);
  DCHECK_NE(nullptr, b);
  if (b->Remaining() >= Http2PushPromiseFields::EncodedSize()) {
    DoDecode(out, b);
    return true;
  }
  return false;
}

bool SlowDecode(Http2PushPromiseFields* out,
                DecodeBuffer* b,
                uint32_t* offset) {
  DCHECK_NE(nullptr, out);
  DCHECK_NE(nullptr, b);
  DCHECK_NE(nullptr, offset);
  DCHECK_LT(*offset, Http2PushPromiseFields::EncodedSize());
  if (b->SlowDecodeUInt31(0 /* field_offset */, offset,
                          &out->promised_stream_id)) {
    DCHECK_EQ(Http2PushPromiseFields::EncodedSize(), *offset);
    return true;
  }
  DCHECK_LT(*offset, Http2PushPromiseFields::EncodedSize());
  return false;
}

// Http2PingFields decoding:

void DoDecode(Http2PingFields* out, DecodeBuffer* b) {
  DCHECK_NE(nullptr, out);
  DCHECK_NE(nullptr, b);
  DCHECK_LE(Http2PingFields::EncodedSize(), b->Remaining());
  memcpy(out->opaque_data, b->cursor(), Http2PingFields::EncodedSize());
  b->AdvanceCursor(Http2PingFields::EncodedSize());
}

bool MaybeDecode(Http2PingFields* out, DecodeBuffer* b) {
  DCHECK_NE(nullptr, out);
  DCHECK_NE(nullptr, b);
  if (b->Remaining() >= Http2PingFields::EncodedSize()) {
    DoDecode(out, b);
    return true;
  }
  return false;
}

bool SlowDecode(Http2PingFields* out, DecodeBuffer* b, uint32_t* offset) {
  DCHECK_NE(nullptr, out);
  DCHECK_NE(nullptr, b);
  DCHECK_NE(nullptr, offset);
  DCHECK_LT(*offset, Http2PingFields::EncodedSize());
  while (*offset < Http2PingFields::EncodedSize()) {
    if (b->Empty()) {
      return false;
    }
    out->opaque_data[(*offset)++] = b->DecodeUInt8();
  }
  return true;
}

// Http2GoAwayFields decoding:

void DoDecode(Http2GoAwayFields* out, DecodeBuffer* b) {
  DCHECK_NE(nullptr, out);
  DCHECK_NE(nullptr, b);
  DCHECK_LE(Http2GoAwayFields::EncodedSize(), b->Remaining());
  out->last_stream_id = b->DecodeUInt31();
  out->error_code = static_cast<Http2ErrorCode>(b->DecodeUInt32());
}

bool MaybeDecode(Http2GoAwayFields* out, DecodeBuffer* b) {
  DCHECK_NE(nullptr, out);
  DCHECK_NE(nullptr, b);
  if (b->Remaining() >= Http2GoAwayFields::EncodedSize()) {
    DoDecode(out, b);
    return true;
  }
  return false;
}

bool SlowDecode(Http2GoAwayFields* out, DecodeBuffer* b, uint32_t* offset) {
  DCHECK_NE(nullptr, out);
  DCHECK_NE(nullptr, b);
  DCHECK_NE(nullptr, offset);
  DCHECK_LT(*offset, Http2GoAwayFields::EncodedSize());
  if (b->SlowDecodeUInt31(0 /* field_offset */, offset, &out->last_stream_id) &&
      b->SlowDecodeEnum(4 /* field_size */, 4 /* field_offset */, offset,
                        &out->error_code)) {
    DCHECK_EQ(Http2GoAwayFields::EncodedSize(), *offset);
    return true;
  }
  DCHECK_LT(*offset, Http2GoAwayFields::EncodedSize());
  return false;
}

// Http2WindowUpdateFields decoding:

void DoDecode(Http2WindowUpdateFields* out, DecodeBuffer* b) {
  DCHECK_NE(nullptr, out);
  DCHECK_NE(nullptr, b);
  DCHECK_LE(Http2WindowUpdateFields::EncodedSize(), b->Remaining());
  out->window_size_increment = b->DecodeUInt31();
}

bool MaybeDecode(Http2WindowUpdateFields* out, DecodeBuffer* b) {
  DCHECK_NE(nullptr, out);
  DCHECK_NE(nullptr, b);
  if (b->Remaining() >= Http2WindowUpdateFields::EncodedSize()) {
    DoDecode(out, b);
    return true;
  }
  return false;
}

bool SlowDecode(Http2WindowUpdateFields* out,
                DecodeBuffer* b,
                uint32_t* offset) {
  DCHECK_NE(nullptr, out);
  DCHECK_NE(nullptr, b);
  DCHECK_NE(nullptr, offset);
  DCHECK_LT(*offset, Http2WindowUpdateFields::EncodedSize());
  if (b->SlowDecodeUInt31(0 /* field_offset */, offset,
                          &out->window_size_increment)) {
    DCHECK_EQ(Http2WindowUpdateFields::EncodedSize(), *offset);
    return true;
  }
  DCHECK_LT(*offset, Http2WindowUpdateFields::EncodedSize());
  return false;
}

// Http2AltSvcFields decoding:

void DoDecode(Http2AltSvcFields* out, DecodeBuffer* b) {
  DCHECK_NE(nullptr, out);
  DCHECK_NE(nullptr, b);
  DCHECK_LE(Http2AltSvcFields::EncodedSize(), b->Remaining());
  out->origin_length = b->DecodeUInt16();
}

bool MaybeDecode(Http2AltSvcFields* out, DecodeBuffer* b) {
  DCHECK_NE(nullptr, out);
  DCHECK_NE(nullptr, b);
  if (b->Remaining() >= Http2AltSvcFields::EncodedSize()) {
    DoDecode(out, b);
    return true;
  }
  return false;
}

bool SlowDecode(Http2AltSvcFields* out, DecodeBuffer* b, uint32_t* offset) {
  DCHECK_NE(nullptr, out);
  DCHECK_NE(nullptr, b);
  DCHECK_NE(nullptr, offset);
  DCHECK_LT(*offset, Http2AltSvcFields::EncodedSize());
  if (b->SlowDecodeUInt16(0 /* field_offset */, offset, &out->origin_length)) {
    DCHECK_EQ(Http2AltSvcFields::EncodedSize(), *offset);
    return true;
  }
  DCHECK_LT(*offset, Http2AltSvcFields::EncodedSize());
  return false;
}

}  // namespace net
