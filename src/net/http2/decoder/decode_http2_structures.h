// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_HTTP2_DECODER_DECODE_HTTP2_STRUCTURES_H_
#define NET_HTTP2_DECODER_DECODE_HTTP2_STRUCTURES_H_

// Provides functions for decoding the fixed size structures in the HTTP/2 spec.

// TODO(jamessynge): Consider whether the value of the SlowDecode methods is
// worth their complexity; in particular, dropping back to buffering at most
// 9 bytes (the largest fixed size structure) may actually be more efficient
// than using the SlowDecode methods, or at least worth the complexity
// reduction.
// See http2_structure_decoder.h et al for an experiment in removing all except
// DoDecode.

#include "net/base/net_export.h"
#include "net/http2/decoder/decode_buffer.h"
#include "net/http2/http2_structures.h"

namespace net {

// DoDecode(STRUCTURE* out, DecodeBuffer* b) decodes the structure from start
// to end, advancing the cursor by STRUCTURE::EncodedSize(). The decoder buffer
// must be large enough (i.e. b->Remaining() >= STRUCTURE::EncodedSize()).

NET_EXPORT_PRIVATE void DoDecode(Http2FrameHeader* out, DecodeBuffer* b);
NET_EXPORT_PRIVATE void DoDecode(Http2PriorityFields* out, DecodeBuffer* b);
NET_EXPORT_PRIVATE void DoDecode(Http2RstStreamFields* out, DecodeBuffer* b);
NET_EXPORT_PRIVATE void DoDecode(Http2SettingFields* out, DecodeBuffer* b);
NET_EXPORT_PRIVATE void DoDecode(Http2PushPromiseFields* out, DecodeBuffer* b);
NET_EXPORT_PRIVATE void DoDecode(Http2PingFields* out, DecodeBuffer* b);
NET_EXPORT_PRIVATE void DoDecode(Http2GoAwayFields* out, DecodeBuffer* b);
NET_EXPORT_PRIVATE void DoDecode(Http2WindowUpdateFields* out, DecodeBuffer* b);
NET_EXPORT_PRIVATE void DoDecode(Http2AltSvcFields* out, DecodeBuffer* b);

// MaybeDecode(STRUCTURE* out, DecodeBuffer* b) decodes the structure from
// start to end if the decoder buffer is large enough, advancing the cursor
// by STRUCTURE::EncodedSize(), then returns true.
// If the decode buffer isn't large enough, does nothing and returns false.
// The buffer is large enough if b->Remaining() >= STRUCTURE::EncodedSize().

NET_EXPORT_PRIVATE bool MaybeDecode(Http2FrameHeader* out, DecodeBuffer* b);
NET_EXPORT_PRIVATE bool MaybeDecode(Http2PriorityFields* out, DecodeBuffer* b);
NET_EXPORT_PRIVATE bool MaybeDecode(Http2RstStreamFields* out, DecodeBuffer* b);
NET_EXPORT_PRIVATE bool MaybeDecode(Http2SettingFields* out, DecodeBuffer* b);
NET_EXPORT_PRIVATE bool MaybeDecode(Http2PushPromiseFields* out,
                                    DecodeBuffer* b);
NET_EXPORT_PRIVATE bool MaybeDecode(Http2PingFields* out, DecodeBuffer* b);
NET_EXPORT_PRIVATE bool MaybeDecode(Http2GoAwayFields* out, DecodeBuffer* b);
NET_EXPORT_PRIVATE bool MaybeDecode(Http2WindowUpdateFields* out,
                                    DecodeBuffer* b);
NET_EXPORT_PRIVATE bool MaybeDecode(Http2AltSvcFields* out, DecodeBuffer* b);

// SlowDecode(STRUCTURE* out, DecodeBuffer* b, uint32_t* offset) provides
// incremental decoding of a structure, supporting cases where the structure
// is split across multiple input buffers. *offset represents the offset within
// the encoding of the structure, in the range [0, STRUCTURE::EncodedSize()].
// Returns true when it is able to completely decode the structure, false
// before that. Updates *offset to record the progress decoding the structure;
// if false is returned, then b->Remaining() == 0 when SlowDecode returns.

NET_EXPORT_PRIVATE bool SlowDecode(Http2FrameHeader* out,
                                   DecodeBuffer* b,
                                   uint32_t* offset);
NET_EXPORT_PRIVATE bool SlowDecode(Http2PriorityFields* out,
                                   DecodeBuffer* b,
                                   uint32_t* offset);
NET_EXPORT_PRIVATE bool SlowDecode(Http2RstStreamFields* out,
                                   DecodeBuffer* b,
                                   uint32_t* offset);
NET_EXPORT_PRIVATE bool SlowDecode(Http2SettingFields* out,
                                   DecodeBuffer* b,
                                   uint32_t* offset);
NET_EXPORT_PRIVATE bool SlowDecode(Http2PushPromiseFields* out,
                                   DecodeBuffer* b,
                                   uint32_t* offset);
NET_EXPORT_PRIVATE bool SlowDecode(Http2PingFields* out,
                                   DecodeBuffer* b,
                                   uint32_t* offset);
NET_EXPORT_PRIVATE bool SlowDecode(Http2GoAwayFields* out,
                                   DecodeBuffer* b,
                                   uint32_t* offset);
NET_EXPORT_PRIVATE bool SlowDecode(Http2WindowUpdateFields* out,
                                   DecodeBuffer* b,
                                   uint32_t* offset);
NET_EXPORT_PRIVATE bool SlowDecode(Http2AltSvcFields* out,
                                   DecodeBuffer* b,
                                   uint32_t* offset);

}  // namespace net

#endif  // NET_HTTP2_DECODER_DECODE_HTTP2_STRUCTURES_H_
