// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SPDY_CORE_HTTP2_FRAME_DECODER_ADAPTER_H_
#define NET_SPDY_CORE_HTTP2_FRAME_DECODER_ADAPTER_H_

// Provides a SpdyFramerDecoderAdapter that uses Http2FrameDecoder for decoding
// HTTP/2 frames. The adapter does not directly decode HPACK, but instead calls
// SpdyFramer::GetHpackDecoderForAdapter() to get the decoder to be used.

#include <memory>

#include "net/spdy/core/spdy_framer.h"
#include "net/spdy/core/spdy_framer_decoder_adapter.h"

namespace net {

std::unique_ptr<SpdyFramerDecoderAdapter> CreateHttp2FrameDecoderAdapter(
    SpdyFramer* outer_framer);

}  // namespace net

#endif  // NET_SPDY_CORE_HTTP2_FRAME_DECODER_ADAPTER_H_
