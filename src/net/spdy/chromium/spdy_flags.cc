// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/chromium/spdy_flags.h"

namespace net {

// Log compressed size of HTTP/2 requests.
bool FLAGS_chromium_http2_flag_log_compressed_size = true;

// Use //net/http2/hpack/decoder as complete HPACK decoder.
bool FLAGS_chromium_http2_flag_spdy_use_hpack_decoder3 = true;

// Use Http2FrameDecoderAdapter.
// TODO(jamessynge): Remove flag once no longer set by scripts.
bool FLAGS_chromium_http2_flag_spdy_use_http2_frame_decoder_adapter = true;

// Use NestedSpdyFramerDecoder.
bool FLAGS_use_nested_spdy_framer_decoder = false;

}  // namespace net
