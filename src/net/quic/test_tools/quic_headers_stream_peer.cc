// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/test_tools/quic_headers_stream_peer.h"

#include "net/quic/core/quic_headers_stream.h"

namespace net {
namespace test {

// static
const SpdyFramer& QuicHeadersStreamPeer::GetSpdyFramer(
    QuicHeadersStream* stream) {
  return stream->spdy_framer_;
}

}  // namespace test
}  // namespace net
