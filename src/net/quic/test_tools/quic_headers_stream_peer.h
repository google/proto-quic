// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_TEST_TOOLS_QUIC_HEADERS_STREAM_PEER_H_
#define NET_QUIC_TEST_TOOLS_QUIC_HEADERS_STREAM_PEER_H_

#include "net/spdy/spdy_framer.h"

namespace net {

class QuicHeadersStream;

namespace test {

class QuicHeadersStreamPeer {
 public:
  static const SpdyFramer& GetSpdyFramer(QuicHeadersStream* stream);

 private:
  DISALLOW_COPY_AND_ASSIGN(QuicHeadersStreamPeer);
};

}  // namespace test

}  // namespace net

#endif  // NET_QUIC_TEST_TOOLS_QUIC_HEADERS_STREAM_PEER_H_
