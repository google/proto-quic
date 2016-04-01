// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_TEST_TOOLS_QUIC_SPDY_SESSION_PEER_H_
#define NET_QUIC_TEST_TOOLS_QUIC_SPDY_SESSION_PEER_H_

#include "base/macros.h"
#include "net/quic/quic_protocol.h"
#include "net/quic/quic_write_blocked_list.h"

namespace net {

class QuicHeadersStream;
class QuicSpdySession;

namespace test {

class QuicSpdySessionPeer {
 public:
  static QuicHeadersStream* GetHeadersStream(QuicSpdySession* session);
  static void SetHeadersStream(QuicSpdySession* session,
                               QuicHeadersStream* headers_stream);

 private:
  DISALLOW_COPY_AND_ASSIGN(QuicSpdySessionPeer);
};

}  // namespace test

}  // namespace net

#endif  // NET_QUIC_TEST_TOOLS_QUIC_SPDY_SESSION_PEER_H_
