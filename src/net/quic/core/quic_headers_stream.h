// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_CORE_QUIC_HEADERS_STREAM_H_
#define NET_QUIC_CORE_QUIC_HEADERS_STREAM_H_

#include <cstddef>
#include <memory>

#include "base/macros.h"
#include "net/quic/core/quic_header_list.h"
#include "net/quic/core/quic_packets.h"
#include "net/quic/core/quic_stream.h"
#include "net/quic/platform/api/quic_export.h"
#include "net/spdy/core/spdy_framer.h"

namespace net {

class QuicSpdySession;

namespace test {
class QuicHeadersStreamPeer;
}  // namespace test

// Headers in QUIC are sent as HTTP/2 HEADERS or PUSH_PROMISE frames over a
// reserved stream with the id 3.  Each endpoint (client and server) will
// allocate an instance of QuicHeadersStream to send and receive headers.
class QUIC_EXPORT_PRIVATE QuicHeadersStream : public QuicStream {
 public:
  explicit QuicHeadersStream(QuicSpdySession* session);
  ~QuicHeadersStream() override;

  // QuicStream implementation
  void OnDataAvailable() override;

  // Release underlying buffer if allowed.
  void MaybeReleaseSequencerBuffer();

 private:
  friend class test::QuicHeadersStreamPeer;

  // Returns true if the session is still connected.
  bool IsConnected();

  QuicSpdySession* spdy_session_;

  DISALLOW_COPY_AND_ASSIGN(QuicHeadersStream);
};

}  // namespace net

#endif  // NET_QUIC_CORE_QUIC_HEADERS_STREAM_H_
