// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_TOOLS_QUIC_QUIC_SPDY_SERVER_STREAM_H_
#define NET_TOOLS_QUIC_QUIC_SPDY_SERVER_STREAM_H_

#include <string>

#include "base/basictypes.h"
#include "net/quic/quic_data_stream.h"
#include "net/quic/quic_protocol.h"
#include "net/spdy/spdy_framer.h"

namespace net {

class QuicSession;

namespace tools {

namespace test {
class QuicSpdyServerStreamPeer;
}  // namespace test

// All this does right now is aggregate data, and on fin, send an HTTP
// response.
class QuicSpdyServerStream : public QuicDataStream {
 public:
  QuicSpdyServerStream(QuicStreamId id, QuicSession* session);
  ~QuicSpdyServerStream() override;

  // ReliableQuicStream implementation called by the session when there's
  // data for us.
  uint32 ProcessData(const char* data, uint32 data_len) override;
  void OnFinRead() override;

 private:
  friend class test::QuicSpdyServerStreamPeer;

  // Parses the request headers from |data| to |request_headers_|.
  // Returns false if there was an error parsing the headers.
  bool ParseRequestHeaders(const char* data, uint32 data_len);

  // Sends a basic 200 response using SendHeaders for the headers and WriteData
  // for the body.
  void SendResponse();

  // Sends a basic 500 response using SendHeaders for the headers and WriteData
  // for the body
  void SendErrorResponse();

  void SendHeadersAndBody(const SpdyHeaderBlock& response_headers,
                          base::StringPiece body);

  // Returns the key for |request_headers_| which identifies the host.
  const std::string GetHostKey();

  // The parsed headers received from the client.
  SpdyHeaderBlock request_headers_;
  int content_length_;
  std::string body_;

  DISALLOW_COPY_AND_ASSIGN(QuicSpdyServerStream);
};

}  // namespace tools
}  // namespace net

#endif  // NET_TOOLS_QUIC_QUIC_SPDY_SERVER_STREAM_H_
