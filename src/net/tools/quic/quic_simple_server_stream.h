// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// // Use of this source code is governed by a BSD-style license that can be
// // found in the LICENSE file.

#ifndef NET_TOOLS_QUIC_QUIC_SIMPLE_SERVER_STREAM_H_
#define NET_TOOLS_QUIC_QUIC_SIMPLE_SERVER_STREAM_H_

#include <stddef.h>

#include <string>

#include "base/macros.h"
#include "net/quic/quic_protocol.h"
#include "net/quic/quic_spdy_stream.h"
#include "net/spdy/spdy_framer.h"

namespace net {


namespace test {
class QuicSimpleServerStreamPeer;
}  // namespace test

// All this does right now is aggregate data, and on fin, send an HTTP
// response.
class QuicSimpleServerStream : public QuicSpdyStream {
 public:
  QuicSimpleServerStream(QuicStreamId id, QuicSpdySession* session);
  ~QuicSimpleServerStream() override;

  // QuicSpdyStream
  void OnInitialHeadersComplete(bool fin, size_t frame_len) override;
  void OnTrailingHeadersComplete(bool fin, size_t frame_len) override;
  void OnInitialHeadersComplete(bool fin,
                                size_t frame_len,
                                const QuicHeaderList& header_list) override;
  void OnTrailingHeadersComplete(bool fin,
                                 size_t frame_len,
                                 const QuicHeaderList& header_list) override;

  // ReliableQuicStream implementation called by the sequencer when there is
  // data (or a FIN) to be read.
  void OnDataAvailable() override;

  // Make this stream start from as if it just finished parsing an incoming
  // request whose headers are equivalent to |push_request_headers|.
  // Doing so will trigger this toy stream to fetch response and send it back.
  virtual void PushResponse(SpdyHeaderBlock push_request_headers);

  // The response body of error responses.
  static const char* const kErrorResponseBody;
  static const char* const kNotFoundResponseBody;

 protected:
  // Sends a basic 200 response using SendHeaders for the headers and WriteData
  // for the body.
  virtual void SendResponse();

  // Sends a basic 500 response using SendHeaders for the headers and WriteData
  // for the body.
  virtual void SendErrorResponse();

  // Sends a basic 404 response using SendHeaders for the headers and WriteData
  // for the body.
  void SendNotFoundResponse();

  void SendHeadersAndBody(const SpdyHeaderBlock& response_headers,
                          base::StringPiece body);
  void SendHeadersAndBodyAndTrailers(const SpdyHeaderBlock& response_headers,
                                     base::StringPiece body,
                                     const SpdyHeaderBlock& response_trailers);

  SpdyHeaderBlock* request_headers() { return &request_headers_; }

  const std::string& body() { return body_; }

 private:
  friend class test::QuicSimpleServerStreamPeer;

  // The parsed headers received from the client.
  SpdyHeaderBlock request_headers_;
  int64_t content_length_;
  std::string body_;

  DISALLOW_COPY_AND_ASSIGN(QuicSimpleServerStream);
};

}  // namespace net

#endif  // NET_TOOLS_QUIC_QUIC_SIMPLE_SERVER_STREAM_H_
