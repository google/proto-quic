// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_TOOLS_QUIC_QUIC_SPDY_CLIENT_STREAM_H_
#define NET_TOOLS_QUIC_QUIC_SPDY_CLIENT_STREAM_H_

#include <stddef.h>
#include <sys/types.h>
#include <string>

#include "base/macros.h"
#include "base/strings/string_piece.h"
#include "net/quic/quic_protocol.h"
#include "net/quic/quic_spdy_stream.h"
#include "net/spdy/spdy_framer.h"

namespace net {

class QuicClientSession;

// All this does right now is send an SPDY request, and aggregate the
// SPDY response.
class QuicSpdyClientStream : public QuicSpdyStream {
 public:
  QuicSpdyClientStream(QuicStreamId id, QuicClientSession* session);
  ~QuicSpdyClientStream() override;

  // Override the base class to close the write side as soon as we get a
  // response.
  // SPDY/HTTP does not support bidirectional streaming.
  void OnStreamFrame(const QuicStreamFrame& frame) override;

  // Override the base class to parse and store headers.
  void OnInitialHeadersComplete(bool fin, size_t frame_len) override;

  // Override the base class to parse and store headers.
  void OnInitialHeadersComplete(bool fin,
                                size_t frame_len,
                                const QuicHeaderList& header_list) override;

  // Override the base class to parse and store trailers.
  void OnTrailingHeadersComplete(bool fin, size_t frame_len) override;

  // Override the base class to handle creation of the push stream.
  void OnPromiseHeadersComplete(QuicStreamId promised_stream_id,
                                size_t frame_len) override;

  // Override the base class to handle creation of the push stream.
  void OnPromiseHeaderList(QuicStreamId promised_id,
                           size_t frame_len,
                           const QuicHeaderList& header_list) override;

  // ReliableQuicStream implementation called by the session when there's
  // data for us.
  void OnDataAvailable() override;

  // Serializes the headers and body, sends it to the server, and
  // returns the number of bytes sent.
  size_t SendRequest(const SpdyHeaderBlock& headers,
                     base::StringPiece body,
                     bool fin);

  // Returns the response data.
  const std::string& data() { return data_; }

  // Returns whatever headers have been received for this stream.
  const SpdyHeaderBlock& response_headers() { return response_headers_; }

  size_t header_bytes_read() const { return header_bytes_read_; }

  size_t header_bytes_written() const { return header_bytes_written_; }

  size_t trailer_bytes_read() const { return header_bytes_read_; }

  int response_code() const { return response_code_; }

  // While the server's SetPriority shouldn't be called externally, the creator
  // of client-side streams should be able to set the priority.
  using QuicSpdyStream::SetPriority;

  void set_allow_bidirectional_data(bool value) {
    allow_bidirectional_data_ = value;
  }

  bool allow_bidirectional_data() const { return allow_bidirectional_data_; }

 private:
  // The parsed headers received from the server.
  SpdyHeaderBlock response_headers_;

  // The parsed content-length, or -1 if none is specified.
  int64_t content_length_;
  int response_code_;
  std::string data_;
  size_t header_bytes_read_;
  size_t header_bytes_written_;
  // When true allows the sending of a request to continue while the response is
  // arriving.
  bool allow_bidirectional_data_;

  QuicClientSession* session_;

  DISALLOW_COPY_AND_ASSIGN(QuicSpdyClientStream);
};

}  // namespace net

#endif  // NET_TOOLS_QUIC_QUIC_SPDY_CLIENT_STREAM_H_
