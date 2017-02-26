// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// The base class for streams which deliver data to/from an application.
// In each direction, the data on such a stream first contains compressed
// headers then body data.

#ifndef NET_QUIC_CORE_QUIC_SPDY_STREAM_H_
#define NET_QUIC_CORE_QUIC_SPDY_STREAM_H_

#include <sys/types.h>

#include <cstddef>
#include <list>
#include <string>

#include "base/macros.h"
#include "base/strings/string_piece.h"
#include "net/base/iovec.h"
#include "net/quic/core/quic_flags.h"
#include "net/quic/core/quic_header_list.h"
#include "net/quic/core/quic_packets.h"
#include "net/quic/core/quic_stream.h"
#include "net/quic/core/quic_stream_sequencer.h"
#include "net/quic/platform/api/quic_export.h"
#include "net/quic/platform/api/quic_socket_address.h"
#include "net/spdy/spdy_framer.h"

namespace net {

namespace test {
class QuicSpdyStreamPeer;
class QuicStreamPeer;
}  // namespace test

class QuicSpdySession;

// This is somewhat arbitrary.  It's possible, but unlikely, we will either fail
// to set a priority client-side, or cancel a stream before stripping the
// priority from the wire server-side.  In either case, start out with a
// priority in the middle.
const SpdyPriority kDefaultPriority = 3;

// A QUIC stream that can send and receive HTTP2 (SPDY) headers.
class QUIC_EXPORT_PRIVATE QuicSpdyStream : public QuicStream {
 public:
  // Visitor receives callbacks from the stream.
  class QUIC_EXPORT_PRIVATE Visitor {
   public:
    Visitor() {}

    // Called when the stream is closed.
    virtual void OnClose(QuicSpdyStream* stream) = 0;

    // Allows subclasses to override and do work.
    virtual void OnPromiseHeadersComplete(QuicStreamId promised_id,
                                          size_t frame_len) {}

   protected:
    virtual ~Visitor() {}

   private:
    DISALLOW_COPY_AND_ASSIGN(Visitor);
  };

  QuicSpdyStream(QuicStreamId id, QuicSpdySession* spdy_session);
  ~QuicSpdyStream() override;

  void StopReading() override;

  // QuicStream implementation
  void OnClose() override;

  // Override to maybe close the write side after writing.
  void OnCanWrite() override;

  // Called by the session when headers with a priority have been received
  // for this stream.  This method will only be called for server streams.
  virtual void OnStreamHeadersPriority(SpdyPriority priority);

  // Called by the session when decompressed headers have been completely
  // delivered to this stream.  If |fin| is true, then this stream
  // should be closed; no more data will be sent by the peer.
  virtual void OnStreamHeaderList(bool fin,
                                  size_t frame_len,
                                  const QuicHeaderList& header_list);

  // Called when the received headers are too large. By default this will
  // reset the stream.
  virtual void OnHeadersTooLarge();

  // Called by the session when decompressed push promise headers have
  // been completely delivered to this stream.
  virtual void OnPromiseHeaderList(QuicStreamId promised_id,
                                   size_t frame_len,
                                   const QuicHeaderList& header_list);

  // Override the base class to not discard response when receiving
  // QUIC_STREAM_NO_ERROR.
  void OnStreamReset(const QuicRstStreamFrame& frame) override;

  // Writes the headers contained in |header_block| to the dedicated
  // headers stream.
  virtual size_t WriteHeaders(
      SpdyHeaderBlock header_block,
      bool fin,
      QuicReferenceCountedPointer<QuicAckListenerInterface> ack_listener);

  // Sends |data| to the peer, or buffers if it can't be sent immediately.
  void WriteOrBufferBody(
      const std::string& data,
      bool fin,
      QuicReferenceCountedPointer<QuicAckListenerInterface> ack_listener);

  // Writes the trailers contained in |trailer_block| to the dedicated
  // headers stream. Trailers will always have the FIN set.
  virtual size_t WriteTrailers(
      SpdyHeaderBlock trailer_block,
      QuicReferenceCountedPointer<QuicAckListenerInterface> ack_listener);

  // Marks the trailers as consumed. This applies to the case where this object
  // receives headers and trailers as QuicHeaderLists via calls to
  // OnStreamHeaderList().
  void MarkTrailersConsumed();

  // Clears |header_list_|.
  void ConsumeHeaderList();

  // This block of functions wraps the sequencer's functions of the same
  // name.  These methods return uncompressed data until that has
  // been fully processed.  Then they simply delegate to the sequencer.
  virtual size_t Readv(const struct iovec* iov, size_t iov_len);
  virtual int GetReadableRegions(iovec* iov, size_t iov_len) const;
  void MarkConsumed(size_t num_bytes);

  // Returns true if header contains a valid 3-digit status and parse the status
  // code to |status_code|.
  bool ParseHeaderStatusCode(const SpdyHeaderBlock& header,
                             int* status_code) const;

  // Returns true when all data has been read from the peer, including the fin.
  bool IsDoneReading() const;
  bool HasBytesToRead() const;

  void set_visitor(Visitor* visitor) { visitor_ = visitor; }

  bool headers_decompressed() const { return headers_decompressed_; }

  const QuicHeaderList& header_list() const { return header_list_; }

  bool trailers_decompressed() const { return trailers_decompressed_; }

  // Returns whatever trailers have been received for this stream.
  const SpdyHeaderBlock& received_trailers() const {
    return received_trailers_;
  }

  // Returns true if headers have been fully read and consumed.
  bool FinishedReadingHeaders() const;

  // Returns true if trailers have been fully read and consumed, or FIN has
  // been received and there are no trailers.
  bool FinishedReadingTrailers() const;

  virtual SpdyPriority priority() const;

  // Sets priority_ to priority.  This should only be called before bytes are
  // written to the server.
  void SetPriority(SpdyPriority priority);

  // Called when owning session is getting deleted to avoid subsequent
  // use of the spdy_session_ member.
  void ClearSession();

  // Returns true if the sequencer has delivered the FIN, and no more body bytes
  // will be available.
  bool IsClosed() { return sequencer()->IsClosed(); }

  void set_allow_bidirectional_data(bool value) {
    allow_bidirectional_data_ = value;
  }

  bool allow_bidirectional_data() const {
    return FLAGS_quic_reloadable_flag_quic_always_enable_bidi_streaming ||
           allow_bidirectional_data_;
  }

  using QuicStream::CloseWriteSide;

 protected:
  virtual void OnInitialHeadersComplete(bool fin,
                                        size_t frame_len,
                                        const QuicHeaderList& header_list);
  virtual void OnTrailingHeadersComplete(bool fin,
                                         size_t frame_len,
                                         const QuicHeaderList& header_list);
  QuicSpdySession* spdy_session() const { return spdy_session_; }
  Visitor* visitor() { return visitor_; }

  // Redirects to the headers stream if force HOL blocking enabled,
  // otherwise just pass through.
  QuicConsumedData WritevDataInner(
      QuicIOVector iov,
      QuicStreamOffset offset,
      bool fin,
      QuicReferenceCountedPointer<QuicAckListenerInterface> ack_listener)
      override;

  void set_headers_decompressed(bool val) { headers_decompressed_ = val; }

 private:
  friend class test::QuicSpdyStreamPeer;
  friend class test::QuicStreamPeer;
  friend class QuicStreamUtils;

  QuicSpdySession* spdy_session_;

  Visitor* visitor_;
  // If true, allow sending of a request to continue while the response is
  // arriving.
  bool allow_bidirectional_data_;
  // True if the headers have been completely decompressed.
  bool headers_decompressed_;
  // The priority of the stream, once parsed.
  SpdyPriority priority_;
  // Contains a copy of the decompressed header (name, value) pairs until they
  // are consumed via Readv.
  QuicHeaderList header_list_;

  // True if the trailers have been completely decompressed.
  bool trailers_decompressed_;
  // True if the trailers have been consumed.
  bool trailers_consumed_;
  // The parsed trailers received from the peer.
  SpdyHeaderBlock received_trailers_;

  DISALLOW_COPY_AND_ASSIGN(QuicSpdyStream);
};

}  // namespace net

#endif  // NET_QUIC_CORE_QUIC_SPDY_STREAM_H_
