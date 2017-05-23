// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// NOTE: This code is not shared between Google and Chrome.

#ifndef NET_QUIC_CHROMIUM_QUIC_CHROMIUM_CLIENT_STREAM_H_
#define NET_QUIC_CHROMIUM_QUIC_CHROMIUM_CLIENT_STREAM_H_

#include <stddef.h>

#include <deque>
#include <vector>

#include "base/callback_forward.h"
#include "base/macros.h"
#include "net/base/ip_endpoint.h"
#include "net/base/net_export.h"
#include "net/base/upload_data_stream.h"
#include "net/http/http_request_info.h"
#include "net/http/http_response_info.h"
#include "net/http/http_stream.h"
#include "net/log/net_log_with_source.h"
#include "net/quic/core/quic_spdy_stream.h"
#include "net/quic/platform/api/quic_string_piece.h"

namespace net {

class QuicClientSessionBase;

// A client-initiated ReliableQuicStream.  Instances of this class
// are owned by the QuicClientSession which created them.
class NET_EXPORT_PRIVATE QuicChromiumClientStream : public QuicSpdyStream {
 public:
  // TODO(rch): Remove this class completely in favor of async methods
  // on the Handle.
  // Delegate handles protocol specific behavior of a quic stream.
  class NET_EXPORT_PRIVATE Delegate {
   public:
    Delegate() {}

    // Called when trailing headers are available.
    virtual void OnTrailingHeadersAvailable(const SpdyHeaderBlock& headers,
                                            size_t frame_len) = 0;

    // Called when data is available to be read.
    virtual void OnDataAvailable() = 0;

    // Called when the stream is closed by the peer.
    virtual void OnClose() = 0;

    // Called when the stream is closed because of an error.
    virtual void OnError(int error) = 0;

   protected:
    virtual ~Delegate() {}

   private:
    DISALLOW_COPY_AND_ASSIGN(Delegate);
  };

  // Wrapper for interacting with the session in a restricted fashion.
  class NET_EXPORT_PRIVATE Handle {
   public:
    ~Handle();

    // Returns true if the stream is still connected.
    bool IsOpen() { return stream_ != nullptr; }

    // Reads initial headers into |header_block| and returns the length of
    // the HEADERS frame which contained them. If headers are not available,
    // returns ERR_IO_PENDING and will invoke |callback| asynchronously when
    // the headers arrive.
    // TODO(rch): Invoke |callback| when there is a stream or connection error
    // instead of calling OnClose() or OnError().
    int ReadInitialHeaders(SpdyHeaderBlock* header_block,
                           const CompletionCallback& callback);

    // Writes |header_block| to the peer. Closes the write side if |fin| is
    // true. If non-null, |ack_notifier_delegate| will be notified when the
    // headers are ACK'd by the peer.
    size_t WriteHeaders(SpdyHeaderBlock header_block,
                        bool fin,
                        QuicReferenceCountedPointer<QuicAckListenerInterface>
                            ack_notifier_delegate);

    // Writes |data| to the peer. Closes the write side if |fin| is true.
    // If the data could not be written immediately, returns ERR_IO_PENDING
    // and invokes |callback| asynchronously when the write completes.
    int WriteStreamData(base::StringPiece data,
                        bool fin,
                        const CompletionCallback& callback);

    // Same as WriteStreamData except it writes data from a vector of IOBuffers,
    // with the length of each buffer at the corresponding index in |lengths|.
    int WritevStreamData(const std::vector<scoped_refptr<IOBuffer>>& buffers,
                         const std::vector<int>& lengths,
                         bool fin,
                         const CompletionCallback& callback);

    // Reads at most |buf_len| bytes into |buf|. Returns the number of bytes
    // read.
    int Read(IOBuffer* buf, int buf_len);

    // Called to notify the stream when the final incoming data is read.
    void OnFinRead();

    // Prevents the connection from migrating to a new network while this
    // stream is open.
    void DisableConnectionMigration();

    // Sets the priority of the stream to |priority|.
    void SetPriority(SpdyPriority priority);

    // Sends a RST_STREAM frame to the peer and closes the streams.
    void Reset(QuicRstStreamErrorCode error_code);

    // Clears |delegate_| from this Handle, but does not disconnect the Handle
    // from |stream_|.
    void ClearDelegate();

    QuicStreamId id() const;
    QuicErrorCode connection_error() const;
    QuicRstStreamErrorCode stream_error() const;
    bool fin_sent() const;
    bool fin_received() const;
    uint64_t stream_bytes_read() const;
    uint64_t stream_bytes_written() const;
    size_t NumBytesConsumed() const;
    bool IsDoneReading() const;
    bool IsFirstStream() const;

    // TODO(rch): Move these test-only methods to a peer, or else remove.
    void OnPromiseHeaderList(QuicStreamId promised_id,
                             size_t frame_len,
                             const QuicHeaderList& header_list);
    SpdyPriority priority() const;
    bool can_migrate();

    Delegate* GetDelegate();

   private:
    friend class QuicChromiumClientStream;

    // Constucts a new Handle for |stream| with |delegate| set to receive
    // up calls on various events.
    Handle(QuicChromiumClientStream* stream, Delegate* delegate);

    // Methods invoked by the stream.
    void OnInitialHeadersAvailable();
    void OnTrailingHeadersAvailable(const SpdyHeaderBlock& headers,
                                    size_t frame_len);
    void OnDataAvailable();
    void OnClose();
    void OnError(int error);

    // Saves various fields from the stream before the stream goes away.
    void SaveState();

    QuicChromiumClientStream* stream_;  // Unowned.
    Delegate* delegate_;                // Owns this.

    CompletionCallback read_headers_callback_;
    SpdyHeaderBlock* read_headers_buffer_;

    QuicStreamId id_;
    QuicErrorCode connection_error_;
    QuicRstStreamErrorCode stream_error_;
    bool fin_sent_;
    bool fin_received_;
    uint64_t stream_bytes_read_;
    uint64_t stream_bytes_written_;
    bool is_done_reading_;
    bool is_first_stream_;
    size_t num_bytes_consumed_;
    SpdyPriority priority_;

    DISALLOW_COPY_AND_ASSIGN(Handle);
  };

  QuicChromiumClientStream(QuicStreamId id,
                           QuicClientSessionBase* session,
                           const NetLogWithSource& net_log);

  ~QuicChromiumClientStream() override;

  // QuicSpdyStream
  void OnInitialHeadersComplete(bool fin,
                                size_t frame_len,
                                const QuicHeaderList& header_list) override;
  void OnTrailingHeadersComplete(bool fin,
                                 size_t frame_len,
                                 const QuicHeaderList& header_list) override;
  void OnPromiseHeaderList(QuicStreamId promised_id,
                           size_t frame_len,
                           const QuicHeaderList& header_list) override;
  void OnDataAvailable() override;
  void OnClose() override;
  void OnCanWrite() override;
  size_t WriteHeaders(SpdyHeaderBlock header_block,
                      bool fin,
                      QuicReferenceCountedPointer<QuicAckListenerInterface>
                          ack_listener) override;
  SpdyPriority priority() const override;

  // While the server's set_priority shouldn't be called externally, the creator
  // of client-side streams should be able to set the priority.
  using QuicSpdyStream::SetPriority;

  int WriteStreamData(QuicStringPiece data,
                      bool fin,
                      const CompletionCallback& callback);
  // Same as WriteStreamData except it writes data from a vector of IOBuffers,
  // with the length of each buffer at the corresponding index in |lengths|.
  int WritevStreamData(const std::vector<scoped_refptr<IOBuffer>>& buffers,
                       const std::vector<int>& lengths,
                       bool fin,
                       const CompletionCallback& callback);

  // Creates a new Handle for this stream and sets |delegate| on the handle.
  // Must only be called once.
  std::unique_ptr<QuicChromiumClientStream::Handle> CreateHandle(
      QuicChromiumClientStream::Delegate* delegate);

  // Clears |handle_| from this stream.
  void ClearHandle();

  void OnError(int error);

  // Reads at most |buf_len| bytes into |buf|. Returns the number of bytes read.
  int Read(IOBuffer* buf, int buf_len);

  const NetLogWithSource& net_log() const { return net_log_; }

  // Prevents this stream from migrating to a new network. May cause other
  // concurrent streams within the session to also not migrate.
  void DisableConnectionMigration();

  bool can_migrate() { return can_migrate_; }

  // True if this stream is the first data stream created on this session.
  bool IsFirstStream();

  bool DeliverInitialHeaders(SpdyHeaderBlock* header_block, int* frame_len);

  using QuicSpdyStream::HasBufferedData;
  using QuicStream::sequencer;

 private:
  void NotifyHandleOfInitialHeadersAvailableLater();
  void NotifyHandleOfInitialHeadersAvailable();
  void NotifyHandleOfTrailingHeadersAvailableLater(SpdyHeaderBlock headers,
                                                   size_t frame_len);
  void NotifyHandleOfTrailingHeadersAvailable(SpdyHeaderBlock headers,
                                              size_t frame_len);
  void NotifyHandleOfDataAvailableLater();
  void NotifyHandleOfDataAvailable();

  NetLogWithSource net_log_;
  Handle* handle_;

  bool headers_delivered_;

  // True when initial headers have been sent.
  bool initial_headers_sent_;

  // Callback to be invoked when WriteStreamData or WritevStreamData completes
  // asynchronously.
  CompletionCallback write_callback_;

  QuicClientSessionBase* session_;

  // Set to false if this stream to not be migrated during connection migration.
  bool can_migrate_;

  // Stores the initial header if they arrive before the delegate.
  SpdyHeaderBlock initial_headers_;
  // Length of the HEADERS frame containing initial headers.
  size_t initial_headers_frame_len_;

  base::WeakPtrFactory<QuicChromiumClientStream> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(QuicChromiumClientStream);
};

}  // namespace net

#endif  // NET_QUIC_CHROMIUM_QUIC_CHROMIUM_CLIENT_STREAM_H_
