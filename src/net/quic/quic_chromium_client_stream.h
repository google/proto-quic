// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// NOTE: This code is not shared between Google and Chrome.

#ifndef NET_QUIC_QUIC_RELIABLE_CLIENT_STREAM_H_
#define NET_QUIC_QUIC_RELIABLE_CLIENT_STREAM_H_

#include <stddef.h>
#include <vector>

#include "base/callback_forward.h"
#include "base/macros.h"
#include "net/base/ip_endpoint.h"
#include "net/base/upload_data_stream.h"
#include "net/http/http_request_info.h"
#include "net/http/http_response_info.h"
#include "net/http/http_stream.h"
#include "net/quic/quic_spdy_stream.h"

namespace net {

class QuicClientSessionBase;

// A client-initiated ReliableQuicStream.  Instances of this class
// are owned by the QuicClientSession which created them.
class NET_EXPORT_PRIVATE QuicChromiumClientStream : public QuicSpdyStream {
 public:
  // Delegate handles protocol specific behavior of a quic stream.
  class NET_EXPORT_PRIVATE Delegate {
   public:
    Delegate() {}

    // Called when headers are available.
    virtual void OnHeadersAvailable(const SpdyHeaderBlock& headers,
                                    size_t frame_len) = 0;

    // Called when data is available to be read.
    virtual void OnDataAvailable() = 0;

    // Called when the stream is closed by the peer.
    virtual void OnClose(QuicErrorCode error) = 0;

    // Called when the stream is closed because of an error.
    virtual void OnError(int error) = 0;

    // Returns true if sending of headers has completed.
    virtual bool HasSendHeadersComplete() = 0;

   protected:
    virtual ~Delegate() {}

   private:
    DISALLOW_COPY_AND_ASSIGN(Delegate);
  };

  QuicChromiumClientStream(QuicStreamId id,
                           QuicClientSessionBase* session,
                           const BoundNetLog& net_log);

  ~QuicChromiumClientStream() override;

  // QuicSpdyStream
  void OnStreamHeadersComplete(bool fin, size_t frame_len) override;
  void OnPromiseHeadersComplete(QuicStreamId promised_stream_id,
                                size_t frame_len) override;
  void OnDataAvailable() override;
  void OnClose() override;
  void OnCanWrite() override;
  size_t WriteHeaders(const SpdyHeaderBlock& header_block,
                      bool fin,
                      QuicAckListenerInterface* ack_notifier_delegate) override;
  SpdyPriority priority() const override;

  // While the server's set_priority shouldn't be called externally, the creator
  // of client-side streams should be able to set the priority.
  using QuicSpdyStream::SetPriority;

  int WriteStreamData(base::StringPiece data,
                      bool fin,
                      const CompletionCallback& callback);
  // Same as WriteStreamData except it writes data from a vector of IOBuffers,
  // with the length of each buffer at the corresponding index in |lengths|.
  int WritevStreamData(const std::vector<IOBuffer*>& buffers,
                       const std::vector<int>& lengths,
                       bool fin,
                       const CompletionCallback& callback);
  // Set new |delegate|. |delegate| must not be NULL.
  // If this stream has already received data, OnDataReceived() will be
  // called on the delegate.
  void SetDelegate(Delegate* delegate);
  Delegate* GetDelegate() { return delegate_; }
  void OnError(int error);

  // Reads at most |buf_len| bytes into |buf|. Returns the number of bytes read.
  int Read(IOBuffer* buf, int buf_len);

  // Returns true if the stream can possible write data.  (The socket may
  // turn out to be write blocked, of course).  If the stream can not write,
  // this method returns false, and |callback| will be invoked when
  // it becomes writable.
  bool CanWrite(const CompletionCallback& callback);

  const BoundNetLog& net_log() const { return net_log_; }

  // Prevents this stream from migrating to a new network. May cause other
  // concurrent streams within the session to also not migrate.
  void DisableConnectionMigration();

  bool can_migrate() { return can_migrate_; }

  using QuicSpdyStream::HasBufferedData;

 private:
  void NotifyDelegateOfHeadersCompleteLater(const SpdyHeaderBlock& headers,
                                            size_t frame_len);
  void NotifyDelegateOfHeadersComplete(SpdyHeaderBlock headers,
                                       size_t frame_len);
  void NotifyDelegateOfDataAvailableLater();
  void NotifyDelegateOfDataAvailable();
  void RunOrBuffer(base::Closure closure);

  BoundNetLog net_log_;
  Delegate* delegate_;

  bool headers_delivered_;

  CompletionCallback callback_;

  QuicClientSessionBase* session_;

  // Set to false if this stream to not be migrated during connection migration.
  bool can_migrate_;

  // Holds notifications generated before delegate_ is set.
  std::deque<base::Closure> delegate_tasks_;

  base::WeakPtrFactory<QuicChromiumClientStream> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(QuicChromiumClientStream);
};

}  // namespace net

#endif  // NET_QUIC_QUIC_RELIABLE_CLIENT_STREAM_H_
