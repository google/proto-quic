// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_BIDIRECTIONAL_STREAM_QUIC_IMPL_H_
#define NET_QUIC_BIDIRECTIONAL_STREAM_QUIC_IMPL_H_

#include <stdint.h>

#include <memory>

#include "base/macros.h"
#include "base/memory/weak_ptr.h"
#include "net/http/bidirectional_stream_impl.h"
#include "net/quic/quic_chromium_client_session.h"
#include "net/quic/quic_chromium_client_stream.h"

namespace base {
class Timer;
}  // namespace base

namespace net {

struct BidirectionalStreamRequestInfo;
class BoundNetLog;
class IOBuffer;
class SpdyHeaderBlock;

class NET_EXPORT_PRIVATE BidirectionalStreamQuicImpl
    : public BidirectionalStreamImpl,
      public QuicChromiumClientStream::Delegate,
      public QuicChromiumClientSession::Observer {
 public:
  explicit BidirectionalStreamQuicImpl(
      const base::WeakPtr<QuicChromiumClientSession>& session);

  ~BidirectionalStreamQuicImpl() override;

  // BidirectionalStreamImpl implementation:
  void Start(const BidirectionalStreamRequestInfo* request_info,
             const BoundNetLog& net_log,
             bool disable_auto_flush,
             BidirectionalStreamImpl::Delegate* delegate,
             std::unique_ptr<base::Timer> timer) override;
  int ReadData(IOBuffer* buffer, int buffer_len) override;
  void SendData(IOBuffer* data, int length, bool end_stream) override;
  void SendvData(const std::vector<IOBuffer*>& buffers,
                 const std::vector<int>& lengths,
                 bool end_stream) override;
  void Cancel() override;
  NextProto GetProtocol() const override;
  int64_t GetTotalReceivedBytes() const override;
  int64_t GetTotalSentBytes() const override;

 private:
  // QuicChromiumClientStream::Delegate implementation:
  void OnHeadersAvailable(const SpdyHeaderBlock& headers,
                          size_t frame_len) override;
  void OnDataAvailable() override;
  void OnClose(QuicErrorCode error) override;
  void OnError(int error) override;
  bool HasSendHeadersComplete() override;

  // QuicChromiumClientSession::Observer implementation:
  void OnCryptoHandshakeConfirmed() override;
  void OnSessionClosed(int error, bool port_migration_detected) override;

  void OnStreamReady(int rv);
  void OnSendDataComplete(int rv);
  void OnReadDataComplete(int rv);

  // Helper method to send request headers.
  void SendRequestHeaders();
  // Notifies the delegate of an error.
  void NotifyError(int error);
  // Resets the stream and ensures that |delegate_| won't be called back.
  void ResetStream();

  base::WeakPtr<QuicChromiumClientSession> session_;
  bool was_handshake_confirmed_;  // True if the crypto handshake succeeded.
  QuicChromiumClientSession::StreamRequest stream_request_;
  QuicChromiumClientStream* stream_;  // Non-owning.

  const BidirectionalStreamRequestInfo* request_info_;
  BidirectionalStreamImpl::Delegate* delegate_;
  // Saves the response status if the stream is explicitly closed via OnError
  // or OnClose with an error. Once all buffered data has been returned, this
  // will be used as the final response.
  int response_status_;

  // The protocol that is negotiated.
  NextProto negotiated_protocol_;
  // User provided read buffer for ReadData() response.
  scoped_refptr<IOBuffer> read_buffer_;
  int read_buffer_len_;

  // Number of bytes received by the headers stream on behalf of this stream.
  int64_t headers_bytes_received_;
  // Number of bytes sent by the headers stream on behalf of this stream.
  int64_t headers_bytes_sent_;
  // After |stream_| has been closed, this keeps track of the total number of
  // bytes received over the network for |stream_| while it was open.
  int64_t closed_stream_received_bytes_;
  // After |stream_| has been closed, this keeps track of the total number of
  // bytes sent over the network for |stream_| while it was open.
  int64_t closed_stream_sent_bytes_;
  // Indicates whether initial headers have been sent.
  bool has_sent_headers_;
  // Indicates whether initial headers have been received.
  bool has_received_headers_;

  bool disable_auto_flush_;

  base::WeakPtrFactory<BidirectionalStreamQuicImpl> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(BidirectionalStreamQuicImpl);
};

}  // namespace net

#endif  // NET_QUIC_BIDIRECTIONAL_STREAM_QUIC_IMPL_H_
