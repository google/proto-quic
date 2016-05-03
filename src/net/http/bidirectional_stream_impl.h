// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_HTTP_BIDIRECTIONAL_STREAM_IMPL_H_
#define NET_HTTP_BIDIRECTIONAL_STREAM_IMPL_H_

#include <stdint.h>

#include <memory>

#include "base/macros.h"
#include "net/base/net_export.h"
#include "net/socket/next_proto.h"

namespace base {
class Timer;
}  // namespace base

namespace net {

class BoundNetLog;
class IOBuffer;
class SpdyHeaderBlock;
struct BidirectionalStreamRequestInfo;

// Exposes an interface to do HTTP/2 bidirectional streaming.
// Note that only one ReadData or SendData should be in flight until the
// operation completes synchronously or asynchronously.
// BidirectionalStreamImpl once created by HttpStreamFactoryImpl should be owned
// by BidirectionalStream.
class NET_EXPORT_PRIVATE BidirectionalStreamImpl {
 public:
  // Delegate to handle BidirectionalStreamImpl events.
  class NET_EXPORT_PRIVATE Delegate {
   public:
    Delegate();

    // Called when the stream is ready for reading and writing.
    // The delegate may call BidirectionalStreamImpl::ReadData to start reading,
    // call BidirectionalStreamImpl::SendData to send data,
    // or call BidirectionalStreamImpl::Cancel to cancel the stream.
    // The delegate should not call BidirectionalStreamImpl::Cancel
    // during this callback.
    virtual void OnStreamReady() = 0;

    // Called when response headers are received.
    // This is called at most once for the lifetime of a stream.
    // The delegate may call BidirectionalStreamImpl::ReadData to start
    // reading, call BidirectionalStreamImpl::SendData to send data,
    // or call BidirectionalStreamImpl::Cancel to cancel the stream.
    virtual void OnHeadersReceived(const SpdyHeaderBlock& response_headers) = 0;

    // Called when read is completed asynchronously. |bytes_read| specifies how
    // much data is available.
    // The delegate may call BidirectionalStreamImpl::ReadData to continue
    // reading, call BidirectionalStreamImpl::SendData to send data,
    // or call BidirectionalStreamImpl::Cancel to cancel the stream.
    virtual void OnDataRead(int bytes_read) = 0;

    // Called when the entire buffer passed through SendData is sent.
    // The delegate may call BidirectionalStreamImpl::ReadData to continue
    // reading, or call BidirectionalStreamImpl::SendData to send data.
    // The delegate should not call BidirectionalStreamImpl::Cancel
    // during this callback.
    virtual void OnDataSent() = 0;

    // Called when trailers are received. This is called as soon as trailers
    // are received, which can happen before a read completes.
    // The delegate is able to continue reading if there is no pending read and
    // EOF has not been received, or to send data if there is no pending send.
    virtual void OnTrailersReceived(const SpdyHeaderBlock& trailers) = 0;

    // Called when an error occurred.
    // No other delegate functions will be called after this.
    virtual void OnFailed(int status) = 0;

   protected:
    virtual ~Delegate();

   private:
    DISALLOW_COPY_AND_ASSIGN(Delegate);
  };

  BidirectionalStreamImpl();

  // |this| should not be destroyed during Delegate::OnHeadersSent or
  // Delegate::OnDataSent.
  virtual ~BidirectionalStreamImpl();

  // Starts the BidirectionalStreamImpl and sends request headers.
  virtual void Start(const BidirectionalStreamRequestInfo* request_info,
                     const BoundNetLog& net_log,
                     bool disable_auto_flush,
                     BidirectionalStreamImpl::Delegate* delegate,
                     std::unique_ptr<base::Timer> timer) = 0;

  // Reads at most |buf_len| bytes into |buf|. Returns the number of bytes read,
  // ERR_IO_PENDING if the read is to be completed asynchronously, or an error
  // code if any error occurred. If returns 0, there is no more data to read.
  // This should not be called before Delegate::OnHeadersReceived is invoked,
  // and should not be called again unless it returns with number greater than
  // 0 or until Delegate::OnDataRead is invoked.
  virtual int ReadData(IOBuffer* buf, int buf_len) = 0;

  // Sends data. This should not be called be called before
  // Delegate::OnHeadersSent is invoked, and should not be called again until
  // Delegate::OnDataSent is invoked. If |end_stream| is true, the DATA frame
  // will have an END_STREAM flag.
  virtual void SendData(IOBuffer* data, int length, bool end_stream) = 0;

  virtual void SendvData(const std::vector<IOBuffer*>& buffers,
                         const std::vector<int>& lengths,
                         bool end_stream) = 0;

  // Cancels the stream. No Delegate method will be called. Any pending
  // operations may or may not succeed.
  virtual void Cancel() = 0;

  // Returns the protocol used by this stream. If stream has not been
  // established, return kProtoUnknown.
  virtual NextProto GetProtocol() const = 0;

  // Total number of bytes received over the network of SPDY data, headers, and
  // push_promise frames associated with this stream, including the size of
  // frame headers, after SSL decryption and not including proxy overhead.
  virtual int64_t GetTotalReceivedBytes() const = 0;

  // Total number of bytes sent over the network of SPDY frames associated with
  // this stream, including the size of frame headers, before SSL encryption and
  // not including proxy overhead. Note that some SPDY frames such as pings are
  // not associated with any stream, and are not included in this value.
  virtual int64_t GetTotalSentBytes() const = 0;

 private:
  DISALLOW_COPY_AND_ASSIGN(BidirectionalStreamImpl);
};

}  // namespace net

#endif  // NET_HTTP_BIDIRECTIONAL_STREAM_IMPL_H_
