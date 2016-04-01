// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SPDY_SPDY_HTTP_STREAM_H_
#define NET_SPDY_SPDY_HTTP_STREAM_H_

#include <stdint.h>

#include <list>

#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/memory/weak_ptr.h"
#include "net/base/completion_callback.h"
#include "net/http/http_stream.h"
#include "net/log/net_log.h"
#include "net/spdy/spdy_read_queue.h"
#include "net/spdy/spdy_session.h"
#include "net/spdy/spdy_stream.h"

namespace net {

class DrainableIOBuffer;
struct HttpRequestInfo;
class HttpResponseInfo;
class IOBuffer;
class SpdySession;
class UploadDataStream;

// The SpdyHttpStream is a HTTP-specific type of stream known to a SpdySession.
class NET_EXPORT_PRIVATE SpdyHttpStream : public SpdyStream::Delegate,
                                          public HttpStream {
 public:
  // |spdy_session| must not be NULL.
  SpdyHttpStream(const base::WeakPtr<SpdySession>& spdy_session, bool direct);
  ~SpdyHttpStream() override;

  SpdyStream* stream() { return stream_.get(); }

  // Cancels any callbacks from being invoked and deletes the stream.
  void Cancel();

  // HttpStream implementation.

  int InitializeStream(const HttpRequestInfo* request_info,
                       RequestPriority priority,
                       const BoundNetLog& net_log,
                       const CompletionCallback& callback) override;

  int SendRequest(const HttpRequestHeaders& headers,
                  HttpResponseInfo* response,
                  const CompletionCallback& callback) override;
  UploadProgress GetUploadProgress() const override;
  int ReadResponseHeaders(const CompletionCallback& callback) override;
  int ReadResponseBody(IOBuffer* buf,
                       int buf_len,
                       const CompletionCallback& callback) override;
  void Close(bool not_reusable) override;
  HttpStream* RenewStreamForAuth() override;
  bool IsResponseBodyComplete() const override;

  // Must not be called if a NULL SpdySession was pssed into the
  // constructor.
  bool IsConnectionReused() const override;

  void SetConnectionReused() override;
  bool CanReuseConnection() const override;
  // Total number of bytes received over the network of SPDY data, headers, and
  // push_promise frames associated with this stream, including the size of
  // frame headers, after SSL decryption and not including proxy overhead.
  int64_t GetTotalReceivedBytes() const override;
  // Total number of bytes sent over the network of SPDY frames associated with
  // this stream, including the size of frame headers, before SSL encryption and
  // not including proxy overhead. Note that some SPDY frames such as pings are
  // not associated with any stream, and are not included in this value.
  int64_t GetTotalSentBytes() const override;
  bool GetLoadTimingInfo(LoadTimingInfo* load_timing_info) const override;
  void GetSSLInfo(SSLInfo* ssl_info) override;
  void GetSSLCertRequestInfo(SSLCertRequestInfo* cert_request_info) override;
  bool GetRemoteEndpoint(IPEndPoint* endpoint) override;
  Error GetSignedEKMForTokenBinding(crypto::ECPrivateKey* key,
                                    std::vector<uint8_t>* out) override;
  void Drain(HttpNetworkSession* session) override;
  void PopulateNetErrorDetails(NetErrorDetails* details) override;
  void SetPriority(RequestPriority priority) override;

  // SpdyStream::Delegate implementation.
  void OnRequestHeadersSent() override;
  SpdyResponseHeadersStatus OnResponseHeadersUpdated(
      const SpdyHeaderBlock& response_headers) override;
  void OnDataReceived(scoped_ptr<SpdyBuffer> buffer) override;
  void OnDataSent() override;
  void OnTrailers(const SpdyHeaderBlock& trailers) override;
  void OnClose(int status) override;

 private:
  // Must be called only when |request_info_| is non-NULL.
  bool HasUploadData() const;

  void OnStreamCreated(const CompletionCallback& callback, int rv);

  // Reads the remaining data (whether chunked or not) from the
  // request body stream and sends it if there's any. The read and
  // subsequent sending may happen asynchronously. Must be called only
  // when HasUploadData() is true.
  void ReadAndSendRequestBodyData();

  // Called when data has just been read from the request body stream;
  // does the actual sending of data.
  void OnRequestBodyReadCompleted(int status);

  // Call the user callback associated with sending the request.
  void DoRequestCallback(int rv);

  // Call the user callback associated with reading the response.
  void DoResponseCallback(int rv);

  void ScheduleBufferedReadCallback();
  void DoBufferedReadCallback();
  bool ShouldWaitForMoreBufferedData() const;

  const base::WeakPtr<SpdySession> spdy_session_;
  bool is_reused_;
  SpdyStreamRequest stream_request_;
  base::WeakPtr<SpdyStream> stream_;

  bool stream_closed_;

  // Set only when |stream_closed_| is true.
  int closed_stream_status_;
  SpdyStreamId closed_stream_id_;
  bool closed_stream_has_load_timing_info_;
  LoadTimingInfo closed_stream_load_timing_info_;
  // After |stream_| has been closed, this keeps track of the total number of
  // bytes received over the network for |stream_| while it was open.
  int64_t closed_stream_received_bytes_;
  // After |stream_| has been closed, this keeps track of the total number of
  // bytes sent over the network for |stream_| while it was open.
  int64_t closed_stream_sent_bytes_;

  // The request to send.
  const HttpRequestInfo* request_info_;

  // |response_info_| is the HTTP response data object which is filled in
  // when a SYN_REPLY comes in for the stream.
  // It is not owned by this stream object, or point to |push_response_info_|.
  HttpResponseInfo* response_info_;

  scoped_ptr<HttpResponseInfo> push_response_info_;

  // We don't use SpdyStream's |response_header_status_| as we
  // sometimes call back into our delegate before it is updated.
  SpdyResponseHeadersStatus response_headers_status_;

  // We buffer the response body as it arrives asynchronously from the stream.
  SpdyReadQueue response_body_queue_;

  CompletionCallback request_callback_;
  CompletionCallback response_callback_;

  // User provided buffer for the ReadResponseBody() response.
  scoped_refptr<IOBuffer> user_buffer_;
  int user_buffer_len_;

  // Temporary buffer used to read the request body from UploadDataStream.
  scoped_refptr<IOBufferWithSize> request_body_buf_;
  int request_body_buf_size_;

  // Is there a scheduled read callback pending.
  bool buffered_read_callback_pending_;
  // Has more data been received from the network during the wait for the
  // scheduled read callback.
  bool more_read_data_pending_;

  // Is this spdy stream direct to the origin server (or to a proxy).
  bool direct_;

  base::WeakPtrFactory<SpdyHttpStream> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(SpdyHttpStream);
};

}  // namespace net

#endif  // NET_SPDY_SPDY_HTTP_STREAM_H_
