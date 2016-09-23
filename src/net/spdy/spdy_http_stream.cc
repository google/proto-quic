// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/spdy_http_stream.h"

#include <algorithm>
#include <list>
#include <utility>

#include "base/bind.h"
#include "base/callback_helpers.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/stringprintf.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/values.h"
#include "net/base/host_port_pair.h"
#include "net/base/upload_data_stream.h"
#include "net/http/http_request_headers.h"
#include "net/http/http_request_info.h"
#include "net/http/http_response_info.h"
#include "net/log/net_log.h"
#include "net/log/net_log_event_type.h"
#include "net/spdy/spdy_header_block.h"
#include "net/spdy/spdy_http_utils.h"
#include "net/spdy/spdy_protocol.h"
#include "net/spdy/spdy_session.h"

namespace net {

const size_t SpdyHttpStream::kRequestBodyBufferSize = 1 << 14;  // 16KB

SpdyHttpStream::SpdyHttpStream(const base::WeakPtr<SpdySession>& spdy_session,
                               bool direct)
    : spdy_session_(spdy_session),
      is_reused_(spdy_session_->IsReused()),
      stream_closed_(false),
      closed_stream_status_(ERR_FAILED),
      closed_stream_id_(0),
      closed_stream_received_bytes_(0),
      closed_stream_sent_bytes_(0),
      request_info_(NULL),
      response_info_(NULL),
      response_headers_status_(RESPONSE_HEADERS_ARE_INCOMPLETE),
      user_buffer_len_(0),
      request_body_buf_size_(0),
      buffered_read_callback_pending_(false),
      more_read_data_pending_(false),
      direct_(direct),
      was_alpn_negotiated_(false),
      negotiated_protocol_(kProtoUnknown),
      weak_factory_(this) {
  DCHECK(spdy_session_.get());
}

SpdyHttpStream::~SpdyHttpStream() {
  if (stream_.get()) {
    stream_->DetachDelegate();
    DCHECK(!stream_.get());
  }
}

int SpdyHttpStream::InitializeStream(const HttpRequestInfo* request_info,
                                     RequestPriority priority,
                                     const NetLogWithSource& stream_net_log,
                                     const CompletionCallback& callback) {
  DCHECK(!stream_);
  if (!spdy_session_)
    return ERR_CONNECTION_CLOSED;

  request_info_ = request_info;
  if (request_info_->method == "GET") {
    int error = spdy_session_->GetPushStream(request_info_->url, &stream_,
                                             stream_net_log);
    if (error != OK)
      return error;

    // |stream_| may be NULL even if OK was returned.
    if (stream_.get()) {
      DCHECK_EQ(stream_->type(), SPDY_PUSH_STREAM);
      InitializeStreamHelper();
      return OK;
    }
  }

  int rv = stream_request_.StartRequest(
      SPDY_REQUEST_RESPONSE_STREAM, spdy_session_, request_info_->url,
      priority, stream_net_log,
      base::Bind(&SpdyHttpStream::OnStreamCreated,
                 weak_factory_.GetWeakPtr(), callback));

  if (rv == OK) {
    stream_ = stream_request_.ReleaseStream();
    InitializeStreamHelper();
  }

  return rv;
}

int SpdyHttpStream::ReadResponseHeaders(const CompletionCallback& callback) {
  CHECK(!callback.is_null());
  if (stream_closed_)
    return closed_stream_status_;

  CHECK(stream_.get());

  // Check if we already have the response headers. If so, return synchronously.
  if (response_headers_status_ == RESPONSE_HEADERS_ARE_COMPLETE) {
    CHECK(!stream_->IsIdle());
    return OK;
  }

  // Still waiting for the response, return IO_PENDING.
  CHECK(response_callback_.is_null());
  response_callback_ = callback;
  return ERR_IO_PENDING;
}

int SpdyHttpStream::ReadResponseBody(
    IOBuffer* buf, int buf_len, const CompletionCallback& callback) {
  if (stream_.get())
    CHECK(!stream_->IsIdle());

  CHECK(buf);
  CHECK(buf_len);
  CHECK(!callback.is_null());

  // If we have data buffered, complete the IO immediately.
  if (!response_body_queue_.IsEmpty()) {
    return response_body_queue_.Dequeue(buf->data(), buf_len);
  } else if (stream_closed_) {
    return closed_stream_status_;
  }

  CHECK(response_callback_.is_null());
  CHECK(!user_buffer_.get());
  CHECK_EQ(0, user_buffer_len_);

  response_callback_ = callback;
  user_buffer_ = buf;
  user_buffer_len_ = buf_len;
  return ERR_IO_PENDING;
}

void SpdyHttpStream::Close(bool not_reusable) {
  // Note: the not_reusable flag has no meaning for SPDY streams.

  Cancel();
  DCHECK(!stream_.get());
}

HttpStream* SpdyHttpStream::RenewStreamForAuth() {
  return NULL;
}

bool SpdyHttpStream::IsResponseBodyComplete() const {
  return stream_closed_;
}

bool SpdyHttpStream::IsConnectionReused() const {
  return is_reused_;
}

void SpdyHttpStream::SetConnectionReused() {
  // SPDY doesn't need an indicator here.
}

bool SpdyHttpStream::CanReuseConnection() const {
  // SPDY streams aren't considered reusable.
  return false;
}

int64_t SpdyHttpStream::GetTotalReceivedBytes() const {
  if (stream_closed_)
    return closed_stream_received_bytes_;

  if (!stream_)
    return 0;

  return stream_->raw_received_bytes();
}

int64_t SpdyHttpStream::GetTotalSentBytes() const {
  if (stream_closed_)
    return closed_stream_sent_bytes_;

  if (!stream_)
    return 0;

  return stream_->raw_sent_bytes();
}

bool SpdyHttpStream::GetLoadTimingInfo(LoadTimingInfo* load_timing_info) const {
  if (stream_closed_) {
    if (!closed_stream_has_load_timing_info_)
      return false;
    *load_timing_info = closed_stream_load_timing_info_;
    return true;
  }

  // If |stream_| has yet to be created, or does not yet have an ID, fail.
  // The reused flag can only be correctly set once a stream has an ID.  Streams
  // get their IDs once the request has been successfully sent, so this does not
  // behave that differently from other stream types.
  if (!stream_ || stream_->stream_id() == 0)
    return false;

  return stream_->GetLoadTimingInfo(load_timing_info);
}

int SpdyHttpStream::SendRequest(const HttpRequestHeaders& request_headers,
                                HttpResponseInfo* response,
                                const CompletionCallback& callback) {
  if (stream_closed_) {
    return closed_stream_status_;
  }

  base::Time request_time = base::Time::Now();
  CHECK(stream_.get());

  stream_->SetRequestTime(request_time);
  // This should only get called in the case of a request occurring
  // during server push that has already begun but hasn't finished,
  // so we set the response's request time to be the actual one
  if (response_info_)
    response_info_->request_time = request_time;

  CHECK(!request_body_buf_.get());
  if (HasUploadData()) {
    request_body_buf_ = new IOBufferWithSize(kRequestBodyBufferSize);
    // The request body buffer is empty at first.
    request_body_buf_size_ = 0;
  }

  CHECK(!callback.is_null());
  CHECK(response);

  // SendRequest can be called in two cases.
  //
  // a) A client initiated request. In this case, |response_info_| should be
  //    NULL to start with.
  // b) A client request which matches a response that the server has already
  //    pushed.
  if (push_response_info_.get()) {
    *response = *(push_response_info_.get());
    push_response_info_.reset();
  } else {
    DCHECK_EQ(static_cast<HttpResponseInfo*>(NULL), response_info_);
  }

  response_info_ = response;

  // Put the peer's IP address and port into the response.
  IPEndPoint address;
  int result = stream_->GetPeerAddress(&address);
  if (result != OK)
    return result;
  response_info_->socket_address = HostPortPair::FromIPEndPoint(address);

  if (stream_->type() == SPDY_PUSH_STREAM) {
    // Pushed streams do not send any data, and should always be
    // idle. However, we still want to return ERR_IO_PENDING to mimic
    // non-push behavior. The callback will be called when the
    // response is received.
    CHECK(response_callback_.is_null());
    response_callback_ = callback;
    return ERR_IO_PENDING;
  }

  SpdyHeaderBlock headers;
  CreateSpdyHeadersFromHttpRequest(*request_info_, request_headers, direct_,
                                   &headers);
  stream_->net_log().AddEvent(
      NetLogEventType::HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS,
      base::Bind(&SpdyHeaderBlockNetLogCallback, &headers));
  result = stream_->SendRequestHeaders(
      std::move(headers),
      HasUploadData() ? MORE_DATA_TO_SEND : NO_MORE_DATA_TO_SEND);

  if (result == ERR_IO_PENDING) {
    CHECK(request_callback_.is_null());
    request_callback_ = callback;
  }
  return result;
}

void SpdyHttpStream::Cancel() {
  request_callback_.Reset();
  response_callback_.Reset();
  if (stream_.get()) {
    stream_->Cancel();
    DCHECK(!stream_.get());
  }
}

void SpdyHttpStream::OnRequestHeadersSent() {
  if (HasUploadData()) {
    ReadAndSendRequestBodyData();
  } else {
    MaybePostRequestCallback(OK);
  }
}

SpdyResponseHeadersStatus SpdyHttpStream::OnResponseHeadersUpdated(
    const SpdyHeaderBlock& response_headers) {
  CHECK_EQ(response_headers_status_, RESPONSE_HEADERS_ARE_INCOMPLETE);

  if (!response_info_) {
    DCHECK_EQ(stream_->type(), SPDY_PUSH_STREAM);
    push_response_info_.reset(new HttpResponseInfo);
    response_info_ = push_response_info_.get();
  }

  if (!SpdyHeadersToHttpResponse(response_headers, response_info_)) {
    // We do not have complete headers yet.
    return RESPONSE_HEADERS_ARE_INCOMPLETE;
  }

  response_info_->response_time = stream_->response_time();
  response_headers_status_ = RESPONSE_HEADERS_ARE_COMPLETE;
  // Don't store the SSLInfo in the response here, HttpNetworkTransaction
  // will take care of that part.
  response_info_->was_alpn_negotiated = was_alpn_negotiated_;
  response_info_->alpn_negotiated_protocol =
      SSLClientSocket::NextProtoToString(negotiated_protocol_);
  response_info_->request_time = stream_->GetRequestTime();
  response_info_->connection_info =
      HttpResponseInfo::ConnectionInfoFromNextProto(kProtoHTTP2);
  response_info_->vary_data
      .Init(*request_info_, *response_info_->headers.get());

  if (!response_callback_.is_null()) {
    DoResponseCallback(OK);
  }

  return RESPONSE_HEADERS_ARE_COMPLETE;
}

void SpdyHttpStream::OnDataReceived(std::unique_ptr<SpdyBuffer> buffer) {
  CHECK_EQ(response_headers_status_, RESPONSE_HEADERS_ARE_COMPLETE);

  // Note that data may be received for a SpdyStream prior to the user calling
  // ReadResponseBody(), therefore user_buffer_ may be NULL.  This may often
  // happen for server initiated streams.
  DCHECK(stream_.get());
  DCHECK(!stream_->IsClosed() || stream_->type() == SPDY_PUSH_STREAM);
  if (buffer) {
    response_body_queue_.Enqueue(std::move(buffer));

    if (user_buffer_.get()) {
      // Handing small chunks of data to the caller creates measurable overhead.
      // We buffer data in short time-spans and send a single read notification.
      ScheduleBufferedReadCallback();
    }
  }
}

void SpdyHttpStream::OnDataSent() {
  request_body_buf_size_ = 0;
  ReadAndSendRequestBodyData();
}

// TODO(xunjieli): Maybe do something with the trailers. crbug.com/422958.
void SpdyHttpStream::OnTrailers(const SpdyHeaderBlock& trailers) {}

void SpdyHttpStream::OnClose(int status) {
  // Cancel any pending reads from the upload data stream.
  if (request_info_->upload_data_stream)
    request_info_->upload_data_stream->Reset();

  if (stream_.get()) {
    stream_closed_ = true;
    closed_stream_status_ = status;
    closed_stream_id_ = stream_->stream_id();
    closed_stream_has_load_timing_info_ =
        stream_->GetLoadTimingInfo(&closed_stream_load_timing_info_);
    closed_stream_received_bytes_ = stream_->raw_received_bytes();
    closed_stream_sent_bytes_ = stream_->raw_sent_bytes();
  }
  stream_.reset();

  // Callbacks might destroy |this|.
  base::WeakPtr<SpdyHttpStream> self = weak_factory_.GetWeakPtr();

  if (!request_callback_.is_null()) {
    DoRequestCallback(status);
    if (!self)
      return;
  }

  if (status == OK) {
    // We need to complete any pending buffered read now.
    DoBufferedReadCallback();
    if (!self)
      return;
  }

  if (!response_callback_.is_null()) {
    DoResponseCallback(status);
  }
}

bool SpdyHttpStream::HasUploadData() const {
  CHECK(request_info_);
  return
      request_info_->upload_data_stream &&
      ((request_info_->upload_data_stream->size() > 0) ||
       request_info_->upload_data_stream->is_chunked());
}

void SpdyHttpStream::OnStreamCreated(
    const CompletionCallback& callback,
    int rv) {
  if (rv == OK) {
    stream_ = stream_request_.ReleaseStream();
    InitializeStreamHelper();
  }
  callback.Run(rv);
}

void SpdyHttpStream::ReadAndSendRequestBodyData() {
  CHECK(HasUploadData());
  CHECK_EQ(request_body_buf_size_, 0);
  if (request_info_->upload_data_stream->IsEOF()) {
    MaybePostRequestCallback(OK);
    return;
  }

  // Read the data from the request body stream.
  const int rv = request_info_->upload_data_stream
      ->Read(request_body_buf_.get(),
             request_body_buf_->size(),
             base::Bind(&SpdyHttpStream::OnRequestBodyReadCompleted,
                        weak_factory_.GetWeakPtr()));

  if (rv != ERR_IO_PENDING)
    OnRequestBodyReadCompleted(rv);
}

void SpdyHttpStream::InitializeStreamHelper() {
  stream_->SetDelegate(this);
  stream_->GetSSLInfo(&ssl_info_);
  was_alpn_negotiated_ = stream_->WasNpnNegotiated();
  negotiated_protocol_ = stream_->GetNegotiatedProtocol();
}

void SpdyHttpStream::ResetStreamInternal() {
  spdy_session_->ResetStream(stream()->stream_id(), RST_STREAM_INTERNAL_ERROR,
                             std::string());
}

void SpdyHttpStream::OnRequestBodyReadCompleted(int status) {
  if (status < 0) {
    DCHECK_NE(ERR_IO_PENDING, status);
    // Post |request_callback_| with received error.  This should be posted
    // before ResetStreamInternal, because the latter would call
    // |request_callback_| via OnClose with an error code potentially different
    // from |status|.
    MaybePostRequestCallback(status);

    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, base::Bind(&SpdyHttpStream::ResetStreamInternal,
                              weak_factory_.GetWeakPtr()));

    return;
  }

  CHECK_GE(status, 0);
  request_body_buf_size_ = status;
  const bool eof = request_info_->upload_data_stream->IsEOF();
  // Only the final frame may have a length of 0.
  if (eof) {
    CHECK_GE(request_body_buf_size_, 0);
  } else {
    CHECK_GT(request_body_buf_size_, 0);
  }
  stream_->SendData(request_body_buf_.get(),
                    request_body_buf_size_,
                    eof ? NO_MORE_DATA_TO_SEND : MORE_DATA_TO_SEND);
}

void SpdyHttpStream::ScheduleBufferedReadCallback() {
  // If there is already a scheduled DoBufferedReadCallback, don't issue
  // another one.  Mark that we have received more data and return.
  if (buffered_read_callback_pending_) {
    more_read_data_pending_ = true;
    return;
  }

  more_read_data_pending_ = false;
  buffered_read_callback_pending_ = true;
  const base::TimeDelta kBufferTime = base::TimeDelta::FromMilliseconds(1);
  base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(
      FROM_HERE, base::Bind(&SpdyHttpStream::DoBufferedReadCallback,
                            weak_factory_.GetWeakPtr()),
      kBufferTime);
}

// Checks to see if we should wait for more buffered data before notifying
// the caller.  Returns true if we should wait, false otherwise.
bool SpdyHttpStream::ShouldWaitForMoreBufferedData() const {
  // If the response is complete, there is no point in waiting.
  if (stream_closed_)
    return false;

  DCHECK_GT(user_buffer_len_, 0);
  return response_body_queue_.GetTotalSize() <
      static_cast<size_t>(user_buffer_len_);
}

void SpdyHttpStream::DoBufferedReadCallback() {
  buffered_read_callback_pending_ = false;

  // If the transaction is cancelled or errored out, we don't need to complete
  // the read.
  if (!stream_.get() && !stream_closed_)
    return;

  int stream_status =
      stream_closed_ ? closed_stream_status_ : stream_->response_status();
  if (stream_status != OK)
    return;

  // When more_read_data_pending_ is true, it means that more data has
  // arrived since we started waiting.  Wait a little longer and continue
  // to buffer.
  if (more_read_data_pending_ && ShouldWaitForMoreBufferedData()) {
    ScheduleBufferedReadCallback();
    return;
  }

  int rv = 0;
  if (user_buffer_.get()) {
    rv = ReadResponseBody(user_buffer_.get(), user_buffer_len_,
                          response_callback_);
    CHECK_NE(rv, ERR_IO_PENDING);
    user_buffer_ = NULL;
    user_buffer_len_ = 0;
    DoResponseCallback(rv);
  }
}

void SpdyHttpStream::DoRequestCallback(int rv) {
  CHECK_NE(rv, ERR_IO_PENDING);
  CHECK(!request_callback_.is_null());
  // Since Run may result in being called back, reset request_callback_ in
  // advance.
  base::ResetAndReturn(&request_callback_).Run(rv);
}

void SpdyHttpStream::MaybeDoRequestCallback(int rv) {
  CHECK_NE(ERR_IO_PENDING, rv);
  if (request_callback_)
    base::ResetAndReturn(&request_callback_).Run(rv);
}

void SpdyHttpStream::MaybePostRequestCallback(int rv) {
  CHECK_NE(ERR_IO_PENDING, rv);
  if (request_callback_)
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, base::Bind(&SpdyHttpStream::MaybeDoRequestCallback,
                              weak_factory_.GetWeakPtr(), rv));
}

void SpdyHttpStream::DoResponseCallback(int rv) {
  CHECK_NE(rv, ERR_IO_PENDING);
  CHECK(!response_callback_.is_null());

  // Since Run may result in being called back, reset response_callback_ in
  // advance.
  base::ResetAndReturn(&response_callback_).Run(rv);
}

void SpdyHttpStream::GetSSLInfo(SSLInfo* ssl_info) {
  *ssl_info = ssl_info_;
}

void SpdyHttpStream::GetSSLCertRequestInfo(
    SSLCertRequestInfo* cert_request_info) {
  // A SPDY stream cannot request client certificates. Client authentication may
  // only occur during the initial SSL handshake.
  NOTREACHED();
}

bool SpdyHttpStream::GetRemoteEndpoint(IPEndPoint* endpoint) {
  if (!spdy_session_)
    return false;

  return spdy_session_->GetPeerAddress(endpoint) == OK;
}

Error SpdyHttpStream::GetTokenBindingSignature(crypto::ECPrivateKey* key,
                                               TokenBindingType tb_type,
                                               std::vector<uint8_t>* out) {
  return spdy_session_->GetTokenBindingSignature(key, tb_type, out);
}

void SpdyHttpStream::Drain(HttpNetworkSession* session) {
  NOTREACHED();
  Close(false);
  delete this;
}

void SpdyHttpStream::PopulateNetErrorDetails(NetErrorDetails* details) {
  details->connection_info = HttpResponseInfo::CONNECTION_INFO_HTTP2;
  return;
}

void SpdyHttpStream::SetPriority(RequestPriority priority) {
  // TODO(akalin): Plumb this through to |stream_request_| and
  // |stream_|.
}

}  // namespace net
