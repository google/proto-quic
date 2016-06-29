// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_http_stream.h"

#include <utility>

#include "base/callback_helpers.h"
#include "base/metrics/histogram_macros.h"
#include "base/strings/string_split.h"
#include "base/strings/stringprintf.h"
#include "net/base/load_flags.h"
#include "net/base/net_errors.h"
#include "net/http/http_response_headers.h"
#include "net/http/http_util.h"
#include "net/quic/quic_client_promised_info.h"
#include "net/quic/quic_http_utils.h"
#include "net/quic/quic_utils.h"
#include "net/quic/spdy_utils.h"
#include "net/socket/next_proto.h"
#include "net/spdy/spdy_frame_builder.h"
#include "net/spdy/spdy_framer.h"
#include "net/spdy/spdy_http_utils.h"
#include "net/ssl/ssl_info.h"

namespace net {

namespace {

std::unique_ptr<base::Value> NetLogQuicPushStreamCallback(
    QuicStreamId stream_id,
    const GURL* url,
    NetLogCaptureMode capture_mode) {
  std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());
  dict->SetInteger("stream_id", stream_id);
  dict->SetString("url", url->spec());
  return std::move(dict);
}

}  // namespace

QuicHttpStream::QuicHttpStream(
    const base::WeakPtr<QuicChromiumClientSession>& session)
    : next_state_(STATE_NONE),
      session_(session),
      session_error_(OK),
      was_handshake_confirmed_(session->IsCryptoHandshakeConfirmed()),
      stream_(nullptr),
      request_info_(nullptr),
      request_body_stream_(nullptr),
      priority_(MINIMUM_PRIORITY),
      response_info_(nullptr),
      response_status_(OK),
      response_headers_received_(false),
      headers_bytes_received_(0),
      headers_bytes_sent_(0),
      closed_stream_received_bytes_(0),
      closed_stream_sent_bytes_(0),
      user_buffer_len_(0),
      quic_connection_error_(QUIC_NO_ERROR),
      port_migration_detected_(false),
      found_promise_(false),
      push_handle_(nullptr),
      weak_factory_(this) {
  DCHECK(session_);
  session_->AddObserver(this);
}

QuicHttpStream::~QuicHttpStream() {
  Close(false);
  if (session_)
    session_->RemoveObserver(this);
}

bool QuicHttpStream::CheckVary(const SpdyHeaderBlock& client_request,
                               const SpdyHeaderBlock& promise_request,
                               const SpdyHeaderBlock& promise_response) {
  HttpResponseInfo promise_response_info;

  HttpRequestInfo promise_request_info;
  ConvertHeaderBlockToHttpRequestHeaders(promise_request,
                                         &promise_request_info.extra_headers);
  HttpRequestInfo client_request_info;
  ConvertHeaderBlockToHttpRequestHeaders(client_request,
                                         &client_request_info.extra_headers);

  if (!SpdyHeadersToHttpResponse(promise_response, HTTP2,
                                 &promise_response_info)) {
    DLOG(WARNING) << "Invalid headers";
    return false;
  }

  HttpVaryData vary_data;
  if (!vary_data.Init(promise_request_info,
                      *promise_response_info.headers.get())) {
    // Promise didn't contain valid vary info, so URL match was sufficient.
    return true;
  }
  // Now compare the client request for matching.
  return vary_data.MatchesRequest(client_request_info,
                                  *promise_response_info.headers.get());
}

void QuicHttpStream::OnRendezvousResult(QuicSpdyStream* stream) {
  push_handle_ = nullptr;
  if (stream) {
    stream_ = static_cast<QuicChromiumClientStream*>(stream);
    stream_->SetDelegate(this);
  }
  // callback_ should be non-null in the case of asynchronous
  // rendezvous; i.e. |Try()| returned QUIC_PENDING.
  if (!callback_.is_null()) {
    if (stream) {
      next_state_ = STATE_OPEN;
      stream_net_log_.AddEvent(
          NetLog::TYPE_QUIC_HTTP_STREAM_ADOPTED_PUSH_STREAM,
          base::Bind(&NetLogQuicPushStreamCallback, stream_->id(),
                     &request_info_->url));
      session_->net_log().AddEvent(
          NetLog::TYPE_QUIC_HTTP_STREAM_ADOPTED_PUSH_STREAM,
          base::Bind(&NetLogQuicPushStreamCallback, stream_->id(),
                     &request_info_->url));
      DoCallback(OK);
      return;
    }
    // rendezvous has failed so proceed as with a non-push request.
    next_state_ = STATE_REQUEST_STREAM;
    OnIOComplete(OK);
  }
}

int QuicHttpStream::InitializeStream(const HttpRequestInfo* request_info,
                                     RequestPriority priority,
                                     const BoundNetLog& stream_net_log,
                                     const CompletionCallback& callback) {
  DCHECK(!stream_);
  if (!session_)
    return was_handshake_confirmed_ ? ERR_CONNECTION_CLOSED
                                    : ERR_QUIC_HANDSHAKE_FAILED;

  stream_net_log.AddEvent(
      NetLog::TYPE_HTTP_STREAM_REQUEST_BOUND_TO_QUIC_SESSION,
      session_->net_log().source().ToEventParametersCallback());

  stream_net_log_ = stream_net_log;
  request_info_ = request_info;
  request_time_ = base::Time::Now();
  priority_ = priority;

  bool success = session_->GetSSLInfo(&ssl_info_);
  DCHECK(success);
  DCHECK(ssl_info_.cert.get());

  std::string url(request_info->url.spec());
  QuicClientPromisedInfo* promised =
      session_->push_promise_index()->GetPromised(url);
  if (promised) {
    found_promise_ = true;
    stream_net_log_.AddEvent(
        NetLog::TYPE_QUIC_HTTP_STREAM_PUSH_PROMISE_RENDEZVOUS,
        base::Bind(&NetLogQuicPushStreamCallback, promised->id(),
                   &request_info_->url));
    session_->net_log().AddEvent(
        NetLog::TYPE_QUIC_HTTP_STREAM_PUSH_PROMISE_RENDEZVOUS,
        base::Bind(&NetLogQuicPushStreamCallback, promised->id(),
                   &request_info_->url));
    return OK;
  }

  next_state_ = STATE_REQUEST_STREAM;
  int rv = DoLoop(OK);
  if (rv == ERR_IO_PENDING)
    callback_ = callback;

  return rv;
}

void QuicHttpStream::OnStreamReady(int rv) {
  DCHECK(rv == OK || !stream_);
  if (rv == OK) {
    stream_->SetDelegate(this);
    if (request_info_->load_flags & LOAD_DISABLE_CONNECTION_MIGRATION) {
      stream_->DisableConnectionMigration();
    }
    if (response_info_) {
      // This happens in the case of a asynchronous push rendezvous
      // that ultimately fails (e.g. vary failure).  |response_info_|
      // non-null implies that |DoStreamRequest()| was called via
      // |SendRequest()|.
      next_state_ = STATE_SET_REQUEST_PRIORITY;
      rv = DoLoop(OK);
    }
  } else if (!was_handshake_confirmed_) {
    rv = ERR_QUIC_HANDSHAKE_FAILED;
  }
  if (rv != ERR_IO_PENDING) {
    DoCallback(rv);
  }
}

bool QuicHttpStream::CancelPromiseIfHasBody() {
  if (!request_body_stream_)
    return false;
  // Method type or request with body ineligble for push.
  this->push_handle_->Cancel();
  this->push_handle_ = nullptr;
  next_state_ = STATE_REQUEST_STREAM;
  return true;
}

int QuicHttpStream::HandlePromise() {
  QuicAsyncStatus push_status = session_->push_promise_index()->Try(
      request_headers_, this, &this->push_handle_);

  switch (push_status) {
    case QUIC_FAILURE:
      // Push rendezvous failed.
      next_state_ = STATE_REQUEST_STREAM;
      break;
    case QUIC_SUCCESS:
      next_state_ = STATE_OPEN;
      if (!CancelPromiseIfHasBody()) {
        stream_net_log_.AddEvent(
            NetLog::TYPE_QUIC_HTTP_STREAM_ADOPTED_PUSH_STREAM,
            base::Bind(&NetLogQuicPushStreamCallback, stream_->id(),
                       &request_info_->url));
        session_->net_log().AddEvent(
            NetLog::TYPE_QUIC_HTTP_STREAM_ADOPTED_PUSH_STREAM,
            base::Bind(&NetLogQuicPushStreamCallback, stream_->id(),
                       &request_info_->url));
        // Avoid the call to |DoLoop()| below, which would reset
        // next_state_ to STATE_NONE.
        return OK;
      }

      break;
    case QUIC_PENDING:
      if (!CancelPromiseIfHasBody()) {
        // Have a promise but the promised stream doesn't exist yet.
        // Still have to do validation before accepting the promised
        // stream for sure.
        return ERR_IO_PENDING;
      }
      break;
  }
  return DoLoop(OK);
}

int QuicHttpStream::SendRequest(const HttpRequestHeaders& request_headers,
                                HttpResponseInfo* response,
                                const CompletionCallback& callback) {
  CHECK(!request_body_stream_);
  CHECK(!response_info_);
  CHECK(!callback.is_null());
  CHECK(response);

  // TODO(rch): remove this once we figure out why channel ID is not being
  // sent when it should be.
  HostPortPair origin = HostPortPair::FromURL(request_info_->url);
  if (origin.Equals(HostPortPair("accounts.google.com", 443)) &&
      request_headers.HasHeader(HttpRequestHeaders::kCookie)) {
    UMA_HISTOGRAM_BOOLEAN("Net.QuicSession.CookieSentToAccountsOverChannelId",
                          ssl_info_.channel_id_sent);
  }
  if ((!found_promise_ && !stream_) || !session_) {
    return was_handshake_confirmed_ ? ERR_CONNECTION_CLOSED
                                    : ERR_QUIC_HANDSHAKE_FAILED;
  }

  // Store the serialized request headers.
  CreateSpdyHeadersFromHttpRequest(*request_info_, request_headers, HTTP2,
                                   /*direct=*/true, &request_headers_);

  // Store the request body.
  request_body_stream_ = request_info_->upload_data_stream;
  if (request_body_stream_) {
    // TODO(rch): Can we be more precise about when to allocate
    // raw_request_body_buf_. Removed the following check. DoReadRequestBody()
    // was being called even if we didn't yet allocate raw_request_body_buf_.
    //   && (request_body_stream_->size() ||
    //       request_body_stream_->is_chunked()))
    // Use 10 packets as the body buffer size to give enough space to
    // help ensure we don't often send out partial packets.
    raw_request_body_buf_ =
        new IOBufferWithSize(static_cast<size_t>(10 * kMaxPacketSize));
    // The request body buffer is empty at first.
    request_body_buf_ = new DrainableIOBuffer(raw_request_body_buf_.get(), 0);
  }

  // Store the response info.
  response_info_ = response;

  int rv;

  if (found_promise_) {
    rv = HandlePromise();
  } else {
    next_state_ = STATE_SET_REQUEST_PRIORITY;
    rv = DoLoop(OK);
  }

  if (rv == ERR_IO_PENDING)
    callback_ = callback;

  return rv > 0 ? OK : rv;
}

UploadProgress QuicHttpStream::GetUploadProgress() const {
  if (!request_body_stream_)
    return UploadProgress();

  return UploadProgress(request_body_stream_->position(),
                        request_body_stream_->size());
}

int QuicHttpStream::ReadResponseHeaders(const CompletionCallback& callback) {
  CHECK(!callback.is_null());

  if (stream_ == nullptr)
    return response_status_;

  // Check if we already have the response headers. If so, return synchronously.
  if (response_headers_received_)
    return OK;

  // Still waiting for the response, return IO_PENDING.
  CHECK(callback_.is_null());
  callback_ = callback;
  return ERR_IO_PENDING;
}

int QuicHttpStream::ReadResponseBody(IOBuffer* buf,
                                     int buf_len,
                                     const CompletionCallback& callback) {
  if (!stream_) {
    // If the stream is already closed, there is no body to read.
    return response_status_;
  }

  int rv = ReadAvailableData(buf, buf_len);
  if (rv != ERR_IO_PENDING)
    return rv;

  CHECK(callback_.is_null());
  CHECK(!user_buffer_.get());
  CHECK_EQ(0, user_buffer_len_);

  callback_ = callback;
  user_buffer_ = buf;
  user_buffer_len_ = buf_len;
  return ERR_IO_PENDING;
}

void QuicHttpStream::Close(bool not_reusable) {
  // Note: the not_reusable flag has no meaning for SPDY streams.
  if (stream_) {
    stream_->SetDelegate(nullptr);
    stream_->Reset(QUIC_STREAM_CANCELLED);
    ResetStream();
    response_status_ = was_handshake_confirmed_ ? ERR_CONNECTION_CLOSED
                                                : ERR_QUIC_HANDSHAKE_FAILED;
  }
}

HttpStream* QuicHttpStream::RenewStreamForAuth() {
  return nullptr;
}

bool QuicHttpStream::IsResponseBodyComplete() const {
  return next_state_ == STATE_OPEN && !stream_;
}

bool QuicHttpStream::IsConnectionReused() const {
  // TODO(rch): do something smarter here.
  return stream_ && stream_->id() > 1;
}

void QuicHttpStream::SetConnectionReused() {
  // QUIC doesn't need an indicator here.
}

bool QuicHttpStream::CanReuseConnection() const {
  // QUIC streams aren't considered reusable.
  return false;
}

int64_t QuicHttpStream::GetTotalReceivedBytes() const {
  // TODO(sclittle): Currently, this only includes headers and response body
  // bytes. Change this to include QUIC overhead as well.
  int64_t total_received_bytes = headers_bytes_received_;
  if (stream_) {
    total_received_bytes += stream_->stream_bytes_read();
  } else {
    total_received_bytes += closed_stream_received_bytes_;
  }
  return total_received_bytes;
}

int64_t QuicHttpStream::GetTotalSentBytes() const {
  // TODO(sclittle): Currently, this only includes request headers and body
  // bytes. Change this to include QUIC overhead as well.
  int64_t total_sent_bytes = headers_bytes_sent_;
  if (stream_) {
    total_sent_bytes += stream_->stream_bytes_written();
  } else {
    total_sent_bytes += closed_stream_sent_bytes_;
  }
  return total_sent_bytes;
}

bool QuicHttpStream::GetLoadTimingInfo(LoadTimingInfo* load_timing_info) const {
  // TODO(mmenke):  Figure out what to do here.
  return true;
}

void QuicHttpStream::GetSSLInfo(SSLInfo* ssl_info) {
  *ssl_info = ssl_info_;
}

void QuicHttpStream::GetSSLCertRequestInfo(
    SSLCertRequestInfo* cert_request_info) {
  DCHECK(stream_);
  NOTIMPLEMENTED();
}

bool QuicHttpStream::GetRemoteEndpoint(IPEndPoint* endpoint) {
  if (!session_)
    return false;

  *endpoint = session_->peer_address();
  return true;
}

Error QuicHttpStream::GetSignedEKMForTokenBinding(crypto::ECPrivateKey* key,
                                                  std::vector<uint8_t>* out) {
  return session_->GetTokenBindingSignature(key, out);
}

void QuicHttpStream::Drain(HttpNetworkSession* session) {
  NOTREACHED();
  Close(false);
  delete this;
}

void QuicHttpStream::PopulateNetErrorDetails(NetErrorDetails* details) {
  details->connection_info = HttpResponseInfo::CONNECTION_INFO_QUIC1_SPDY3;
  if (was_handshake_confirmed_)
    details->quic_connection_error = quic_connection_error_;
  if (session_) {
    session_->PopulateNetErrorDetails(details);
  } else {
    details->quic_port_migration_detected = port_migration_detected_;
  }
}

void QuicHttpStream::SetPriority(RequestPriority priority) {
  priority_ = priority;
}

void QuicHttpStream::OnHeadersAvailable(const SpdyHeaderBlock& headers,
                                        size_t frame_len) {
  headers_bytes_received_ += frame_len;

  // QuicHttpStream ignores trailers.
  if (response_headers_received_) {
    if (stream_->IsDoneReading()) {
      // Close the read side. If the write side has been closed, this will
      // invoke QuicHttpStream::OnClose to reset the stream.
      stream_->OnFinRead();
    }
    return;
  }

  int rv = ProcessResponseHeaders(headers);
  if (rv != ERR_IO_PENDING && !callback_.is_null()) {
    DoCallback(rv);
  }
}

void QuicHttpStream::OnDataAvailable() {
  if (callback_.is_null()) {
    // Data is available, but can't be delivered
    return;
  }

  CHECK(user_buffer_.get());
  CHECK_NE(0, user_buffer_len_);
  int rv = ReadAvailableData(user_buffer_.get(), user_buffer_len_);
  if (rv == ERR_IO_PENDING) {
    // This was a spurrious notification. Wait for the next one.
    return;
  }

  CHECK(!callback_.is_null());
  user_buffer_ = nullptr;
  user_buffer_len_ = 0;
  DoCallback(rv);
}

void QuicHttpStream::OnClose() {
  if (stream_->connection_error() != QUIC_NO_ERROR ||
      stream_->stream_error() != QUIC_STREAM_NO_ERROR) {
    response_status_ = was_handshake_confirmed_ ? ERR_QUIC_PROTOCOL_ERROR
                                                : ERR_QUIC_HANDSHAKE_FAILED;
  } else if (!response_headers_received_) {
    response_status_ = ERR_ABORTED;
  }

  quic_connection_error_ = stream_->connection_error();
  ResetStream();
  if (!callback_.is_null()) {
    DoCallback(response_status_);
  }
}

void QuicHttpStream::OnError(int error) {
  ResetStream();
  response_status_ =
      was_handshake_confirmed_ ? error : ERR_QUIC_HANDSHAKE_FAILED;
  if (!callback_.is_null())
    DoCallback(response_status_);
}

bool QuicHttpStream::HasSendHeadersComplete() {
  return next_state_ > STATE_SEND_HEADERS_COMPLETE;
}

void QuicHttpStream::OnCryptoHandshakeConfirmed() {
  was_handshake_confirmed_ = true;
  if (next_state_ == STATE_WAIT_FOR_CONFIRMATION_COMPLETE) {
    int rv = DoLoop(OK);

    if (rv != ERR_IO_PENDING && !callback_.is_null()) {
      DoCallback(rv);
    }
  }
}

void QuicHttpStream::OnSessionClosed(int error, bool port_migration_detected) {
  Close(false);
  session_error_ = error;
  port_migration_detected_ = port_migration_detected;
  session_.reset();
}

void QuicHttpStream::OnIOComplete(int rv) {
  rv = DoLoop(rv);

  if (rv != ERR_IO_PENDING && !callback_.is_null()) {
    DoCallback(rv);
  }
}

void QuicHttpStream::DoCallback(int rv) {
  CHECK_NE(rv, ERR_IO_PENDING);
  CHECK(!callback_.is_null());

  // The client callback can do anything, including destroying this class,
  // so any pending callback must be issued after everything else is done.
  base::ResetAndReturn(&callback_).Run(rv);
}

int QuicHttpStream::DoLoop(int rv) {
  do {
    State state = next_state_;
    next_state_ = STATE_NONE;
    switch (state) {
      case STATE_REQUEST_STREAM:
        rv = DoStreamRequest();
        break;
      case STATE_SET_REQUEST_PRIORITY:
        rv = DoSetRequestPriority();
        break;
      case STATE_WAIT_FOR_CONFIRMATION:
        CHECK_EQ(OK, rv);
        rv = DoWaitForConfirmation();
        break;
      case STATE_WAIT_FOR_CONFIRMATION_COMPLETE:
        rv = DoWaitForConfirmationComplete(rv);
        break;
      case STATE_SEND_HEADERS:
        CHECK_EQ(OK, rv);
        rv = DoSendHeaders();
        break;
      case STATE_SEND_HEADERS_COMPLETE:
        rv = DoSendHeadersComplete(rv);
        break;
      case STATE_READ_REQUEST_BODY:
        CHECK_EQ(OK, rv);
        rv = DoReadRequestBody();
        break;
      case STATE_READ_REQUEST_BODY_COMPLETE:
        rv = DoReadRequestBodyComplete(rv);
        break;
      case STATE_SEND_BODY:
        CHECK_EQ(OK, rv);
        rv = DoSendBody();
        break;
      case STATE_SEND_BODY_COMPLETE:
        rv = DoSendBodyComplete(rv);
        break;
      case STATE_OPEN:
        CHECK_EQ(OK, rv);
        break;
      default:
        NOTREACHED() << "next_state_: " << next_state_;
        break;
    }
  } while (next_state_ != STATE_NONE && next_state_ != STATE_OPEN &&
           rv != ERR_IO_PENDING);

  return rv;
}

int QuicHttpStream::DoStreamRequest() {
  // TODO(rtenneti) Bug: b/28676259 - a temporary fix until we find out why
  // |session_| could be a nullptr. Delete |null_session| check and histogram if
  // session is never a nullptr.
  bool null_session = session_ == nullptr;
  if (null_session) {
    UMA_HISTOGRAM_BOOLEAN("Net.QuicHttpStream::DoStreamRequest.IsNullSession",
                          null_session);
    return was_handshake_confirmed_ ? ERR_CONNECTION_CLOSED
                                    : ERR_QUIC_HANDSHAKE_FAILED;
  }
  int rv = stream_request_.StartRequest(
      session_, &stream_,
      base::Bind(&QuicHttpStream::OnStreamReady, weak_factory_.GetWeakPtr()));
  if (rv == OK) {
    stream_->SetDelegate(this);
    if (request_info_->load_flags & LOAD_DISABLE_CONNECTION_MIGRATION) {
      stream_->DisableConnectionMigration();
    }
    if (response_info_) {
      next_state_ = STATE_SET_REQUEST_PRIORITY;
    }
  } else if (rv != ERR_IO_PENDING && !was_handshake_confirmed_) {
    rv = ERR_QUIC_HANDSHAKE_FAILED;
  }
  return rv;
}

int QuicHttpStream::DoSetRequestPriority() {
  // Set priority according to request
  DCHECK(stream_);
  DCHECK(response_info_);
  SpdyPriority priority = ConvertRequestPriorityToQuicPriority(priority_);
  stream_->SetPriority(priority);
  next_state_ = STATE_WAIT_FOR_CONFIRMATION;
  return OK;
}

int QuicHttpStream::DoWaitForConfirmation() {
  next_state_ = STATE_WAIT_FOR_CONFIRMATION_COMPLETE;
  if (!session_->IsCryptoHandshakeConfirmed() &&
      request_info_->method == "POST") {
    return ERR_IO_PENDING;
  }
  return OK;
}

int QuicHttpStream::DoWaitForConfirmationComplete(int rv) {
  if (rv < 0)
    return rv;

  next_state_ = STATE_SEND_HEADERS;
  return OK;
}

int QuicHttpStream::DoSendHeaders() {
  if (!stream_)
    return ERR_UNEXPECTED;

  // Log the actual request with the URL Request's net log.
  stream_net_log_.AddEvent(
      NetLog::TYPE_HTTP_TRANSACTION_QUIC_SEND_REQUEST_HEADERS,
      base::Bind(&QuicRequestNetLogCallback, stream_->id(), &request_headers_,
                 priority_));
  bool has_upload_data = request_body_stream_ != nullptr;

  next_state_ = STATE_SEND_HEADERS_COMPLETE;
  size_t frame_len = stream_->WriteHeaders(std::move(request_headers_),
                                           !has_upload_data, nullptr);
  headers_bytes_sent_ += frame_len;

  request_headers_ = SpdyHeaderBlock();
  return static_cast<int>(frame_len);
}

int QuicHttpStream::DoSendHeadersComplete(int rv) {
  if (rv < 0)
    return rv;

  // If the stream is already closed, don't read the request the body.
  if (!stream_)
    return response_status_;

  next_state_ = request_body_stream_ ? STATE_READ_REQUEST_BODY : STATE_OPEN;

  return OK;
}

int QuicHttpStream::DoReadRequestBody() {
  next_state_ = STATE_READ_REQUEST_BODY_COMPLETE;
  return request_body_stream_->Read(
      raw_request_body_buf_.get(), raw_request_body_buf_->size(),
      base::Bind(&QuicHttpStream::OnIOComplete, weak_factory_.GetWeakPtr()));
}

int QuicHttpStream::DoReadRequestBodyComplete(int rv) {
  // If the stream is already closed, don't continue.
  if (!stream_)
    return response_status_;

  // |rv| is the result of read from the request body from the last call to
  // DoSendBody().
  if (rv < 0) {
    stream_->SetDelegate(nullptr);
    stream_->Reset(QUIC_ERROR_PROCESSING_STREAM);
    ResetStream();
    return rv;
  }

  request_body_buf_ = new DrainableIOBuffer(raw_request_body_buf_.get(), rv);
  if (rv == 0) {  // Reached the end.
    DCHECK(request_body_stream_->IsEOF());
  }

  next_state_ = STATE_SEND_BODY;
  return OK;
}

int QuicHttpStream::DoSendBody() {
  if (!stream_)
    return ERR_UNEXPECTED;

  CHECK(request_body_stream_);
  CHECK(request_body_buf_.get());
  const bool eof = request_body_stream_->IsEOF();
  int len = request_body_buf_->BytesRemaining();
  if (len > 0 || eof) {
    next_state_ = STATE_SEND_BODY_COMPLETE;
    base::StringPiece data(request_body_buf_->data(), len);
    return stream_->WriteStreamData(
        data, eof,
        base::Bind(&QuicHttpStream::OnIOComplete, weak_factory_.GetWeakPtr()));
  }

  next_state_ = STATE_OPEN;
  return OK;
}

int QuicHttpStream::DoSendBodyComplete(int rv) {
  if (rv < 0)
    return rv;

  // If the stream is already closed, don't continue.
  if (!stream_)
    return response_status_;

  request_body_buf_->DidConsume(request_body_buf_->BytesRemaining());

  if (!request_body_stream_->IsEOF()) {
    next_state_ = STATE_READ_REQUEST_BODY;
    return OK;
  }

  next_state_ = STATE_OPEN;
  return OK;
}

int QuicHttpStream::ProcessResponseHeaders(const SpdyHeaderBlock& headers) {
  if (!SpdyHeadersToHttpResponse(headers, HTTP2, response_info_)) {
    DLOG(WARNING) << "Invalid headers";
    return ERR_QUIC_PROTOCOL_ERROR;
  }
  // Put the peer's IP address and port into the response.
  IPEndPoint address = session_->peer_address();
  response_info_->socket_address = HostPortPair::FromIPEndPoint(address);
  response_info_->connection_info =
      HttpResponseInfo::CONNECTION_INFO_QUIC1_SPDY3;
  response_info_->vary_data.Init(*request_info_,
                                 *response_info_->headers.get());
  response_info_->was_npn_negotiated = true;
  response_info_->npn_negotiated_protocol = "quic/1+spdy/3";
  response_info_->response_time = base::Time::Now();
  response_info_->request_time = request_time_;
  response_headers_received_ = true;

  return OK;
}

int QuicHttpStream::ReadAvailableData(IOBuffer* buf, int buf_len) {
  int rv = stream_->Read(buf, buf_len);
  // TODO(rtenneti): Temporary fix for crbug.com/585591. Added a check for null
  // |stream_| to fix crash bug. Delete |stream_| check and histogram after fix
  // is merged.
  bool null_stream = stream_ == nullptr;
  UMA_HISTOGRAM_BOOLEAN("Net.QuicReadAvailableData.NullStream", null_stream);
  if (null_stream)
    return rv;
  if (stream_->IsDoneReading()) {
    stream_->SetDelegate(nullptr);
    stream_->OnFinRead();
    ResetStream();
  }
  return rv;
}

void QuicHttpStream::ResetStream() {
  if (push_handle_) {
    push_handle_->Cancel();
    push_handle_ = nullptr;
  }
  if (!stream_)
    return;
  closed_stream_received_bytes_ = stream_->stream_bytes_read();
  closed_stream_sent_bytes_ = stream_->stream_bytes_written();
  stream_ = nullptr;

  // If |request_body_stream_| is non-NULL, Reset it, to abort any in progress
  // read.
  if (request_body_stream_)
    request_body_stream_->Reset();
}

}  // namespace net
