// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/chromium/bidirectional_stream_quic_impl.h"

#include <utility>

#include "base/bind.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/timer/timer.h"
#include "net/http/bidirectional_stream_request_info.h"
#include "net/quic/core/quic_connection.h"
#include "net/quic/platform/api/quic_string_piece.h"
#include "net/socket/next_proto.h"
#include "net/spdy/chromium/spdy_http_utils.h"
#include "net/spdy/core/spdy_header_block.h"

namespace net {
namespace {
// Sets a boolean to a value, and restores it to the previous value once
// the saver goes out of scope.
class ScopedBoolSaver {
 public:
  ScopedBoolSaver(bool* var, bool new_val) : var_(var), old_val_(*var) {
    *var_ = new_val;
  }

  ~ScopedBoolSaver() { *var_ = old_val_; }

 private:
  bool* var_;
  bool old_val_;
};
}  // namespace

BidirectionalStreamQuicImpl::BidirectionalStreamQuicImpl(
    std::unique_ptr<QuicChromiumClientSession::Handle> session)
    : session_(std::move(session)),
      stream_(nullptr),
      request_info_(nullptr),
      delegate_(nullptr),
      response_status_(OK),
      negotiated_protocol_(kProtoUnknown),
      read_buffer_len_(0),
      headers_bytes_received_(0),
      headers_bytes_sent_(0),
      closed_stream_received_bytes_(0),
      closed_stream_sent_bytes_(0),
      closed_is_first_stream_(false),
      has_sent_headers_(false),
      send_request_headers_automatically_(true),
      may_invoke_callbacks_(true),
      weak_factory_(this) {}

BidirectionalStreamQuicImpl::~BidirectionalStreamQuicImpl() {
  if (stream_) {
    delegate_ = nullptr;
    stream_->Reset(QUIC_STREAM_CANCELLED);
  }
}

void BidirectionalStreamQuicImpl::Start(
    const BidirectionalStreamRequestInfo* request_info,
    const NetLogWithSource& net_log,
    bool send_request_headers_automatically,
    BidirectionalStreamImpl::Delegate* delegate,
    std::unique_ptr<base::Timer> /* timer */) {
  ScopedBoolSaver saver(&may_invoke_callbacks_, false);
  DCHECK(!stream_);
  CHECK(delegate);
  DLOG_IF(WARNING, !session_->IsConnected())
      << "Trying to start request headers after session has been closed.";

  send_request_headers_automatically_ = send_request_headers_automatically;
  delegate_ = delegate;
  request_info_ = request_info;

  int rv = session_->RequestStream(
      request_info_->method == "POST",
      base::Bind(&BidirectionalStreamQuicImpl::OnStreamReady,
                 weak_factory_.GetWeakPtr()));
  if (rv == ERR_IO_PENDING)
    return;

  if (rv != OK) {
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, base::Bind(&BidirectionalStreamQuicImpl::NotifyError,
                              weak_factory_.GetWeakPtr(),
                              session_->IsCryptoHandshakeConfirmed()
                                  ? rv
                                  : ERR_QUIC_HANDSHAKE_FAILED));
    return;
  }

  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE, base::Bind(&BidirectionalStreamQuicImpl::OnStreamReady,
                            weak_factory_.GetWeakPtr(), rv));
}

void BidirectionalStreamQuicImpl::SendRequestHeaders() {
  ScopedBoolSaver saver(&may_invoke_callbacks_, false);
  // If this fails, a task will have been posted to notify the delegate
  // asynchronously.
  WriteHeaders();
}

bool BidirectionalStreamQuicImpl::WriteHeaders() {
  DCHECK(!has_sent_headers_);
  if (!stream_) {
    LOG(ERROR)
        << "Trying to send request headers after stream has been destroyed.";
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, base::Bind(&BidirectionalStreamQuicImpl::NotifyError,
                              weak_factory_.GetWeakPtr(), ERR_UNEXPECTED));
    return false;
  }

  SpdyHeaderBlock headers;
  HttpRequestInfo http_request_info;
  http_request_info.url = request_info_->url;
  http_request_info.method = request_info_->method;
  http_request_info.extra_headers = request_info_->extra_headers;

  CreateSpdyHeadersFromHttpRequest(
      http_request_info, http_request_info.extra_headers, true, &headers);
  // Sending the request might result in the stream being closed via OnClose
  // which will post a task to notify the delegate asynchronously.
  // TODO(rch): Clean up this interface when OnClose and OnError are removed.
  size_t headers_bytes_sent = stream_->WriteHeaders(
      std::move(headers), request_info_->end_stream_on_headers, nullptr);
  if (!stream_)
    return false;

  headers_bytes_sent_ += headers_bytes_sent;
  has_sent_headers_ = true;
  return true;
}

int BidirectionalStreamQuicImpl::ReadData(IOBuffer* buffer, int buffer_len) {
  ScopedBoolSaver saver(&may_invoke_callbacks_, false);
  DCHECK(buffer);
  DCHECK(buffer_len);

  if (!stream_) {
    // If the stream is already closed, there is no body to read.
    return response_status_;
  }
  int rv = stream_->ReadBody(
      buffer, buffer_len,
      base::Bind(&BidirectionalStreamQuicImpl::OnReadDataComplete,
                 weak_factory_.GetWeakPtr()));
  if (rv == ERR_IO_PENDING) {
    read_buffer_ = buffer;
    read_buffer_len_ = buffer_len;
    return ERR_IO_PENDING;
  }

  if (rv < 0)
    return rv;

  if (stream_->IsDoneReading()) {
    // If the write side is closed, OnFinRead() will call
    // BidirectionalStreamQuicImpl::OnClose().
    stream_->OnFinRead();
  }
  return rv;
}

void BidirectionalStreamQuicImpl::SendvData(
    const std::vector<scoped_refptr<IOBuffer>>& buffers,
    const std::vector<int>& lengths,
    bool end_stream) {
  ScopedBoolSaver saver(&may_invoke_callbacks_, false);
  DCHECK_EQ(buffers.size(), lengths.size());

  if (!stream_) {
    LOG(ERROR) << "Trying to send data after stream has been destroyed.";
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, base::Bind(&BidirectionalStreamQuicImpl::NotifyError,
                              weak_factory_.GetWeakPtr(), ERR_UNEXPECTED));
    return;
  }

  std::unique_ptr<QuicConnection::ScopedPacketBundler> bundler(
      session_->CreatePacketBundler(QuicConnection::SEND_ACK_IF_PENDING));
  if (!has_sent_headers_) {
    DCHECK(!send_request_headers_automatically_);
    // Sending the request might result in the stream being closed.
    if (!WriteHeaders())
      return;
  }

  int rv = stream_->WritevStreamData(
      buffers, lengths, end_stream,
      base::Bind(&BidirectionalStreamQuicImpl::OnSendDataComplete,
                 weak_factory_.GetWeakPtr()));

  DCHECK(rv == OK || rv == ERR_IO_PENDING);
  if (rv == OK) {
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, base::Bind(&BidirectionalStreamQuicImpl::OnSendDataComplete,
                              weak_factory_.GetWeakPtr(), OK));
  }
}

NextProto BidirectionalStreamQuicImpl::GetProtocol() const {
  return negotiated_protocol_;
}

int64_t BidirectionalStreamQuicImpl::GetTotalReceivedBytes() const {
  if (stream_)
    return headers_bytes_received_ + stream_->stream_bytes_read();
  return headers_bytes_received_ + closed_stream_received_bytes_;
}

int64_t BidirectionalStreamQuicImpl::GetTotalSentBytes() const {
  if (stream_)
    return headers_bytes_sent_ + stream_->stream_bytes_written();
  return headers_bytes_sent_ + closed_stream_sent_bytes_;
}

bool BidirectionalStreamQuicImpl::GetLoadTimingInfo(
    LoadTimingInfo* load_timing_info) const {
  bool is_first_stream = closed_is_first_stream_;
  if (stream_)
    is_first_stream = stream_->IsFirstStream();
  if (is_first_stream) {
    load_timing_info->socket_reused = false;
    load_timing_info->connect_timing = connect_timing_;
  } else {
    load_timing_info->socket_reused = true;
  }
  return true;
}

void BidirectionalStreamQuicImpl::OnClose() {
  DCHECK(stream_);

  if (stream_->connection_error() != QUIC_NO_ERROR ||
      stream_->stream_error() != QUIC_STREAM_NO_ERROR) {
    OnError(session_->IsCryptoHandshakeConfirmed() ? ERR_QUIC_PROTOCOL_ERROR
                                                   : ERR_QUIC_HANDSHAKE_FAILED);
    return;
  }

  if (!stream_->fin_sent() || !stream_->fin_received()) {
    // The connection must have been closed by the peer with QUIC_NO_ERROR,
    // which is improper.
    OnError(ERR_UNEXPECTED);
    return;
  }

  // The connection was closed normally so there is no need to notify
  // the delegate.
  ResetStream();
}

void BidirectionalStreamQuicImpl::OnError(int error) {
  // Avoid reentrancy by notifying the delegate asynchronously.
  NotifyErrorImpl(error, /*notify_delegate_later*/ true);
}

void BidirectionalStreamQuicImpl::OnStreamReady(int rv) {
  DCHECK_NE(ERR_IO_PENDING, rv);
  DCHECK(rv == OK || !stream_);
  if (rv != OK) {
    NotifyError(rv);
    return;
  }

  stream_ = session_->ReleaseStream(this);

  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE, base::Bind(&BidirectionalStreamQuicImpl::ReadInitialHeaders,
                            weak_factory_.GetWeakPtr()));

  NotifyStreamReady();
}

void BidirectionalStreamQuicImpl::OnSendDataComplete(int rv) {
  CHECK(may_invoke_callbacks_);
  DCHECK(rv == OK || !stream_);
  if (rv != 0) {
    NotifyError(rv);
    return;
  }

  if (delegate_)
    delegate_->OnDataSent();
}

void BidirectionalStreamQuicImpl::OnReadInitialHeadersComplete(int rv) {
  CHECK(may_invoke_callbacks_);
  DCHECK_NE(ERR_IO_PENDING, rv);
  if (rv < 0) {
    NotifyError(rv);
    return;
  }

  headers_bytes_received_ += rv;
  negotiated_protocol_ = kProtoQUIC;
  connect_timing_ = session_->GetConnectTiming();
  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE, base::Bind(&BidirectionalStreamQuicImpl::ReadTrailingHeaders,
                            weak_factory_.GetWeakPtr()));
  if (delegate_)
    delegate_->OnHeadersReceived(initial_headers_);
}

void BidirectionalStreamQuicImpl::ReadInitialHeaders() {
  int rv = stream_->ReadInitialHeaders(
      &initial_headers_,
      base::Bind(&BidirectionalStreamQuicImpl::OnReadInitialHeadersComplete,
                 weak_factory_.GetWeakPtr()));

  if (rv != ERR_IO_PENDING)
    OnReadInitialHeadersComplete(rv);
}

void BidirectionalStreamQuicImpl::ReadTrailingHeaders() {
  int rv = stream_->ReadTrailingHeaders(
      &trailing_headers_,
      base::Bind(&BidirectionalStreamQuicImpl::OnReadTrailingHeadersComplete,
                 weak_factory_.GetWeakPtr()));

  if (rv != ERR_IO_PENDING)
    OnReadTrailingHeadersComplete(rv);
}

void BidirectionalStreamQuicImpl::OnReadTrailingHeadersComplete(int rv) {
  CHECK(may_invoke_callbacks_);
  DCHECK_NE(ERR_IO_PENDING, rv);
  if (rv < 0) {
    NotifyError(rv);
    return;
  }

  headers_bytes_received_ += rv;

  if (delegate_)
    delegate_->OnTrailersReceived(trailing_headers_);
}

void BidirectionalStreamQuicImpl::OnReadDataComplete(int rv) {
  CHECK(may_invoke_callbacks_);
  DCHECK_GE(rv, 0);
  read_buffer_ = nullptr;
  read_buffer_len_ = 0;

  if (stream_->IsDoneReading()) {
    // If the write side is closed, OnFinRead() will call
    // BidirectionalStreamQuicImpl::OnClose().
    stream_->OnFinRead();
  }

  if (delegate_)
    delegate_->OnDataRead(rv);
}

void BidirectionalStreamQuicImpl::NotifyError(int error) {
  NotifyErrorImpl(error, /*notify_delegate_later*/ false);
}

void BidirectionalStreamQuicImpl::NotifyErrorImpl(int error,
                                                  bool notify_delegate_later) {
  DCHECK_NE(OK, error);
  DCHECK_NE(ERR_IO_PENDING, error);

  ResetStream();
  if (delegate_) {
    response_status_ = error;
    BidirectionalStreamImpl::Delegate* delegate = delegate_;
    delegate_ = nullptr;
    // Cancel any pending callback.
    weak_factory_.InvalidateWeakPtrs();
    if (notify_delegate_later) {
      base::ThreadTaskRunnerHandle::Get()->PostTask(
          FROM_HERE, base::Bind(&BidirectionalStreamQuicImpl::NotifyFailure,
                                weak_factory_.GetWeakPtr(), delegate, error));
    } else {
      NotifyFailure(delegate, error);
      // |this| might be destroyed at this point.
    }
  }
}

void BidirectionalStreamQuicImpl::NotifyFailure(
    BidirectionalStreamImpl::Delegate* delegate,
    int error) {
  CHECK(may_invoke_callbacks_);
  delegate->OnFailed(error);
  // |this| might be destroyed at this point.
}

void BidirectionalStreamQuicImpl::NotifyStreamReady() {
  CHECK(may_invoke_callbacks_);
  // Sending the request might result in the stream being closed.
  if (send_request_headers_automatically_ && !WriteHeaders())
    return;

  if (delegate_)
    delegate_->OnStreamReady(has_sent_headers_);
}

void BidirectionalStreamQuicImpl::ResetStream() {
  if (!stream_)
    return;
  closed_stream_received_bytes_ = stream_->stream_bytes_read();
  closed_stream_sent_bytes_ = stream_->stream_bytes_written();
  closed_is_first_stream_ = stream_->IsFirstStream();
  stream_->ClearDelegate();
  stream_ = nullptr;
}

}  // namespace net
