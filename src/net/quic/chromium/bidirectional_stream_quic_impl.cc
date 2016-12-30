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
#include "net/socket/next_proto.h"
#include "net/spdy/spdy_header_block.h"
#include "net/spdy/spdy_http_utils.h"

namespace net {

BidirectionalStreamQuicImpl::BidirectionalStreamQuicImpl(
    const base::WeakPtr<QuicChromiumClientSession>& session)
    : session_(session),
      was_handshake_confirmed_(session->IsCryptoHandshakeConfirmed()),
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
      has_received_headers_(false),
      send_request_headers_automatically_(true),
      waiting_for_confirmation_(false),
      weak_factory_(this) {
  DCHECK(session_);
  session_->AddObserver(this);
}

BidirectionalStreamQuicImpl::~BidirectionalStreamQuicImpl() {
  if (stream_) {
    delegate_ = nullptr;
    stream_->Reset(QUIC_STREAM_CANCELLED);
  }

  if (session_)
    session_->RemoveObserver(this);
}

void BidirectionalStreamQuicImpl::Start(
    const BidirectionalStreamRequestInfo* request_info,
    const NetLogWithSource& net_log,
    bool send_request_headers_automatically,
    BidirectionalStreamImpl::Delegate* delegate,
    std::unique_ptr<base::Timer> /* timer */) {
  DCHECK(!stream_);
  CHECK(delegate);

  send_request_headers_automatically_ = send_request_headers_automatically;
  if (!session_) {
    NotifyError(was_handshake_confirmed_ ? ERR_QUIC_PROTOCOL_ERROR
                                         : ERR_QUIC_HANDSHAKE_FAILED);
    return;
  }

  delegate_ = delegate;
  request_info_ = request_info;

  int rv = stream_request_.StartRequest(
      session_, &stream_,
      base::Bind(&BidirectionalStreamQuicImpl::OnStreamReady,
                 weak_factory_.GetWeakPtr()));
  if (rv == OK) {
    OnStreamReady(rv);
  } else if (!was_handshake_confirmed_) {
    NotifyError(ERR_QUIC_HANDSHAKE_FAILED);
  }
}

void BidirectionalStreamQuicImpl::SendRequestHeaders() {
  DCHECK(!has_sent_headers_);
  if (!stream_) {
    LOG(ERROR)
        << "Trying to send request headers after stream has been destroyed.";
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, base::Bind(&BidirectionalStreamQuicImpl::NotifyError,
                              weak_factory_.GetWeakPtr(), ERR_UNEXPECTED));
    return;
  }

  SpdyHeaderBlock headers;
  HttpRequestInfo http_request_info;
  http_request_info.url = request_info_->url;
  http_request_info.method = request_info_->method;
  http_request_info.extra_headers = request_info_->extra_headers;

  CreateSpdyHeadersFromHttpRequest(
      http_request_info, http_request_info.extra_headers, true, &headers);
  size_t headers_bytes_sent = stream_->WriteHeaders(
      std::move(headers), request_info_->end_stream_on_headers, nullptr);
  headers_bytes_sent_ += headers_bytes_sent;
  has_sent_headers_ = true;
}

int BidirectionalStreamQuicImpl::ReadData(IOBuffer* buffer, int buffer_len) {
  DCHECK(buffer);
  DCHECK(buffer_len);

  if (!stream_) {
    // If the stream is already closed, there is no body to read.
    return response_status_;
  }
  int rv = stream_->Read(buffer, buffer_len);
  if (rv != ERR_IO_PENDING) {
    if (stream_->IsDoneReading()) {
      // If the write side is closed, OnFinRead() will call
      // BidirectionalStreamQuicImpl::OnClose().
      stream_->OnFinRead();
    }
    return rv;
  }
  // Read will complete asynchronously and Delegate::OnReadCompleted will be
  // called upon completion.
  read_buffer_ = buffer;
  read_buffer_len_ = buffer_len;
  return ERR_IO_PENDING;
}

void BidirectionalStreamQuicImpl::SendData(const scoped_refptr<IOBuffer>& data,
                                           int length,
                                           bool end_stream) {
  DCHECK(length > 0 || (length == 0 && end_stream));
  if (!stream_) {
    LOG(ERROR) << "Trying to send data after stream has been destroyed.";
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, base::Bind(&BidirectionalStreamQuicImpl::NotifyError,
                              weak_factory_.GetWeakPtr(), ERR_UNEXPECTED));
    return;
  }

  std::unique_ptr<QuicConnection::ScopedPacketBundler> bundler;
  if (!has_sent_headers_) {
    DCHECK(!send_request_headers_automatically_);
    // Creates a bundler only if there are headers to be sent along with the
    // single data buffer.
    bundler.reset(new QuicConnection::ScopedPacketBundler(
        session_->connection(), QuicConnection::SEND_ACK_IF_PENDING));
    SendRequestHeaders();
  }

  base::StringPiece string_data(data->data(), length);
  int rv = stream_->WriteStreamData(
      string_data, end_stream,
      base::Bind(&BidirectionalStreamQuicImpl::OnSendDataComplete,
                 weak_factory_.GetWeakPtr()));
  DCHECK(rv == OK || rv == ERR_IO_PENDING);
  if (rv == OK) {
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, base::Bind(&BidirectionalStreamQuicImpl::OnSendDataComplete,
                              weak_factory_.GetWeakPtr(), OK));
  }
}

void BidirectionalStreamQuicImpl::SendvData(
    const std::vector<scoped_refptr<IOBuffer>>& buffers,
    const std::vector<int>& lengths,
    bool end_stream) {
  DCHECK_EQ(buffers.size(), lengths.size());

  if (!stream_) {
    LOG(ERROR) << "Trying to send data after stream has been destroyed.";
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, base::Bind(&BidirectionalStreamQuicImpl::NotifyError,
                              weak_factory_.GetWeakPtr(), ERR_UNEXPECTED));
    return;
  }

  QuicConnection::ScopedPacketBundler bundler(
      session_->connection(), QuicConnection::SEND_ACK_IF_PENDING);
  if (!has_sent_headers_) {
    DCHECK(!send_request_headers_automatically_);
    SendRequestHeaders();
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

void BidirectionalStreamQuicImpl::OnHeadersAvailable(
    const SpdyHeaderBlock& headers,
    size_t frame_len) {
  headers_bytes_received_ += frame_len;
  negotiated_protocol_ = kProtoQUIC;
  if (!has_received_headers_) {
    has_received_headers_ = true;
    connect_timing_ = session_->GetConnectTiming();
    if (delegate_)
      delegate_->OnHeadersReceived(headers);
  } else {
    if (delegate_)
      delegate_->OnTrailersReceived(headers);
    // |this| can be destroyed after this point.
  }
}

void BidirectionalStreamQuicImpl::OnDataAvailable() {
  // Return early if ReadData has not been called.
  if (!read_buffer_)
    return;

  int rv = ReadData(read_buffer_.get(), read_buffer_len_);
  if (rv == ERR_IO_PENDING) {
    // Spurrious notification. Wait for the next one.
    return;
  }
  read_buffer_ = nullptr;
  read_buffer_len_ = 0;
  if (delegate_)
    delegate_->OnDataRead(rv);
}

void BidirectionalStreamQuicImpl::OnClose() {
  DCHECK(stream_);

  if (stream_->connection_error() == QUIC_NO_ERROR &&
      stream_->stream_error() == QUIC_STREAM_NO_ERROR) {
    ResetStream();
    return;
  }
  NotifyError(was_handshake_confirmed_ ? ERR_QUIC_PROTOCOL_ERROR
                                       : ERR_QUIC_HANDSHAKE_FAILED);
}

void BidirectionalStreamQuicImpl::OnError(int error) {
  NotifyError(error);
}

bool BidirectionalStreamQuicImpl::HasSendHeadersComplete() {
  return has_sent_headers_;
}

void BidirectionalStreamQuicImpl::OnCryptoHandshakeConfirmed() {
  was_handshake_confirmed_ = true;
  if (waiting_for_confirmation_)
    NotifyStreamReady();
}

void BidirectionalStreamQuicImpl::OnSuccessfulVersionNegotiation(
    const QuicVersion& version) {}

void BidirectionalStreamQuicImpl::OnSessionClosed(
    int error,
    bool /*port_migration_detected*/) {
  DCHECK_NE(OK, error);
  session_.reset();
  NotifyError(error);
}

void BidirectionalStreamQuicImpl::OnStreamReady(int rv) {
  DCHECK_NE(ERR_IO_PENDING, rv);
  DCHECK(rv == OK || !stream_);
  if (rv == OK) {
    stream_->SetDelegate(this);
    if (!was_handshake_confirmed_ && request_info_->method == "POST") {
      waiting_for_confirmation_ = true;
      return;
    }
    NotifyStreamReady();
  } else {
    NotifyError(rv);
  }
}

void BidirectionalStreamQuicImpl::OnSendDataComplete(int rv) {
  DCHECK(rv == OK || !stream_);
  if (rv == OK) {
    if (delegate_)
      delegate_->OnDataSent();
  } else {
    NotifyError(rv);
  }
}

void BidirectionalStreamQuicImpl::NotifyError(int error) {
  DCHECK_NE(OK, error);
  DCHECK_NE(ERR_IO_PENDING, error);

  ResetStream();
  if (delegate_) {
    response_status_ = error;
    BidirectionalStreamImpl::Delegate* delegate = delegate_;
    delegate_ = nullptr;
    // Cancel any pending callback.
    weak_factory_.InvalidateWeakPtrs();
    delegate->OnFailed(error);
    // |this| might be destroyed at this point.
  }
}

void BidirectionalStreamQuicImpl::NotifyStreamReady() {
  if (send_request_headers_automatically_) {
    SendRequestHeaders();
  }
  if (delegate_)
    delegate_->OnStreamReady(has_sent_headers_);
}

void BidirectionalStreamQuicImpl::ResetStream() {
  if (!stream_)
    return;
  closed_stream_received_bytes_ = stream_->stream_bytes_read();
  closed_stream_sent_bytes_ = stream_->stream_bytes_written();
  closed_is_first_stream_ = stream_->IsFirstStream();
  stream_->SetDelegate(nullptr);
  stream_ = nullptr;
}

}  // namespace net
