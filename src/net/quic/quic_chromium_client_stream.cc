// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_chromium_client_stream.h"

#include "base/callback_helpers.h"
#include "base/location.h"
#include "base/thread_task_runner_handle.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"
#include "net/quic/quic_chromium_client_session.h"
#include "net/quic/quic_http_utils.h"
#include "net/quic/quic_spdy_session.h"
#include "net/quic/quic_write_blocked_list.h"
#include "net/quic/spdy_utils.h"

namespace net {

QuicChromiumClientStream::QuicChromiumClientStream(
    QuicStreamId id,
    QuicClientSessionBase* session,
    const BoundNetLog& net_log)
    : QuicSpdyStream(id, session),
      net_log_(net_log),
      delegate_(nullptr),
      headers_delivered_(false),
      session_(session),
      can_migrate_(true),
      weak_factory_(this) {}

QuicChromiumClientStream::~QuicChromiumClientStream() {
  if (delegate_)
    delegate_->OnClose(connection_error());
}

void QuicChromiumClientStream::OnStreamHeadersComplete(bool fin,
                                                       size_t frame_len) {
  QuicSpdyStream::OnStreamHeadersComplete(fin, frame_len);
  if (decompressed_headers().empty() && !decompressed_trailers().empty()) {
    DCHECK(trailers_decompressed());
    // The delegate will read the trailers via a posted task.
    NotifyDelegateOfHeadersCompleteLater(received_trailers(), frame_len);
  } else {
    DCHECK(!headers_delivered_);
    SpdyHeaderBlock headers;
    SpdyFramer framer(HTTP2);
    size_t headers_len = decompressed_headers().length();
    const char* header_data = decompressed_headers().data();
    if (!framer.ParseHeaderBlockInBuffer(header_data, headers_len, &headers)) {
      DLOG(WARNING) << "Invalid headers";
      Reset(QUIC_BAD_APPLICATION_PAYLOAD);
      return;
    }
    MarkHeadersConsumed(headers_len);
    session_->OnInitialHeadersComplete(id(), headers);

    // The delegate will read the headers via a posted task.
    NotifyDelegateOfHeadersCompleteLater(headers, frame_len);
  }
}

void QuicChromiumClientStream::OnPromiseHeadersComplete(
    QuicStreamId promised_id,
    size_t frame_len) {
  size_t headers_len = decompressed_headers().length();
  SpdyHeaderBlock headers;
  SpdyFramer framer(HTTP2);
  if (!framer.ParseHeaderBlockInBuffer(decompressed_headers().data(),
                                       headers_len, &headers)) {
    DLOG(WARNING) << "Invalid headers";
    Reset(QUIC_BAD_APPLICATION_PAYLOAD);
    return;
  }
  MarkHeadersConsumed(headers_len);

  session_->HandlePromised(id(), promised_id, headers);
}

void QuicChromiumClientStream::OnDataAvailable() {
  if (!FinishedReadingHeaders() || !headers_delivered_) {
    // Buffer the data in the sequencer until the headers have been read.
    return;
  }

  // The delegate will read the data via a posted task, and
  // will be able to, potentially, read all data which has queued up.
  NotifyDelegateOfDataAvailableLater();
}

void QuicChromiumClientStream::OnClose() {
  if (delegate_) {
    delegate_->OnClose(connection_error());
    delegate_ = nullptr;
    delegate_tasks_.clear();
  }
  ReliableQuicStream::OnClose();
}

void QuicChromiumClientStream::OnCanWrite() {
  ReliableQuicStream::OnCanWrite();

  if (!HasBufferedData() && !callback_.is_null()) {
    base::ResetAndReturn(&callback_).Run(OK);
  }
}

size_t QuicChromiumClientStream::WriteHeaders(
    const SpdyHeaderBlock& header_block,
    bool fin,
    QuicAckListenerInterface* ack_notifier_delegate) {
  net_log_.AddEvent(
      NetLog::TYPE_QUIC_CHROMIUM_CLIENT_STREAM_SEND_REQUEST_HEADERS,
      base::Bind(&QuicRequestNetLogCallback, id(), &header_block,
                 QuicSpdyStream::priority()));
  return QuicSpdyStream::WriteHeaders(header_block, fin, ack_notifier_delegate);
}

SpdyPriority QuicChromiumClientStream::priority() const {
  if (delegate_ && delegate_->HasSendHeadersComplete()) {
    return QuicSpdyStream::priority();
  }
  return net::kV3HighestPriority;
}

int QuicChromiumClientStream::WriteStreamData(
    base::StringPiece data,
    bool fin,
    const CompletionCallback& callback) {
  // We should not have data buffered.
  DCHECK(!HasBufferedData());
  // Writes the data, or buffers it.
  WriteOrBufferData(data, fin, nullptr);
  if (!HasBufferedData()) {
    return OK;
  }

  callback_ = callback;
  return ERR_IO_PENDING;
}

int QuicChromiumClientStream::WritevStreamData(
    const std::vector<IOBuffer*>& buffers,
    const std::vector<int>& lengths,
    bool fin,
    const CompletionCallback& callback) {
  // Must not be called when data is buffered.
  DCHECK(!HasBufferedData());
  // Writes the data, or buffers it.
  for (size_t i = 0; i < buffers.size(); ++i) {
    bool is_fin = fin && (i == buffers.size() - 1);
    base::StringPiece string_data(buffers[i]->data(), lengths[i]);
    WriteOrBufferData(string_data, is_fin, nullptr);
  }
  if (!HasBufferedData()) {
    return OK;
  }

  callback_ = callback;
  return ERR_IO_PENDING;
}

void QuicChromiumClientStream::SetDelegate(
    QuicChromiumClientStream::Delegate* delegate) {
  DCHECK(!(delegate_ && delegate));
  delegate_ = delegate;
  while (!delegate_tasks_.empty()) {
    base::Closure closure = delegate_tasks_.front();
    delegate_tasks_.pop_front();
    closure.Run();
  }
  if (delegate == nullptr && sequencer()->IsClosed()) {
    OnFinRead();
  }
}

void QuicChromiumClientStream::OnError(int error) {
  if (delegate_) {
    QuicChromiumClientStream::Delegate* delegate = delegate_;
    delegate_ = nullptr;
    delegate_tasks_.clear();
    delegate->OnError(error);
  }
}

int QuicChromiumClientStream::Read(IOBuffer* buf, int buf_len) {
  if (sequencer()->IsClosed())
    return 0;  // EOF

  if (!HasBytesToRead())
    return ERR_IO_PENDING;

  iovec iov;
  iov.iov_base = buf->data();
  iov.iov_len = buf_len;
  return Readv(&iov, 1);
}

bool QuicChromiumClientStream::CanWrite(const CompletionCallback& callback) {
  bool can_write = session()->connection()->CanWrite(HAS_RETRANSMITTABLE_DATA);
  if (!can_write) {
    session()->MarkConnectionLevelWriteBlocked(id());
    DCHECK(callback_.is_null());
    callback_ = callback;
  }
  return can_write;
}

void QuicChromiumClientStream::NotifyDelegateOfHeadersCompleteLater(
    const SpdyHeaderBlock& headers,
    size_t frame_len) {
  RunOrBuffer(
      base::Bind(&QuicChromiumClientStream::NotifyDelegateOfHeadersComplete,
                 weak_factory_.GetWeakPtr(), headers, frame_len));
}

void QuicChromiumClientStream::NotifyDelegateOfHeadersComplete(
    SpdyHeaderBlock headers,
    size_t frame_len) {
  if (!delegate_)
    return;
  // Only mark trailers consumed when we are about to notify delegate.
  if (headers_delivered_) {
    MarkTrailersConsumed(decompressed_trailers().length());
    net_log_.AddEvent(
        NetLog::TYPE_QUIC_CHROMIUM_CLIENT_STREAM_READ_RESPONSE_TRAILERS,
        base::Bind(&SpdyHeaderBlockNetLogCallback, &headers));
  } else {
    headers_delivered_ = true;
    net_log_.AddEvent(
        NetLog::TYPE_QUIC_CHROMIUM_CLIENT_STREAM_READ_RESPONSE_HEADERS,
        base::Bind(&SpdyHeaderBlockNetLogCallback, &headers));
  }

  delegate_->OnHeadersAvailable(headers, frame_len);
}

void QuicChromiumClientStream::NotifyDelegateOfDataAvailableLater() {
  RunOrBuffer(
      base::Bind(&QuicChromiumClientStream::NotifyDelegateOfDataAvailable,
                 weak_factory_.GetWeakPtr()));
}

void QuicChromiumClientStream::NotifyDelegateOfDataAvailable() {
  if (delegate_)
    delegate_->OnDataAvailable();
}

void QuicChromiumClientStream::RunOrBuffer(base::Closure closure) {
  if (delegate_) {
    base::ThreadTaskRunnerHandle::Get()->PostTask(FROM_HERE, closure);
  } else {
    delegate_tasks_.push_back(closure);
  }
}

void QuicChromiumClientStream::DisableConnectionMigration() {
  can_migrate_ = false;
}

}  // namespace net
