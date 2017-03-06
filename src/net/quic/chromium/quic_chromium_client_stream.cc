// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/chromium/quic_chromium_client_stream.h"

#include <utility>

#include "base/bind_helpers.h"
#include "base/callback_helpers.h"
#include "base/location.h"
#include "base/threading/thread_task_runner_handle.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"
#include "net/log/net_log_event_type.h"
#include "net/quic/chromium/quic_chromium_client_session.h"
#include "net/quic/chromium/quic_http_utils.h"
#include "net/quic/core/quic_spdy_session.h"
#include "net/quic/core/quic_write_blocked_list.h"
#include "net/quic/core/spdy_utils.h"

namespace net {

QuicChromiumClientStream::QuicChromiumClientStream(
    QuicStreamId id,
    QuicClientSessionBase* session,
    const NetLogWithSource& net_log)
    : QuicSpdyStream(id, session),
      net_log_(net_log),
      delegate_(nullptr),
      headers_delivered_(false),
      session_(session),
      can_migrate_(true),
      weak_factory_(this) {}

QuicChromiumClientStream::~QuicChromiumClientStream() {
  if (delegate_)
    delegate_->OnClose();
}

void QuicChromiumClientStream::OnInitialHeadersComplete(
    bool fin,
    size_t frame_len,
    const QuicHeaderList& header_list) {
  QuicSpdyStream::OnInitialHeadersComplete(fin, frame_len, header_list);

  SpdyHeaderBlock header_block;
  int64_t length = -1;
  if (!SpdyUtils::CopyAndValidateHeaders(header_list, &length, &header_block)) {
    DLOG(ERROR) << "Failed to parse header list: " << header_list.DebugString();
    ConsumeHeaderList();
    Reset(QUIC_BAD_APPLICATION_PAYLOAD);
    return;
  }

  ConsumeHeaderList();
  session_->OnInitialHeadersComplete(id(), header_block);

  // The delegate will read the headers via a posted task.
  NotifyDelegateOfHeadersCompleteLater(std::move(header_block), frame_len);
}

void QuicChromiumClientStream::OnTrailingHeadersComplete(
    bool fin,
    size_t frame_len,
    const QuicHeaderList& header_list) {
  QuicSpdyStream::OnTrailingHeadersComplete(fin, frame_len, header_list);
  NotifyDelegateOfHeadersCompleteLater(received_trailers().Clone(), frame_len);
}

void QuicChromiumClientStream::OnPromiseHeaderList(
    QuicStreamId promised_id,
    size_t frame_len,
    const QuicHeaderList& header_list) {
  SpdyHeaderBlock promise_headers;
  int64_t content_length = -1;
  if (!SpdyUtils::CopyAndValidateHeaders(header_list, &content_length,
                                         &promise_headers)) {
    DLOG(ERROR) << "Failed to parse header list: " << header_list.DebugString();
    ConsumeHeaderList();
    Reset(QUIC_BAD_APPLICATION_PAYLOAD);
    return;
  }
  ConsumeHeaderList();

  session_->HandlePromised(id(), promised_id, promise_headers);
}

void QuicChromiumClientStream::OnDataAvailable() {
  if (!FinishedReadingHeaders() || !headers_delivered_) {
    // Buffer the data in the sequencer until the headers have been read.
    return;
  }

  if (!sequencer()->HasBytesToRead() && !FinishedReadingTrailers()) {
    // If there is no data to read, wait until either FIN is received or
    // trailers are delivered.
    return;
  }

  // The delegate will read the data via a posted task, and
  // will be able to, potentially, read all data which has queued up.
  NotifyDelegateOfDataAvailableLater();
}

void QuicChromiumClientStream::OnClose() {
  if (delegate_) {
    delegate_->OnClose();
    delegate_ = nullptr;
    delegate_tasks_.clear();
  }
  QuicStream::OnClose();
}

void QuicChromiumClientStream::OnCanWrite() {
  QuicStream::OnCanWrite();

  if (!HasBufferedData() && !callback_.is_null()) {
    base::ResetAndReturn(&callback_).Run(OK);
  }
}

size_t QuicChromiumClientStream::WriteHeaders(
    SpdyHeaderBlock header_block,
    bool fin,
    QuicReferenceCountedPointer<QuicAckListenerInterface> ack_listener) {
  if (!session()->IsCryptoHandshakeConfirmed()) {
    auto entry = header_block.find(":method");
    DCHECK(entry != header_block.end());
    DCHECK_NE("POST", entry->second);
  }
  net_log_.AddEvent(
      NetLogEventType::QUIC_CHROMIUM_CLIENT_STREAM_SEND_REQUEST_HEADERS,
      base::Bind(&QuicRequestNetLogCallback, id(), &header_block,
                 QuicSpdyStream::priority()));
  return QuicSpdyStream::WriteHeaders(std::move(header_block), fin,
                                      std::move(ack_listener));
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
    const std::vector<scoped_refptr<IOBuffer>>& buffers,
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
  if (delegate == nullptr) {
    DCHECK(delegate_tasks_.empty());
    return;
  }
  while (!delegate_tasks_.empty()) {
    base::Closure closure = delegate_tasks_.front();
    delegate_tasks_.pop_front();
    closure.Run();
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
  if (IsDoneReading())
    return 0;  // EOF

  if (!HasBytesToRead())
    return ERR_IO_PENDING;

  iovec iov;
  iov.iov_base = buf->data();
  iov.iov_len = buf_len;
  size_t bytes_read = Readv(&iov, 1);
  // If no more body bytes and trailers are to be delivered, return
  // ERR_IO_PENDING now because onDataAvailable() will be called after trailers.
  if (bytes_read == 0 && !FinishedReadingTrailers())
    return ERR_IO_PENDING;
  return bytes_read;
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
    SpdyHeaderBlock headers,
    size_t frame_len) {
  RunOrBuffer(base::Bind(
      &QuicChromiumClientStream::NotifyDelegateOfHeadersComplete,
      weak_factory_.GetWeakPtr(), base::Passed(std::move(headers)), frame_len));
}

void QuicChromiumClientStream::NotifyDelegateOfHeadersComplete(
    SpdyHeaderBlock headers,
    size_t frame_len) {
  if (!delegate_)
    return;
  // Only mark trailers consumed when we are about to notify delegate.
  if (headers_delivered_) {
    MarkTrailersConsumed();
    // Post an async task to notify delegate of the FIN flag.
    NotifyDelegateOfDataAvailableLater();
    net_log_.AddEvent(
        NetLogEventType::QUIC_CHROMIUM_CLIENT_STREAM_READ_RESPONSE_TRAILERS,
        base::Bind(&SpdyHeaderBlockNetLogCallback, &headers));
  } else {
    headers_delivered_ = true;
    net_log_.AddEvent(
        NetLogEventType::QUIC_CHROMIUM_CLIENT_STREAM_READ_RESPONSE_HEADERS,
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

bool QuicChromiumClientStream::IsFirstStream() {
  return id() == kHeadersStreamId + 2;
}

}  // namespace net
