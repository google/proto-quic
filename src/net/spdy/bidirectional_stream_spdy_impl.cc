// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/bidirectional_stream_spdy_impl.h"

#include "base/bind.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/time/time.h"
#include "base/timer/timer.h"
#include "net/http/bidirectional_stream_request_info.h"
#include "net/spdy/spdy_buffer.h"
#include "net/spdy/spdy_header_block.h"
#include "net/spdy/spdy_http_utils.h"
#include "net/spdy/spdy_stream.h"

namespace net {

namespace {

// Time to wait in millisecond to notify |delegate_| of data received.
// Handing small chunks of data to the caller creates measurable overhead.
// So buffer data in short time-spans and send a single read notification.
const int kBufferTimeMs = 1;

}  // namespace

BidirectionalStreamSpdyImpl::BidirectionalStreamSpdyImpl(
    const base::WeakPtr<SpdySession>& spdy_session)
    : spdy_session_(spdy_session),
      request_info_(nullptr),
      delegate_(nullptr),
      negotiated_protocol_(kProtoUnknown),
      more_read_data_pending_(false),
      read_buffer_len_(0),
      stream_closed_(false),
      closed_stream_status_(ERR_FAILED),
      closed_stream_received_bytes_(0),
      closed_stream_sent_bytes_(0),
      weak_factory_(this) {}

BidirectionalStreamSpdyImpl::~BidirectionalStreamSpdyImpl() {
  Cancel();
}

void BidirectionalStreamSpdyImpl::Start(
    const BidirectionalStreamRequestInfo* request_info,
    const BoundNetLog& net_log,
    bool /*send_request_headers_automatically*/,
    BidirectionalStreamImpl::Delegate* delegate,
    std::unique_ptr<base::Timer> timer) {
  DCHECK(!stream_);
  DCHECK(timer);

  delegate_ = delegate;
  timer_ = std::move(timer);

  if (!spdy_session_) {
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE,
        base::Bind(&BidirectionalStreamSpdyImpl::NotifyError,
                   weak_factory_.GetWeakPtr(), ERR_CONNECTION_CLOSED));
    return;
  }

  request_info_ = request_info;

  int rv = stream_request_.StartRequest(
      SPDY_BIDIRECTIONAL_STREAM, spdy_session_, request_info_->url,
      request_info_->priority, net_log,
      base::Bind(&BidirectionalStreamSpdyImpl::OnStreamInitialized,
                 weak_factory_.GetWeakPtr()));
  if (rv != ERR_IO_PENDING)
    OnStreamInitialized(rv);
}

void BidirectionalStreamSpdyImpl::SendRequestHeaders() {
  // Request headers will be sent automatically.
  NOTREACHED();
}

int BidirectionalStreamSpdyImpl::ReadData(IOBuffer* buf, int buf_len) {
  if (stream_)
    DCHECK(!stream_->IsIdle());

  DCHECK(buf);
  DCHECK(buf_len);
  DCHECK(!timer_->IsRunning()) << "There should be only one ReadData in flight";

  // If there is data buffered, complete the IO immediately.
  if (!read_data_queue_.IsEmpty()) {
    return read_data_queue_.Dequeue(buf->data(), buf_len);
  } else if (stream_closed_) {
    return closed_stream_status_;
  }
  // Read will complete asynchronously and Delegate::OnReadCompleted will be
  // called upon completion.
  read_buffer_ = buf;
  read_buffer_len_ = buf_len;
  return ERR_IO_PENDING;
}

void BidirectionalStreamSpdyImpl::SendData(const scoped_refptr<IOBuffer>& data,
                                           int length,
                                           bool end_stream) {
  DCHECK(length > 0 || (length == 0 && end_stream));

  if (!stream_) {
    LOG(ERROR) << "Trying to send data after stream has been destroyed.";
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, base::Bind(&BidirectionalStreamSpdyImpl::NotifyError,
                              weak_factory_.GetWeakPtr(), ERR_UNEXPECTED));
    return;
  }

  DCHECK(!stream_closed_);
  stream_->SendData(data.get(), length,
                    end_stream ? NO_MORE_DATA_TO_SEND : MORE_DATA_TO_SEND);
}

void BidirectionalStreamSpdyImpl::SendvData(
    const std::vector<scoped_refptr<IOBuffer>>& buffers,
    const std::vector<int>& lengths,
    bool end_stream) {
  DCHECK_EQ(buffers.size(), lengths.size());

  if (!stream_) {
    LOG(ERROR) << "Trying to send data after stream has been destroyed.";
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, base::Bind(&BidirectionalStreamSpdyImpl::NotifyError,
                              weak_factory_.GetWeakPtr(), ERR_UNEXPECTED));
    return;
  }

  DCHECK(!stream_closed_);
  int total_len = 0;
  for (int len : lengths) {
    total_len += len;
  }

  pending_combined_buffer_ = new net::IOBuffer(total_len);
  int len = 0;
  // TODO(xunjieli): Get rid of extra copy. Coalesce headers and data frames.
  for (size_t i = 0; i < buffers.size(); ++i) {
    memcpy(pending_combined_buffer_->data() + len, buffers[i]->data(),
           lengths[i]);
    len += lengths[i];
  }
  stream_->SendData(pending_combined_buffer_.get(), total_len,
                    end_stream ? NO_MORE_DATA_TO_SEND : MORE_DATA_TO_SEND);
}

void BidirectionalStreamSpdyImpl::Cancel() {
  if (delegate_) {
    delegate_ = nullptr;
    // Cancel any pending callback.
    weak_factory_.InvalidateWeakPtrs();
  }
  ResetStream();
}

NextProto BidirectionalStreamSpdyImpl::GetProtocol() const {
  return negotiated_protocol_;
}

int64_t BidirectionalStreamSpdyImpl::GetTotalReceivedBytes() const {
  if (stream_closed_)
    return closed_stream_received_bytes_;

  if (!stream_)
    return 0;

  return stream_->raw_received_bytes();
}

int64_t BidirectionalStreamSpdyImpl::GetTotalSentBytes() const {
  if (stream_closed_)
    return closed_stream_sent_bytes_;

  if (!stream_)
    return 0;

  return stream_->raw_sent_bytes();
}

void BidirectionalStreamSpdyImpl::OnRequestHeadersSent() {
  DCHECK(stream_);

  negotiated_protocol_ = stream_->GetProtocol();
  if (delegate_)
    delegate_->OnStreamReady(/*request_headers_sent=*/true);
}

SpdyResponseHeadersStatus BidirectionalStreamSpdyImpl::OnResponseHeadersUpdated(
    const SpdyHeaderBlock& response_headers) {
  DCHECK(stream_);

  if (delegate_)
    delegate_->OnHeadersReceived(response_headers);

  return RESPONSE_HEADERS_ARE_COMPLETE;
}

void BidirectionalStreamSpdyImpl::OnDataReceived(
    std::unique_ptr<SpdyBuffer> buffer) {
  DCHECK(stream_);
  DCHECK(!stream_closed_);

  // If |buffer| is null, BidirectionalStreamSpdyImpl::OnClose will be invoked
  // by SpdyStream to indicate the end of stream.
  if (!buffer)
    return;

  // When buffer is consumed, SpdyStream::OnReadBufferConsumed will adjust
  // recv window size accordingly.
  read_data_queue_.Enqueue(std::move(buffer));
  if (read_buffer_) {
    // Handing small chunks of data to the caller creates measurable overhead.
    // So buffer data in short time-spans and send a single read notification.
    ScheduleBufferedRead();
  }
}

void BidirectionalStreamSpdyImpl::OnDataSent() {
  DCHECK(stream_);
  DCHECK(!stream_closed_);

  pending_combined_buffer_ = nullptr;
  if (delegate_)
    delegate_->OnDataSent();
}

void BidirectionalStreamSpdyImpl::OnTrailers(const SpdyHeaderBlock& trailers) {
  DCHECK(stream_);
  DCHECK(!stream_closed_);

  if (delegate_)
    delegate_->OnTrailersReceived(trailers);
}

void BidirectionalStreamSpdyImpl::OnClose(int status) {
  DCHECK(stream_);

  stream_closed_ = true;
  closed_stream_status_ = status;
  closed_stream_received_bytes_ = stream_->raw_received_bytes();
  closed_stream_sent_bytes_ = stream_->raw_sent_bytes();

  if (status != OK) {
    NotifyError(status);
    return;
  }
  ResetStream();
  // Complete any remaining read, as all data has been buffered.
  // If user has not called ReadData (i.e |read_buffer_| is nullptr), this will
  // do nothing.
  timer_->Stop();
  DoBufferedRead();
}

int BidirectionalStreamSpdyImpl::SendRequestHeadersHelper() {
  std::unique_ptr<SpdyHeaderBlock> headers(new SpdyHeaderBlock);
  HttpRequestInfo http_request_info;
  http_request_info.url = request_info_->url;
  http_request_info.method = request_info_->method;
  http_request_info.extra_headers = request_info_->extra_headers;

  CreateSpdyHeadersFromHttpRequest(
      http_request_info, http_request_info.extra_headers,
      stream_->GetProtocolVersion(), true, headers.get());
  return stream_->SendRequestHeaders(std::move(headers),
                                     request_info_->end_stream_on_headers
                                         ? NO_MORE_DATA_TO_SEND
                                         : MORE_DATA_TO_SEND);
}

void BidirectionalStreamSpdyImpl::OnStreamInitialized(int rv) {
  DCHECK_NE(ERR_IO_PENDING, rv);
  if (rv == OK) {
    stream_ = stream_request_.ReleaseStream();
    stream_->SetDelegate(this);
    rv = SendRequestHeadersHelper();
    if (rv == OK) {
      OnRequestHeadersSent();
      return;
    } else if (rv == ERR_IO_PENDING) {
      return;
    }
  }
  NotifyError(rv);
}

void BidirectionalStreamSpdyImpl::NotifyError(int rv) {
  ResetStream();
  if (delegate_) {
    BidirectionalStreamImpl::Delegate* delegate = delegate_;
    delegate_ = nullptr;
    // Cancel any pending callback.
    weak_factory_.InvalidateWeakPtrs();
    delegate->OnFailed(rv);
    // |this| can be null when returned from delegate.
  }
}

void BidirectionalStreamSpdyImpl::ResetStream() {
  if (!stream_)
    return;
  if (!stream_->IsClosed()) {
    // This sends a RST to the remote.
    stream_->DetachDelegate();
    DCHECK(!stream_);
  } else {
    // Stream is already closed, so it is not legal to call DetachDelegate.
    stream_.reset();
  }
}

void BidirectionalStreamSpdyImpl::ScheduleBufferedRead() {
  // If there is already a scheduled DoBufferedRead, don't issue
  // another one. Mark that we have received more data and return.
  if (timer_->IsRunning()) {
    more_read_data_pending_ = true;
    return;
  }

  more_read_data_pending_ = false;
  timer_->Start(FROM_HERE, base::TimeDelta::FromMilliseconds(kBufferTimeMs),
                base::Bind(&BidirectionalStreamSpdyImpl::DoBufferedRead,
                           weak_factory_.GetWeakPtr()));
}

void BidirectionalStreamSpdyImpl::DoBufferedRead() {
  DCHECK(!timer_->IsRunning());
  // Check to see that the stream has not errored out.
  DCHECK(stream_ || stream_closed_);
  DCHECK(!stream_closed_ || closed_stream_status_ == OK);

  // When |more_read_data_pending_| is true, it means that more data has arrived
  // since started waiting. Wait a little longer and continue to buffer.
  if (more_read_data_pending_ && ShouldWaitForMoreBufferedData()) {
    ScheduleBufferedRead();
    return;
  }

  int rv = 0;
  if (read_buffer_) {
    rv = ReadData(read_buffer_.get(), read_buffer_len_);
    DCHECK_NE(ERR_IO_PENDING, rv);
    read_buffer_ = nullptr;
    read_buffer_len_ = 0;
    if (delegate_)
      delegate_->OnDataRead(rv);
  }
}

bool BidirectionalStreamSpdyImpl::ShouldWaitForMoreBufferedData() const {
  if (stream_closed_)
    return false;
  DCHECK_GT(read_buffer_len_, 0);
  return read_data_queue_.GetTotalSize() <
         static_cast<size_t>(read_buffer_len_);
}

}  // namespace net
