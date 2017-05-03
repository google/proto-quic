// Copyright (c) 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quartc/quartc_stream.h"

#include "net/quic/platform/api/quic_string_piece.h"

namespace net {

QuartcStream::QuartcStream(QuicStreamId id, QuicSession* session)
    : QuicStream(id, session) {}
QuartcStream::~QuartcStream() {}

void QuartcStream::OnDataAvailable() {
  struct iovec iov;
  while (sequencer()->GetReadableRegions(&iov, 1) == 1) {
    DCHECK(delegate_);
    delegate_->OnReceived(this, reinterpret_cast<const char*>(iov.iov_base),
                          iov.iov_len);
    sequencer()->MarkConsumed(iov.iov_len);
  }
  // All the data has been received if the sequencer is closed.
  // Notify the delegate by calling the callback function one more time with
  // iov_len = 0.
  if (sequencer()->IsClosed()) {
    delegate_->OnReceived(this, reinterpret_cast<const char*>(iov.iov_base), 0);
  }
}

void QuartcStream::OnClose() {
  QuicStream::OnClose();
  DCHECK(delegate_);
  delegate_->OnClose(this, connection_error());
}

void QuartcStream::OnCanWrite() {
  QuicStream::OnCanWrite();
  DCHECK(delegate_);
  delegate_->OnBufferedAmountDecrease(this);
}

uint32_t QuartcStream::stream_id() {
  return id();
}

uint64_t QuartcStream::buffered_amount() {
  return queued_data_bytes();
}

bool QuartcStream::fin_sent() {
  return QuicStream::fin_sent();
}

void QuartcStream::Write(const char* data,
                         size_t size,
                         const WriteParameters& param) {
  WriteOrBufferData(QuicStringPiece(data, size), param.fin, nullptr);
}

void QuartcStream::Close() {
  QuicStream::session()->CloseStream(id());
}

void QuartcStream::SetDelegate(QuartcStreamInterface::Delegate* delegate) {
  if (delegate_) {
    LOG(WARNING) << "The delegate for Stream " << id()
                 << " has already been set.";
  }
  delegate_ = delegate;
  DCHECK(delegate_);
}

}  // namespace net
