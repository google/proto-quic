// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/filter/mock_source_stream.h"

#include "base/logging.h"
#include "net/base/io_buffer.h"

namespace net {

MockSourceStream::MockSourceStream()
    : SourceStream(SourceStream::TYPE_NONE),
      awaiting_completion_(false),
      dest_buffer_(nullptr),
      dest_buffer_size_(0) {}

MockSourceStream::~MockSourceStream() {
  DCHECK(!awaiting_completion_);
  DCHECK(results_.empty());
}

int MockSourceStream::Read(IOBuffer* dest_buffer,
                           int buffer_size,
                           const CompletionCallback& callback) {
  DCHECK(!awaiting_completion_);
  DCHECK(!results_.empty());

  if (results_.empty())
    return ERR_UNEXPECTED;

  QueuedResult r = results_.front();
  DCHECK_GE(buffer_size, r.len);
  if (r.mode == ASYNC) {
    awaiting_completion_ = true;
    dest_buffer_ = dest_buffer;
    dest_buffer_size_ = buffer_size;
    callback_ = callback;
    return ERR_IO_PENDING;
  }

  results_.pop();
  memcpy(dest_buffer->data(), r.data, r.len);
  return r.error == OK ? r.len : r.error;
}

std::string MockSourceStream::Description() const {
  return "";
}

MockSourceStream::QueuedResult::QueuedResult(const char* data,
                                             int len,
                                             Error error,
                                             Mode mode)
    : data(data), len(len), error(error), mode(mode) {}

void MockSourceStream::AddReadResult(const char* data,
                                     int len,
                                     Error error,
                                     Mode mode) {
  QueuedResult result(data, len, error, mode);
  results_.push(result);
}

void MockSourceStream::CompleteNextRead() {
  DCHECK(awaiting_completion_);

  awaiting_completion_ = false;
  QueuedResult r = results_.front();
  DCHECK_EQ(ASYNC, r.mode);
  results_.pop();
  DCHECK_GE(dest_buffer_size_, r.len);
  memcpy(dest_buffer_->data(), r.data, r.len);
  dest_buffer_ = nullptr;
  callback_.Run(r.error == OK ? r.len : r.error);
}

}  // namespace net
