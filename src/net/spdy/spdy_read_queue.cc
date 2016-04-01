// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/spdy_read_queue.h"

#include "base/logging.h"
#include "base/stl_util.h"
#include "net/spdy/spdy_buffer.h"

namespace net {

SpdyReadQueue::SpdyReadQueue() : total_size_(0) {}

SpdyReadQueue::~SpdyReadQueue() {
  Clear();
}

bool SpdyReadQueue::IsEmpty() const {
  DCHECK_EQ(queue_.empty(), total_size_ == 0);
  return queue_.empty();
}

size_t SpdyReadQueue::GetTotalSize() const {
  return total_size_;
}

void SpdyReadQueue::Enqueue(scoped_ptr<SpdyBuffer> buffer) {
  DCHECK_GT(buffer->GetRemainingSize(), 0u);
  total_size_ += buffer->GetRemainingSize();
  queue_.push_back(buffer.release());
}

size_t SpdyReadQueue::Dequeue(char* out, size_t len) {
  DCHECK_GT(len, 0u);
  size_t bytes_copied = 0;
  while (!queue_.empty() && bytes_copied < len) {
    SpdyBuffer* buffer = queue_.front();
    size_t bytes_to_copy =
        std::min(len - bytes_copied, buffer->GetRemainingSize());
    memcpy(out + bytes_copied, buffer->GetRemainingData(), bytes_to_copy);
    bytes_copied += bytes_to_copy;
    if (bytes_to_copy == buffer->GetRemainingSize()) {
      delete queue_.front();
      queue_.pop_front();
    } else {
      buffer->Consume(bytes_to_copy);
    }
  }
  total_size_ -= bytes_copied;
  return bytes_copied;
}

void SpdyReadQueue::Clear() {
  STLDeleteElements(&queue_);
}

}  // namespace net
