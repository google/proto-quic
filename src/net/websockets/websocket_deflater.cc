// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/websockets/websocket_deflater.h"

#include <string.h>
#include <algorithm>
#include <deque>
#include <vector>

#include "base/logging.h"
#include "net/base/io_buffer.h"
#include "third_party/zlib/zlib.h"

namespace net {

WebSocketDeflater::WebSocketDeflater(ContextTakeOverMode mode)
    : mode_(mode), are_bytes_added_(false) {}

WebSocketDeflater::~WebSocketDeflater() {
  if (stream_) {
    deflateEnd(stream_.get());
    stream_.reset(NULL);
  }
}

bool WebSocketDeflater::Initialize(int window_bits) {
  DCHECK(!stream_);
  stream_.reset(new z_stream);

  DCHECK_LE(8, window_bits);
  DCHECK_GE(15, window_bits);
  memset(stream_.get(), 0, sizeof(*stream_));
  int result = deflateInit2(stream_.get(),
                            Z_DEFAULT_COMPRESSION,
                            Z_DEFLATED,
                            -window_bits,  // Negative value for raw deflate
                            8,  // default mem level
                            Z_DEFAULT_STRATEGY);
  if (result != Z_OK) {
    deflateEnd(stream_.get());
    stream_.reset();
    return false;
  }
  const size_t kFixedBufferSize = 4096;
  fixed_buffer_.resize(kFixedBufferSize);
  return true;
}

bool WebSocketDeflater::AddBytes(const char* data, size_t size) {
  if (!size)
    return true;

  are_bytes_added_ = true;
  stream_->next_in = reinterpret_cast<Bytef*>(const_cast<char*>(data));
  stream_->avail_in = size;

  int result = Deflate(Z_NO_FLUSH);
  DCHECK(result != Z_BUF_ERROR || !stream_->avail_in);
  return result == Z_BUF_ERROR;
}

bool WebSocketDeflater::Finish() {
  if (!are_bytes_added_) {
    // Since consecutive calls of deflate with Z_SYNC_FLUSH and no input
    // lead to an error, we create and return the output for the empty input
    // manually.
    buffer_.push_back('\x00');
    ResetContext();
    return true;
  }
  stream_->next_in = NULL;
  stream_->avail_in = 0;

  int result = Deflate(Z_SYNC_FLUSH);
  // Deflate returning Z_BUF_ERROR means that it's successfully flushed and
  // blocked for input data.
  if (result != Z_BUF_ERROR) {
    ResetContext();
    return false;
  }
  // Remove 4 octets from the tail as the specification requires.
  if (CurrentOutputSize() < 4) {
    ResetContext();
    return false;
  }
  buffer_.resize(buffer_.size() - 4);
  ResetContext();
  return true;
}

void WebSocketDeflater::PushSyncMark() {
  DCHECK(!are_bytes_added_);
  const char data[] = {'\x00', '\x00', '\xff', '\xff'};
  buffer_.insert(buffer_.end(), &data[0], &data[sizeof(data)]);
}

scoped_refptr<IOBufferWithSize> WebSocketDeflater::GetOutput(size_t size) {
  size_t length_to_copy = std::min(size, buffer_.size());
  std::deque<char>::iterator begin = buffer_.begin();
  std::deque<char>::iterator end = begin + length_to_copy;

  scoped_refptr<IOBufferWithSize> result = new IOBufferWithSize(length_to_copy);
  std::copy(begin, end, result->data());
  buffer_.erase(begin, end);
  return result;
}

void WebSocketDeflater::ResetContext() {
  if (mode_ == DO_NOT_TAKE_OVER_CONTEXT)
    deflateReset(stream_.get());
  are_bytes_added_ = false;
}

int WebSocketDeflater::Deflate(int flush) {
  int result = Z_OK;
  do {
    stream_->next_out = reinterpret_cast<Bytef*>(&fixed_buffer_[0]);
    stream_->avail_out = fixed_buffer_.size();
    result = deflate(stream_.get(), flush);
    size_t size = fixed_buffer_.size() - stream_->avail_out;
    buffer_.insert(buffer_.end(), &fixed_buffer_[0], &fixed_buffer_[0] + size);
  } while (result == Z_OK);
  return result;
}

}  // namespace net
