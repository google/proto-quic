// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/spdy_buffer_producer.h"

#include <utility>

#include "base/logging.h"
#include "net/spdy/spdy_buffer.h"
#include "net/spdy/spdy_protocol.h"

namespace net {

SpdyBufferProducer::SpdyBufferProducer() {}

SpdyBufferProducer::~SpdyBufferProducer() {}

SimpleBufferProducer::SimpleBufferProducer(std::unique_ptr<SpdyBuffer> buffer)
    : buffer_(std::move(buffer)) {}

SimpleBufferProducer::~SimpleBufferProducer() {}

std::unique_ptr<SpdyBuffer> SimpleBufferProducer::ProduceBuffer() {
  DCHECK(buffer_);
  return std::move(buffer_);
}

}  // namespace net
