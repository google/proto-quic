// Copyright (c) 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <algorithm>

#include "net/quic/core/crypto/crypto_protocol.h"
#include "net/quic/core/quic_data_writer.h"
#include "net/quic/core/quic_stream_send_buffer.h"
#include "net/quic/core/quic_utils.h"
#include "net/quic/platform/api/quic_bug_tracker.h"

namespace net {

QuicStreamDataSlice::QuicStreamDataSlice(UniqueStreamBuffer data,
                                         QuicStreamOffset offset,
                                         QuicByteCount data_length)
    : data(std::move(data)),
      offset(offset),
      data_length(data_length),
      data_length_waiting_for_acks(data_length) {}

QuicStreamDataSlice::~QuicStreamDataSlice() {}

QuicStreamSendBuffer::QuicStreamSendBuffer(QuicBufferAllocator* allocator)
    : allocator_(allocator) {}

QuicStreamSendBuffer::~QuicStreamSendBuffer() {}

void QuicStreamSendBuffer::SaveStreamData(QuicIOVector iov,
                                          size_t iov_offset,
                                          QuicStreamOffset offset,
                                          QuicByteCount data_length) {
  DCHECK_LE(iov_offset + data_length, iov.total_length);
  UniqueStreamBuffer buffer = NewStreamBuffer(allocator_, data_length);
  QuicUtils::CopyToBuffer(iov, iov_offset, data_length, buffer.get());
  send_buffer_.emplace_back(std::move(buffer), offset, data_length);
}

bool QuicStreamSendBuffer::WriteStreamData(QuicStreamOffset offset,
                                           QuicByteCount data_length,
                                           QuicDataWriter* writer) {
  for (const QuicStreamDataSlice& slice : send_buffer_) {
    if (offset < slice.offset) {
      break;
    }
    if (offset >= slice.offset + slice.data_length) {
      continue;
    }
    QuicByteCount slice_offset = offset - slice.offset;
    QuicByteCount copy_length =
        std::min(data_length, slice.data_length - slice_offset);
    if (!writer->WriteBytes(slice.data.get() + slice_offset, copy_length)) {
      return false;
    }
    offset += copy_length;
    data_length -= copy_length;
  }

  return data_length == 0;
}

void QuicStreamSendBuffer::RemoveStreamFrame(QuicStreamOffset offset,
                                             QuicByteCount data_length) {
  DCHECK_LT(0u, data_length);
  for (QuicStreamDataSlice& slice : send_buffer_) {
    if (offset < slice.offset) {
      break;
    }
    if (offset >= slice.offset + slice.data_length) {
      continue;
    }
    QuicByteCount slice_offset = offset - slice.offset;
    QuicByteCount removing_length =
        std::min(data_length, slice.data_length - slice_offset);
    slice.data_length_waiting_for_acks -= removing_length;
    offset += removing_length;
    data_length -= removing_length;
  }
  DCHECK_EQ(0u, data_length);

  // Remove data which stops waiting for acks. Please note, data can be
  // acked out of order, but send buffer is cleaned up in order.
  while (!send_buffer_.empty() &&
         send_buffer_.front().data_length_waiting_for_acks == 0) {
    send_buffer_.pop_front();
  }
}

size_t QuicStreamSendBuffer::size() const {
  return send_buffer_.size();
}

}  // namespace net
