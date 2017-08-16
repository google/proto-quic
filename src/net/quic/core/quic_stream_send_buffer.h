// Copyright (c) 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_CORE_QUIC_STREAM_SEND_BUFFER_H_
#define NET_QUIC_CORE_QUIC_STREAM_SEND_BUFFER_H_

#include <deque>

#include "net/quic/core/frames/quic_stream_frame.h"
#include "net/quic/core/quic_iovector.h"

namespace net {

namespace test {
class QuicStreamSendBufferPeer;
}  // namespace test

class QuicDataWriter;

// QuicStreamDataSlice comprises information of a piece of stream data.
struct QuicStreamDataSlice {
  QuicStreamDataSlice(UniqueStreamBuffer data,
                      QuicStreamOffset offset,
                      QuicByteCount data_length);
  QuicStreamDataSlice(const QuicStreamDataSlice& other) = delete;
  QuicStreamDataSlice(QuicStreamDataSlice&& other) = delete;
  ~QuicStreamDataSlice();

  // Stream data of this data slice.
  UniqueStreamBuffer data;
  // Location of this data slice in the stream.
  QuicStreamOffset offset;
  // Length of this data slice in bytes.
  QuicByteCount data_length;
  // Length of payload which is outstanding and waiting for acks.
  QuicByteCount outstanding_data_length;
};

// QuicStreamSendBuffer contains a list of QuicStreamDataSlices. New data slices
// are added to the tail of the list. Data slices are removed from the head of
// the list when they get fully acked. Stream data can be retrieved and acked
// across slice boundaries.
class QUIC_EXPORT_PRIVATE QuicStreamSendBuffer {
 public:
  explicit QuicStreamSendBuffer(QuicBufferAllocator* allocator);
  QuicStreamSendBuffer(const QuicStreamSendBuffer& other) = delete;
  QuicStreamSendBuffer(QuicStreamSendBuffer&& other) = delete;
  ~QuicStreamSendBuffer();

  // Save |data_length| of data starts at |iov_offset| in |iov| to send buffer.
  void SaveStreamData(QuicIOVector iov,
                      size_t iov_offset,
                      QuicByteCount data_length);

  // Write |data_length| of data starts at |offset|.
  bool WriteStreamData(QuicStreamOffset offset,
                       QuicByteCount data_length,
                       QuicDataWriter* writer);

  // Called when data [offset, offset + data_length) is acked or removed as
  // stream is canceled. Removes fully acked data slice from send buffer.
  void RemoveStreamFrame(QuicStreamOffset offset, QuicByteCount data_length);

  // Number of data slices in send buffer.
  size_t size() const;

  QuicStreamOffset stream_offset() const { return stream_offset_; }

 private:
  friend class test::QuicStreamSendBufferPeer;
  // Save |data_length| of data starts at |iov_offset| in |iov| to one data
  // slice which contains data in a contiguous memory space.
  void SaveStreamDataOneSlice(QuicIOVector iov,
                              size_t iov_offset,
                              QuicByteCount data_length);

  std::deque<QuicStreamDataSlice> send_buffer_;

  // Offset of next inserted byte.
  QuicStreamOffset stream_offset_;

  QuicBufferAllocator* allocator_;
};

}  // namespace net

#endif  // NET_QUIC_CORE_QUIC_STREAM_SEND_BUFFER_H_
