// Copyright (c) 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_CORE_QUIC_STREAM_FRAME_DATA_PRODUCER_H_
#define NET_QUIC_CORE_QUIC_STREAM_FRAME_DATA_PRODUCER_H_

#include "net/quic/core/quic_iovector.h"
#include "net/quic/core/quic_types.h"

namespace net {

class QuicDataWriter;

// Pure virtual class to save and retrieve stream data.
class QUIC_EXPORT_PRIVATE QuicStreamFrameDataProducer {
 public:
  virtual ~QuicStreamFrameDataProducer() {}

  // Save |data_length| data starts at |iov_offset| in |iov|.
  virtual void SaveStreamData(QuicStreamId id,
                              QuicIOVector iov,
                              size_t iov_offset,
                              QuicStreamOffset offset,
                              QuicByteCount data_length) = 0;

  // Let |writer| write |data_length| data with |offset| of stream |id|. Returns
  // false when the writing fails either because stream is closed or
  // corresponding data is failed to be retrieved. This method allows writing a
  // single stream frame from data that spans multiple buffers.
  virtual bool WriteStreamData(QuicStreamId id,
                               QuicStreamOffset offset,
                               QuicByteCount data_length,
                               QuicDataWriter* writer) = 0;
};

}  // namespace net

#endif  // NET_QUIC_CORE_QUIC_STREAM_FRAME_DATA_PRODUCER_H_
