// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SPDY_SPDY_WRITE_QUEUE_H_
#define NET_SPDY_SPDY_WRITE_QUEUE_H_

#include <deque>
#include <memory>

#include "base/macros.h"
#include "base/memory/weak_ptr.h"
#include "net/base/net_export.h"
#include "net/base/request_priority.h"
#include "net/spdy/spdy_protocol.h"

namespace net {

class SpdyBufferProducer;
class SpdyStream;

// A queue of SpdyBufferProducers to produce frames to write. Ordered
// by priority, and then FIFO.
class NET_EXPORT_PRIVATE SpdyWriteQueue {
 public:
  SpdyWriteQueue();
  ~SpdyWriteQueue();

  // Returns whether there is anything in the write queue,
  // i.e. whether the next call to Dequeue will return true.
  bool IsEmpty() const;

  // Enqueues the given frame producer of the given type at the given
  // priority associated with the given stream, which may be NULL if
  // the frame producer is not associated with a stream. If |stream|
  // is non-NULL, its priority must be equal to |priority|, and it
  // must remain non-NULL until the write is dequeued or removed.
  void Enqueue(RequestPriority priority,
               SpdyFrameType frame_type,
               std::unique_ptr<SpdyBufferProducer> frame_producer,
               const base::WeakPtr<SpdyStream>& stream);

  // Dequeues the frame producer with the highest priority that was
  // enqueued the earliest and its associated stream. Returns true and
  // fills in |frame_type|, |frame_producer|, and |stream| if
  // successful -- otherwise, just returns false.
  bool Dequeue(SpdyFrameType* frame_type,
               std::unique_ptr<SpdyBufferProducer>* frame_producer,
               base::WeakPtr<SpdyStream>* stream);

  // Removes all pending writes for the given stream, which must be
  // non-NULL.
  void RemovePendingWritesForStream(const base::WeakPtr<SpdyStream>& stream);

  // Removes all pending writes for streams after |last_good_stream_id|
  // and streams with no stream id.
  void RemovePendingWritesForStreamsAfter(SpdyStreamId last_good_stream_id);

  // Removes all pending writes.
  void Clear();

  // Returns the estimate of dynamically allocated memory in bytes.
  size_t EstimateMemoryUsage() const;

 private:
  // A struct holding a frame producer and its associated stream.
  struct PendingWrite {
    SpdyFrameType frame_type;
    std::unique_ptr<SpdyBufferProducer> frame_producer;
    base::WeakPtr<SpdyStream> stream;
    // Whether |stream| was non-NULL when enqueued.
    bool has_stream;

    PendingWrite();
    PendingWrite(SpdyFrameType frame_type,
                 std::unique_ptr<SpdyBufferProducer> frame_producer,
                 const base::WeakPtr<SpdyStream>& stream);
    ~PendingWrite();
    PendingWrite(PendingWrite&& other);
    PendingWrite& operator=(PendingWrite&& other);

    size_t EstimateMemoryUsage() const;

    DISALLOW_COPY_AND_ASSIGN(PendingWrite);
  };

  bool removing_writes_;

  // The actual write queue, binned by priority.
  std::deque<PendingWrite> queue_[NUM_PRIORITIES];

  DISALLOW_COPY_AND_ASSIGN(SpdyWriteQueue);
};

}  // namespace net

#endif  // NET_SPDY_SPDY_WRITE_QUEUE_H_
