// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SPDY_WRITE_SCHEDULER_H_
#define NET_SPDY_WRITE_SCHEDULER_H_

#include <vector>

#include "net/spdy/spdy_protocol.h"

namespace net {

// Abstract superclass for classes that decide which SPDY or HTTP/2 stream to
// write next. Concrete subclasses implement various scheduling policies:
//
// PriorityWriteScheduler: implements SPDY priority-based stream scheduling,
//     where (writable) higher-priority streams are always given precedence
//     over lower-priority streams.
//
// Http2PriorityWriteScheduler: implements SPDY priority-based stream
//     scheduling coupled with the HTTP/2 stream dependency model. This is only
//     intended as a transitional step towards Http2WeightedWriteScheduler.
//
// Http2WeightedWriteScheduler (coming soon): implements the HTTP/2 stream
//     dependency model with weighted stream scheduling, fully conforming to
//     RFC 7540.
//
// The type used to represent stream IDs (StreamIdType) is templated in order
// to allow for use by both SPDY and QUIC codebases. It must be a POD that
// supports comparison (i.e., a numeric type).
//
// Each stream can be in one of two states: ready or not ready (for writing).
// Ready state is changed by calling the MarkStreamReady() and
// MarkStreamNotReady() methods. Only streams in the ready state can be
// returned by PopNextReadyStream(); when returned by that method, the stream's
// state changes to not ready.
template <typename StreamIdType>
class NET_EXPORT_PRIVATE WriteScheduler {
 public:
  virtual ~WriteScheduler() {}

  // Registers new stream |stream_id| with the scheduler, assigning it the
  // given weight, which should be in the range [1, 256]. If the scheduler
  // supports stream dependencies, the stream is inserted into the dependency
  // tree under the specified parent stream.
  //
  // Preconditions: |stream_id| should be unregistered, and |parent_id| should
  // be registered or |kHttp2RootStreamId|.
  virtual void RegisterStream(StreamIdType stream_id,
                              StreamIdType parent_id,
                              int weight,
                              bool exclusive) = 0;

  // Registers a new stream with the scheduler, assigning it the given
  // priority.
  //
  // Preconditions: |stream_id| should be unregistered.
  virtual void RegisterStream(StreamIdType stream_id,
                              SpdyPriority priority) = 0;

  // Unregisters the given stream from the scheduler, which will no longer keep
  // state for it.
  //
  // Preconditions: |stream_id| should be registered.
  virtual void UnregisterStream(StreamIdType stream_id) = 0;

  // Returns true if the given stream is currently registered.
  virtual bool StreamRegistered(StreamIdType stream_id) const = 0;

  // Returns the priority value for the specified stream. If the scheduler uses
  // weights rather than priorities, the returned value is the stream's weight
  // mapped to a SPDY priority.
  //
  // Preconditions: |stream_id| should be registered.
  virtual SpdyPriority GetStreamPriority(StreamIdType stream_id) const = 0;

  // Updates the priority of the given stream.
  //
  // Preconditions: |stream_id| should be registered.
  virtual void UpdateStreamPriority(StreamIdType stream_id,
                                    SpdyPriority priority) = 0;

  // Returns the weight value for the specified stream. If the scheduler uses
  // SPDY priorities rather than weights, the returned value is the stream's
  // SPDY priority mapped to a weight.
  //
  // Preconditions: |stream_id| should be registered.
  virtual int GetStreamWeight(StreamIdType stream_id) const = 0;

  // Updates the weight of the given stream.
  //
  // Preconditions: |stream_id| should be registered.
  virtual void UpdateStreamWeight(StreamIdType stream_id, int weight) = 0;

  // Returns the parent stream of |stream_id|. If the scheduler
  // doesn't support stream dependencies, returns |kHttp2RootStreamId|.
  //
  // Preconditions: |stream_id| should be registered.
  virtual StreamIdType GetStreamParent(StreamIdType stream_id) const = 0;

  // Updates which stream is the parent stream of |stream_id|. If the scheduler
  // doesn't support stream dependencies of the stream, does nothing.
  //
  // Preconditions: |stream_id| should be registered.
  virtual void UpdateStreamParent(StreamIdType stream_id,
                                  StreamIdType parent_id,
                                  bool exclusive) = 0;

  // Returns child streams of the given stream, if any. If the scheduler
  // doesn't support stream dependencies, returns an empty vector.
  //
  // Preconditions: |stream_id| should be registered.
  virtual std::vector<StreamIdType> GetStreamChildren(
      StreamIdType stream_id) const = 0;

  // Records time (in microseconds) of a read/write event for the given
  // stream.
  //
  // Preconditions: |stream_id| should be registered.
  virtual void RecordStreamEventTime(StreamIdType stream_id,
                                     int64_t now_in_usec) = 0;

  // Returns time (in microseconds) of the last read/write event for a stream
  // with higher priority than the priority of the given stream, or 0 if there
  // is no such event.
  //
  // Preconditions: |stream_id| should be registered.
  virtual int64_t GetLatestEventWithPrecedence(
      StreamIdType stream_id) const = 0;

  // If the scheduler has any ready streams, returns the next scheduled
  // ready stream, in the process transitioning the stream from ready to not
  // ready.
  //
  // Preconditions: |HasReadyStreams() == true|
  virtual StreamIdType PopNextReadyStream() = 0;

  // Returns true if there's another stream ahead of the given stream in the
  // scheduling queue.  This function can be called to see if the given stream
  // should yield work to another stream.
  //
  // Preconditions: |stream_id| should be registered.
  virtual bool ShouldYield(StreamIdType stream_id) const = 0;

  // Marks the stream as ready to write. If the stream was already ready, does
  // nothing. If add_to_front is true, the stream is scheduled ahead of other
  // streams of the same priority/weight, otherwise it is scheduled behind them.
  //
  // Preconditions: |stream_id| should be registered.
  virtual void MarkStreamReady(StreamIdType stream_id, bool add_to_front) = 0;

  // Marks the stream as not ready to write. If the stream is not registered or
  // not ready, does nothing.
  //
  // Preconditions: |stream_id| should be registered.
  virtual void MarkStreamNotReady(StreamIdType stream_id) = 0;

  // Returns true iff the scheduler has any ready streams.
  virtual bool HasReadyStreams() const = 0;

  // Returns the number of streams currently marked ready.
  virtual size_t NumReadyStreams() const = 0;
};

// Returns SPDY priority value clamped to the valid range of [0, 7].
NET_EXPORT_PRIVATE SpdyPriority ClampSpdyPriority(SpdyPriority priority);

// Returns HTTP/2 weight clamped to the valid range of [1, 256].
NET_EXPORT_PRIVATE int ClampHttp2Weight(int weight);

// Maps SPDY priority value in range [0, 7] to HTTP/2 weight value in range
// [1, 256], where priority 0 (i.e. highest precedence) corresponds to maximum
// weight 256 and priority 7 (lowest precedence) corresponds to minimum weight
// 1.
NET_EXPORT_PRIVATE int SpdyPriorityToHttp2Weight(SpdyPriority priority);

// Maps HTTP/2 weight value in range [1, 256] to SPDY priority value in range
// [0, 7], where minimum weight 1 corresponds to priority 7 (lowest precedence)
// and maximum weight 256 corresponds to priority 0 (highest precedence).
NET_EXPORT_PRIVATE SpdyPriority Http2WeightToSpdyPriority(int weight);

}  // namespace net

#endif  // NET_SPDY_WRITE_SCHEDULER_H_
