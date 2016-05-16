// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SPDY_PRIORITY_WRITE_SCHEDULER_H_
#define NET_SPDY_PRIORITY_WRITE_SCHEDULER_H_

#include <stddef.h>
#include <stdint.h>

#include <algorithm>
#include <deque>
#include <unordered_map>
#include <utility>
#include <vector>

#include "base/logging.h"
#include "net/spdy/spdy_bug_tracker.h"
#include "net/spdy/spdy_protocol.h"
#include "net/spdy/write_scheduler.h"

namespace net {

namespace test {
template <typename StreamIdType>
class PriorityWriteSchedulerPeer;
}

// WriteScheduler implementation that manages the order in which streams are
// written using the SPDY priority scheme described at:
// https://www.chromium.org/spdy/spdy-protocol/spdy-protocol-draft3-1#TOC-2.3.3-Stream-priority
//
// Internally, PriorityWriteScheduler consists of 8 PriorityInfo objects, one
// for each priority value.  Each PriorityInfo contains a list of streams of
// that priority that are ready to write, as well as a timestamp of the last
// I/O event that occurred for a stream of that priority.
template <typename StreamIdType>
class PriorityWriteScheduler : public WriteScheduler<StreamIdType> {
 public:
  // Creates scheduler with no streams.
  PriorityWriteScheduler() = default;

  void RegisterStream(StreamIdType stream_id,
                      StreamIdType parent_id,
                      int weight,
                      bool exclusive) override {
    // parent_id not used here, but may as well validate it
    SPDY_BUG_IF(parent_id != kHttp2RootStreamId && !StreamRegistered(parent_id))
        << "Stream " << parent_id << " not registered";
    RegisterStream(stream_id, Http2WeightToSpdyPriority(weight));
  }

  void RegisterStream(StreamIdType stream_id, SpdyPriority priority) override {
    if (stream_id == kHttp2RootStreamId) {
      SPDY_BUG << "Stream " << kHttp2RootStreamId << " already registered";
      return;
    }
    priority = ClampSpdyPriority(priority);
    StreamInfo stream_info = {priority, false};
    bool inserted =
        stream_infos_.insert(std::make_pair(stream_id, stream_info)).second;
    SPDY_BUG_IF(!inserted) << "Stream " << stream_id << " already registered";
  }

  void UnregisterStream(StreamIdType stream_id) override {
    auto it = stream_infos_.find(stream_id);
    if (it == stream_infos_.end()) {
      SPDY_BUG << "Stream " << stream_id << " not registered";
      return;
    }
    StreamInfo& stream_info = it->second;
    if (stream_info.ready) {
      bool erased =
          Erase(&priority_infos_[stream_info.priority].ready_list, stream_id);
      DCHECK(erased);
    }
    stream_infos_.erase(it);
  }

  bool StreamRegistered(StreamIdType stream_id) const override {
    return stream_infos_.find(stream_id) != stream_infos_.end();
  }

  SpdyPriority GetStreamPriority(StreamIdType stream_id) const override {
    auto it = stream_infos_.find(stream_id);
    if (it == stream_infos_.end()) {
      SPDY_BUG << "Stream " << stream_id << " not registered";
      return kV3LowestPriority;
    }
    return it->second.priority;
  }

  void UpdateStreamPriority(StreamIdType stream_id,
                            SpdyPriority priority) override {
    auto it = stream_infos_.find(stream_id);
    if (it == stream_infos_.end()) {
      SPDY_BUG << "Stream " << stream_id << " not registered";
      return;
    }
    StreamInfo& stream_info = it->second;
    if (stream_info.priority == priority) {
      return;
    }
    if (stream_info.ready) {
      bool erased =
          Erase(&priority_infos_[stream_info.priority].ready_list, stream_id);
      DCHECK(erased);
      priority_infos_[priority].ready_list.push_back(stream_id);
    }
    stream_info.priority = priority;
  }

  int GetStreamWeight(StreamIdType stream_id) const override {
    return SpdyPriorityToHttp2Weight(GetStreamPriority(stream_id));
  }

  void UpdateStreamWeight(StreamIdType stream_id, int weight) override {
    UpdateStreamPriority(stream_id, Http2WeightToSpdyPriority(weight));
  }

  StreamIdType GetStreamParent(StreamIdType stream_id) const override {
    return kHttp2RootStreamId;
  }

  void UpdateStreamParent(StreamIdType stream_id,
                          StreamIdType parent_id,
                          bool exclusive) override {}

  std::vector<StreamIdType> GetStreamChildren(
      StreamIdType stream_id) const override {
    return std::vector<StreamIdType>();
  }

  void RecordStreamEventTime(StreamIdType stream_id,
                             int64_t now_in_usec) override {
    auto it = stream_infos_.find(stream_id);
    if (it == stream_infos_.end()) {
      SPDY_BUG << "Stream " << stream_id << " not registered";
      return;
    }
    PriorityInfo& priority_info = priority_infos_[it->second.priority];
    priority_info.last_event_time_usec =
        std::max(priority_info.last_event_time_usec, now_in_usec);
  }

  int64_t GetLatestEventWithPrecedence(StreamIdType stream_id) const override {
    auto it = stream_infos_.find(stream_id);
    if (it == stream_infos_.end()) {
      SPDY_BUG << "Stream " << stream_id << " not registered";
      return 0;
    }
    int64_t last_event_time_usec = 0;
    const StreamInfo& stream_info = it->second;
    for (SpdyPriority p = kV3HighestPriority; p < stream_info.priority; ++p) {
      last_event_time_usec = std::max(last_event_time_usec,
                                      priority_infos_[p].last_event_time_usec);
    }
    return last_event_time_usec;
  }

  StreamIdType PopNextReadyStream() override {
    StreamIdType stream_id = 0;
    for (SpdyPriority p = kV3HighestPriority; p <= kV3LowestPriority; ++p) {
      StreamIdList& ready_list = priority_infos_[p].ready_list;
      if (!ready_list.empty()) {
        stream_id = ready_list.front();
        ready_list.pop_front();

        auto it = stream_infos_.find(stream_id);
        if (it == stream_infos_.end()) {
          SPDY_BUG << "Missing StreamInfo for stream " << stream_id;
        } else {
          it->second.ready = false;
        }
        return stream_id;
      }
    }
    SPDY_BUG << "No ready streams available";
    return stream_id;
  }

  bool ShouldYield(StreamIdType stream_id) const override {
    auto it = stream_infos_.find(stream_id);
    if (it == stream_infos_.end()) {
      SPDY_BUG << "Stream " << stream_id << " not registered";
      return false;
    }

    // If there's a higher priority stream, this stream should yield.
    const StreamInfo& stream_info = it->second;
    for (SpdyPriority p = kV3HighestPriority; p < stream_info.priority; ++p) {
      if (!priority_infos_[p].ready_list.empty()) {
        return true;
      }
    }

    // If this priority level is empty, or this stream is the next up, there's
    // no need to yield.
    auto ready_list = priority_infos_[it->second.priority].ready_list;
    if (ready_list.empty() || ready_list.front() == stream_id) {
      return false;
    }

    // There are other streams in this priority level which take precedence.
    // Yield.
    return true;
  }

  void MarkStreamReady(StreamIdType stream_id, bool add_to_front) override {
    auto it = stream_infos_.find(stream_id);
    if (it == stream_infos_.end()) {
      SPDY_BUG << "Stream " << stream_id << " not registered";
      return;
    }
    StreamInfo& stream_info = it->second;
    if (stream_info.ready) {
      return;
    }
    StreamIdList& ready_list = priority_infos_[stream_info.priority].ready_list;
    if (add_to_front) {
      ready_list.push_front(stream_id);
    } else {
      ready_list.push_back(stream_id);
    }
    stream_info.ready = true;
  }

  void MarkStreamNotReady(StreamIdType stream_id) override {
    auto it = stream_infos_.find(stream_id);
    if (it == stream_infos_.end()) {
      SPDY_BUG << "Stream " << stream_id << " not registered";
      return;
    }
    StreamInfo& stream_info = it->second;
    if (!stream_info.ready) {
      return;
    }
    bool erased =
        Erase(&priority_infos_[stream_info.priority].ready_list, stream_id);
    DCHECK(erased);
    stream_info.ready = false;
  }

  // Returns true iff the number of ready streams is non-zero.
  bool HasReadyStreams() const override {
    for (SpdyPriority i = kV3HighestPriority; i <= kV3LowestPriority; ++i) {
      if (!priority_infos_[i].ready_list.empty()) {
        return true;
      }
    }
    return false;
  }

  // Returns the number of ready streams.
  size_t NumReadyStreams() const override {
    size_t n = 0;
    for (SpdyPriority i = kV3HighestPriority; i <= kV3LowestPriority; ++i) {
      n += priority_infos_[i].ready_list.size();
    }
    return n;
  }

 private:
  friend class test::PriorityWriteSchedulerPeer<StreamIdType>;

  // 0(1) size lookup, 0(1) insert at front or back.
  typedef std::deque<StreamIdType> StreamIdList;

  // State kept for all registered streams. All ready streams have ready = true
  // and should be present in priority_infos_[priority].ready_list.
  struct StreamInfo {
    SpdyPriority priority;
    bool ready;
  };

  // State kept for each priority level.
  struct PriorityInfo {
    // IDs of streams that are ready to write.
    StreamIdList ready_list;
    // Time of latest write event for stream of this priority, in microseconds.
    int64_t last_event_time_usec = 0;
  };

  typedef std::unordered_map<StreamIdType, StreamInfo> StreamInfoMap;

  // Erases first occurrence (which should be the only one) of |stream_id| in
  // |ready_list|, returning true if found (and erased), or false otherwise.
  bool Erase(StreamIdList* ready_list, StreamIdType stream_id) {
    auto it = std::find(ready_list->begin(), ready_list->end(), stream_id);
    if (it == ready_list->end()) {
      return false;
    }
    ready_list->erase(it);
    return true;
  }

  // Per-priority state, including ready lists.
  PriorityInfo priority_infos_[kV3LowestPriority + 1];
  // StreamInfos for all registered streams.
  StreamInfoMap stream_infos_;
};

}  // namespace net

#endif  // NET_SPDY_PRIORITY_WRITE_SCHEDULER_H_
