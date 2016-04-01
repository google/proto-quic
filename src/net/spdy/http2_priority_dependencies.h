// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_HTTP2_PRIORITY_DEPENDENCIES_H_
#define NET_HTTP2_PRIORITY_DEPENDENCIES_H_

#include <list>
#include <map>

#include "net/spdy/spdy_protocol.h"

namespace net {

// A helper class encapsulating the state and logic to set dependencies of
// HTTP2 streams based on their SpdyPriority and the ordering
// of creation and deletion of the streams.
class NET_EXPORT_PRIVATE Http2PriorityDependencies {
 public:
  Http2PriorityDependencies();
  ~Http2PriorityDependencies();

  // Called when a stream SYN is sent to the server.  Note that in the
  // case of server push, a stream may be created without this routine
  // being called.  In such cases, the client ignores the stream's priority
  // (as the server is effectively overriding the client's notions of
  // priority anyway).
  // On return, |*dependent_stream_id| is set to the stream id that
  // this stream should be made dependent on, and |*exclusive| set to
  // whether that dependency should be exclusive.
  void OnStreamSynSent(SpdyStreamId id,
                       SpdyPriority priority,
                       SpdyStreamId* dependent_stream_id,
                       bool* exclusive);

  void OnStreamDestruction(SpdyStreamId id);

 private:
  // The requirements for the internal data structure for this class are:
  //     a) Constant time insertion of entries at the end of the list,
  //     b) Fast removal of any entry based on its id.
  //     c) Constant time lookup of the entry at the end of the list.
  // std::list would satisfy (a) & (c), but some form of map is
  // needed for (b).  The priority must be included in the map
  // entries so that deletion can determine which list in id_priority_lists_
  // to erase from.
  using IdList = std::list<std::pair<SpdyStreamId, SpdyPriority>>;
  using EntryMap = std::map<SpdyStreamId, IdList::iterator>;

  IdList id_priority_lists_[kV3LowestPriority + 1];

  // Tracks the location of an id anywhere in the above vector of lists.
  // Iterators to list elements remain valid until those particular elements
  // are erased.
  EntryMap entry_by_stream_id_;
};

}  // namespace net

#endif  // NET_HTTP2_PRIORITY_DEPENDENCIES_H_
