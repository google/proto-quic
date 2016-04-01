// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/http2_priority_dependencies.h"

namespace net {

Http2PriorityDependencies::Http2PriorityDependencies() {}

Http2PriorityDependencies::~Http2PriorityDependencies() {}

void Http2PriorityDependencies::OnStreamSynSent(
    SpdyStreamId id,
    SpdyPriority priority,
    SpdyStreamId* dependent_stream_id,
    bool* exclusive) {
  DCHECK(entry_by_stream_id_.find(id) == entry_by_stream_id_.end());

  *dependent_stream_id = 0ul;
  *exclusive = true;

  // Find the next highest entry in total order.
  for (int i = priority; i >= kV3HighestPriority; --i) {
    if (!id_priority_lists_[i].empty()) {
      *dependent_stream_id = id_priority_lists_[i].back().first;
      break;
    }
  }

  id_priority_lists_[priority].push_back(std::make_pair(id, priority));
  IdList::iterator it = id_priority_lists_[priority].end();
  --it;
  entry_by_stream_id_[id] = it;
}

void Http2PriorityDependencies::OnStreamDestruction(SpdyStreamId id) {
  EntryMap::iterator emit = entry_by_stream_id_.find(id);

  // This routine may be called without a matching call to
  // OnStreamSynSent above, in the case of server push.  In that case,
  // it's a no-op.
  if (emit == entry_by_stream_id_.end())
    return;

  IdList::iterator it = emit->second;
  id_priority_lists_[it->second].erase(it);
  entry_by_stream_id_.erase(emit);
}

}  // namespace net
