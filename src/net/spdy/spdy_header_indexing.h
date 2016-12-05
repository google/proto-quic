// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SPDY_SPDY_HEADER_INDEXING_H_
#define NET_SPDY_SPDY_HEADER_INDEXING_H_

#include <stdint.h>
#include <memory>
#include <string>
#include <unordered_set>
#include <utility>

#include "base/strings/string_piece.h"
#include "net/base/net_export.h"

namespace net {

namespace test {
class HeaderIndexingPeer;
}

NET_EXPORT_PRIVATE extern int32_t FLAGS_gfe_spdy_indexing_set_bound;
NET_EXPORT_PRIVATE extern int32_t FLAGS_gfe_spdy_tracking_set_bound;

// Maintain two headers sets: Indexing set and tracking
// set. Call ShouldIndex() for each header to decide if to index it. If for some
// connections, we decide to index all headers, we may still want to call
// UpdateSets to log the headers into both sets.
class NET_EXPORT HeaderIndexing {
 public:
  using HeaderSet = std::unordered_set<std::string>;

  HeaderIndexing();
  ~HeaderIndexing();

  void CreateInitIndexingHeaders();

  // Decide if a header should be indexed. We only use |header|. Add |value| to
  // be consistent with HPACK indexing policy interface.
  bool ShouldIndex(base::StringPiece header, base::StringPiece value);

  // Not to make the indexing decision but to update sets.
  void UpdateSets(base::StringPiece header, base::StringPiece value) {
    update_only_header_count_++;
    ShouldIndex(header, value);
  }

  int64_t total_header_count() { return total_header_count_; }
  int64_t update_only_header_count() { return update_only_header_count_; }
  int64_t missed_headers_in_indexing() { return missed_header_in_indexing_; }
  int64_t missed_headers_in_tracking() { return missed_header_in_tracking_; }

 private:
  friend class test::HeaderIndexingPeer;
  void TryInsertHeader(std::string&& header, HeaderSet* set, size_t bound);
  // Headers to index.
  HeaderSet indexing_set_;
  // Headers seen so far.
  HeaderSet tracking_set_;
  const size_t indexing_set_bound_;
  const size_t tracking_set_bound_;
  int64_t total_header_count_ = 0;
  int64_t update_only_header_count_ = 0;
  int64_t missed_header_in_indexing_ = 0;
  int64_t missed_header_in_tracking_ = 0;
};

}  // namespace net

#endif  // NET_SPDY_SPDY_HEADER_INDEXING_H_
