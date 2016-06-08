// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_NQE_CACHED_NETWORK_QUALITY_H_
#define NET_NQE_CACHED_NETWORK_QUALITY_H_

#include "base/macros.h"
#include "base/time/time.h"
#include "net/base/net_export.h"
#include "net/nqe/network_quality.h"

namespace net {

namespace nqe {

namespace internal {

// CachedNetworkQuality stores the quality of a previously seen network.
class NET_EXPORT_PRIVATE CachedNetworkQuality {
 public:
  explicit CachedNetworkQuality(const NetworkQuality& network_quality);
  CachedNetworkQuality(const CachedNetworkQuality& other);
  ~CachedNetworkQuality();

  // Returns the network quality associated with this cached entry.
  const NetworkQuality& network_quality() const { return network_quality_; }

  // Returns true if this cache entry was updated before
  // |cached_network_quality|.
  bool OlderThan(const CachedNetworkQuality& cached_network_quality) const;

  // Time when this cache entry was last updated.
  const base::TimeTicks last_update_time_;

  // Quality of this cached network.
  const NetworkQuality network_quality_;

 private:
  DISALLOW_ASSIGN(CachedNetworkQuality);
};

}  // namespace internal

}  // namespace nqe

}  // namespace net

#endif  // NET_NQE_CACHED_NETWORK_QUALITY_H_