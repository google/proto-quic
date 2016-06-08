// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/nqe/cached_network_quality.h"

namespace net {

namespace nqe {

namespace internal {

CachedNetworkQuality::CachedNetworkQuality(
    const NetworkQuality& network_quality)
    : last_update_time_(base::TimeTicks::Now()),
      network_quality_(network_quality) {}

CachedNetworkQuality::CachedNetworkQuality(const CachedNetworkQuality& other)
    : last_update_time_(other.last_update_time_),
      network_quality_(other.network_quality_) {}

CachedNetworkQuality::~CachedNetworkQuality() {}

bool CachedNetworkQuality::OlderThan(
    const CachedNetworkQuality& cached_network_quality) const {
  return last_update_time_ < cached_network_quality.last_update_time_;
}

}  // namespace internal

}  // namespace nqe

}  // namespace net