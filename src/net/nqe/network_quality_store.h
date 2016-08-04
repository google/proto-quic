// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_NQE_NETWORK_QUALITY_STORE_H_
#define NET_NQE_NETWORK_QUALITY_STORE_H_

#include <map>

#include "base/macros.h"
#include "base/threading/thread_checker.h"
#include "net/base/net_export.h"
#include "net/nqe/cached_network_quality.h"
#include "net/nqe/network_id.h"

namespace net {

namespace nqe {

namespace internal {

// NetworkQualityStore holds the network qualities of different networks in
// memory. Entries are stored in LRU order, and older entries may be evicted.
class NET_EXPORT_PRIVATE NetworkQualityStore {
 public:
  NetworkQualityStore();
  ~NetworkQualityStore();

  // Stores the network quality |cached_network_quality| of network with ID
  // |network_id|.
  void Add(const nqe::internal::NetworkID& network_id,
           const nqe::internal::CachedNetworkQuality& cached_network_quality);

  // Returns true if the network quality estimate was successfully read
  // for a network with ID |network_id|, and sets |cached_network_quality| to
  // the estimate read.
  bool GetById(const nqe::internal::NetworkID& network_id,
               nqe::internal::CachedNetworkQuality* cached_network_quality);

 private:
  // Maximum size of the store that holds network quality estimates.
  // A smaller size may reduce the cache hit rate due to frequent evictions.
  // A larger size may affect performance.
  static const size_t kMaximumNetworkQualityCacheSize = 10;

  // This does not use an unordered_map or hash_map for code simplicity (the key
  // just implements operator<, rather than hash and equality) and because the
  // map is tiny.
  typedef std::map<nqe::internal::NetworkID,
                   nqe::internal::CachedNetworkQuality>
      CachedNetworkQualities;

  // Data structure that stores the qualities of networks.
  CachedNetworkQualities cached_network_qualities_;

  base::ThreadChecker thread_checker_;

  DISALLOW_COPY_AND_ASSIGN(NetworkQualityStore);
};

}  // namespace internal

}  // namespace nqe

}  // namespace net

#endif  // NET_NQE_NETWORK_QUALITY_STORE_H_
