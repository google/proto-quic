// Copyright (c) 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_PLATFORM_IMPL_QUIC_CONTAINERS_IMPL_H_
#define NET_QUIC_PLATFORM_IMPL_QUIC_CONTAINERS_IMPL_H_

#include <unordered_map>

#include "base/containers/small_map.h"
#include "net/base/interval_set.h"
#include "net/base/linked_hash_map.h"

namespace net {

// A map which offers insertion-ordered iteration.
template <typename Key, typename Value>
using QuicLinkedHashMapImpl = linked_hash_map<Key, Value>;

// A map which is faster than (for example) hash_map for a certain number of
// unique key-value-pair elements, and upgrades itself to unordered_map when
// runs out of space.
template <typename Key, typename Value, int Size>
using QuicSmallMapImpl = base::SmallMap<std::unordered_map<Key, Value>, Size>;

// A data structure used to represent a sorted set of non-empty, non-adjacent,
// and mutually disjoint intervals.
template <typename T>
using QuicIntervalSetImpl = IntervalSet<T>;

}  // namespace net

#endif  // NET_QUIC_PLATFORM_IMPL_QUIC_CONTAINERS_IMPL_H_
