// Copyright (c) 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_PLATFORM_API_QUIC_CONTAINERS_H_
#define NET_QUIC_PLATFORM_API_QUIC_CONTAINERS_H_

#include "net/quic/platform/impl/quic_containers_impl.h"

namespace net {

// A map which offers insertion-ordered iteration.
template <typename Key, typename Value>
using QuicLinkedHashMap = QuicLinkedHashMapImpl<Key, Value>;

// Used for maps that are typically small, then it is faster than (for example)
// hash_map which is optimized for large data sets. QuicSmallMap upgrades itself
// automatically to a QuicSmallMapImpl-specified map when it runs out of space.
template <typename Key, typename Value, int Size>
using QuicSmallMap = QuicSmallMapImpl<Key, Value, Size>;

// A data structure used to represent a sorted set of non-empty, non-adjacent,
// and mutually disjoint intervals.
template <typename T>
using QuicIntervalSet = QuicIntervalSetImpl<T>;

}  // namespace net

#endif  // NET_QUIC_PLATFORM_API_QUIC_CONTAINERS_H_
