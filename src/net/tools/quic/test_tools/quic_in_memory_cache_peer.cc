// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/quic/test_tools/quic_in_memory_cache_peer.h"

#include "net/tools/quic/quic_in_memory_cache.h"

namespace net {
namespace test {

// static
void QuicInMemoryCachePeer::ResetForTests() {
  QuicInMemoryCache::GetInstance()->ResetForTests();
}

}  // namespace test
}  // namespace net
