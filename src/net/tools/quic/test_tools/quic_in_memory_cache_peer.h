// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_TOOLS_QUIC_TEST_TOOLS_QUIC_IN_MEMORY_CACHE_PEER_H_
#define NET_TOOLS_QUIC_TEST_TOOLS_QUIC_IN_MEMORY_CACHE_PEER_H_

#include "base/macros.h"
#include "net/tools/quic/quic_in_memory_cache.h"

namespace net {
namespace test {

class QuicInMemoryCachePeer {
 public:
  // Resets the singleton QuicInMemoryCache to a fresh state.
  static void ResetForTests();

 private:
  DISALLOW_COPY_AND_ASSIGN(QuicInMemoryCachePeer);
};

}  // namespace test
}  // namespace net

#endif  // NET_TOOLS_QUIC_TEST_TOOLS_QUIC_IN_MEMORY_CACHE_PEER_H_
