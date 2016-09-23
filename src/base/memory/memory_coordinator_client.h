// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_MEMORY_MEMORY_COORDINATOR_CLIENT_H_
#define BASE_MEMORY_MEMORY_COORDINATOR_CLIENT_H_

#include "base/base_export.h"

namespace base {

// MemoryState is an indicator that processes can use to guide their memory
// allocation policies. For example, a process that receives the suspended
// state can use that as as signal to drop memory caches.
enum class MemoryState {
  // The state is unknown.
  UNKNOWN = -1,
  // No memory constraints.
  NORMAL = 0,
  // Running and interactive but allocation should be throttled.
  THROTTLED = 1,
  // Still resident in memory but core processing logic has been suspended.
  SUSPENDED = 2,
};

// This is an interface for components which can respond to memory status
// changes.
class BASE_EXPORT MemoryCoordinatorClient {
 public:
  virtual ~MemoryCoordinatorClient() {}

  // Called when memory state has changed.
  virtual void OnMemoryStateChange(MemoryState state) = 0;
};

}  // namespace base

#endif  // BASE_MEMORY_MEMORY_COORDINATOR_CLIENT_H_
