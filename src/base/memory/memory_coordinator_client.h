// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_MEMORY_MEMORY_COORDINATOR_CLIENT_H_
#define BASE_MEMORY_MEMORY_COORDINATOR_CLIENT_H_

#include "base/base_export.h"

namespace base {

// OVERVIEW:
//
// MemoryCoordinatorClient is an interface which a component can implement to
// respond to memory state changes. Unlike MemoryPressureListener, this is a
// stateful mechanism and clients receive notifications only when memory states
// are changed. State transitions are throttled to avoid thrashing; the exact
// throttling period is platform dependent, but will be at least 5-10 seconds.
// Clients are expected to make changes in memory usage that persist for the
// duration of the memory state.

// MemoryState is an indicator that processes can use to guide their memory
// allocation policies. For example, a process that receives the suspended
// state can use that as as signal to drop memory caches.
enum class MemoryState {
  // The state is unknown.
  UNKNOWN = -1,
  // No memory constraints.
  NORMAL = 0,
  // Running and interactive but allocation should be throttled.
  // Clients should free up any memory that is used as an optimization but
  // that is not necessary for the process to run (e.g. caches).
  THROTTLED = 1,
  // Still resident in memory but core processing logic has been suspended.
  // Clients should free up any memory that is used as an optimization, or
  // any memory whose contents can be reproduced when transitioning out of
  // the suspended state (e.g. parsed resource that can be reloaded from disk).
  SUSPENDED = 2,
};

// Returns a string representation of MemoryState.
BASE_EXPORT const char* MemoryStateToString(MemoryState state);

// This is an interface for components which can respond to memory status
// changes. An initial state is NORMAL. See MemoryCoordinatorClientRegistry for
// threading guarantees and ownership management.
class BASE_EXPORT MemoryCoordinatorClient {
 public:
  // Called when memory state has changed. Any transition can occur except for
  // UNKNOWN. General guidelines are:
  //  * NORMAL:    Restore the default settings for memory allocation/usage if
  //               it has changed.
  //  * THROTTLED: Use smaller limits for memory allocations and caches.
  //  * SUSPENDED: Purge memory.
  virtual void OnMemoryStateChange(MemoryState state) = 0;

protected:
  virtual ~MemoryCoordinatorClient() {}
};

}  // namespace base

#endif  // BASE_MEMORY_MEMORY_COORDINATOR_CLIENT_H_
