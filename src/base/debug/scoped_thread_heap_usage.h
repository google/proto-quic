// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_DEBUG_SCOPED_THREAD_HEAP_USAGE_H_
#define BASE_DEBUG_SCOPED_THREAD_HEAP_USAGE_H_

#include <stdint.h>

#include "base/allocator/features.h"
#include "base/base_export.h"
#include "base/threading/thread_checker.h"

namespace base {
namespace allocator {
struct AllocatorDispatch;
}  // namespace allocator

namespace debug {

// By keeping a tally on heap operations, it's possible to track:
// - the number of alloc/free operations, where a realloc is zero or one
//   of each, depending on the input parameters (see man realloc).
// - the number of bytes allocated/freed.
// - the number of estimated bytes of heap overhead used.
// - the high-watermark amount of bytes allocated in the scope.
// This in turn allows measuring the memory usage and memory usage churn over
// a scope. Scopes must be cleanly nested, and each scope must be
// destroyed on the thread where it's created.
//
// Note that this depends on the capabilities of the underlying heap shim. If
// that shim can not yield a size estimate for an allocation, it's not possible
// to keep track of overhead, freed bytes and the allocation high water mark.
class BASE_EXPORT ScopedThreadHeapUsage {
 public:
  struct ThreadAllocatorUsage {
    // The cumulative number of allocation operations.
    uint64_t alloc_ops;

    // The cumulative number of allocated bytes. Where available, this is
    // inclusive heap padding and estimated or actual heap overhead.
    uint64_t alloc_bytes;

    // Where available, cumulative number of heap padding heap
    // and overhead bytes.
    uint64_t alloc_overhead_bytes;

    // The cumulative number of free operations.
    uint64_t free_ops;

    // The cumulative number of bytes freed.
    // Only recorded if the underlying heap shim can return the size of an
    // allocation.
    uint64_t free_bytes;

    // The maximal value of alloc_bytes - free_bytes seen for this thread.
    // Only recorded if the underlying heap shim supports returning the size of
    // an allocation.
    uint64_t max_allocated_bytes;
  };

  ScopedThreadHeapUsage();
  ~ScopedThreadHeapUsage();

  const ThreadAllocatorUsage& usage_at_creation() const {
    return usage_at_creation_;
  }

  // Returns this thread's allocator usage from the creation of the innermost
  // enclosing ScopedThreadHeapUsage instance, if any. Note that this is
  // inclusive allocator usage in all inner scopes.
  static ThreadAllocatorUsage CurrentUsage();

  // Initializes the TLS machinery this class uses. Must be called before
  // creating instances of this class.
  static void Initialize();

  // Enables the heap intercept. May only be called once, and only if the heap
  // shim is available, e.g. if BUILDFLAG(USE_EXPERIMENTAL_ALLOCATOR_SHIM) is
  // true.
  static void EnableHeapTracking();

 protected:
  // Exposed for testing only - note that it's safe to re-EnableHeapTracking()
  // after calling this function in tests.
  static void DisableHeapTrackingForTesting();

  // Exposed to allow testing the shim without inserting it in the allocator
  // shim chain.
  static base::allocator::AllocatorDispatch* GetDispatchForTesting();

 private:
  static void EnsureTLSInitialized();

  ThreadChecker thread_checker_;
  // The allocator usage captured at creation of this instance.
  ThreadAllocatorUsage usage_at_creation_;
};

}  // namespace debug
}  // namespace base

#endif  // BASE_DEBUG_SCOPED_THREAD_HEAP_USAGE_H_