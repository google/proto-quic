// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/debug/thread_heap_usage_tracker.h"

#include <stdint.h>
#include <algorithm>
#include <type_traits>

#include "base/allocator/allocator_shim.h"
#include "base/allocator/features.h"
#include "base/logging.h"
#include "base/threading/thread_local_storage.h"
#include "build/build_config.h"

#if defined(OS_MACOSX) || defined(OS_IOS)
#include <malloc/malloc.h>
#else
#include <malloc.h>
#endif

namespace base {
namespace debug {

namespace {

using base::allocator::AllocatorDispatch;

ThreadLocalStorage::StaticSlot g_thread_allocator_usage = TLS_INITIALIZER;

ThreadHeapUsage* const kInitializingSentinel =
    reinterpret_cast<ThreadHeapUsage*>(-1);

bool g_heap_tracking_enabled = false;

// Forward declared as it needs to delegate memory allocation to the next
// lower shim.
ThreadHeapUsage* GetOrCreateThreadUsage();

size_t GetAllocSizeEstimate(const AllocatorDispatch* next, void* ptr) {
  if (ptr == nullptr)
    return 0U;

  return next->get_size_estimate_function(next, ptr);
}

void RecordAlloc(const AllocatorDispatch* next, void* ptr, size_t size) {
  ThreadHeapUsage* usage = GetOrCreateThreadUsage();
  if (usage == nullptr)
    return;

  usage->alloc_ops++;
  size_t estimate = GetAllocSizeEstimate(next, ptr);
  if (size && estimate) {
    // Only keep track of the net number of bytes allocated in the scope if the
    // size estimate function returns sane values, e.g. non-zero.
    usage->alloc_bytes += estimate;
    usage->alloc_overhead_bytes += estimate - size;

    // Record the max outstanding number of bytes, but only if the difference
    // is net positive (e.g. more bytes allocated than freed in the scope).
    if (usage->alloc_bytes > usage->free_bytes) {
      uint64_t allocated_bytes = usage->alloc_bytes - usage->free_bytes;
      if (allocated_bytes > usage->max_allocated_bytes)
        usage->max_allocated_bytes = allocated_bytes;
    }
  } else {
    usage->alloc_bytes += size;
  }
}

void RecordFree(const AllocatorDispatch* next, void* ptr) {
  ThreadHeapUsage* usage = GetOrCreateThreadUsage();
  if (usage == nullptr)
    return;

  size_t estimate = GetAllocSizeEstimate(next, ptr);
  usage->free_ops++;
  usage->free_bytes += estimate;
}

void* AllocFn(const AllocatorDispatch* self, size_t size) {
  void* ret = self->next->alloc_function(self->next, size);
  if (ret != nullptr)
    RecordAlloc(self->next, ret, size);

  return ret;
}

void* AllocZeroInitializedFn(const AllocatorDispatch* self,
                             size_t n,
                             size_t size) {
  void* ret = self->next->alloc_zero_initialized_function(self->next, n, size);
  if (ret != nullptr)
    RecordAlloc(self->next, ret, size);

  return ret;
}

void* AllocAlignedFn(const AllocatorDispatch* self,
                     size_t alignment,
                     size_t size) {
  void* ret = self->next->alloc_aligned_function(self->next, alignment, size);
  if (ret != nullptr)
    RecordAlloc(self->next, ret, size);

  return ret;
}

void* ReallocFn(const AllocatorDispatch* self, void* address, size_t size) {
  if (address != nullptr)
    RecordFree(self->next, address);

  void* ret = self->next->realloc_function(self->next, address, size);
  if (ret != nullptr && size != 0)
    RecordAlloc(self->next, ret, size);

  return ret;
}

void FreeFn(const AllocatorDispatch* self, void* address) {
  if (address != nullptr)
    RecordFree(self->next, address);
  self->next->free_function(self->next, address);
}

size_t GetSizeEstimateFn(const AllocatorDispatch* self, void* address) {
  return self->next->get_size_estimate_function(self->next, address);
}

// The allocator dispatch used to intercept heap operations.
AllocatorDispatch allocator_dispatch = {
    &AllocFn, &AllocZeroInitializedFn, &AllocAlignedFn, &ReallocFn,
    &FreeFn,  &GetSizeEstimateFn,      nullptr};

ThreadHeapUsage* GetOrCreateThreadUsage() {
  ThreadHeapUsage* allocator_usage =
      static_cast<ThreadHeapUsage*>(g_thread_allocator_usage.Get());
  if (allocator_usage == kInitializingSentinel)
    return nullptr;  // Re-entrancy case.

  if (allocator_usage == nullptr) {
    // Prevent reentrancy due to the allocation below.
    g_thread_allocator_usage.Set(kInitializingSentinel);

    allocator_usage = new ThreadHeapUsage;
    memset(allocator_usage, 0, sizeof(*allocator_usage));
    g_thread_allocator_usage.Set(allocator_usage);
  }

  return allocator_usage;
}

}  // namespace

ThreadHeapUsageTracker::ThreadHeapUsageTracker() : thread_usage_(nullptr) {
  static_assert(std::is_pod<ThreadHeapUsage>::value, "Must be POD.");
}

ThreadHeapUsageTracker::~ThreadHeapUsageTracker() {
  DCHECK(thread_checker_.CalledOnValidThread());

  if (thread_usage_ != nullptr) {
    // If this tracker wasn't stopped, make it inclusive so that the
    // usage isn't lost.
    Stop(false);
  }
}

void ThreadHeapUsageTracker::Start() {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK(g_thread_allocator_usage.initialized());

  thread_usage_ = GetOrCreateThreadUsage();
  usage_ = *thread_usage_;

  // Reset the stats for our current scope.
  // The per-thread usage instance now tracks this scope's usage, while this
  // instance persists the outer scope's usage stats. On destruction, this
  // instance will restore the outer scope's usage stats with this scope's
  // usage added.
  memset(thread_usage_, 0, sizeof(*thread_usage_));
}

void ThreadHeapUsageTracker::Stop(bool usage_is_exclusive) {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK_NE(nullptr, thread_usage_);

  ThreadHeapUsage current = *thread_usage_;
  if (usage_is_exclusive) {
    // Restore the outer scope.
    *thread_usage_ = usage_;
  } else {
    // Update the outer scope with the accrued inner usage.
    if (thread_usage_->max_allocated_bytes) {
      uint64_t outer_net_alloc_bytes = usage_.alloc_bytes - usage_.free_bytes;

      thread_usage_->max_allocated_bytes =
          std::max(usage_.max_allocated_bytes,
                   outer_net_alloc_bytes + thread_usage_->max_allocated_bytes);
    }

    thread_usage_->alloc_ops += usage_.alloc_ops;
    thread_usage_->alloc_bytes += usage_.alloc_bytes;
    thread_usage_->alloc_overhead_bytes += usage_.alloc_overhead_bytes;
    thread_usage_->free_ops += usage_.free_ops;
    thread_usage_->free_bytes += usage_.free_bytes;
  }

  thread_usage_ = nullptr;
  usage_ = current;
}

ThreadHeapUsage ThreadHeapUsageTracker::GetUsageSnapshot() {
  DCHECK(g_thread_allocator_usage.initialized());

  ThreadHeapUsage* usage = GetOrCreateThreadUsage();
  DCHECK_NE(nullptr, usage);
  return *usage;
}

void ThreadHeapUsageTracker::EnableHeapTracking() {
  EnsureTLSInitialized();

  CHECK_EQ(false, g_heap_tracking_enabled) << "No double-enabling.";
  g_heap_tracking_enabled = true;
#if BUILDFLAG(USE_EXPERIMENTAL_ALLOCATOR_SHIM)
  base::allocator::InsertAllocatorDispatch(&allocator_dispatch);
#else
  CHECK(false) << "Can't enable heap tracking without the shim.";
#endif  // BUILDFLAG(USE_EXPERIMENTAL_ALLOCATOR_SHIM)
}

bool ThreadHeapUsageTracker::IsHeapTrackingEnabled() {
  return g_heap_tracking_enabled;
}

void ThreadHeapUsageTracker::DisableHeapTrackingForTesting() {
#if BUILDFLAG(USE_EXPERIMENTAL_ALLOCATOR_SHIM)
  base::allocator::RemoveAllocatorDispatchForTesting(&allocator_dispatch);
#else
  CHECK(false) << "Can't disable heap tracking without the shim.";
#endif  // BUILDFLAG(USE_EXPERIMENTAL_ALLOCATOR_SHIM)
  DCHECK_EQ(true, g_heap_tracking_enabled) << "Heap tracking not enabled.";
  g_heap_tracking_enabled = false;
}

base::allocator::AllocatorDispatch*
ThreadHeapUsageTracker::GetDispatchForTesting() {
  return &allocator_dispatch;
}

void ThreadHeapUsageTracker::EnsureTLSInitialized() {
  if (!g_thread_allocator_usage.initialized()) {
    g_thread_allocator_usage.Initialize([](void* allocator_usage) {
      delete static_cast<ThreadHeapUsage*>(allocator_usage);
    });
  }
}

}  // namespace debug
}  // namespace base
