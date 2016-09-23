// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/debug/scoped_thread_heap_usage.h"

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

ScopedThreadHeapUsage::ThreadAllocatorUsage* const kInitializingSentinel =
    reinterpret_cast<ScopedThreadHeapUsage::ThreadAllocatorUsage*>(-1);

bool g_heap_tracking_enabled = false;

// Forward declared as it needs to delegate memory allocation to the next
// lower shim.
ScopedThreadHeapUsage::ThreadAllocatorUsage* GetOrCreateThreadUsage();

size_t GetAllocSizeEstimate(const AllocatorDispatch* next, void* ptr) {
  if (ptr == nullptr)
    return 0U;

  return next->get_size_estimate_function(next, ptr);
}

void RecordAlloc(const AllocatorDispatch* next, void* ptr, size_t size) {
  ScopedThreadHeapUsage::ThreadAllocatorUsage* usage = GetOrCreateThreadUsage();
  if (usage == nullptr)
    return;

  usage->alloc_ops++;
  size_t estimate = GetAllocSizeEstimate(next, ptr);
  if (size && estimate) {
    usage->alloc_bytes += estimate;
    usage->alloc_overhead_bytes += estimate - size;

    // Only keep track of the net number of bytes allocated in the scope if the
    // size estimate function returns sane values, e.g. non-zero.
    uint64_t allocated_bytes = usage->alloc_bytes - usage->free_bytes;
    if (allocated_bytes > usage->max_allocated_bytes)
      usage->max_allocated_bytes = allocated_bytes;
  } else {
    usage->alloc_bytes += size;
  }
}

void RecordFree(const AllocatorDispatch* next, void* ptr) {
  ScopedThreadHeapUsage::ThreadAllocatorUsage* usage = GetOrCreateThreadUsage();
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

ScopedThreadHeapUsage::ThreadAllocatorUsage* GetOrCreateThreadUsage() {
  ScopedThreadHeapUsage::ThreadAllocatorUsage* allocator_usage =
      static_cast<ScopedThreadHeapUsage::ThreadAllocatorUsage*>(
          g_thread_allocator_usage.Get());
  if (allocator_usage == kInitializingSentinel)
    return nullptr;  // Re-entrancy case.

  if (allocator_usage == nullptr) {
    // Prevent reentrancy due to the allocation below.
    g_thread_allocator_usage.Set(kInitializingSentinel);

    allocator_usage = new ScopedThreadHeapUsage::ThreadAllocatorUsage;
    memset(allocator_usage, 0, sizeof(*allocator_usage));
    g_thread_allocator_usage.Set(allocator_usage);
  }

  return allocator_usage;
}

}  // namespace

ScopedThreadHeapUsage::ScopedThreadHeapUsage() {
  // Initialize must be called before creating instances of this class.
  CHECK(g_thread_allocator_usage.initialized());

  ThreadAllocatorUsage* usage = GetOrCreateThreadUsage();
  usage_at_creation_ = *usage;

  // Reset the stats for our current scope.
  // The per-thread usage instance now tracks this scope's usage, while this
  // instance persists the outer scope's usage stats. On destruction, this
  // instance will restore the outer scope's usage stats with this scope's usage
  // added.
  memset(usage, 0, sizeof(*usage));

  static_assert(std::is_pod<ThreadAllocatorUsage>::value, "Must be POD.");
}

ScopedThreadHeapUsage::~ScopedThreadHeapUsage() {
  DCHECK(thread_checker_.CalledOnValidThread());

  ThreadAllocatorUsage* usage = GetOrCreateThreadUsage();

  // Update the outer max.
  if (usage->max_allocated_bytes) {
    uint64_t outer_net_alloc_bytes =
        usage_at_creation_.alloc_bytes - usage_at_creation_.free_bytes;

    usage->max_allocated_bytes =
        std::max(usage_at_creation_.max_allocated_bytes,
                 outer_net_alloc_bytes + usage->max_allocated_bytes);
  }

  usage->alloc_ops += usage_at_creation_.alloc_ops;
  usage->alloc_bytes += usage_at_creation_.alloc_bytes;
  usage->alloc_overhead_bytes += usage_at_creation_.alloc_overhead_bytes;
  usage->free_ops += usage_at_creation_.free_ops;
  usage->free_bytes += usage_at_creation_.free_bytes;
}

ScopedThreadHeapUsage::ThreadAllocatorUsage
ScopedThreadHeapUsage::CurrentUsage() {
  ThreadAllocatorUsage* usage = GetOrCreateThreadUsage();
  return *usage;
}

void ScopedThreadHeapUsage::Initialize() {
  if (!g_thread_allocator_usage.initialized()) {
    g_thread_allocator_usage.Initialize([](void* allocator_usage) {
      delete static_cast<ScopedThreadHeapUsage::ThreadAllocatorUsage*>(
          allocator_usage);
    });
  }
}

void ScopedThreadHeapUsage::EnableHeapTracking() {
  CHECK_EQ(false, g_heap_tracking_enabled) << "No double-enabling.";
  g_heap_tracking_enabled = true;
#if BUILDFLAG(USE_EXPERIMENTAL_ALLOCATOR_SHIM)
  base::allocator::InsertAllocatorDispatch(&allocator_dispatch);
#else
  CHECK(false) << "Can't enable heap tracking without the shim.";
#endif  // BUILDFLAG(USE_EXPERIMENTAL_ALLOCATOR_SHIM)
}

void ScopedThreadHeapUsage::DisableHeapTrackingForTesting() {
#if BUILDFLAG(USE_EXPERIMENTAL_ALLOCATOR_SHIM)
  base::allocator::RemoveAllocatorDispatchForTesting(&allocator_dispatch);
#else
  CHECK(false) << "Can't disable heap tracking without the shim.";
#endif  // BUILDFLAG(USE_EXPERIMENTAL_ALLOCATOR_SHIM)
  DCHECK_EQ(true, g_heap_tracking_enabled) << "Heap tracking not enabled.";
  g_heap_tracking_enabled = false;
}

base::allocator::AllocatorDispatch*
ScopedThreadHeapUsage::GetDispatchForTesting() {
  return &allocator_dispatch;
}

}  // namespace debug
}  // namespace base
