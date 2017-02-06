// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/allocator/allocator_shim_default_dispatch_to_mac_zoned_malloc.h"

#include <utility>

#include "base/allocator/allocator_interception_mac.h"
#include "base/allocator/allocator_shim.h"
#include "base/logging.h"

namespace base {
namespace allocator {

namespace {

// This is the zone that the allocator shim will call to actually perform heap
// allocations. It should be populated with the original, unintercepted default
// malloc zone.
MallocZoneFunctions g_default_zone;

void* MallocImpl(const AllocatorDispatch*, size_t size) {
  return g_default_zone.malloc(malloc_default_zone(), size);
}

void* CallocImpl(const AllocatorDispatch*, size_t n, size_t size) {
  return g_default_zone.calloc(malloc_default_zone(), n, size);
}

void* MemalignImpl(const AllocatorDispatch*, size_t alignment, size_t size) {
  return g_default_zone.memalign(malloc_default_zone(), alignment, size);
}

void* ReallocImpl(const AllocatorDispatch*, void* ptr, size_t size) {
  return g_default_zone.realloc(malloc_default_zone(), ptr, size);
}

void FreeImpl(const AllocatorDispatch*, void* ptr) {
  g_default_zone.free(malloc_default_zone(), ptr);
}

size_t GetSizeEstimateImpl(const AllocatorDispatch*, void* ptr) {
  return g_default_zone.size(malloc_default_zone(), ptr);
}

unsigned BatchMallocImpl(const AllocatorDispatch* self,
                         size_t size,
                         void** results,
                         unsigned num_requested) {
  return g_default_zone.batch_malloc(malloc_default_zone(), size, results,
                                     num_requested);
}

void BatchFreeImpl(const AllocatorDispatch* self,
                   void** to_be_freed,
                   unsigned num_to_be_freed) {
  g_default_zone.batch_free(malloc_default_zone(), to_be_freed,
                            num_to_be_freed);
}

void FreeDefiniteSizeImpl(const AllocatorDispatch* self,
                          void* ptr,
                          size_t size) {
  g_default_zone.free_definite_size(malloc_default_zone(), ptr, size);
}

}  // namespace

void InitializeDefaultDispatchToMacAllocator() {
  StoreFunctionsForDefaultZone(&g_default_zone);
}

const AllocatorDispatch AllocatorDispatch::default_dispatch = {
    &MallocImpl,           /* alloc_function */
    &CallocImpl,           /* alloc_zero_initialized_function */
    &MemalignImpl,         /* alloc_aligned_function */
    &ReallocImpl,          /* realloc_function */
    &FreeImpl,             /* free_function */
    &GetSizeEstimateImpl,  /* get_size_estimate_function */
    &BatchMallocImpl,      /* batch_malloc_function */
    &BatchFreeImpl,        /* batch_free_function */
    &FreeDefiniteSizeImpl, /* free_definite_size_function */
    nullptr,               /* next */
};

}  // namespace allocator
}  // namespace base
