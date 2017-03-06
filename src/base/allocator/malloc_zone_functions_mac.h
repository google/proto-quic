// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_ALLOCATOR_MALLOC_ZONE_FUNCTIONS_MAC_H_
#define BASE_ALLOCATOR_MALLOC_ZONE_FUNCTIONS_MAC_H_

#include <malloc/malloc.h>
#include <stddef.h>

#include "base/base_export.h"
#include "base/logging.h"
#include "third_party/apple_apsl/malloc.h"

namespace base {
namespace allocator {

typedef void* (*malloc_type)(struct _malloc_zone_t* zone, size_t size);
typedef void* (*calloc_type)(struct _malloc_zone_t* zone,
                             size_t num_items,
                             size_t size);
typedef void* (*valloc_type)(struct _malloc_zone_t* zone, size_t size);
typedef void (*free_type)(struct _malloc_zone_t* zone, void* ptr);
typedef void* (*realloc_type)(struct _malloc_zone_t* zone,
                              void* ptr,
                              size_t size);
typedef void* (*memalign_type)(struct _malloc_zone_t* zone,
                               size_t alignment,
                               size_t size);
typedef unsigned (*batch_malloc_type)(struct _malloc_zone_t* zone,
                                      size_t size,
                                      void** results,
                                      unsigned num_requested);
typedef void (*batch_free_type)(struct _malloc_zone_t* zone,
                                void** to_be_freed,
                                unsigned num_to_be_freed);
typedef void (*free_definite_size_type)(struct _malloc_zone_t* zone,
                                        void* ptr,
                                        size_t size);
typedef size_t (*size_fn_type)(struct _malloc_zone_t* zone, const void* ptr);

struct MallocZoneFunctions {
  MallocZoneFunctions();
  malloc_type malloc = nullptr;
  calloc_type calloc = nullptr;
  valloc_type valloc = nullptr;
  free_type free = nullptr;
  realloc_type realloc = nullptr;
  memalign_type memalign = nullptr;
  batch_malloc_type batch_malloc = nullptr;
  batch_free_type batch_free = nullptr;
  free_definite_size_type free_definite_size = nullptr;
  size_fn_type size = nullptr;
  const ChromeMallocZone* context = nullptr;
};

void StoreZoneFunctions(const ChromeMallocZone* zone,
                        MallocZoneFunctions* functions);
static constexpr int kMaxZoneCount = 30;
BASE_EXPORT extern MallocZoneFunctions* g_malloc_zones;

// The array g_malloc_zones stores all information about malloc zones before
// they are shimmed. This information needs to be accessed during dispatch back
// into the zone, and additional zones may be added later in the execution fo
// the program, so the array needs to be both thread-safe and high-performance.
//
// We begin by creating an array of MallocZoneFunctions of fixed size. We will
// never modify the container, which provides thread-safety to iterators.  When
// we want to add a MallocZoneFunctions to the container, we:
//   1. Fill in all the fields.
//   2. Update the total zone count.
//   3. Insert a memory barrier.
//   4. Insert our shim.
//
// Each MallocZoneFunctions is uniquely identified by |context|, which is a
// pointer to the original malloc zone. When we wish to dispatch back to the
// original malloc zones, we iterate through the array, looking for a matching
// |context|.
//
// Most allocations go through the default allocator. We will ensure that the
// default allocator is stored as the first MallocZoneFunctions.
BASE_EXPORT void StoreMallocZone(ChromeMallocZone* zone);
BASE_EXPORT bool IsMallocZoneAlreadyStored(ChromeMallocZone* zone);

BASE_EXPORT int GetMallocZoneCountForTesting();
BASE_EXPORT void ClearAllMallocZonesForTesting();

inline MallocZoneFunctions& GetFunctionsForZone(void* zone) {
  for (unsigned int i = 0; i < kMaxZoneCount; ++i) {
    if (g_malloc_zones[i].context == zone)
      return g_malloc_zones[i];
  }
  IMMEDIATE_CRASH();
}

}  // namespace allocator
}  // namespace base

#endif  // BASE_ALLOCATOR_MALLOC_ZONE_FUNCTIONS_MAC_H_
