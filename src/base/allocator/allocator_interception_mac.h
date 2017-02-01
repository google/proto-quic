// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_ALLOCATOR_ALLOCATOR_INTERCEPTION_MAC_H_
#define BASE_ALLOCATOR_ALLOCATOR_INTERCEPTION_MAC_H_

#include <malloc/malloc.h>
#include <stddef.h>

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

struct MallocZoneFunctions {
  malloc_type malloc = nullptr;
  calloc_type calloc = nullptr;
  valloc_type valloc = nullptr;
  free_type free = nullptr;
  realloc_type realloc = nullptr;
  memalign_type memalign = nullptr;
};

// Saves the function pointers currently used by |zone| into |functions|.
void StoreZoneFunctions(ChromeMallocZone* zone, MallocZoneFunctions* functions);

// Updates the malloc zone to use the functions specified by |functions|.
void ReplaceZoneFunctions(ChromeMallocZone* zone,
                          const MallocZoneFunctions* functions);

// Calls the original implementation of malloc/calloc prior to interception.
bool UncheckedMallocMac(size_t size, void** result);
bool UncheckedCallocMac(size_t num_items, size_t size, void** result);

// Intercepts calls to default and purgeable malloc zones. Intercepts Core
// Foundation and Objective-C allocations.
void InterceptAllocationsMac();
}  // namespace allocator
}  // namespace base

#endif  // BASE_ALLOCATOR_ALLOCATOR_INTERCEPTION_MAC_H_
