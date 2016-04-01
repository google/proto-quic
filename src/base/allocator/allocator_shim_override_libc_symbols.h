// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Its purpose is to SHIM_ALIAS_SYMBOL the Libc symbols for malloc/new to the
// shim layer entry points.

#ifdef BASE_ALLOCATOR_ALLOCATOR_SHIM_OVERRIDE_LIBC_SYMBOLS_H_
#error This header is meant to be included only once by allocator_shim.cc
#endif
#define BASE_ALLOCATOR_ALLOCATOR_SHIM_OVERRIDE_LIBC_SYMBOLS_H_

#include <malloc.h>

#include "base/allocator/allocator_shim_internals.h"

extern "C" {

SHIM_ALWAYS_EXPORT void* malloc(size_t size) __THROW
    SHIM_ALIAS_SYMBOL(ShimMalloc);

SHIM_ALWAYS_EXPORT void free(void* ptr) __THROW
    SHIM_ALIAS_SYMBOL(ShimFree);

SHIM_ALWAYS_EXPORT void* realloc(void* ptr, size_t size) __THROW
    SHIM_ALIAS_SYMBOL(ShimRealloc);

SHIM_ALWAYS_EXPORT void* calloc(size_t n, size_t size) __THROW
    SHIM_ALIAS_SYMBOL(ShimCalloc);

SHIM_ALWAYS_EXPORT void cfree(void* ptr) __THROW
    SHIM_ALIAS_SYMBOL(ShimFree);

SHIM_ALWAYS_EXPORT void* memalign(size_t align, size_t s) __THROW
    SHIM_ALIAS_SYMBOL(ShimMemalign);

SHIM_ALWAYS_EXPORT void* valloc(size_t size) __THROW
    SHIM_ALIAS_SYMBOL(ShimValloc);

SHIM_ALWAYS_EXPORT void* pvalloc(size_t size) __THROW
    SHIM_ALIAS_SYMBOL(ShimPvalloc);

SHIM_ALWAYS_EXPORT int posix_memalign(void** r, size_t a, size_t s) __THROW
    SHIM_ALIAS_SYMBOL(ShimPosixMemalign);

// The default dispatch translation unit has to define also the following
// symbols (unless they are ultimately routed to the system symbols):
//   void malloc_stats(void);
//   int mallopt(int, int);
//   struct mallinfo mallinfo(void);
//   size_t malloc_size(void*);
//   size_t malloc_usable_size(const void*);

}  // extern "C"
