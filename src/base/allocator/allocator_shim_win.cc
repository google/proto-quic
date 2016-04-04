// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// The allocator shim is only enabled in Release Static builds.
// This #if is needed as gyp can't have different compile
// targets between Debug and Release.
// TODO(wfh): Remove this once gyp is dead.
#if defined(ALLOCATOR_SHIM)

#include <limits.h>
#include <malloc.h>
#include <new.h>
#include <windows.h>
#include <stddef.h>

#include "allocator_shim_win.h"

// This shim make it possible to perform additional checks on allocations
// before passing them to the Heap functions.

// Override heap functions to perform additional checks:
// 1. Enforcing the maximum size that can be allocated to 2Gb.
// 2. Calling new_handler if malloc fails

// See definitions of original functions in ucrt\corecrt_malloc.h in SDK
// include directory.

namespace base {
namespace allocator {
bool g_is_win_shim_layer_initialized = false;
}  // namespace allocator
}  // namespace base

namespace {

const size_t kWindowsPageSize = 4096;
const size_t kMaxWindowsAllocation = INT_MAX - kWindowsPageSize;
int new_mode = 0;

inline HANDLE get_heap_handle() {
  return reinterpret_cast<HANDLE>(_get_heap_handle());
}

void* win_heap_malloc(size_t size) {
  if (size < kMaxWindowsAllocation)
    return HeapAlloc(get_heap_handle(), 0, size);
  return nullptr;
}

void win_heap_free(void* size) {
  HeapFree(get_heap_handle(), 0, size);
}

void* win_heap_realloc(void* ptr, size_t size) {
  if (!ptr)
    return win_heap_malloc(size);
  if (!size) {
    win_heap_free(ptr);
    return nullptr;
  }
  if (size < kMaxWindowsAllocation)
    return HeapReAlloc(get_heap_handle(), 0, ptr, size);
  return nullptr;
}

// Call the new handler, if one has been set.
// Returns true on successfully calling the handler, false otherwise.
inline bool call_new_handler(bool nothrow, size_t size) {
  // Get the current new handler.
  _PNH nh = _query_new_handler();
#if defined(_HAS_EXCEPTIONS) && !_HAS_EXCEPTIONS
  if (!nh)
    return false;
  // Since exceptions are disabled, we don't really know if new_handler
  // failed.  Assume it will abort if it fails.
  return nh(size) ? true : false;
#else
#error "Exceptions in allocator shim are not supported!"
#endif  // defined(_HAS_EXCEPTIONS) && !_HAS_EXCEPTIONS
}

}  // namespace

extern "C" {

// Symbol to allow weak linkage to win_heap_malloc from memory_win.cc.
void* (*malloc_unchecked)(size_t) = &win_heap_malloc;

// This function behaves similarly to MSVC's _set_new_mode.
// If flag is 0 (default), calls to malloc will behave normally.
// If flag is 1, calls to malloc will behave like calls to new,
// and the std_new_handler will be invoked on failure.
// Returns the previous mode.
//
// Replaces _set_new_mode in ucrt\heap\new_mode.cpp
int _set_new_mode(int flag) {
  // The MS CRT calls this function early on in startup, so this serves as a low
  // overhead proof that the allocator shim is in place for this process.
  base::allocator::g_is_win_shim_layer_initialized = true;
  int old_mode = new_mode;
  new_mode = flag;
  return old_mode;
}

// Replaces _query_new_mode in ucrt\heap\new_mode.cpp
int _query_new_mode() {
  return new_mode;
}

// Replaces malloc in ucrt\heap\malloc.cpp
__declspec(restrict) void* malloc(size_t size) {
  void* ptr;
  for (;;) {
    ptr = win_heap_malloc(size);
    if (ptr)
      return ptr;

    if (!new_mode || !call_new_handler(true, size))
      break;
  }
  return ptr;
}

// Replaces free in ucrt\heap\free.cpp
void free(void* p) {
  win_heap_free(p);
  return;
}

// Replaces realloc in ucrt\heap\realloc.cpp
__declspec(restrict) void* realloc(void* ptr, size_t size) {
  // Webkit is brittle for allocators that return NULL for malloc(0).  The
  // realloc(0, 0) code path does not guarantee a non-NULL return, so be sure
  // to call malloc for this case.
  if (!ptr)
    return malloc(size);

  void* new_ptr;
  for (;;) {
    new_ptr = win_heap_realloc(ptr, size);

    // Subtle warning:  NULL return does not alwas indicate out-of-memory.  If
    // the requested new size is zero, realloc should free the ptr and return
    // NULL.
    if (new_ptr || !size)
      return new_ptr;
    if (!new_mode || !call_new_handler(true, size))
      break;
  }
  return new_ptr;
}

// Replaces calloc in ucrt\heap\calloc.cpp
__declspec(restrict) void* calloc(size_t n, size_t elem_size) {
  // Overflow check.
  const size_t size = n * elem_size;
  if (elem_size != 0 && size / elem_size != n)
    return nullptr;

  void* result = malloc(size);
  if (result) {
    memset(result, 0, size);
  }
  return result;
}

}  // extern C

#endif  // defined(ALLOCATOR_SHIM)
